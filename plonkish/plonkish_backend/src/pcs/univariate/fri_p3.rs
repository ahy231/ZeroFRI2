use rayon::iter::ParallelBridge;

use crate::util::fake_extension::MyFr;
use crate::{
    pcs::{AdditiveCommitment, Commitment, Evaluation, Point, PolynomialCommitmentScheme},
    poly::{
        univariate::{CoefficientBasis, UnivariatePolynomial},
        Polynomial,
    },
    util::{
        arithmetic::{div_ceil, horner, inner_product, steps, BatchInvert, Field, PrimeField},
        code::{Brakedown, BrakedownSpec, LinearCodes},
        expression::{Expression, Query, Rotation},
        hash::{Hash, Output},
        parallel::{num_threads, parallelize, parallelize_iter},
        transcript::{FieldTranscript, TranscriptRead, TranscriptWrite},
        BigUint, Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use core::ptr::addr_of;
use ff::BatchInverter;
use p3_baby_bear::Poseidon2BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Mmcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeField64;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{BatchOpening, FriConfig, FriProof, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use p3_matrix::extension::FlatMatrixView;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation,
};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use rayon::iter::IntoParallelIterator;
use std::{any::type_name, collections::HashMap, iter, ops::Deref, time::Instant};

use plonky2_util::{reverse_bits, reverse_index_bits_in_place};
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha12Rng,
};
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{borrow::Cow, marker::PhantomData, mem::size_of, slice};

type Val = MyFr;
type Challenge = BinomialExtensionField<Val, 1, Val>;

type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher32<ByteHash>;

type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;

type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

type Dft = Radix2DitParallel<Val>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type FriPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub static mut pcs: Option<TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>> = None;
pub static mut val_mmcs: Option<ValMmcs> = None;
pub static mut challenge_mmcs: Option<ChallengeMmcs> = None;
pub static mut commitment: Option<p3_symmetric::Hash<Val, u8, 32>> = None;
pub static mut prover_data: Option<p3_merkle_tree::MerkleTree<Val, u8, DenseMatrix<Val>, 32>> =
    None;
pub static mut openings: Option<Vec<Vec<Vec<Vec<Challenge>>>>> = None;
pub static mut proof: Option<
    FriProof<
        Challenge,
        ExtensionMmcs<
            Val,
            Challenge,
            MerkleTreeMmcs<
                Val,
                u8,
                SerializingHasher32<Keccak256Hash>,
                CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
                32,
            >,
        >,
        Val,
        Vec<
            BatchOpening<
                Val,
                MerkleTreeMmcs<
                    Val,
                    u8,
                    SerializingHasher32<Keccak256Hash>,
                    CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
                    32,
                >,
            >,
        >,
    >,
> = None;
pub static mut log_blowup: usize = 0;
pub static mut log_final_poly_len: usize = 0;
pub static mut num_queries: usize = 0;
pub static mut proof_of_work_bits: usize = 0;
pub static mut degree_bound: usize = 0;

pub static mut query_paths_static: Option<Vec<(Vec<Challenge>, Vec<usize>, Vec<Val>)>> = None;
pub static mut merkle_paths_static: Option<Vec<Vec<(Vec<Vec<Challenge>>, Vec<[u8; 32]>)>>> = None;
pub static mut first_merkle_paths_static: Option<Vec<Vec<[u8; 32]>>> = None;
pub static mut intermediate_oracles_static: Option<Vec<Val>> = None;
pub static mut final_value_static: Option<Challenge> = None;
pub static mut first_oracle_static: Option<p3_symmetric::Hash<Val, u8, 32>> = None;

pub static mut ldes: Option<HashMap<Vec<Val>, Vec<Val>>> = None;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct FriP3Commitment<F: PrimeField, H: Hash> {
    phantom: PhantomData<(F, H)>,
}

impl<F: PrimeField, H: Hash> PartialEq for FriP3Commitment<F, H> {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

impl<F: PrimeField, H: Hash> Eq for FriP3Commitment<F, H> {}
#[derive(Debug)]
pub struct FriP3<F: PrimeField, H: Hash>(PhantomData<(F, H)>);

impl<F: PrimeField, H: Hash> Clone for FriP3<F, H> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<F: PrimeField, H: Hash> AsRef<[Output<H>]> for FriP3Commitment<F, H> {
    fn as_ref(&self) -> &[Output<H>] {
        &[]
    }
}

fn new_fri_config() -> FriConfig<ChallengeMmcs> {
    FriConfig {
        log_blowup: unsafe { log_blowup },
        log_final_poly_len: unsafe { log_final_poly_len },
        num_queries: unsafe { num_queries },
        proof_of_work_bits: unsafe { proof_of_work_bits },
        mmcs: unsafe { challenge_mmcs.clone().unwrap() },
    }
}

impl<H> PolynomialCommitmentScheme<Val> for FriP3<Val, H>
where
    H: Hash,
{
    type Param = ();
    type ProverParam = ();
    type VerifierParam = ();
    type Polynomial = UnivariatePolynomial<Val, CoefficientBasis>;
    type Commitment = FriP3Commitment<Val, H>;
    type CommitmentChunk = Output<H>;

    fn setup(poly_size: usize, _: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        let byte_hash = ByteHash {};
        let field_hash = FieldHash::new(byte_hash);
        let compress = MyCompress::new(byte_hash);

        unsafe {
            log_blowup = 3;
            log_final_poly_len = 0;
            num_queries = 10;
            proof_of_work_bits = 8;
            val_mmcs = Some(ValMmcs::new(field_hash, compress));
            challenge_mmcs = Some(ChallengeMmcs::new(val_mmcs.clone().unwrap()));
            ldes = Some(HashMap::new());
            pcs = Some(FriPcs::new(
                Dft::default(),
                val_mmcs.clone().unwrap(),
                new_fri_config(),
            ));
        }

        Ok(())
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        Ok(((), ()))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        Self::batch_commit(pp, [poly]).map(|v| v[0].clone())
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let polys = polys.into_iter().collect_vec();
        if polys.is_empty() {
            return Ok(vec![]);
        }
        let poly_num = polys.len();
        let polys = polys
            .into_iter()
            .map(|p| p.clone().into_evals())
            .collect_vec();
        let polys = (0..polys[0].len())
            .flat_map(|i| polys.iter().map(|p| p[i]).collect_vec())
            .collect_vec();
        let degree = polys.len() / poly_num;

        let matrix = RowMajorMatrix::new(polys, poly_num);
        let pcs_ = unsafe { pcs.as_ref().unwrap() };
        let domain = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
            &pcs_, degree,
        );
        let (comm, prover_data_) = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(
            &pcs_,
            vec![(domain, matrix.clone())],
        );

        unsafe {
            prover_data = Some(prover_data_);
            commitment = Some(comm);
            degree_bound = degree;
        }

        Ok(vec![])
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<Val, Self::Polynomial>,
        eval: &Val,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, Val>,
    ) -> Result<(), Error> {
        Self::batch_open(
            pp,
            [poly],
            [comm],
            &[*point],
            &[Evaluation::new(0, 0, *eval)],
            transcript,
        )
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<Val, Self::Polynomial>],
        evals: &[Evaluation<Val>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, Val>,
    ) -> Result<(), Error> {
        let pcs_ = unsafe { pcs.as_ref().unwrap() };
        let prover_data_ = unsafe { prover_data.as_ref().unwrap() };

        let (openings_, proof_) = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::open(
            &pcs_,
            vec![(&prover_data_, vec![vec![Challenge::from(points[0])]])],
            &mut Challenger::from_hasher(vec![], ByteHash {}),
        );

        unsafe {
            openings = Some(openings_);
            proof = Some(proof_);
        }

        Ok(())
    }

    fn read_commitments(
        _: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, Val>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        Ok(vec![Self::Commitment::default()])
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<Val, Self::Polynomial>,
        eval: &Val,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, Val>,
    ) -> Result<(), Error> {
        Self::batch_verify(
            vp,
            [comm],
            &[*point],
            &[Evaluation::new(0, 0, *eval)],
            transcript,
        )
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<Val, Self::Polynomial>],
        evals: &[Evaluation<Val>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, Val>,
    ) -> Result<(), Error> {
        let pcs_ = unsafe { pcs.as_ref().unwrap() };

        let prover_data_ = unsafe { prover_data.as_ref().unwrap() };

        let (openings_, proof_) = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::open(
            &pcs_,
            vec![(&prover_data_, vec![vec![Challenge::from(points[0])]])],
            &mut Challenger::from_hasher(vec![], ByteHash {}),
        );

        let domain = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
            &pcs_,
            unsafe { degree_bound },
        );
        let comm = unsafe { commitment.as_ref().unwrap() };
        let rounds = vec![(
            *comm,
            vec![(
                domain,
                vec![(Challenge::from(points[0]), unsafe {
                    openings.as_ref().unwrap()[0][0][0].clone()
                })],
            )],
        )];

        assert_eq!(
            serde_json::to_string(&proof_).unwrap(),
            serde_json::to_string(&unsafe { proof.as_ref().unwrap() }).unwrap()
        );

        <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::verify(
            &pcs_,
            rounds.clone(),
            &proof_,
            &mut Challenger::from_hasher(vec![], ByteHash {}),
        )
        .unwrap();

        // <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::verify(
        //     &pcs_,
        //     rounds.clone(),
        //     unsafe { proof.as_ref().unwrap() },
        //     &mut Challenger::from_hasher(vec![], ByteHash {}),
        // )
        // .unwrap();

        Ok(())
    }
}
