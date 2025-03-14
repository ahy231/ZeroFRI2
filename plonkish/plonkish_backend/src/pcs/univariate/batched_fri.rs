use crate::pcs::Evaluation;
use crate::poly::Polynomial;
use crate::util::fake_extension::{FakeExtension, MyFr};
use crate::util::hash::Hash;
use crate::{
    pcs::PolynomialCommitmentScheme,
    poly::univariate::{CoefficientBasis, UnivariatePolynomial},
};
use ff::{Field, PrimeField};
use itertools::{izip, Itertools};
use p3_baby_bear::Poseidon2BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Mmcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeField64;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use p3_matrix::extension::FlatMatrixView;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation,
};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use rand::SeedableRng as _;
use rand_9::Rng;
use rand_9::SeedableRng as _;
use rand_chacha_9::ChaCha20Rng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use std::collections::HashMap;
use std::marker::PhantomData;

type Val = MyFr;
type Challenge = FakeExtension;

type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher32<ByteHash>;

type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;

type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

type Dft = Radix2DitParallel<Val>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

type FriPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub static mut pcs: Option<TwoAdicFriPcs<MyFr, Dft, ValMmcs, ChallengeMmcs>> = None;
pub static mut val_mmcs: Option<ValMmcs> = None;
pub static mut challenge_mmcs: Option<ChallengeMmcs> = None;
pub static mut commitment: Option<p3_symmetric::Hash<MyFr, u8, 32>> = None;
pub static mut prover_data: Option<p3_merkle_tree::MerkleTree<MyFr, u8, DenseMatrix<MyFr>, 32>> =
    None;
pub static mut log_blowup: usize = 0;
pub static mut log_final_poly_len: usize = 0;
pub static mut num_queries: usize = 0;
pub static mut proof_of_work_bits: usize = 0;
pub static mut degree_bound: usize = 0;

pub static mut query_paths_static: Option<Vec<(Vec<FakeExtension>, Vec<usize>, Vec<MyFr>)>> = None;
pub static mut merkle_paths_static: Option<Vec<Vec<(Vec<Vec<FakeExtension>>, Vec<[u8; 32]>)>>> =
    None;
pub static mut first_merkle_paths_static: Option<Vec<Vec<[u8; 32]>>> = None;
pub static mut intermediate_oracles_static: Option<Vec<MyFr>> = None;
pub static mut final_value_static: Option<FakeExtension> = None;
pub static mut first_oracle_static: Option<p3_symmetric::Hash<MyFr, u8, 32>> = None;

pub static mut ldes: Option<HashMap<Vec<MyFr>, Vec<MyFr>>> = None;

fn new_fri_config() -> FriConfig<ChallengeMmcs> {
    FriConfig {
        log_blowup: unsafe { log_blowup },
        log_final_poly_len: unsafe { log_final_poly_len },
        num_queries: unsafe { num_queries },
        proof_of_work_bits: unsafe { proof_of_work_bits },
        mmcs: unsafe { challenge_mmcs.clone().unwrap() },
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BatchedFri<F, H> {
    phantom: PhantomData<(F, H)>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct BatchedFriCommitment<F, H> {
    phantom: PhantomData<(F, H)>,
}

impl<F: PrimeField, H: Hash> AsRef<[Output<H>]> for BatchedFriCommitment<F, H> {
    fn as_ref(&self) -> &[Output<H>] {
        &[]
    }
}

impl<H: Hash> PolynomialCommitmentScheme<MyFr> for BatchedFri<MyFr, H>
where
    DenseMatrix<MyFr>: Matrix<MyFr>,
{
    type Param = ();

    type ProverParam = ();

    type VerifierParam = ();

    type Polynomial = UnivariatePolynomial<MyFr, CoefficientBasis>;

    type Commitment = BatchedFriCommitment<MyFr, H>;

    type CommitmentChunk = Output<H>;

    fn setup(
        poly_size: usize,
        batch_size: usize,
        rng: impl rand::RngCore,
    ) -> Result<Self::Param, crate::Error> {
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
            pcs = Some(FriPcs::new(
                Dft::default(),
                val_mmcs.clone().unwrap(),
                new_fri_config(),
            ));
            ldes = Some(HashMap::new());
        }

        Ok(())
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        Ok(((), ()))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, crate::Error> {
        Self::batch_commit(pp, [poly]).map(|v| v[0].clone())
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, crate::Error>
    where
        Self::Polynomial: 'a,
    {
        let polys = polys.into_iter().collect_vec();
        let log_rate = unsafe { log_blowup };
        let mmcs_copy = unsafe { val_mmcs.clone().unwrap() };
        let (comm, prover_data_) = mmcs_copy.commit(
            polys
                .clone()
                .into_iter()
                .map(|p| {
                    let coeffs = p.coeffs().to_vec();
                    let mut coeffs_appended =
                        vec![<MyFr as ff::Field>::ZERO; coeffs.len() << log_rate];
                    coeffs_appended[..coeffs.len()].copy_from_slice(&coeffs);
                    let dft = Dft::default();
                    let evals = dft.dft(coeffs_appended);
                    unsafe {
                        ldes.as_mut().unwrap().insert(coeffs, evals.clone());
                    }
                    RowMajorMatrix::new_col(evals)
                })
                .collect(),
        );
        unsafe {
            commitment = Some(comm);
            prover_data = Some(prover_data_);
            degree_bound = polys.into_iter().next().unwrap().coeffs().len();
        };

        Ok(vec![BatchedFriCommitment {
            phantom: PhantomData,
        }])
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &crate::pcs::Point<MyFr, Self::Polynomial>,
        eval: &MyFr,
        transcript: &mut impl crate::util::transcript::TranscriptWrite<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), crate::Error> {
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
        points: &[crate::pcs::Point<MyFr, Self::Polynomial>],
        evals: &[crate::pcs::Evaluation<MyFr>],
        transcript: &mut impl crate::util::transcript::TranscriptWrite<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), crate::Error>
    where
        Self::Polynomial: 'a,
        Self::Commitment: 'a,
    {
        let comm = unsafe { commitment.clone().unwrap() };
        let mmcs = unsafe { val_mmcs.clone().unwrap() };
        let polys = polys.into_iter().collect_vec();
        let log_rate = unsafe { log_blowup };
        let quotients = polys
            .clone()
            .into_iter()
            .zip(evals.into_iter().map(|e| e.value))
            .zip(points.into_iter())
            .map(|((p, eval), point)| {
                let num_vars = log2_strict_usize(p.coeffs().len()) + log_rate;
                let gen = Val::two_adic_generator(num_vars);

                let coeffs = p.coeffs().to_vec();
                let p_evals = unsafe { ldes.as_ref().unwrap().get(&coeffs).unwrap().clone() };
                assert!(p_evals.len() == 1 << num_vars);
                let numerator = p_evals.clone().into_iter().map(|e| e - eval).collect_vec();

                let mut acc = <Val as ff::Field>::ONE;
                let mut denominator = Vec::with_capacity(1 << num_vars);
                for i in 0..(1 << num_vars) {
                    denominator.push(acc - point);
                    acc *= gen;
                }

                let quotient = numerator
                    .into_iter()
                    .zip(denominator.into_iter())
                    .map(|(n, d)| n / d)
                    .collect_vec();

                let mut acc = <Val as ff::Field>::ONE;

                quotient
            })
            .collect_vec();

        let num_vars = log2_strict_usize(polys.clone().into_iter().next().unwrap().coeffs().len());
        let lambda = transcript.squeeze_challenge();
        let mut folded =
            vec![FakeExtension::from(<Val as ff::Field>::ZERO); 1 << (num_vars + log_rate)];
        let mmcs_val = unsafe { val_mmcs.clone().unwrap() };
        let mmcs_challenge = unsafe { challenge_mmcs.clone().unwrap() };
        let mut gen = Val::two_adic_generator(num_vars + log_rate);

        let mut trees = Vec::with_capacity(num_vars - 1);
        let mut comms = Vec::with_capacity(num_vars - 1);
        let mut tree_evals = Vec::with_capacity(num_vars - 1);
        for i in 0..num_vars {
            let alpha = FakeExtension::from(transcript.squeeze_challenge());

            folded = folded
                .into_iter()
                .zip(quotients[i].clone().into_iter())
                .enumerate()
                .map(|(j, (a, b))| {
                    a + FakeExtension::from(b)
                        * (<Val as ff::Field>::ONE + lambda * gen.pow(&[j as u64]))
                })
                .collect_vec();

            let (comm, tree) =
                mmcs_challenge.commit_matrix(RowMajorMatrix::new_col(folded.clone()));
            trees.push(tree);
            tree_evals.push(folded.clone());

            folded = fold_row(folded, alpha, gen);

            let mut field_element = <MyFr as ff::Field>::ZERO;
            for byte in comm.as_ref() {
                field_element *= MyFr::from_u16(1u16 << 8);
                field_element += MyFr::from_u8(*byte);
            }
            transcript.write_field_element(&field_element);
            comms.push(field_element);

            gen *= gen;
        }

        let query_num = unsafe { num_queries };
        let queries = transcript
            .squeeze_challenges(query_num)
            .into_iter()
            .map(|q| q.as_canonical_u64() as usize % (1usize << (num_vars + log_rate)))
            .collect_vec();

        let mut query_paths = Vec::with_capacity(query_num);
        for q in queries.clone() {
            gen = Val::two_adic_generator(num_vars + log_rate);
            let mut query_range = 1 << (num_vars + log_rate);
            let mut cur_path = Vec::with_capacity(query_range);
            let mut indices = Vec::with_capacity(query_range);
            let mut reduced_openings = Vec::with_capacity(query_range);
            let mut q_copy = q;

            for i in 0..num_vars {
                let q_sibling = q_copy ^ (query_range / 2);
                assert!(
                    q_sibling < tree_evals[i].len(),
                    "q_copy: {}, q_sibling: {}, tree_evals[i].len(): {}, query_range: {}, query_range / 2: {}",
                    q_copy,
                    q_sibling,
                    tree_evals[i].len(),
                    query_range,
                    query_range / 2
                );
                cur_path.push(tree_evals[i][q_sibling]);
                reduced_openings.push(polys[i].evaluate(&gen.pow(&[q_copy as u64])));

                indices.push(q_copy);
                if q_sibling < q_copy {
                    q_copy = q_sibling;
                }
                query_range >>= 1;
                gen *= gen;
            }

            reduced_openings.push(polys.last().unwrap().evaluate(&gen.pow(&[q as u64])));
            query_paths.push((cur_path, indices, reduced_openings));
        }

        let mut first_merkle_paths = Vec::with_capacity(query_num);
        let prove_data = unsafe { prover_data.as_ref().unwrap() };
        for q in queries {
            let (_openings, mmcs_proof) = mmcs_val.open_batch(q, prove_data);
            first_merkle_paths.push(mmcs_proof);
        }

        let mut merkle_paths = Vec::with_capacity(query_num);
        for (cur_path, indices, _ros) in query_paths.clone() {
            let mut cur_query_paths = Vec::with_capacity(num_vars);
            for (tree, idx) in trees.iter().zip(indices.iter()) {
                cur_query_paths.push(mmcs_challenge.open_batch(*idx, tree));
            }
            merkle_paths.push(cur_query_paths);
        }

        unsafe {
            query_paths_static = Some(query_paths);
            merkle_paths_static = Some(merkle_paths);
            first_merkle_paths_static = Some(first_merkle_paths);
            intermediate_oracles_static = Some(comms);
            final_value_static = Some(folded[0]);
            first_oracle_static = Some(comm);
        }

        Ok(())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl crate::util::transcript::TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<Vec<Self::Commitment>, crate::Error> {
        Ok(vec![BatchedFriCommitment {
            phantom: PhantomData,
        }])
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &crate::pcs::Point<MyFr, Self::Polynomial>,
        eval: &MyFr,
        transcript: &mut impl crate::util::transcript::TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), crate::Error> {
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
        points: &[crate::pcs::Point<MyFr, Self::Polynomial>],
        evals: &[crate::pcs::Evaluation<MyFr>],
        transcript: &mut impl crate::util::transcript::TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), crate::Error>
    where
        Self::Commitment: 'a,
    {
        let degree_bound_ = unsafe { degree_bound };
        let num_queries_ = unsafe { num_queries };
        let log_blowup_ = unsafe { log_blowup };
        let rate = 1 << log_blowup_;

        let log_degree_bound = log2_ceil_usize(degree_bound_);
        let log_evals = log2_strict_usize(degree_bound_ * rate);

        let gen = Val::two_adic_generator(log_evals);

        let table = (0..log_evals)
            .map(|j| {
                (0..1 << (log_evals - j))
                    .map(move |i| gen.pow(&[1 << j as u64]).pow(&[i as u64]))
                    .collect_vec()
            })
            .collect_vec();

        let first_oracle = unsafe { first_oracle_static.unwrap() };
        let intermediate_oracles = unsafe { intermediate_oracles_static.clone().unwrap() };
        let final_value = unsafe { final_value_static.unwrap() };
        let query_paths = unsafe { query_paths_static.clone().unwrap() };
        let merkle_paths = unsafe { merkle_paths_static.clone().unwrap() };
        let first_merkle_paths = unsafe { first_merkle_paths_static.clone().unwrap() };

        let lambda = transcript.squeeze_challenge();
        let mut fold_challenges = Vec::with_capacity(log_degree_bound);

        for i in 0..log_degree_bound {
            fold_challenges.push(transcript.squeeze_challenge());
            let _oracle = transcript.read_field_element();
        }

        let query_num = unsafe { num_queries };
        let queries = transcript
            .squeeze_challenges(query_num)
            .into_iter()
            .map(|q| q.as_canonical_u64() as usize % (1usize << log_evals))
            .collect_vec();

        for (q, (cur_path, indices, reduced_openings), mps, fmp) in izip!(
            queries,
            query_paths.into_iter(),
            merkle_paths.into_iter(),
            first_merkle_paths.into_iter()
        ) {
            let mut num_vars_copy = degree_bound_ * rate;
            let mut folded = <MyFr as ff::Field>::ZERO;

            let mmcs_val = unsafe { val_mmcs.clone().unwrap() };
            let mmcs_challenge = unsafe { challenge_mmcs.clone().unwrap() };

            let opened_values = reduced_openings
                .clone()
                .into_iter()
                .map(|r| vec![r])
                .collect_vec();
            let dimensions = (log_degree_bound..=log_blowup_)
                .map(|i| Dimensions {
                    width: 1,
                    height: 1 << i,
                })
                .collect_vec();
            mmcs_val.verify_batch(
                &first_oracle,
                &dimensions,
                q,
                &opened_values.as_slice(),
                &fmp,
            );

            let mut q_copy = q;
            for i in 0..log_degree_bound {
                let cur_quotient = (<MyFr as ff::Field>::ONE + lambda * table[i][q_copy])
                    * (reduced_openings[i] - evals[i].value)
                    / (table[i][q_copy] - points[0]);
                folded += cur_quotient;

                let sibling = q_copy ^ (num_vars_copy / 2);

                let alpha = fold_challenges[i];
                let mut evals = vec![cur_path[i].value; 2];
                assert!(
                    q_copy / (num_vars_copy / 2) < evals.len(),
                    "q_copy: {}, num_vars_copy: {}, evals.len(): {}",
                    q_copy,
                    num_vars_copy,
                    evals.len()
                );
                evals[q_copy / (num_vars_copy / 2)] = folded;

                if sibling < q_copy {
                    q_copy = sibling;
                }

                folded = (evals[0] + evals[1]) / MyFr::TWO
                    + alpha * (evals[0] - evals[1]) / (MyFr::TWO * table[i][q_copy]);
                num_vars_copy >>= 1;
            }

            assert!(folded == final_value.value);
        }

        Ok(())
    }
}

fn seeded_rng() -> impl Rng {
    ChaCha20Rng::seed_from_u64(0)
}

fn fold_row(evals: Vec<FakeExtension>, alpha: FakeExtension, g: MyFr) -> Vec<FakeExtension> {
    assert!(evals.len() % 2 == 0);

    let half = evals.len() / 2;
    let f0_evals = (0..half)
        .map(|i| (evals[i] + evals[half + i]) / FakeExtension::from(MyFr::TWO))
        .collect_vec();
    let f1_evals = (0..half)
        .map(|i| {
            (evals[i] - evals[half + i])
                / (FakeExtension::from(MyFr::TWO) * FakeExtension::from(g.pow(&[i as u64])))
        })
        .collect_vec();

    f0_evals
        .into_iter()
        .zip(f1_evals.into_iter())
        .map(|(a, b)| a + b * alpha)
        .collect_vec()
}

mod test {
    use super::*;

    #[test]
    fn test_all() {}
}
