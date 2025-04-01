use crate::pcs::Evaluation;
use crate::poly::Polynomial;
use crate::util::fake_extension::MyFr;
use crate::util::hash::{Blake2s, Hash};
use crate::{
    pcs::PolynomialCommitmentScheme,
    poly::univariate::{CoefficientBasis, UnivariatePolynomial},
};
use ff::{BatchInvert as _, Field, PrimeField};
use generic_array::typenum::U256;
use generic_array::GenericArray;
use itertools::{izip, Itertools};
use p3_baby_bear::Poseidon2BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Mmcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::ExtensionField;
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
use plonky2_util::reverse_index_bits_in_place;
use rand::SeedableRng as _;
use rand_9::Rng;
use rand_9::SeedableRng as _;
use rand_chacha_9::ChaCha20Rng;
use rayon::iter::{
    IndexedParallelIterator as _, IntoParallelIterator, IntoParallelRefIterator as _,
    IntoParallelRefMutIterator, ParallelIterator,
};
use rayon::prelude::ParallelSliceMut;
use rayon::slice::ParallelSlice as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::digest::{Output, OutputSizeUser};
use std::cmp::min;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::Instant;

type Val = MyFr;
type Challenge = BinomialExtensionField<Val, 1, Val>;

type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher32<ByteHash>;

type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;

type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

type Dft = Radix2DitParallel<Val>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

pub static mut table_static: Option<Vec<Vec<Val>>> = None;
pub static mut commitment: Option<Vec<Vec<[u8; 32]>>> = None;

pub static mut log_blowup: usize = 0;
pub static mut log_final_poly_len: usize = 0;
pub static mut num_queries: usize = 0;
pub static mut proof_of_work_bits: usize = 0;
pub static mut degree_bound: usize = 0;

pub static mut query_paths_static: Option<Vec<(Vec<Challenge>, Vec<usize>, Vec<Val>)>> = None;
pub static mut merkle_paths_static: Option<Vec<Vec<Vec<([u8; 32], [u8; 32])>>>> = None;
pub static mut first_merkle_paths_static: Option<Vec<Vec<[u8; 32]>>> = None;
pub static mut intermediate_oracles_static: Option<Vec<[u8; 32]>> = None;
pub static mut final_value_static: Option<Challenge> = None;
pub static mut first_oracle_static: Option<[u8; 32]> = None;

pub static mut ldes: Option<HashMap<Vec<Val>, Vec<Val>>> = None;

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
pub struct Powers<F: Field> {
    base: F,
    current: F,
}

impl<F: Field> Iterator for Powers<F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        let result = self.current;
        self.current *= self.base;
        Some(result)
    }
}
impl<H: Hash> PolynomialCommitmentScheme<Val> for BatchedFri<Val, H>
where
    DenseMatrix<Val>: Matrix<Val>,
{
    type Param = ();

    type ProverParam = ();

    type VerifierParam = ();

    type Polynomial = UnivariatePolynomial<Val, CoefficientBasis>;

    type Commitment = BatchedFriCommitment<Val, H>;

    type CommitmentChunk = Output<H>;

    fn setup(
        poly_size: usize,
        batch_size: usize,
        rng: impl rand::RngCore,
    ) -> Result<Self::Param, crate::Error> {
        let byte_hash = ByteHash {};
        let field_hash = FieldHash::new(byte_hash);
        let compress = MyCompress::new(byte_hash);

        let log_blowup_ = 3;
        let log_evals = log2_ceil_usize(poly_size) + log_blowup_ - 1;

        let mut gen = Val::two_adic_generator(log_evals);
        let mut table = Vec::with_capacity(log_evals);
        for i in 0..log_evals {
            let mut tmp = <Val as ff::Field>::ONE;
            let mut row = gen.powers().take(1 << (log_evals - i)).collect_vec();
            table.push(row);
            gen *= gen;
        }

        unsafe {
            log_blowup = log_blowup_;
            log_final_poly_len = 0;
            num_queries = 10;
            proof_of_work_bits = 0;
            ldes = Some(HashMap::new());
            table_static = Some(table);
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

        let mut table = unsafe { table_static.clone().unwrap() };
        let mut table_copy = table.clone();
        table_copy.reverse();
        table_copy[0].push(-<Val as ff::Field>::ONE);

        let tree = merkelize_mmcs::<Val, Blake2s>(
            &polys
                .clone()
                .iter()
                .map(|p| {
                    let mut coeffs = p.coeffs().to_vec();
                    reverse_index_bits_in_place(&mut coeffs);
                    let mut evals = evaluate_over_foldable_domain(log_rate, coeffs, &table_copy);
                    reverse_index_bits_in_place(&mut evals);

                    unsafe {
                        ldes.as_mut()
                            .unwrap()
                            .insert(p.coeffs().to_vec(), evals.clone());
                    }

                    evals
                })
                .collect(),
        );

        let comm: Vec<Vec<[u8; 32]>> = tree
            .iter()
            .map(|t| {
                t.iter()
                    .map(|e| {
                        let bytes = e.as_ref();
                        *bytes
                    })
                    .collect()
            })
            .collect();

        unsafe {
            degree_bound = polys.into_iter().next().unwrap().coeffs().len();
            commitment = Some(comm);
        };

        Ok(vec![BatchedFriCommitment {
            phantom: PhantomData,
        }])
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &crate::pcs::Point<Val, Self::Polynomial>,
        eval: &Val,
        transcript: &mut impl crate::util::transcript::TranscriptWrite<Self::CommitmentChunk, Val>,
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
        points: &[crate::pcs::Point<Val, Self::Polynomial>],
        evals: &[crate::pcs::Evaluation<Val>],
        transcript: &mut impl crate::util::transcript::TranscriptWrite<Self::CommitmentChunk, Val>,
    ) -> Result<(), crate::Error>
    where
        Self::Polynomial: 'a,
        Self::Commitment: 'a,
    {
        let comm_original = unsafe { commitment.clone().unwrap() };
        let comm: Vec<Vec<Output<H>>> = comm_original
            .iter()
            .map(|c| {
                let mut res = Vec::with_capacity(c.len());
                for e in c {
                    let bytes = e.as_ref()[..32].try_into().unwrap();
                    res.push(Output::<H>::from_slice(bytes).clone());
                }
                res
            })
            .collect_vec();
        let mut table = unsafe { table_static.clone().unwrap() };
        for layer in table.iter_mut() {
            reverse_index_bits_in_place(layer);
        }

        let polys = polys.into_iter().collect_vec();
        let log_rate = unsafe { log_blowup };
        let p_evals = polys
            .iter()
            .map(|p| unsafe {
                ldes.as_ref()
                    .unwrap()
                    .get(&p.coeffs().to_vec())
                    .unwrap()
                    .clone()
            })
            .collect_vec();

        let mut num_vars =
            log2_strict_usize(polys.clone().into_iter().next().unwrap().coeffs().len()) + log_rate;
        let quotients = p_evals
            .clone()
            .into_iter()
            .zip(evals.into_iter().map(|e| e.value))
            .zip(points.into_iter())
            .enumerate()
            .map(|(i, ((p, eval), point))| {
                let numerator: Vec<Val> = p.par_iter().map(|e| *e - eval).collect();

                let mut denominator = Vec::with_capacity(1 << num_vars);

                for j in 0..(1 << num_vars) {
                    denominator.push(table[i][j] - point);
                }
                denominator.iter_mut().batch_invert();

                let mut quotient: Vec<Val> = numerator
                    .clone()
                    .into_iter()
                    .zip(denominator.clone().into_iter())
                    .collect_vec()
                    .par_iter()
                    .map(|(n, d)| *n * *d)
                    .collect();

                num_vars -= 1;

                quotient
            })
            .collect_vec();

        let num_vars = log2_strict_usize(polys.clone().into_iter().next().unwrap().coeffs().len());
        let lambda = transcript.squeeze_challenge();
        let mut folded =
            vec![Challenge::from(<Val as ff::Field>::ZERO); 1 << (num_vars + log_rate)];

        let mut trees = Vec::with_capacity(num_vars);
        let mut comms = Vec::with_capacity(num_vars);
        let mut tree_evals = Vec::with_capacity(num_vars);
        for i in 0..num_vars + 1 {
            let alpha = Challenge::from(transcript.squeeze_challenge());

            folded = folded
                .into_iter()
                .zip(quotients[i].clone().into_iter())
                .zip(table[i].clone().into_iter())
                .collect_vec()
                .par_iter()
                .map(|((a, b), g)| {
                    *a + Challenge::from(*b) * (<Val as ff::Field>::ONE + lambda * g)
                })
                .collect();

            let folded_repr: Vec<Val> = folded
                .clone()
                .into_iter()
                .map(|e| e.as_base().unwrap())
                .collect_vec();

            let tree = merkelize::<Val, H>(&folded_repr);
            trees.push(tree.clone());
            tree_evals.push(folded.clone());

            folded = fold_row(folded, alpha, table[i].clone());

            // transcript.write_field_element(&field_element);
            let intermediate_oracle: [u8; 32] = tree.iter().last().unwrap()[0].as_ref()[..32]
                .try_into()
                .unwrap();
            comms.push(intermediate_oracle);
        }

        // for i in 1..folded.len() {
        //     assert!(folded[i] == folded[0], "folded: {:?}", folded);
        // }

        let query_num = unsafe { num_queries };
        let queries = transcript
            .squeeze_challenges(query_num)
            .into_iter()
            .map(|q| q.as_canonical_u64() as usize % (1usize << (num_vars + log_rate)))
            .collect_vec();

        let mut query_paths = Vec::with_capacity(query_num);
        for q in queries.clone() {
            let mut query_range = 1 << (num_vars + log_rate);
            let mut cur_path = Vec::with_capacity(query_range);
            let mut indices = Vec::with_capacity(query_range);
            let mut reduced_openings = Vec::with_capacity(query_range);
            let mut q_copy = q;

            for i in 0..num_vars + 1 {
                let q_sibling = q_copy ^ 1;

                cur_path.push(tree_evals[i][q_sibling]);
                reduced_openings.push(p_evals[i][q_copy]);

                indices.push(q_copy);
                q_copy >>= 1;
                query_range >>= 1;
            }

            query_paths.push((cur_path, indices, reduced_openings));
        }

        let mut first_merkle_paths: Vec<Vec<[u8; 32]>> = Vec::with_capacity(query_num);
        for q in queries {
            let mmcs_proof = get_merkle_path_mmcs::<H, Val>(&comm, q);
            let mmcs_proof: Vec<[u8; 32]> = mmcs_proof
                .par_iter()
                .map(|a| {
                    let a: [u8; 32] = a.as_ref()[0..32].try_into().unwrap();
                    a
                })
                .collect();
            first_merkle_paths.push(mmcs_proof);
        }

        let mut merkle_paths = Vec::with_capacity(query_num);
        for (cur_path, indices, _ros) in query_paths.clone() {
            let mut cur_query_paths = Vec::with_capacity(num_vars);
            for (i, (tree, idx)) in trees.iter().zip(indices.iter()).enumerate() {
                let path: Vec<([u8; 32], [u8; 32])> = get_merkle_path::<H, Val>(tree, *idx, false)
                    .par_iter()
                    .map(|v| {
                        let (e0, e1) = (v[0].clone(), v[1].clone());
                        let bytes0: [u8; 32] = e0.as_ref()[0..32].try_into().unwrap();
                        let bytes1: [u8; 32] = e1.as_ref()[0..32].try_into().unwrap();
                        (bytes0, bytes1)
                    })
                    .collect();
                cur_query_paths.push(path);
            }
            merkle_paths.push(cur_query_paths);
        }

        for (cur_path, _indices, reduced_openings) in query_paths.iter() {
            let cur_path_base = cur_path
                .iter()
                .map(|e| {
                    <BinomialExtensionField<Val, 1> as ExtensionField<Val>>::as_base(e).unwrap()
                })
                .collect_vec();
            let base_ref = cur_path_base.iter().collect_vec();
            transcript.write_field_elements(base_ref);
            transcript.write_field_elements(reduced_openings);
        }

        for mp in merkle_paths.iter() {
            transcript.write_field_elements(vec![&Val::TWO; mp.len()]);
        }

        for fp in first_merkle_paths.iter() {
            transcript.write_field_elements(vec![&Val::TWO; fp.len()]);
        }

        transcript.write_field_elements(vec![&Val::TWO; comms.len()]);

        transcript.write_field_element(&folded[0].as_base().unwrap());

        transcript.write_field_element(&Val::TWO); // write comm

        unsafe {
            query_paths_static = Some(query_paths);
            merkle_paths_static = Some(merkle_paths);
            first_merkle_paths_static = Some(first_merkle_paths);
            intermediate_oracles_static = Some(comms);
            final_value_static = Some(folded[0]);
            first_oracle_static = Some(comm_original.iter().last().unwrap()[0]);
        }

        Ok(())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl crate::util::transcript::TranscriptRead<Self::CommitmentChunk, Val>,
    ) -> Result<Vec<Self::Commitment>, crate::Error> {
        Ok(vec![BatchedFriCommitment {
            phantom: PhantomData,
        }])
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &crate::pcs::Point<Val, Self::Polynomial>,
        eval: &Val,
        transcript: &mut impl crate::util::transcript::TranscriptRead<Self::CommitmentChunk, Val>,
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
        points: &[crate::pcs::Point<Val, Self::Polynomial>],
        evals: &[crate::pcs::Evaluation<Val>],
        transcript: &mut impl crate::util::transcript::TranscriptRead<Self::CommitmentChunk, Val>,
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

        let mut table = unsafe { table_static.clone().unwrap() };
        for layer in table.iter_mut() {
            reverse_index_bits_in_place(layer);
        }
        let first_oracle = unsafe { first_oracle_static.clone().unwrap() };
        let intermediate_oracles = unsafe { intermediate_oracles_static.clone().unwrap() };
        let final_value = unsafe { final_value_static.unwrap() };
        let query_paths = unsafe { query_paths_static.clone().unwrap() };
        let merkle_paths = unsafe { merkle_paths_static.clone().unwrap() };
        let first_merkle_paths = unsafe { first_merkle_paths_static.clone().unwrap() };

        let lambda = transcript.squeeze_challenge();
        let mut fold_challenges = Vec::with_capacity(log_degree_bound);

        for i in 0..log_degree_bound + 1 {
            fold_challenges.push(transcript.squeeze_challenge());
            // let _oracle = transcript.read_field_element();
        }

        let query_num = unsafe { num_queries };
        let queries = transcript
            .squeeze_challenges(query_num)
            .into_iter()
            .map(|q| q.as_canonical_u64() as usize % (1usize << log_evals))
            .collect_vec();

        let inv_two = Val::TWO.invert().unwrap();

        for (q, (cur_path, indices, reduced_openings), mps, fmp) in izip!(
            queries,
            query_paths.clone().into_iter(),
            merkle_paths.clone().into_iter(),
            first_merkle_paths.clone().into_iter()
        ) {
            let mut folded = <Val as ff::Field>::ZERO;

            let fmp_vec = fmp.iter().map(|v| Output::<H>::from_slice(v)).collect_vec();
            authenticate_merkle_path_mmcs::<H, Val>(
                &fmp_vec,
                &reduced_openings,
                q,
                log_evals,
                Output::<H>::from_slice(&first_oracle),
            );

            let mut q_copy = q;
            for i in 0..log_degree_bound + 1 {
                let p = table[i][q_copy];

                let tmp = (reduced_openings[i] - evals[i].value) / (p - points[0]);
                let cur_quotient = (<Val as ff::Field>::ONE + lambda * p) * tmp;

                folded += cur_quotient;

                let sibling = q_copy ^ 1;

                let alpha = fold_challenges[i];
                let mut evals = vec![cur_path[i].as_base().unwrap(); 2];

                evals[q_copy & 1] = folded;

                let leaves = (evals[0], evals[1]);

                authenticate_merkle_path_root::<H, Val>(
                    &mps[i]
                        .iter()
                        .map(|v| {
                            vec![
                                Output::<H>::from_slice(&v.0).clone(),
                                Output::<H>::from_slice(&v.1).clone(),
                            ]
                        })
                        .collect_vec(),
                    leaves,
                    q_copy,
                    Output::<H>::from_slice(&intermediate_oracles[i]),
                );

                if sibling < q_copy {
                    q_copy = sibling;
                }

                let p = table[i][q_copy];
                let inv_p = p.invert().unwrap();
                folded = (evals[0] + evals[1]) * inv_two
                    + alpha * (evals[0] - evals[1]) * inv_two * inv_p;

                q_copy >>= 1;
            }

            assert!(folded == final_value.as_base().unwrap());
        }

        for (cur_path, _indices, reduced_openings) in query_paths.iter() {
            transcript.read_field_elements(cur_path.len());
            transcript.read_field_elements(reduced_openings.len());
        }

        for mp in merkle_paths.iter() {
            for tree in mp.iter() {
                for (e0, e1) in tree.iter() {
                    transcript.read_field_elements(e0.len());
                    transcript.read_field_elements(e1.len());
                }
            }
        }

        for fp in first_merkle_paths.iter() {
            for el in fp.iter() {
                transcript.read_field_element();
            }
        }

        transcript.read_field_elements(log_degree_bound);

        transcript.read_field_element();
        transcript.read_field_element();

        Ok(())
    }
}

fn fold_row(evals: Vec<Challenge>, alpha: Challenge, mut table: Vec<Val>) -> Vec<Challenge> {
    assert!(evals.len() % 2 == 0);
    assert!(table.len() == evals.len());

    let inv_two = Val::TWO.invert().unwrap();
    table.batch_invert();

    evals
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, chunk)| {
            let inv_p = table[2 * i];
            let a = (chunk[0] + chunk[1]) * inv_two;
            let b = (chunk[0] - chunk[1]) * inv_two * inv_p;
            a + alpha * b
        })
        .collect()
}

pub fn evaluate_over_foldable_domain<F: PrimeField>(
    log_rate: usize,
    mut coeffs: Vec<F>,
    table: &Vec<Vec<F>>,
) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.len();
    //    println!("k {:?}", k);
    let logk = log2_strict_usize(k);
    let cl = 1 << (logk + log_rate);
    let rate = 1 << log_rate;
    let mut coeffs_with_rep = Vec::with_capacity(cl);
    for i in 0..cl {
        coeffs_with_rep.push(F::ZERO);
    }

    let now = Instant::now();
    for i in 0..k {
        for j in 0..rate {
            coeffs_with_rep[i * rate + j] = coeffs[i];
        }
    }

    let mut chunk_size = rate;
    for i in 0..logk {
        let level = &table[i + log_rate];
        chunk_size = chunk_size << 1;
        assert_eq!(level.len(), chunk_size);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs_with_rep)
            .par_chunks_mut(chunk_size)
            .for_each(|chunk| {
                let half_chunk = chunk_size >> 1;
                for j in half_chunk..chunk_size {
                    let rhs = chunk[j] * level[j - half_chunk];
                    chunk[j] = chunk[j - half_chunk] - rhs;
                    chunk[j - half_chunk] = chunk[j - half_chunk] + rhs;
                }
            });
    }
    coeffs_with_rep
}

fn merkelize_mmcs<F: PrimeField, H: Hash>(values: &Vec<Vec<F>>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict_usize(values[0].len());
    let mut tree = Vec::with_capacity(log_v);

    let values: Vec<Vec<Output<H>>> = values
        .par_iter()
        .map(|v| {
            v.par_iter()
                .map(|f| {
                    let mut hasher = H::new();
                    hasher.update_field_element(f);
                    hasher.finalize_fixed()
                })
                .collect()
        })
        .collect();

    tree.push(values[0].clone());
    let mut idx = 1;

    let mut i = 0;
    while idx < values.len() {
        let mut oracle = tree[i]
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();

        if values[idx].len() == 1 << (log_v - i - 1) {
            oracle = oracle
                .iter()
                .zip(values[idx].iter())
                .collect_vec()
                .par_iter()
                .map(|(hash, value)| {
                    let mut hasher = H::new();
                    hasher.update(hash);
                    hasher.update(value);
                    hasher.finalize_fixed()
                })
                .collect();
            idx += 1;
        }

        tree.push(oracle.clone());
        i += 1;
    }

    let mut hasher = H::new();
    hasher.update(&Output::<H>::default());
    let default_hash = hasher.finalize_fixed();

    while i < log_v {
        let mut oracle: Vec<Output<H>> = tree[i]
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect();
        oracle = oracle
            .par_iter()
            .map(|o| {
                let mut hasher = H::new();
                hasher.update(o);
                hasher.update(&default_hash);
                hasher.finalize_fixed()
            })
            .collect();
        tree.push(oracle);
        i += 1;
    }

    tree
}

fn get_merkle_path_mmcs<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
) -> Vec<&Output<H>> {
    let mut queries = Vec::with_capacity(tree.len());

    for (i, oracle) in tree.iter().enumerate() {
        if i == tree.len() - 1 {
            break;
        }
        queries.push(&oracle[x_index ^ 1]);
        x_index >>= 1;
    }

    return queries;
}

fn authenticate_merkle_path_mmcs<H: Hash, F: PrimeField>(
    path: &Vec<&Output<H>>,
    openings: &Vec<F>,
    mut x_index: usize,
    num_vars: usize,
    root: &Output<H>,
) {
    let mut obj;
    let mut hasher = H::new();

    hasher.update_field_element(&openings[0]);
    obj = hasher.finalize_fixed();

    let mut hasher = H::new();
    hasher.update(&Output::<H>::default());
    let default_hash = hasher.finalize_fixed();

    let mut i = 0;
    while i < num_vars {
        let mut hasher = H::new();
        if x_index & 1 == 0 {
            hasher.update(&obj);
            hasher.update(path[i]);
        } else {
            hasher.update(path[i]);
            hasher.update(&obj);
        }
        obj = hasher.finalize_fixed();

        if i < openings.len() - 1 {
            let mut hasher = H::new();
            hasher.update_field_element(&openings[i + 1]);
            let lh = hasher.finalize_fixed();

            let mut hasher = H::new();
            hasher.update(&obj);
            hasher.update(&lh);
            obj = hasher.finalize_fixed();
        } else {
            let mut hasher = H::new();
            hasher.update(&obj);
            hasher.update(&default_hash);
            obj = hasher.finalize_fixed();
        }

        x_index >>= 1;
        i += 1;
    }

    assert_eq!(&obj, root);
}

fn merkelize<F: PrimeField, H: Hash>(values: &Vec<F>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict_usize(values.len());
    let mut tree = Vec::with_capacity(log_v);
    let mut hashes = vec![Output::<H>::default(); (values.len() >> 1)];
    let method1 = Instant::now();
    hashes.par_iter_mut().enumerate().for_each(|(i, mut hash)| {
        let mut hasher = H::new();
        hasher.update_field_element(&values[i + i]);
        hasher.update_field_element(&values[i + i + 1]);
        *hash = hasher.finalize_fixed();
    });

    tree.push(hashes);

    let now = Instant::now();
    for i in 1..(log_v) {
        let oracle = tree[i - 1]
            .par_chunks_exact(2)
            .map(|ys| {
                let mut hasher = H::new();
                let mut hash = Output::<H>::default();
                hasher.update(&ys[0]);
                hasher.update(&ys[1]);
                hasher.finalize_fixed()
            })
            .collect::<Vec<_>>();

        tree.push(oracle);
    }
    tree
}

fn get_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    root: bool,
) -> Vec<Vec<Output<H>>> {
    let mut queries = Vec::with_capacity(tree.len());
    x_index >>= 1;
    for oracle in tree {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        if (oracle.len() == 1) {
            if (root) {
                queries.push(vec![oracle[0].clone(), oracle[0].clone()]);
            }
            break;
        }
        queries.push(vec![oracle[p0].clone(), oracle[p1].clone()]);
        x_index >>= 1;
    }

    return queries;
}

fn authenticate_merkle_path_root<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
    root: &Output<H>,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() - 1 {
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update(&path[path.len() - 1][0]);
    hasher.update(&path[path.len() - 1][1]);
    hasher.finalize_into_reset(&mut hash);
    assert_eq!(&hash, root);
}

mod test {
    use super::*;

    #[test]
    fn test_merkelize() {
        let num_vars = 3;
        let values = (0..(1 << num_vars)).map(|i| Val::from(i)).collect_vec();
        let tree = merkelize::<Val, Blake2s>(&values);

        let idx = 3;
        let path = get_merkle_path::<Blake2s, Val>(&tree, idx, false);
        let mut p0 = idx;
        let mut p1 = idx ^ 1;
        if p1 < p0 {
            p0 = idx ^ 1;
            p1 = idx;
        }
        authenticate_merkle_path_root::<Blake2s, Val>(
            &path,
            (values[p0], values[p1]),
            idx,
            &tree[num_vars - 1][0],
        );
    }
}
