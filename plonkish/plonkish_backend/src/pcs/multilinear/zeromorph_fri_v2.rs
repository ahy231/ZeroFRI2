use crate::util::algebra::batch_bit_reverse;
use crate::util::fake_extension::MyFr;
use crate::util::hash::Output;
use crate::{
    pcs::univariate::FriCommitment,
    piop::sum_check::{
        classic::{ClassicSumCheck, CoefficientsProver},
        eq_xy_eval, SumCheck as _, VirtualPolynomial,
    },
    poly::univariate::CoefficientBasis,
};
use core::num;
use ff::BatchInverter;
use itertools::izip;
use num_traits::{PrimInt as _, WrappingShr as _};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{PrimeCharacteristicRing as _, TwoAdicField as _};
use p3_util::log2_strict_usize;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use std::{collections::HashMap, iter, ops::Deref, time::Instant};

use crate::{
    pcs::{
        multilinear::{additive, quotients},
        univariate::{Fri, FriProverParams, FriVerifierParams},
        AdditiveCommitment, Evaluation, Point, PolynomialCommitmentScheme,
    },
    poly::{multilinear::MultilinearPolynomial, univariate::UnivariatePolynomial, Polynomial},
    util::{
        arithmetic::{
            inner_product, powers, squares, variable_base_msm, BatchInvert, Curve, Field,
            MultiMillerLoop, PrimeField,
        },
        chain,
        expression::{Expression, Query, Rotation},
        hash::Hash,
        izip_eq,
        parallel::parallelize,
        transcript::{TranscriptRead, TranscriptWrite},
        Deserialize, DeserializeOwned, Itertools, Serialize,
    },
    Error,
};
use core::ptr::addr_of;
use plonky2_util::{log2_strict, reverse_bits, reverse_index_bits_in_place};
use rand::RngCore;
use std::{borrow::Cow, marker::PhantomData, mem::size_of, slice};
type SumCheck<F> = ClassicSumCheck<CoefficientsProver<F>>;
#[derive(Clone, Debug)]
pub struct ZeromorphFriV2<Pcs>(PhantomData<Pcs>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeromorphFriProverParam<F: PrimeField> {
    commit_pp: FriProverParams<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeromorphFriVerifierParam<F: PrimeField> {
    pub vp: FriVerifierParams<F>,
}

type F = MyFr;

impl<H> PolynomialCommitmentScheme<F> for ZeromorphFriV2<Fri<F, H>>
where
    F: PrimeField + Serialize + DeserializeOwned,
    H: Hash,
{
    type Param = <Fri<F, H> as PolynomialCommitmentScheme<F>>::Param;
    type ProverParam = ZeromorphFriProverParam<F>;
    type VerifierParam = ZeromorphFriVerifierParam<F>;
    type Polynomial = MultilinearPolynomial<F>;
    type Commitment = <Fri<F, H> as PolynomialCommitmentScheme<F>>::Commitment;
    type CommitmentChunk = <Fri<F, H> as PolynomialCommitmentScheme<F>>::CommitmentChunk;

    fn setup(poly_size: usize, batch_size: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        Fri::<F, H>::setup(poly_size, batch_size, rng)
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let (commit_pp, vp) = Fri::<F, H>::trim(param, poly_size, batch_size)?;

        Ok((
            ZeromorphFriProverParam { commit_pp },
            ZeromorphFriVerifierParam { vp },
        ))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        let mut evals = poly.evals();
        // let (coeffs, evals_) = interpolate_over_boolean_hypercube_with_copy(&evals.to_vec());
        //	println!("after interp");

        let poly = UnivariatePolynomial::new(evals.to_vec());
        Fri::commit(&pp.commit_pp, &poly)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        //	println!("in batch commit");
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().map(|poly| poly).collect();
        polys_vec
            .par_iter()
            .map(|poly| {
                //		println!("ind commit");
                Self::commit(pp, poly)
            })
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        // a proof consists of roots, merkle paths, query paths,  eval, and final oracle
        transcript.write_field_element(&eval); //write eval

        let num_vars = poly.num_vars();

        if cfg!(feature = "sanity-check") {
            assert_eq!(poly.evaluate(point), *eval);
        }

        let (quotients, remainder) = quotients(poly, point, |_, q| UnivariatePolynomial::new(q));
        let quotients_rscoded: Vec<_> = quotients
            .iter()
            .map(|q| {
                let q_coeffs = q.coeffs().to_vec();
                let mut new_coeffs = vec![<F as ff::Field>::ZERO; 1 << num_vars];
                new_coeffs[0..q_coeffs.len()].copy_from_slice(&q_coeffs);
                UnivariatePolynomial::new(new_coeffs)
            })
            .collect();

        if cfg!(feature = "sanity-check") {
            for q in quotients_rscoded.clone() {
                assert_eq!(
                    q.degree(),
                    (1 << num_vars) - 1,
                    "degree of quotient is not correct, q.degree(): {:?}, num_vars: {:?}",
                    q.degree(),
                    num_vars
                );
            }
        }

        let comms =
            Fri::<F, H>::batch_commit_and_write(&pp.commit_pp, &quotients_rscoded, transcript)?;

        if cfg!(feature = "sanity-check") {
            assert_eq!(&remainder, eval);
        }

        let x = transcript.squeeze_challenge();
        let y = transcript.squeeze_challenge();
        let z = transcript.squeeze_challenge();

        let f = UnivariatePolynomial::new(poly.evals().to_vec());

        open_helper(
            &pp.commit_pp,
            &f,
            &quotients_rscoded,
            comm,
            &comms,
            &x,
            &y,
            &z,
            point.as_slice(),
            eval,
            transcript,
        )
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();

        for eval in evals {
            let poly = polys[eval.poly()];
            let comm = comms[eval.poly()];
            let point = &points[eval.point()];
            Self::open(pp, &poly, &comm, point, &eval.value(), transcript)?;
        }

        Ok(())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        Fri::read_commitments(&vp.vp, num_polys, transcript)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        assert_eq!(*eval, transcript.read_field_element()?);
        let num_vars = point.len();
        let lg_n = num_vars + vp.vp.log_rate;

        let q_comms = Fri::<F, H>::read_commitments(&vp.vp, num_vars, transcript)?;

        let x = transcript.squeeze_challenge();
        let y = transcript.squeeze_challenge();
        let z = transcript.squeeze_challenge();

        let (eval_scalar, q_scalars) = eval_and_quotient_scalars(y, x, z, point);

        let fold_challenges = transcript.squeeze_challenges(vp.vp.num_rounds);
        let intermediate_comms = transcript.read_commitments(vp.vp.num_rounds)?;

        let queries = transcript.squeeze_challenges(vp.vp.num_verifier_queries);
        let queries_usize: Vec<usize> = queries
            .iter()
            .map(|x_index| {
                let x_rep = (*x_index).to_repr();
                let mut x: &[u8] = x_rep.as_ref();
                let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
                let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
                ((x_int as usize) % (1 << lg_n)).into()
            })
            .collect_vec();

        let ldt_query_paths: Vec<Vec<Vec<F>>> = transcript
            .read_field_elements(vp.vp.num_verifier_queries * vp.vp.num_rounds * 2)?
            .chunks(vp.vp.num_rounds * 2)
            .map(|chunk| {
                chunk
                    .iter()
                    .collect_vec()
                    .chunks(2)
                    .map(|chunk| chunk.iter().map(|x| **x).collect())
                    .collect()
            })
            .collect();

        let ldt_merkle_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = (0..vp.vp.num_verifier_queries)
            .into_iter()
            .map(|i| {
                let mut merkle_paths: Vec<Vec<Vec<Output<H>>>> =
                    Vec::with_capacity(vp.vp.num_rounds);
                for round in 1..(vp.vp.num_rounds + 1) {
                    let mut merkle_path: Vec<Output<H>> = transcript
                        .read_commitments(2 * (vp.vp.num_vars - round + vp.vp.log_rate - 1))
                        .unwrap();

                    let chunked_path: Vec<Vec<Output<H>>> =
                        merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                    merkle_paths.push(chunked_path);
                }
                merkle_paths
            })
            .collect();

        let corresponding_points: Vec<Vec<Vec<F>>> = transcript
            .read_field_elements(vp.vp.num_verifier_queries * (q_comms.len() + 1) * 2)?
            .chunks((q_comms.len() + 1) * 2)
            .map(|chunk| {
                chunk
                    .iter()
                    .collect_vec()
                    .chunks(2)
                    .map(|chunk| chunk.iter().map(|x| **x).collect())
                    .collect()
            })
            .collect();

        let corresponding_paths: Vec<Vec<Vec<Vec<Output<H>>>>> = transcript
            .read_commitments(
                vp.vp.num_verifier_queries
                    * (q_comms.len() + 1)
                    * (vp.vp.num_rounds + vp.vp.log_rate)
                    * 2,
            )?
            .chunks((q_comms.len() + 1) * (vp.vp.num_rounds + vp.vp.log_rate) * 2)
            .map(|chunk| {
                chunk
                    .iter()
                    .collect_vec()
                    .chunks((vp.vp.num_rounds + vp.vp.log_rate) * 2)
                    .map(|chunk| {
                        chunk
                            .iter()
                            .collect_vec()
                            .chunks(2)
                            .map(|chunk| chunk.iter().map(|x| (**x).clone()).collect())
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let last_level = &vp.vp.table_w_weights[vp.vp.num_vars + vp.vp.log_rate - 1];

        // println!("verifier query {:?}", queries_usize);
        for (i, query) in queries_usize.iter().enumerate() {
            let ldt_query_path = &ldt_query_paths[i];
            let ldt_merkle_path = &ldt_merkle_paths[i];
            let corresponding_points = &corresponding_points[i];
            let corresponding_paths = &corresponding_paths[i];

            // verify merkle paths of f and qs
            for (j, (pair, path)) in corresponding_points
                .iter()
                .zip_eq(corresponding_paths.iter())
                .enumerate()
            {
                assert_eq!(path[path.len() - 1][0], path[path.len() - 1][1]);
                if j == 0 {
                    assert_eq!(
                        path[path.len() - 1][0],
                        comm.codeword_tree[comm.codeword_tree.len() - 1][0]
                    );
                } else {
                    assert_eq!(
                        path[path.len() - 1][0],
                        q_comms[j - 1].codeword_tree[q_comms[j - 1].codeword_tree.len() - 1][0]
                    );
                }
                authenticate_merkle_path::<H, F>(
                    path,
                    (pair[0], pair[1]),
                    *query,
                    vp.vp.num_rounds,
                );
            }

            // calculate virtual g
            let f_eval = corresponding_points[0][query & 1];
            let q_evals = &corresponding_points[1..]
                .iter()
                .map(|x| x[query & 1])
                .collect_vec();

            let mut chosen = last_level[*query / 2].0;
            if *query % 2 == 1 {
                chosen = -chosen;
            }
            let q_hat: F = powers(y)
                .zip(q_evals)
                .enumerate()
                .map(|(j, (power_of_y, q))| {
                    // println!(
                    //     "query {:?}, power_of_y {:?}, q {:?}, chosen {:?}, powers_of_chosen {:?}",
                    //     query,
                    //     power_of_y,
                    //     q,
                    //     chosen,
                    //     chosen.pow([(1 << num_vars) - (1 << j)])
                    // );
                    power_of_y * q * &chosen.pow([(1 << num_vars) - (1 << j)])
                })
                .sum();

            // println!("verifier q_hat {:?}", q_hat);

            let mut virtual_g = f_eval;
            // println!("verifier g0 {:?}", virtual_g);
            virtual_g *= &z;
            // println!("verifier g1 {:?}", virtual_g);
            virtual_g += &q_hat;
            // println!("verifier g2 {:?}", virtual_g);
            virtual_g += &(eval_scalar * eval);
            // println!("verifier g3 {:?}", virtual_g);
            izip!(q_evals, &q_scalars).for_each(|(q, scalar)| virtual_g += &(*scalar * q));
            // println!("verifier g4 {:?}", virtual_g);

            // poly div
            virtual_g *= &(chosen - &x).invert().unwrap();

            // again, calculate virtual g sibling
            let query_sib = query ^ 1;
            let f_eval_sib = corresponding_points[0][query_sib & 1];
            let q_eval_sibs = &corresponding_points[1..]
                .iter()
                .map(|x| x[query_sib & 1])
                .collect_vec();

            let mut chosen_sib = last_level[query_sib / 2].0;
            if query_sib % 2 == 1 {
                chosen_sib = -chosen_sib;
            }
            let q_hat_sib: F = powers(y)
                .zip(q_eval_sibs)
                .enumerate()
                .map(|(j, (power_of_y, q))| {
                    power_of_y * q * &chosen_sib.pow([(1 << num_vars) - (1 << j)])
                })
                .sum();

            let mut virtual_g_sib = f_eval_sib;
            // println!("verifier g0 {:?}", virtual_g_sib);
            virtual_g_sib *= &z;
            // println!("verifier g1 {:?}", virtual_g_sib);
            virtual_g_sib += &q_hat_sib;
            // println!("verifier g2 {:?}", virtual_g_sib);
            virtual_g_sib += &(eval_scalar * eval);
            // println!("verifier g3 {:?}", virtual_g_sib);
            izip!(q_eval_sibs, &q_scalars).for_each(|(q, scalar)| virtual_g_sib += &(*scalar * q));
            // println!("verifier g4 {:?}", virtual_g_sib);

            // poly div
            virtual_g_sib *= &(chosen_sib - &x).invert().unwrap();

            let mut padded_query_path = ldt_query_path.clone();
            let pair;
            if *query % 2 == 0 {
                pair = vec![virtual_g, virtual_g_sib];
            } else {
                pair = vec![virtual_g_sib, virtual_g];
            }
            padded_query_path.insert(0, pair);

            // println!("padded_query_path[0] {:?}", padded_query_path[0]);

            // verify virtual g and virtual g sibling
            verifier_query_phase::<F, H>(
                *query,
                ldt_merkle_path,
                &fold_challenges,
                &padded_query_path,
                vp.vp.num_rounds,
                vp.vp.num_vars,
                vp.vp.log_rate,
                &intermediate_comms,
            )?;
        }

        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let num_vars = points.first().map(|point| point.len()).unwrap_or_default();
        let comms = comms.into_iter().collect_vec();

        for eval in evals {
            let comm = comms[eval.poly()];
            let point = &points[eval.point()];
            Self::verify(vp, &comm, point, &eval.value(), transcript)?;
        }

        Ok(())
    }
}
fn authenticate_merkle_path<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
    height: usize,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..height {
        if (i + 1 == height) {
            break;
        }
        let mut hasher = H::new();
        let mut hash = Output::<H>::default();
        hasher.update(&path[i][0]);
        hasher.update(&path[i][1]);
        hasher.finalize_into_reset(&mut hash);

        assert_eq!(hash, path[i + 1][(x_index >> 1) % 2]);
        x_index >>= 1;
    }
}
fn eval_and_quotient_scalars<F: Field>(y: F, x: F, z: F, u: &[F]) -> (F, Vec<F>) {
    let num_vars = u.len();

    let squares_of_x = squares(x).take(num_vars + 1).collect_vec();
    let offsets_of_x = {
        let mut offsets_of_x = squares_of_x
            .iter()
            .rev()
            .skip(1)
            .scan(F::ONE, |state, power_of_x| {
                *state *= power_of_x;
                Some(*state)
            })
            .collect_vec();
        offsets_of_x.reverse();
        offsets_of_x
    };
    let vs = {
        let v_numer = squares_of_x[num_vars] - F::ONE;
        let mut v_denoms = squares_of_x
            .iter()
            .map(|square_of_x| *square_of_x - F::ONE)
            .collect_vec();
        v_denoms.iter_mut().batch_invert();
        v_denoms
            .iter()
            .map(|v_denom| v_numer * v_denom)
            .collect_vec()
    };
    let q_scalars = izip!(powers(y), offsets_of_x, squares_of_x, &vs, &vs[1..], u)
        .map(|(power_of_y, offset_of_x, square_of_x, v_i, v_j, u_i)| {
            -(power_of_y * offset_of_x + z * (square_of_x * v_j - *u_i * v_i))
        })
        .collect_vec();

    (-vs[0] * z, q_scalars)
}

pub fn interpolate_over_boolean_hypercube<F: PrimeField>(mut evals: Vec<F>) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());
    let now = Instant::now();
    for i in 1..n + 1 {
        let chunk_size = 1 << i;
        evals.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }
    //    println!("for loop {:?}", now.elapsed());
    reverse_index_bits_in_place(&mut evals); //todo: move this to commit so code is cleaner

    evals
}
fn interpolate_over_boolean_hypercube_with_copy<F: PrimeField>(evals: &Vec<F>) -> (Vec<F>, Vec<F>) {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let n = log2_strict(evals.len());
    let mut coeffs = vec![F::ZERO; evals.len()];
    let mut new_evals = vec![F::ZERO; evals.len()];

    let mut j = 0;
    while (j < coeffs.len()) {
        new_evals[j] = evals[j];
        new_evals[j + 1] = evals[j + 1];

        coeffs[j + 1] = evals[j + 1] - evals[j];
        coeffs[j] = evals[j];
        j += 2
    }

    for i in 2..n + 1 {
        let chunk_size = 1 << i;
        coeffs.par_chunks_mut(chunk_size).for_each(|chunk| {
            let half_chunk = chunk_size >> 1;
            for j in half_chunk..chunk_size {
                chunk[j] = chunk[j] - chunk[j - half_chunk];
            }
        });
    }

    (coeffs, new_evals)
}
fn query_codeword<F: PrimeField, H: Hash>(
    query: &usize,
    codeword: &Vec<F>,
    codeword_tree: &Vec<Vec<Output<H>>>,
) -> ((F, F), Vec<(Output<H>, Output<H>)>) {
    let mut p0 = *query;
    let temp = p0;
    let mut p1 = p0 ^ 1;
    if (p1 < p0) {
        p0 = p1;
        p1 = temp;
    }
    return (
        (codeword[p0], codeword[p1]),
        get_merkle_path::<H, F>(&codeword_tree, *query, true),
    );
}
fn get_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    root: bool,
) -> Vec<(Output<H>, Output<H>)> {
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
                queries.push((oracle[0].clone(), oracle[0].clone()));
            }
            break;
        }
        queries.push((oracle[p0].clone(), oracle[p1].clone()));
        x_index >>= 1;
    }

    return queries;
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
        assert_eq!(level.len(), chunk_size >> 1);
        <Vec<F> as AsMut<[F]>>::as_mut(&mut coeffs_with_rep)
            .chunks_mut(chunk_size)
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

pub fn open_helper<H: Hash>(
    pp: &FriProverParams<F>,
    f: &UnivariatePolynomial<F, CoefficientBasis>,
    qs: &Vec<UnivariatePolynomial<F, CoefficientBasis>>,
    f_comm: &FriCommitment<F, H>,
    q_comms: &Vec<FriCommitment<F, H>>,
    x: &F,
    y: &F,
    z: &F,
    point: &[F],
    eval: &F,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
) -> Result<(), Error> {
    //construct evaluation codeword
    let num_vars = pp.num_vars;
    assert_eq!(num_vars, qs.len());
    let mut denominator = Vec::new();
    let mut numerator = Vec::new();
    let last_level = &pp.table_w_weights[pp.table_w_weights.len() - 1];
    let dft = p3_dft::Radix2Dit::default();

    let q_hat = {
        let mut q_hat = vec![<F as ff::Field>::ZERO; 1 << num_vars];
        for (idx, (power_of_y, q)) in izip!(powers(*y), qs).enumerate() {
            let offset = (1 << num_vars) - (1 << idx);
            parallelize(&mut q_hat[offset..], |(q_hat, start)| {
                izip!(q_hat, q.iter().skip(start)).for_each(|(q_hat, q)| *q_hat += power_of_y * q)
            });
            // for i in 0..(1 << idx) {
            //     q_hat[offset + i] += power_of_y * q.coeffs()[i];
            // }
        }
        UnivariatePolynomial::new(q_hat)
    };

    if cfg!(feature = "sanity-check") {
        let q_hat_2 = {
            let mut q_hat = vec![<F as ff::Field>::ZERO; 1 << num_vars];
            for (idx, (power_of_y, q)) in izip!(powers(*y), qs).enumerate() {
                let offset = (1 << num_vars) - (1 << idx);
                // parallelize(&mut q_hat[offset..], |(q_hat, start)| {
                //     izip!(q_hat, q.iter().skip(start)).for_each(|(q_hat, q)| *q_hat += power_of_y * q)
                // });
                // let dft = p3_dft::Radix2Dit::default();
                // println!("q {:?}: {:?}", idx, dft.dft(q_hat.clone()));
                for i in 0..(1 << idx) {
                    q_hat[offset + i] += power_of_y * q.coeffs()[i];
                }
            }
            UnivariatePolynomial::new(q_hat)
        };

        assert_eq!(q_hat, q_hat_2);

        // for q in q_comms {
        //     println!("q {:?}", q.codeword);
        // }

        let mut q_hat_expected = vec![<F as ff::Field>::ZERO; 1 << (num_vars + pp.log_rate)];
        for (idx, (power_of_y, q)) in izip!(powers(*y), q_comms).enumerate() {
            let offset = (1 << num_vars) - (1 << idx);
            for i in 0..1 << (num_vars + pp.log_rate) {
                // let mut x = pp.table_w_weights[num_vars + pp.log_rate - 1]
                //     [i % (1 << (num_vars + pp.log_rate - 1))]
                //     .0;
                let mut x = primitive_root_of_unity::<F>(num_vars + pp.log_rate)
                    .pow([reverse_bits(i, num_vars + pp.log_rate) as u64]);
                assert_eq!(
                    x,
                    pp.table_w_weights[num_vars + pp.log_rate - 1][i / 2].0
                        * if i & 1 == 0 {
                            <F as ff::Field>::ONE
                        } else {
                            -<F as ff::Field>::ONE
                        }
                );
                q_hat_expected[i] += power_of_y * q.codeword[i] * x.pow([offset as u64]);
                // println!(
                //     "i {:?}, q.codeword[i] {:?}, x {:?}, power_of_y {:?}, power_of_x {:?}",
                //     i,
                //     q.codeword[i],
                //     x,
                //     power_of_y,
                //     x.pow([offset as u64])
                // );
            }
        }
        reverse_index_bits_in_place(&mut q_hat_expected);
        let mut q_hat_coeffs = dft.idft(q_hat_expected);
        assert_eq!(q_hat_coeffs[..(1 << num_vars)], q_hat.coeffs().to_vec());
        q_hat_coeffs.dedup();
        assert!(q_hat_coeffs.len() <= 1 << num_vars + 1);

        // println!("prover q_hat {:?}", q_hat);
    }

    let (eval_scalar, q_scalars) = eval_and_quotient_scalars(*y, *x, *z, point);

    let mut g = f.clone();
    if cfg!(feature = "sanity-check") {
        let mut g_coeffs = g.coeffs().to_vec();
        reverse_index_bits_in_place(&mut g_coeffs);
        let mut res = evaluate_over_foldable_domain(pp.log_rate, g_coeffs.clone(), &pp.table);
        reverse_index_bits_in_place(&mut res);
        assert_eq!(res, f_comm.codeword);
        // println!(
        //     "prover g0 {:?}",
        //     evaluate_over_foldable_domain(pp.log_rate, g_coeffs, &pp.table)
        // );
    }
    g *= &z;
    if cfg!(feature = "sanity-check") {
        let mut g_coeffs = g.coeffs().to_vec();
        g_coeffs = g.coeffs().to_vec();
        reverse_index_bits_in_place(&mut g_coeffs);
        // println!(
        //     "prover g1 {:?}",
        //     evaluate_over_foldable_domain(pp.log_rate, g_coeffs, &pp.table)
        // );
    }
    g += &q_hat;
    if cfg!(feature = "sanity-check") {
        let mut g_coeffs = g.coeffs().to_vec();
        g_coeffs = g.coeffs().to_vec();
        reverse_index_bits_in_place(&mut g_coeffs);
        // println!(
        //     "prover g2 {:?}",
        //     evaluate_over_foldable_domain(pp.log_rate, g_coeffs, &pp.table)
        // );
    }
    g[0] += eval_scalar * eval;
    if cfg!(feature = "sanity-check") {
        let mut g_coeffs = g.coeffs().to_vec();
        g_coeffs = g.coeffs().to_vec();
        reverse_index_bits_in_place(&mut g_coeffs);
        // println!(
        //     "prover g3 {:?}",
        //     evaluate_over_foldable_domain(pp.log_rate, g_coeffs, &pp.table)
        // );
    }
    izip!(qs, &q_scalars).for_each(|(q, scalar)| g += (scalar, q));
    if cfg!(feature = "sanity-check") {
        let mut g_coeffs = g.coeffs().to_vec();
        g_coeffs = g.coeffs().to_vec();
        reverse_index_bits_in_place(&mut g_coeffs);
        // println!(
        //     "prover g4 {:?}",
        //     evaluate_over_foldable_domain(pp.log_rate, g_coeffs, &pp.table)
        // );
    }

    let point = x;
    let eval = <F as ff::Field>::ZERO;
    if cfg!(feature = "sanity-check") {
        assert_eq!(eval, g.evaluate(point));
    }

    let mut g_coeffs = g.coeffs().to_vec();
    reverse_index_bits_in_place(&mut g_coeffs);

    let g = evaluate_over_foldable_domain(pp.log_rate, g_coeffs, &pp.table);

    if cfg!(feature = "sanity-check") {
        let dft: p3_dft::Radix2Dit<F> = p3_dft::Radix2Dit::default();
        let g_from_evals = dft.idft(g.clone());

        assert_eq!(g.len(), 1 << (num_vars + pp.log_rate));
        let mut g_cp = g_from_evals.clone();
        g_cp.dedup();
        assert!(
            g_cp.len() <= 1 << num_vars + 1,
            "g_cp.len() {:?}, num_vars {:?}",
            g_cp.len(),
            num_vars
        );

        let gen: F = primitive_root_of_unity(num_vars + pp.log_rate);
        let mut test_slice = gen
            .powers()
            .take(1 << (num_vars + pp.log_rate))
            .collect_vec();
        reverse_index_bits_in_place(&mut test_slice);
    }

    let mut d_pointer = 0;
    let mut rbo_g = g.clone();
    reverse_index_bits_in_place(&mut rbo_g);
    for j in 0..(1 << (num_vars + pp.log_rate)) {
        let mut x: F = last_level[d_pointer].0;
        if j % 2 != 0 {
            d_pointer = d_pointer + 1;
            x = -x;
        }
        // assert_eq!(
        //     x, test_slice[j],
        //     "j {:?}, x {:?}, test_slice[j] {:?}",
        //     j, x, test_slice[j]
        // );
        denominator.push(x - point);
        numerator.push(rbo_g[j] - eval);
    }

    if cfg!(feature = "sanity-check") {
        let mut numerator_cp = numerator.clone();
        reverse_index_bits_in_place(&mut numerator_cp);
        let mut numerator_cp_evals = dft.idft(numerator_cp);
        numerator_cp_evals.dedup();
        assert!(
            numerator_cp_evals.len() <= 1 << num_vars + 1,
            "numerator_cp_evals.len() {:?}, num_vars {:?}",
            numerator_cp_evals.len(),
            num_vars
        );

        let mut denominator_cp = denominator.clone();
        reverse_index_bits_in_place(&mut denominator_cp);
        let mut denominator_cp_evals = dft.idft(denominator_cp);
        denominator_cp_evals.dedup();
        assert!(
            denominator_cp_evals.len() <= 1 << num_vars + 1,
            "denominator_cp_evals.len() {:?}, num_vars {:?}",
            denominator_cp_evals.len(),
            num_vars
        );
    }

    //batch invert denominators
    let mut scratch_space = vec![<F as ff::Field>::ZERO; denominator.len()];
    BatchInverter::invert_with_external_scratch(&mut denominator, &mut scratch_space);

    let mut evaluation_codeword = vec![<F as ff::Field>::ZERO; 1 << (num_vars + pp.log_rate)];
    //multiply numerators and inverted denominators
    evaluation_codeword
        .par_iter_mut()
        .enumerate()
        .for_each(|(j, c)| {
            *c = numerator[j] * denominator[j];
        });

    if cfg!(feature = "sanity-check") {
        let mut evaluation_codeword_rbo = evaluation_codeword.clone();
        reverse_index_bits_in_place(&mut evaluation_codeword_rbo);
        let mut evaluation_codeword_rbo_evals = dft.idft(evaluation_codeword_rbo);
        evaluation_codeword_rbo_evals.dedup();
        assert!(
            evaluation_codeword_rbo_evals.len() <= 1 << num_vars + 1,
            "evaluation_codeword_rbo_evals.len() {:?}, num_vars {:?}",
            evaluation_codeword_rbo_evals.len(),
            num_vars
        );
    }

    // println!("evaluation_codeword {:?}", evaluation_codeword);

    let (trees, mut oracles) = commit_phase::<F, H>(
        &point,
        &evaluation_codeword,
        transcript,
        pp.num_vars,
        pp.num_rounds,
        &pp.table_w_weights,
    );

    let (queried_els, queries_usize) = query_phase::<F, H>(
        transcript,
        &evaluation_codeword,
        &oracles,
        pp.num_verifier_queries,
    );

    // write final oracle
    // let mut final_oracle = oracles.pop().unwrap();
    // transcript.write_field_elements(&final_oracle);

    // write query paths
    queried_els
        .iter()
        .map(|q| &q.0)
        .flatten()
        .for_each(|query| {
            transcript.write_field_element(&query.0);
            transcript.write_field_element(&query.1);
        });

    // write merkle paths
    queried_els.iter().for_each(|query| {
        let indices = &query.1;
        indices.into_iter().enumerate().for_each(|(i, q)| {
            let root = trees[i][trees[i].len() - 1][0].clone();
            println!("write merkle path q {:?}, root {:?}", q, root);
            write_merkle_path::<H, F>(&trees[i], *q, transcript);
        })
    });

    // query corresponding points in original commitment
    let mut corresponding_points = Vec::new();
    let mut corresponding_paths = Vec::new();
    for query in &queries_usize {
        let res = query_codeword::<F, H>(query, &f_comm.codeword, &f_comm.codeword_tree);
        corresponding_points.push(res.0);
        corresponding_paths.push(res.1.clone());
        for q_comm in q_comms {
            let res = query_codeword::<F, H>(query, &q_comm.codeword, &q_comm.codeword_tree);
            corresponding_points.push(res.0);
            corresponding_paths.push(res.1.clone());
        }
    }

    // write corresponding queries
    corresponding_points.iter().for_each(|query| {
        transcript.write_field_element(&query.0);
        transcript.write_field_element(&query.1);
    });

    // write corresponding paths
    corresponding_paths.iter().flatten().for_each(|(h1, h2)| {
        transcript.write_commitment(h1);
        transcript.write_commitment(h2);
    });

    let query = queries_usize[0];
    let x = pp.table_w_weights[pp.num_vars + pp.log_rate - 1]
        [query % (1 << (pp.num_vars + pp.log_rate - 1))]
        .0
        * if query > (1 << (pp.num_vars + pp.log_rate - 1)) {
            -<MyFr as ff::Field>::ONE
        } else {
            <MyFr as ff::Field>::ONE
        };

    let expected = powers(*y)
        .zip(qs)
        .enumerate()
        .map(|(i, (power_of_y, q))| {
            // println!("power_of_y {:?}", power_of_y);
            // println!("q {:?}", q.evaluate(&x));
            // println!("x {:?}", x.pow([1 << num_vars - 1 << i]));
            power_of_y * q.evaluate(&x) * x.pow([1 << num_vars - 1 << i])
        })
        .sum::<F>();
    // println!("prover check 0 {:?}", expected);

    // UnivariatePolynomial::new(q_hat).evaluate(x);
    // println!("prover check 1 q_hat {:?}", q_hat.evaluate(&x));
    let q_evals = &corresponding_points[1..]
        .iter()
        .map(|x| if query % 2 == 0 { x.0 } else { x.1 })
        .collect_vec();

    let mut chosen = last_level[query / 2].0;
    if query % 2 == 1 {
        chosen = -chosen;
    }
    let q_hat: F = powers(*y)
        .zip(q_evals)
        .map(|(power_of_y, q)| power_of_y * q * &chosen)
        .sum();

    // println!("prover check 2 q_hat {:?}", q_hat);

    //	println!("additional overhead {:?}", ov.elapsed());
    Ok(())
}

//outputs (trees, oracles, eval)
fn commit_phase<F: PrimeField, H: Hash>(
    point: &Point<F, UnivariatePolynomial<F, CoefficientBasis>>,
    f: &Vec<F>,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    num_vars: usize,
    num_rounds: usize,
    table_w_weights: &Vec<Vec<(F, F)>>,
) -> (Vec<Vec<Vec<Output<H>>>>, Vec<Vec<F>>) {
    let mut oracles = Vec::with_capacity(num_vars);

    let mut trees = Vec::with_capacity(num_vars);

    let mut root = Output::<H>::default();
    let mut new_oracle = f;

    let num_rounds = num_rounds;

    let challenges: Vec<F> = transcript.squeeze_challenges(num_rounds);

    for i in 0..num_rounds {
        let challenge = challenges[i];
        if cfg!(feature = "sanity-check") {
            println!("challenge {:?}", challenge);
            for (i, el) in new_oracle.iter().enumerate() {
                println!("i {:?}, el {:?}", i, el);
            }
        }
        oracles.push(basefold_one_round_by_interpolation_weights::<F>(
            &table_w_weights,
            i,
            new_oracle,
            challenge,
        ));
        if cfg!(feature = "sanity-check") {
            for (i, el) in oracles[i].iter().enumerate() {
                println!("i {:?}, el {:?}", i, el);
            }
        }

        new_oracle = &oracles[i];

        trees.push(merkelize::<F, H>(&new_oracle));
        root = trees[i][trees[i].len() - 1][0].clone();
        if cfg!(feature = "sanity-check") {
            println!("root {:?}", root);
        }
        transcript.write_commitment(&root).unwrap();
    }

    return (trees, oracles);
}

fn query_phase<F: PrimeField, H: Hash>(
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
    f: &Vec<F>,
    oracles: &Vec<Vec<F>>,
    num_verifier_queries: usize,
) -> (Vec<(Vec<(F, F)>, Vec<usize>)>, Vec<usize>) {
    let mut queries = transcript.squeeze_challenges(num_verifier_queries);

    let queries_usize: Vec<usize> = queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % f.len()).into()
        })
        .collect_vec();

    // println!("prover query {:?}", queries_usize);

    (
        queries_usize
            .par_iter()
            .map(|x_index| {
                return basefold_get_query::<F>(&oracles, *x_index);
            })
            .collect(),
        queries_usize,
    )
}

fn get_query_indices<F: PrimeField>(rand_queries: &Vec<F>, codeword_len: usize) -> Vec<usize> {
    rand_queries
        .iter()
        .map(|x_index| {
            let x_rep = (*x_index).to_repr();
            let mut x: &[u8] = x_rep.as_ref();
            let (int_bytes, rest) = x.split_at(std::mem::size_of::<u32>());
            let x_int: u32 = u32::from_be_bytes(int_bytes.try_into().unwrap());
            ((x_int as usize) % codeword_len).into()
        })
        .collect_vec()
}

fn basefold_one_round_by_interpolation_weights<F: PrimeField>(
    table: &Vec<Vec<(F, F)>>,
    table_offset: usize,
    values: &Vec<F>,
    challenge: F,
) -> Vec<F> {
    let level = &table[table.len() - 1 - table_offset];
    assert_eq!(level.len(), values.len() / 2);

    values
        .par_chunks_exact(2)
        .enumerate()
        .map(|(i, ys)| {
            // println!(
            //     "prover i {:?}, x0 {:?}, y0 {:?}, x1 {:?}, y1 {:?}",
            //     i,
            //     level[i].0,
            //     ys[0],
            //     -(level[i].0),
            //     ys[1]
            // );
            interpolate2_weights::<F>(
                [(level[i].0, ys[0]), (-(level[i].0), ys[1])],
                level[i].1,
                challenge,
            )
        })
        .collect::<Vec<_>>()
}

fn merkelize<F: PrimeField, H: Hash>(values: &Vec<F>) -> Vec<Vec<Output<H>>> {
    let log_v = log2_strict(values.len());
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

pub fn interpolate2_weights<F: PrimeField>(points: [(F, F); 2], weight: F, x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    //    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * weight
}

fn basefold_get_query<F: PrimeField>(
    // first_oracle: &Vec<F>,
    oracles: &Vec<Vec<F>>,
    mut x_index: usize,
) -> (Vec<(F, F)>, Vec<usize>) {
    // println!("x_index {:?}", x_index);
    let mut queries = Vec::with_capacity(oracles.len() + 1);
    let mut indices = Vec::with_capacity(oracles.len() + 1);

    let mut p0 = x_index;
    let mut p1 = x_index ^ 1;

    if (p1 < p0) {
        p0 = x_index ^ 1;
        p1 = x_index;
    }
    // queries.push((first_oracle[p0], first_oracle[p1]));
    // indices.push(p0);
    x_index >>= 1;

    for oracle in oracles {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        queries.push((oracle[p0], oracle[p1]));
        indices.push(p0);
        x_index >>= 1;
    }

    return (queries, indices);
}

fn write_merkle_path<H: Hash, F: PrimeField>(
    tree: &Vec<Vec<Output<H>>>,
    mut x_index: usize,
    transcript: &mut impl TranscriptWrite<Output<H>, F>,
) {
    x_index >>= 1;
    for oracle in tree {
        let mut p0 = x_index;
        let mut p1 = x_index ^ 1;
        if (p1 < p0) {
            p0 = x_index ^ 1;
            p1 = x_index;
        }
        if (oracle.len() == 1) {
            //	    transcript.write_commitment(&oracle[0]);
            break;
        }
        if cfg!(feature = "sanity-check") {
            println!(
                "write merkle path oracle[p0] {:?}, oracle[p1] {:?}",
                oracle[p0], oracle[p1]
            );
        }
        transcript.write_commitment(&oracle[p0]);
        transcript.write_commitment(&oracle[p1]);
        x_index >>= 1;
    }
}

fn verifier_query_phase<F: PrimeField, H: Hash>(
    query_usize: usize,
    query_merkle_paths: &Vec<Vec<Vec<Output<H>>>>,
    fold_challenges: &Vec<F>,
    queries: &Vec<Vec<F>>,
    num_rounds: usize,
    num_vars: usize,
    log_rate: usize,
    roots: &Vec<Output<H>>,
) -> Result<(), Error> {
    let n = (1 << (num_vars + log_rate));
    let lg_n = num_vars + log_rate;

    let mut bases = Vec::with_capacity(lg_n);
    let mut base = primitive_root_of_unity::<F>(lg_n);
    bases.push(base);

    for _ in 1..lg_n {
        base = base * base; // base = g^2^_
        bases.push(base);
    }

    let mut cur_index = query_usize;
    let mut cur_queries = &queries;

    for i in 0..num_rounds {
        let temp = cur_index;
        let mut other_index = cur_index ^ 1;
        if (other_index < cur_index) {
            cur_index = other_index;
            other_index = temp;
        }

        assert_eq!(cur_index % 2, 0);

        let ri0 = reverse_bits(cur_index, num_vars + log_rate - i);
        let ri1 = reverse_bits(other_index, num_vars + log_rate - i);

        let x0 = query_point(
            1 << (num_vars + log_rate - i),
            ri0,
            num_vars + log_rate - i - 1,
            bases[i],
        );

        let x1 = -x0;
        assert_eq!(x0, -F::ONE * x1);
        //                println!("query point {:?}", now.elapsed());
        if cfg!(feature = "sanity-check") {
            println!(
            "verifier cur_index {:?}, ri0 {:?}, x0 {:?}, cur_queries[0] {:?}, other_index {:?}, ri1 {:?}, x1 {:?}, cur_queries[1] {:?}",
            cur_index, ri0, x0, cur_queries[i][0], other_index, ri1, x1, cur_queries[i][1]
        );
        }
        let res = interpolate2(
            [(x0, cur_queries[i][0]), (x1, cur_queries[i][1])],
            fold_challenges[i],
        );

        assert_eq!(res, cur_queries[i + 1][(cur_index >> 1) % 2]);

        if i > 0 {
            if cfg!(feature = "sanity-check") {
                println!("x_index {:?}", cur_index);
                println!("leaves {:?}", (cur_queries[i][0], cur_queries[i][1]));
                println!("root {:?}", roots[i - 1]);
                println!("query_merkle_paths[i] {:?}", query_merkle_paths[i]);
            }
            authenticate_merkle_path_root::<H, F>(
                &query_merkle_paths[i - 1],
                (cur_queries[i][0], cur_queries[i][1]),
                cur_index,
                &roots[i - 1],
            );
        }

        cur_index >>= 1;
    }

    Ok(())
}

fn primitive_root_of_unity<F: PrimeField>(n_log: usize) -> F {
    assert!(n_log <= (F::S as usize));
    let base = F::ROOT_OF_UNITY;
    exp_power_of_2(base, (F::S as usize) - n_log)
}

fn exp_power_of_2<F: PrimeField>(el: F, power_log: usize) -> F {
    let mut res = el;
    for _ in 0..power_log {
        res *= res;
    }
    res
}

pub fn query_point<F: PrimeField>(
    block_length: usize,
    eval_index: usize,
    level: usize,
    base: F,
) -> F {
    let level_index = eval_index % (block_length);

    let mut el = exp_u64(&base, (level_index % (block_length >> 1)) as u64); //F::ONE;

    if level_index >= (block_length >> 1) {
        el = -F::ONE * el;
    }

    return el;
}

fn exp_u64<F: Field>(el: &F, power: u64) -> F {
    let mut current = *el;
    let mut product = F::ONE;
    for j in 0..bits_u64(power) {
        if (power >> j & 1) != 0 {
            product *= current;
        }
        current = current * current;
    }
    product
}

pub fn bits_u64(n: u64) -> usize {
    (64 - n.leading_zeros()) as usize
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

pub fn interpolate2<F: PrimeField>(points: [(F, F); 2], x: F) -> F {
    // a0 -> a1
    // b0 -> b1
    // x  -> a1 + (x-a0)*(b1-a1)/(b0-a0)
    let (a0, a1) = points[0];
    let (b0, b1) = points[1];
    assert_ne!(a0, b0);
    a1 + (x - a0) * (b1 - a1) * (b0 - a0).invert().unwrap()
}
