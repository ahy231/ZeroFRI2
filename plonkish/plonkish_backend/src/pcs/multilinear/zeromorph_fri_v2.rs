use crate::pcs::univariate::batched_fri::BatchedFri;
use crate::pcs::univariate::{open_helper, verify_helper, FriCommitment};
use crate::piop::sum_check::{
    classic::{ClassicSumCheck, CoefficientsProver},
    eq_xy_eval, SumCheck as _, VirtualPolynomial,
};
use crate::util::fake_extension::MyFr;
use crate::util::hash::Output;
use rand::rngs::OsRng;
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
        izip,
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
pub struct ZeromorphFri<Pcs>(PhantomData<Pcs>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeromorphFriProverParam<F: PrimeField> {
    commit_pp: FriProverParams<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeromorphFriVerifierParam<F: PrimeField> {
    vp: FriVerifierParams<F>,
}

impl<H> PolynomialCommitmentScheme<MyFr> for ZeromorphFri<Fri<MyFr, H>>
where
    H: Hash,
{
    type Param = <Fri<MyFr, H> as PolynomialCommitmentScheme<MyFr>>::Param;
    type ProverParam = ZeromorphFriProverParam<MyFr>;
    type VerifierParam = ZeromorphFriVerifierParam<MyFr>;
    type Polynomial = MultilinearPolynomial<MyFr>;
    type Commitment = <Fri<MyFr, H> as PolynomialCommitmentScheme<MyFr>>::Commitment;
    type CommitmentChunk = <Fri<MyFr, H> as PolynomialCommitmentScheme<MyFr>>::CommitmentChunk;

    fn setup(poly_size: usize, batch_size: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        BatchedFri::<MyFr, H>::setup(poly_size, batch_size, OsRng);
        Fri::<MyFr, H>::setup(poly_size, batch_size, rng)
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let (commit_pp, vp) = Fri::<MyFr, H>::trim(param, poly_size, batch_size)?;

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
        point: &Point<MyFr, Self::Polynomial>,
        f_eval: &MyFr,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error> {
        let num_vars = poly.num_vars();
        let uni_poly = UnivariatePolynomial::new(poly.evals().to_vec());

        if cfg!(feature = "sanity-check") {
            assert_eq!(poly.evaluate(point), *f_eval);
        }

        let (quotients, remainder) = quotients(poly, point, |_, q| UnivariatePolynomial::new(q));
        let now = Instant::now();
        let comms = BatchedFri::<MyFr, H>::batch_commit_and_write(
            &(),
            &quotients.clone().into_iter().rev().collect_vec(),
            transcript,
        )?;
        //	println!("batch {:?} batch size {:?}", now.elapsed(),quotients.len());

        if cfg!(feature = "sanity-check") {
            assert_eq!(&remainder, f_eval);
        }

        let x = transcript.squeeze_challenge();

        let (eval_scalar, q_scalars) = eval_and_quotient_scalars(x, &point);

        let mut f = UnivariatePolynomial::new(poly.evals().to_vec());
        let f_eval_at_x = f.evaluate(&x);

        if cfg!(feature = "sanity-check") {
            let mut f_eval = UnivariatePolynomial::new(vec![eval_scalar * f_eval]);
            izip!(&quotients, &q_scalars).for_each(|(q, scalar)| f_eval += (scalar, q));
            assert_eq!(f_eval_at_x, f_eval.evaluate(&x));
        }

        let uni_poly = UnivariatePolynomial::new(poly.evals().to_vec());
        let uni_poly_eval = uni_poly.evaluate(&x);
        transcript.write_field_element(&uni_poly_eval);
        Fri::<MyFr, H>::open(
            &pp.commit_pp,
            &uni_poly,
            &comm,
            &x,
            &uni_poly_eval,
            transcript,
        )?;

        let q_evals = quotients.iter().map(|q| q.evaluate(&x)).collect_vec();
        transcript.write_field_elements(&q_evals);

        let comm = Fri::<MyFr, H>::commit_and_write(&pp.commit_pp, &f, transcript).unwrap();
        Fri::<MyFr, H>::open(&pp.commit_pp, &f, &comm, &x, &f_eval_at_x, transcript)?;

        BatchedFri::<MyFr, H>::batch_open(
            &(),
            &quotients.clone().into_iter().rev().collect_vec(),
            &comms,
            &vec![x; quotients.len()],
            q_evals
                .iter()
                .rev()
                .map(|q_eval| Evaluation::new(0, 0, *q_eval))
                .collect_vec()
                .as_slice()
                .as_ref(),
            transcript,
        )
    }

    // fn batch_open<'a>(
    //     pp: &Self::ProverParam,
    //     polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    //     comms: impl IntoIterator<Item = &'a Self::Commitment>,
    //     points: &[Point<F, Self::Polynomial>],
    //     evals: &[Evaluation<F>],
    //     transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    // ) -> Result<(), Error> {
    //     let polys = polys.into_iter().collect_vec();
    //     let comms = comms.into_iter().collect_vec();
    //     let num_vars = points.first().map(|point| point.len()).unwrap_or_default();

    //     for e in evals {
    //         let poly = polys[e.poly()];
    //         let comm = comms[e.poly()];
    //         let point = &points[e.poly()];
    //         let eval = e.value();
    //         Self::open(pp, poly, comm, point, eval, transcript)?;
    //     }

    //     Ok(())
    // }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<MyFr, Self::Polynomial>],
        evals: &[Evaluation<MyFr>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();
        let num_vars = points.first().map(|point| point.len()).unwrap_or_default();

        let ell = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(ell);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let merged_polys = evals.iter().zip(eq_xt.evals().iter()).fold(
            vec![(MyFr::ONE, Cow::<MultilinearPolynomial<_>>::default()); points.len()],
            |mut merged_polys, (eval, eq_xt_i)| {
                if merged_polys[eval.point()].1.is_zero() {
                    merged_polys[eval.point()] = (*eq_xt_i, Cow::Borrowed(polys[eval.poly()]));
                } else {
                    let coeff = merged_polys[eval.point()].0;
                    if coeff != MyFr::ONE {
                        merged_polys[eval.point()].0 = MyFr::ONE;
                        *merged_polys[eval.point()].1.to_mut() *= &coeff;
                    }
                    *merged_polys[eval.point()].1.to_mut() += (eq_xt_i, polys[eval.poly()]);
                }
                merged_polys
            },
        );

        let unique_merged_polys = merged_polys
            .iter()
            .unique_by(|(_, poly)| addr_of!(*poly.deref()))
            .collect_vec();
        let unique_merged_poly_indices = unique_merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (_, poly))| (addr_of!(*poly.deref()), idx))
            .collect::<HashMap<_, _>>();
        let expression = merged_polys
            .iter()
            .enumerate()
            .map(|(idx, (scalar, poly))| {
                let poly = unique_merged_poly_indices[&addr_of!(*poly.deref())];
                Expression::<MyFr>::eq_xy(idx)
                    * Expression::Polynomial(Query::new(poly, Rotation::cur()))
                    * scalar
            })
            .sum();
        let virtual_poly = VirtualPolynomial::new(
            &expression,
            unique_merged_polys.iter().map(|(_, poly)| poly.deref()),
            &[],
            points,
        );

        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);
        let now = Instant::now();

        let (challenges, _) = SumCheck::prove(
            &(),
            pp.commit_pp.num_vars,
            virtual_poly,
            tilde_gs_sum,
            transcript,
        )?;
        //	println!("sum check time {:?}", now.elapsed().as_millis());

        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&challenges, point))
            .collect_vec();

        let g_prime = merged_polys
            .into_iter()
            .zip(eq_xy_evals.iter())
            .map(|((scalar, poly), eq_xy_eval)| (scalar * eq_xy_eval, poly.into_owned()))
            .sum::<MultilinearPolynomial<_>>();

        let (comm, eval) = if cfg!(feature = "sanity-check") {
            let scalars = evals
                .iter()
                .zip(eq_xt.evals())
                .map(|(eval, eq_xt_i)| eq_xy_evals[eval.point()] * eq_xt_i)
                .collect_vec();
            let bases = evals.iter().map(|eval| comms[eval.poly()]);
            let now = Instant::now();

            let comm = Self::Commitment::sum_with_scalar(&scalars, bases);
            //	    println!("sum with scalar {:?}", now.elapsed().as_millis());
            (comm, g_prime.evaluate(&challenges))
        } else {
            (Self::Commitment::default(), <MyFr as ff::Field>::ZERO)
        };

        let point = challenges;

        //write batch queries

        let poly = g_prime;

        let num_vars = poly.num_vars();

        if cfg!(feature = "sanity-check") {
            assert_eq!(poly.evaluate(&point[..]), eval);
        }

        let (quotients, remainder) =
            quotients(&poly, &point[..], |_, q| UnivariatePolynomial::new(q));
        let now = Instant::now();
        let comms_fri = BatchedFri::<MyFr, H>::batch_commit_and_write(
            &(),
            &quotients.clone().into_iter().rev().collect_vec(),
            transcript,
        )?;
        //	println!("batch {:?} batch size {:?}", now.elapsed(),quotients.len());

        if cfg!(feature = "sanity-check") {
            assert_eq!(remainder, eval);
        }

        let x = transcript.squeeze_challenge();

        let mut fri_polys = Vec::with_capacity(polys.len());
        let mut fri_evals = Vec::with_capacity(evals.len());
        for poly in &polys {
            let uni_poly = UnivariatePolynomial::new(poly.evals().to_vec());
            let uni_poly_eval = uni_poly.evaluate(&x);
            transcript.write_field_element(&uni_poly_eval);
            fri_polys.push(uni_poly);
            fri_evals.push(uni_poly_eval);
        }

        Fri::<MyFr, H>::batch_open(
            &pp.commit_pp,
            &fri_polys,
            comms.clone(),
            &vec![x; fri_polys.len()],
            fri_evals
                .iter()
                .enumerate()
                .map(|(idx, eval)| Evaluation::new(idx, idx, *eval))
                .collect_vec()
                .as_slice(),
            transcript,
        )?;

        // let timer = Instant::now();
        let q_evals = quotients.iter().map(|q| q.evaluate(&x)).collect_vec();
        transcript.write_field_elements(&q_evals);
        BatchedFri::<MyFr, H>::batch_open(
            &(),
            &quotients.clone().into_iter().rev().collect_vec(),
            &comms_fri,
            &vec![x; quotients.len()],
            q_evals
                .iter()
                .rev()
                .enumerate()
                .map(|(idx, q_eval)| Evaluation::new(idx, idx, *q_eval))
                .collect_vec()
                .as_slice()
                .as_ref(),
            transcript,
        )?;
        // let duration = timer.elapsed();
        // println!("batch verify {:?}", duration);

        let (eval_scalar, q_scalars) = eval_and_quotient_scalars(x, &point[..]);

        let mut f = UnivariatePolynomial::new(poly.evals().to_vec());
        let comm = Fri::<MyFr, H>::commit_and_write(&pp.commit_pp, &f, transcript);

        let f_eval_at_x = f.evaluate(&x);
        if cfg!(feature = "sanity-check") {
            let mut f_eval = UnivariatePolynomial::new(vec![eval_scalar * eval]);
            izip!(&quotients, &q_scalars).for_each(|(q, scalar)| f_eval += (scalar, q));
            assert_eq!(f_eval.evaluate(&x), f_eval_at_x);
        }

        let (res, q) = open_helper(
            &pp.commit_pp,
            &f,
            &comm.unwrap(),
            &x,
            &f_eval_at_x,
            transcript,
        );

        let (queried_els, queries_usize) = q;

        let mut individual_queries: Vec<Vec<(MyFr, MyFr)>> =
            Vec::with_capacity(queries_usize.len());

        let mut individual_paths: Vec<Vec<Vec<(Output<H>, Output<H>)>>> =
            Vec::with_capacity(queries_usize.len());

        for query in &queries_usize {
            let mut comm_queries = Vec::with_capacity(evals.len());
            let mut comm_paths = Vec::with_capacity(evals.len());
            for eval in evals {
                let c = &comms[eval.poly()];
                let res = query_codeword::<MyFr, H>(query, &c.codeword, &c.codeword_tree);
                comm_queries.push(res.0);
                comm_paths.push(res.1);
            }

            individual_queries.push(comm_queries);
            individual_paths.push(comm_paths);
        }

        individual_queries.iter().flatten().for_each(|(f1, f2)| {
            transcript.write_field_element(f1).unwrap();
            transcript.write_field_element(f2).unwrap();
        });
        //paths for batch
        individual_paths
            .iter()
            .flatten()
            .flatten()
            .for_each(|(h1, h2)| {
                transcript.write_commitment(h1);
                transcript.write_commitment(h2);
            });

        res
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        Fri::<MyFr, H>::read_commitments(&vp.vp, num_polys, transcript)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<MyFr, Self::Polynomial>,
        eval: &MyFr,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error> {
        let num_vars = point.len();

        let q_comms = BatchedFri::<MyFr, H>::read_commitments(&(), num_vars, transcript)?;

        let x = transcript.squeeze_challenge();

        let (eval_scalar, q_scalars) = eval_and_quotient_scalars(x, &point[..]);

        let uni_poly_eval = transcript.read_field_element().unwrap();
        Fri::verify(&vp.vp, &comm, &x, &uni_poly_eval, transcript)?;

        //check consistency of all commitments vis-a-vis batch commitments

        let q_evals = transcript.read_field_elements(num_vars).unwrap();
        let comm = Fri::<MyFr, H>::read_commitments(&vp.vp, 1, transcript)?;
        let mut f_eval_at_x = eval_scalar * eval;
        izip!(&q_evals, &q_scalars).for_each(|(q, scalar)| f_eval_at_x += *scalar * *q);
        Fri::verify(&vp.vp, &comm[0], &x, &f_eval_at_x, transcript)?;

        BatchedFri::<MyFr, H>::batch_verify(
            &(),
            &q_comms,
            &vec![x; num_vars],
            &q_evals
                .iter()
                .rev()
                .map(|q_eval| Evaluation::new(0, 0, *q_eval))
                .collect_vec()
                .as_slice()
                .as_ref(),
            transcript,
        )
    }

    // fn batch_verify<'a>(
    //     vp: &Self::VerifierParam,
    //     comms: impl IntoIterator<Item = &'a Self::Commitment>,
    //     points: &[Point<F, Self::Polynomial>],
    //     evals: &[Evaluation<F>],
    //     transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    // ) -> Result<(), Error>
    // where
    //     Self::Commitment: 'a,
    // {
    //     let comms = comms.into_iter().collect_vec();
    //     for e in evals {
    //         let comm = &comms[e.poly()];
    //         let point = &points[e.poly()];
    //         let eval = e.value();
    //         Self::verify(vp, comm, point, eval, transcript)?;
    //     }

    //     Ok(())
    // }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<MyFr, Self::Polynomial>],
        evals: &[Evaluation<MyFr>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error> {
        let num_vars = points.first().map(|point| point.len()).unwrap_or_default();
        let comms = comms.into_iter().collect_vec();

        let ell = evals.len().next_power_of_two().ilog2() as usize;
        let t = transcript.squeeze_challenges(ell);

        let eq_xt = MultilinearPolynomial::eq_xy(&t);
        let tilde_gs_sum =
            inner_product(evals.iter().map(Evaluation::value), &eq_xt[..evals.len()]);

        let (g_prime_eval, verify_point) =
            SumCheck::verify(&(), vp.vp.num_vars, 2, tilde_gs_sum, transcript)?;

        let eq_xy_evals = points
            .iter()
            .map(|point| eq_xy_eval(&verify_point, point))
            .collect_vec();

        let comm = Self::Commitment::default();
        let point = verify_point;
        let eval = g_prime_eval;
        let num_vars = point.len();

        let q_comms = BatchedFri::<MyFr, H>::read_commitments(&(), num_vars, transcript)?;

        let x = transcript.squeeze_challenge();

        let uni_evals = transcript.read_field_elements(comms.len()).unwrap();
        Fri::<MyFr, H>::batch_verify(
            &vp.vp,
            comms.clone(),
            &vec![x; comms.len()],
            &uni_evals
                .iter()
                .enumerate()
                .map(|(idx, eval)| Evaluation::new(idx, idx, *eval))
                .collect_vec()
                .as_slice(),
            transcript,
        )?;

        let q_evals = transcript.read_field_elements(num_vars).unwrap();
        BatchedFri::<MyFr, H>::batch_verify(
            &(),
            &q_comms.clone().into_iter().rev().collect_vec(),
            &vec![x; num_vars],
            &q_evals
                .iter()
                .rev()
                .map(|q_eval| Evaluation::new(0, 0, *q_eval))
                .collect_vec()
                .as_slice()
                .as_ref(),
            transcript,
        )?;

        let (eval_scalar, q_scalars) = eval_and_quotient_scalars(x, &point[..]);
        let mut f_eval = eval_scalar * eval;
        izip!(&q_evals, &q_scalars).for_each(|(q, scalar)| f_eval += *scalar * *q);

        //        let scalars = chain![[F::ONE, z, eval_scalar * eval], q_scalars].collect_vec();
        //      let bases = chain![[q_hat_comm, comm.0, vp.g1()], q_comms].collect_vec();
        let comm = Fri::<MyFr, H>::read_commitments(&vp.vp, 1, transcript)?;

        let (v, queries_usize) = verify_helper(&vp.vp, &comm[0], &x, &f_eval, transcript);

        let mut ind_queries = Vec::with_capacity(vp.vp.num_verifier_queries);
        let mut count = 0;
        for i in 0..vp.vp.num_verifier_queries {
            let mut comms_queries = Vec::with_capacity(evals.len());
            for j in 0..evals.len() {
                let queries = transcript.read_field_elements(2).unwrap();
                comms_queries.push(queries);
            }

            ind_queries.push(comms_queries);
        }

        //read merkle paths
        let mut batch_paths = Vec::with_capacity(vp.vp.num_verifier_queries);
        let mut count = 0;
        for i in 0..vp.vp.num_verifier_queries {
            let mut comms_merkle_paths = Vec::with_capacity(evals.len());
            for j in 0..evals.len() {
                let merkle_path = transcript
                    .read_commitments(2 * (vp.vp.num_vars + vp.vp.log_rate))
                    .unwrap();
                let chunked_path = merkle_path.chunks(2).map(|c| c.to_vec()).collect_vec();

                comms_merkle_paths.push(chunked_path);
            }

            batch_paths.push(comms_merkle_paths);
        }

        for vq in 0..vp.vp.num_verifier_queries {
            for cq in 0..ind_queries[vq].len() {
                let tree = &comms[evals[cq].poly].codeword_tree;
                /*
                        assert_eq!(
                                    tree[tree.len() - 1][0],
                                    batch_paths[vq][cq].pop().unwrap().pop().unwrap()
                                );
                */
                authenticate_merkle_path::<H, MyFr>(
                    &batch_paths[vq][cq],
                    (ind_queries[vq][cq][0], ind_queries[vq][cq][1]),
                    queries_usize[vq],
                );

                count += 1;
            }
        }

        Ok(())
    }
}
fn authenticate_merkle_path<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: (F, F),
    mut x_index: usize,
) {
    let mut hasher = H::new();
    let mut hash = Output::<H>::default();
    hasher.update_field_element(&leaves.0);
    hasher.update_field_element(&leaves.1);
    hasher.finalize_into_reset(&mut hash);

    assert_eq!(hash, path[0][(x_index >> 1) % 2]);
    x_index >>= 1;
    for i in 0..path.len() {
        if (i + 1 == path.len()) {
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
fn eval_and_quotient_scalars<F: Field>(x: F, u: &[F]) -> (F, Vec<F>) {
    let num_vars = u.len();

    let squares_of_x = squares(x).take(num_vars + 1).collect_vec();
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
    let q_scalars = izip!(squares_of_x, &vs, &vs[1..], u)
        .map(|(square_of_x, v_i, v_j, u_i)| square_of_x * v_j - *u_i * v_i)
        .collect_vec();

    (vs[0], q_scalars)
}

#[cfg(test)]
mod test {
    use crate::{
        pcs::{
            multilinear::{
                test::{run_batch_commit_open_verify, run_commit_open_verify},
                zeromorph::Zeromorph,
                zeromorph_fri::ZeromorphFri,
            },
            univariate::{Fri, UnivariateKzg},
        },
        util::{
            hash::{Blake2s, Hash, Keccak256, Output},
            transcript::Keccak256Transcript,
        },
    };
    use halo2_curves::bn256::{Bn256, Fr};

    type Pcs = ZeromorphFri<Fri<Fr, Blake2s>>;

    #[test]
    fn commit_open_verify() {
        run_commit_open_verify::<_, Pcs, Keccak256Transcript<_>>();
    }

    #[test]
    fn batch_commit_open_verify() {
        run_batch_commit_open_verify::<_, Pcs, Keccak256Transcript<_>>();
    }
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
