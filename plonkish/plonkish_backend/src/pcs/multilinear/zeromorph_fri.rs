use crate::pcs::univariate::{open_helper, verify_helper, FriCommitment};
use crate::piop::sum_check::{
    classic::{ClassicSumCheck, CoefficientsProver},
    eq_xy_eval, SumCheck as _, VirtualPolynomial,
};
use crate::util::hash::Output;
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

impl<F, H> PolynomialCommitmentScheme<F> for ZeromorphFri<Fri<F, H>>
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
        f_eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let num_vars = poly.num_vars();
        let uni_poly = UnivariatePolynomial::new(poly.evals().to_vec());

        if cfg!(feature = "sanity-check") {
            assert_eq!(poly.evaluate(point), *f_eval);
        }

        let (quotients, remainder) = quotients(poly, point, |_, q| UnivariatePolynomial::new(q));
        let now = Instant::now();
        let comms = Fri::<F, H>::batch_commit_and_write(&pp.commit_pp, &quotients, transcript)?;
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
        Fri::<F, H>::open(
            &pp.commit_pp,
            &uni_poly,
            &comm,
            &x,
            &uni_poly_eval,
            transcript,
        )?;

        let q_evals = quotients.iter().map(|q| q.evaluate(&x)).collect_vec();
        transcript.write_field_elements(&q_evals);

        let comm = Fri::<F, H>::commit_and_write(&pp.commit_pp, &f, transcript).unwrap();
        Fri::<F, H>::open(&pp.commit_pp, &f, &comm, &x, &f_eval_at_x, transcript)?;

        Fri::<F, H>::batch_open(
            &pp.commit_pp,
            &quotients,
            &comms,
            &vec![x; quotients.len()],
            q_evals
                .iter()
                .map(|q_eval| Evaluation::new(0, 0, *q_eval))
                .collect_vec()
                .as_slice()
                .as_ref(),
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
    ) -> Result<(), Error> {
        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();
        let num_vars = points.first().map(|point| point.len()).unwrap_or_default();

        for e in evals {
            let poly = polys[e.poly()];
            let comm = comms[e.poly()];
            let point = &points[e.poly()];
            let eval = e.value();
            Self::open(pp, poly, comm, point, eval, transcript)?;
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
        let num_vars = point.len();

        let q_comms = Fri::<F, H>::read_commitments(&vp.vp, num_vars, transcript)?;

        let x = transcript.squeeze_challenge();

        let (eval_scalar, q_scalars) = eval_and_quotient_scalars(x, &point[..]);

        let uni_poly_eval = transcript.read_field_element().unwrap();
        Fri::verify(&vp.vp, &comm, &x, &uni_poly_eval, transcript)?;

        //check consistency of all commitments vis-a-vis batch commitments

        let q_evals = transcript.read_field_elements(num_vars).unwrap();
        let comm = Fri::<F, H>::read_commitments(&vp.vp, 1, transcript)?;
        let mut f_eval_at_x = eval_scalar * eval;
        izip!(&q_evals, &q_scalars).for_each(|(q, scalar)| f_eval_at_x += *scalar * *q);
        Fri::verify(&vp.vp, &comm[0], &x, &f_eval_at_x, transcript)?;

        Fri::<F, H>::batch_verify(
            &vp.vp,
            &q_comms,
            &vec![x; num_vars],
            &q_evals
                .iter()
                .map(|q_eval| Evaluation::new(0, 0, *q_eval))
                .collect_vec()
                .as_slice()
                .as_ref(),
            transcript,
        )
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let comms = comms.into_iter().collect_vec();
        for e in evals {
            let comm = &comms[e.poly()];
            let point = &points[e.poly()];
            let eval = e.value();
            Self::verify(vp, comm, point, eval, transcript)?;
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
