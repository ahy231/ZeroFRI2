// ZeroFRI2 protocol.
// Main improvement over Improved ZeroFRI (v3): prover `open` is O(N); v3 is O(N log N).
// Also uses rolling batch and MMCS.

use crate::pcs::univariate::batched_fri::BatchedFri;
use crate::pcs::univariate::fri_p3::FriP3;
use crate::pcs::univariate::{open_helper, verify_helper, FriCommitment, FriParams};
use crate::piop::sum_check::{
    classic::{ClassicSumCheck, CoefficientsProver},
    eq_xy_eval, SumCheck as _, VirtualPolynomial,
};
use crate::util::algebra::batch_bit_reverse;
use crate::util::algebra::field::batch_inverse;
use crate::util::fake_extension::MyFr;
use crate::util::hash::{Blake2s, Output};
use p3_field::{eval_poly, PrimeField32};
use p3_util::log2_strict_usize;
use rand::rngs::OsRng;
use rayon::iter::IntoParallelIterator;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
    ParallelSlice, ParallelSliceMut,
};
use sha2::digest::FixedOutput;
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
pub struct ZeromorphFriV4<Pcs>(PhantomData<Pcs>);

impl PolynomialCommitmentScheme<MyFr> for ZeromorphFriV4<Fri<MyFr, Blake2s>> {
    type Param = FriParams<MyFr>;
    type ProverParam = FriProverParams<MyFr>;
    type VerifierParam = FriVerifierParams<MyFr>;
    type Polynomial = MultilinearPolynomial<MyFr>;
    type Commitment = <Fri<MyFr, Blake2s> as PolynomialCommitmentScheme<MyFr>>::Commitment;
    type CommitmentChunk =
        <Fri<MyFr, Blake2s> as PolynomialCommitmentScheme<MyFr>>::CommitmentChunk;

    fn setup(poly_size: usize, batch_size: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        // BatchedFri::<MyFr, H>::setup(poly_size, batch_size, OsRng);
        Fri::<MyFr, Blake2s>::setup(poly_size, batch_size, rng)
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let (commit_pp, vp) = Fri::<MyFr, Blake2s>::trim(param, poly_size, batch_size)?;

        Ok((commit_pp, vp))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        let mut evals = poly.evals();

        let poly = UnivariatePolynomial::new(evals.to_vec());
        Fri::<MyFr, Blake2s>::commit(pp, &poly)
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        // let polys_vec: Vec<UnivariatePolynomial<MyFr, _>> = polys
        //     .into_iter()
        //     .map(|poly| UnivariatePolynomial::new(poly.evals().to_vec()))
        //     .collect();
        // let comms = FriP3::<MyFr, H>::batch_commit(&(), polys_vec.iter()).unwrap();
        let polys_vec: Vec<&Self::Polynomial> = polys.into_iter().map(|poly| poly).collect();
        let mut comms = Vec::with_capacity(polys_vec.len());
        for poly in &polys_vec {
            comms.push(Self::commit(pp, poly)?);
        }
        Ok(comms)
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

        if cfg!(feature = "sanity-check") {
            assert_eq!(poly.evaluate(point), *f_eval);
        }

        let f_tilde = poly;
        let f_hat_coef = poly.evals().to_vec();
        let f_hat_code_reversed = comm.codeword.clone();
        let f_hat_tree = comm.codeword_tree.clone();

        let log_n = pp.num_vars;
        let log_blowup = pp.log_rate;

        let mut quotient_prime_codes = Vec::with_capacity(log_n - 1);
        let mut quotient_prime_coefs = Vec::with_capacity(log_n - 1);
        let mut remainder_code = f_hat_code_reversed.clone();
        let mut remainder_coef = f_hat_coef.clone();
        for i in 0..log_n - 1 {
            quotient_prime_codes.push(quotient_op(
                &remainder_code,
                &pp.table_w_weights[log_n + log_blowup - i - 1],
            ));
            quotient_prime_coefs.push(quotient_op_coef(&remainder_coef));
            remainder_code = remainder_op(
                &remainder_code,
                point[i],
                &pp.table_w_weights[log_n + log_blowup - i - 1],
            );
            remainder_coef = remainder_op_coef(&remainder_coef, point[i]);
        }
        let quotient_prime_last = quotient_op(&remainder_code, &pp.table_w_weights[log_blowup]);
        transcript.write_field_element(&quotient_prime_last[0])?;

        let quotient_prime_tree = merkelize_mmcs::<MyFr, Blake2s>(&quotient_prime_codes);
        transcript.write_commitment(&quotient_prime_tree.last().unwrap()[0])?;

        let alpha = transcript.squeeze_challenge();
        let xi = transcript.squeeze_challenge();
        let padding_lambdas = transcript.squeeze_challenges(log_n - 1);

        let mut batched_degree_n_poly = quotient_prime_codes[log_n - 2].clone();

        for i in 0..log_n - 2 {
            batched_degree_n_poly = batched_degree_n_poly
                .par_iter()
                .enumerate()
                .map(|(j, batched_degree_n_poly_j)| {
                    let t0 = alpha
                        * (MyFr::ONE
                            + padding_lambdas[log_n - i - 2]
                                * pp.table_w_weights[log_blowup + i + 1][j].0)
                        * *batched_degree_n_poly_j
                        + quotient_prime_codes[log_n - i - 3][j << 1];
                    let t1 = alpha
                        * (MyFr::ONE
                            + padding_lambdas[log_n - i - 2]
                                * -pp.table_w_weights[log_blowup + i + 1][j].0)
                        * *batched_degree_n_poly_j
                        + quotient_prime_codes[log_n - i - 3][(j << 1) + 1];
                    vec![t0, t1]
                })
                .flatten()
                .collect::<Vec<MyFr>>();
        }

        batched_degree_n_poly = batched_degree_n_poly
            .par_iter()
            .enumerate()
            .map(|(j, batched_degree_n_poly_j)| {
                let t0 = alpha
                    * (MyFr::ONE
                        + padding_lambdas[0] * pp.table_w_weights[log_blowup + log_n - 1][j].0)
                    * *batched_degree_n_poly_j
                    + f_hat_code_reversed[j << 1];
                let t1 = alpha
                    * (MyFr::ONE
                        + padding_lambdas[0] * -pp.table_w_weights[log_blowup + log_n - 1][j].0)
                    * *batched_degree_n_poly_j
                    + f_hat_code_reversed[(j << 1) + 1];
                vec![t0, t1]
            })
            .flatten()
            .collect::<Vec<MyFr>>();

        let mut xi_openings = Vec::with_capacity(log_n);

        let f_hat_poly = UnivariatePolynomial::new(f_hat_coef);
        xi_openings.push(f_hat_poly.evaluate(&xi));

        let mut batched_value_at_xi = xi_openings[0];
        let mut padding_poly_at_xi = MyFr::ONE;
        let mut xi_power = xi;
        let mut base = alpha;
        for i in 0..log_n - 1 {
            padding_poly_at_xi *= MyFr::ONE + padding_lambdas[i] * xi_power;
            xi_power *= xi_power;

            xi_openings.push(eval_poly(&quotient_prime_coefs[i], xi_power));
            batched_value_at_xi += base * padding_poly_at_xi * xi_openings[i + 1];

            base *= alpha;
        }

        transcript.write_field_elements(&xi_openings);

        let _lambda = transcript.squeeze_challenge();
        let numerators = (0..1 << (log_n + log_blowup))
            .into_par_iter()
            .map(|i| batched_degree_n_poly[i] - batched_value_at_xi)
            .collect::<Vec<MyFr>>();
        let mut denominators = (0..1 << (log_n + log_blowup))
            .into_par_iter()
            .map(|i| {
                let x = pp.table_w_weights[log_n + log_blowup - 1][i >> 1].0;
                let x = if i & 1 == 0 { x } else { -x };
                x - xi
            })
            .collect::<Vec<MyFr>>();
        denominators.iter_mut().batch_invert();
        let degree_n_quotient = (0..1 << (log_n + log_blowup))
            .into_par_iter()
            .map(|i| {
                let x = pp.table_w_weights[log_n + log_blowup - 1][i >> 1].0;
                let x = if i & 1 == 0 { x } else { -x };
                (MyFr::ONE + _lambda * x) * numerators[i] * denominators[i]
            })
            .collect::<Vec<MyFr>>();

        let mut folded = degree_n_quotient;
        let mut beta = transcript.squeeze_challenge();

        let mut trees = Vec::with_capacity(log_n - 1);
        let mut tree_evals = Vec::with_capacity(log_n - 1);
        for i in 0..log_n - 1 {
            folded = fold(
                folded,
                beta,
                &pp.table_w_weights[log_n + log_blowup - i - 1],
            );
            folded
                .par_iter_mut()
                .enumerate()
                .for_each(|(j, folded_j)| *folded_j = *folded_j + quotient_prime_codes[i][j]);
            let tree = merkelize::<MyFr, Blake2s>(&folded);
            trees.push(tree);
            tree_evals.push(folded.clone());

            transcript.write_commitment(&trees[i].last().unwrap()[0])?;
            beta = transcript.squeeze_challenge();
        }

        folded = fold(folded, beta, &pp.table_w_weights[log_blowup]);
        let folded_last = folded[0];
        transcript.write_field_element(&folded_last)?;

        let queries = transcript.squeeze_challenges(pp.num_verifier_queries);

        let mut f_hat_proofs = vec![vec![]; pp.num_verifier_queries];
        let mut f_hat_openings = vec![vec![]; pp.num_verifier_queries];
        let mut mmcs_proofs = vec![vec![]; pp.num_verifier_queries];
        let mut mmcs_openings = vec![vec![]; pp.num_verifier_queries];
        let mut folding_neighbors = vec![vec![]; pp.num_verifier_queries];
        let mut folding_proofs = vec![vec![]; pp.num_verifier_queries];
        queries
            .par_iter()
            .zip(f_hat_openings.par_iter_mut())
            .zip(f_hat_proofs.par_iter_mut())
            .zip(mmcs_proofs.par_iter_mut())
            .zip(mmcs_openings.par_iter_mut())
            .zip(folding_neighbors.par_iter_mut())
            .zip(folding_proofs.par_iter_mut())
            .enumerate()
            .for_each(
                |(
                    i,
                    (
                        (
                            (
                                (((q, f_hat_openings_i), f_hat_proofs_i), mmcs_proofs_i),
                                mmcs_openings_i,
                            ),
                            folding_neighbors_i,
                        ),
                        folding_proofs_i,
                    ),
                )| {
                    let q = q.as_canonical_u32() as usize % (1 << (pp.num_vars + pp.log_rate));
                    *f_hat_openings_i = vec![
                        f_hat_code_reversed[(q >> 1) << 1].clone(),
                        f_hat_code_reversed[((q >> 1) << 1) + 1].clone(),
                    ];
                    *f_hat_proofs_i = get_merkle_path::<Blake2s, MyFr>(&f_hat_tree, q, false);

                    *mmcs_proofs_i =
                        get_merkle_path_mmcs::<Blake2s, MyFr>(&quotient_prime_tree, q >> 1);
                    *mmcs_openings_i = quotient_prime_codes
                        .iter()
                        .enumerate()
                        .map(|(i, code)| code[q >> (i + 1)])
                        .collect::<Vec<MyFr>>();

                    let mut neighbors = Vec::with_capacity(log_n - 1);
                    let mut proofs = Vec::with_capacity(log_n - 1);
                    let mut index = q >> 1;
                    for i in 0..log_n - 1 {
                        index >>= 1;
                        neighbors.push(tree_evals[i][index << 1..(index << 1) + 2].to_vec());
                        proofs.push(get_merkle_path::<Blake2s, MyFr>(
                            &trees[i],
                            index << 1,
                            false,
                        ));

                        // authenticate_merkle_path_root::<Blake2s, MyFr>(
                        //     &proofs[i],
                        //     &(neighbors[i][0], neighbors[i][1]),
                        //     index << 1,
                        //     &trees[i][trees[i].len() - 1][0],
                        // );
                    }
                    *folding_neighbors_i = neighbors;
                    *folding_proofs_i = proofs;
                },
            );

        // f_hat_openings
        f_hat_openings.iter().for_each(|o| {
            transcript.write_field_elements(o);
        });
        // f_hat_proofs
        // assert_eq!(f_hat_proofs.len(), pp.num_verifier_queries);
        // assert_eq!(f_hat_proofs[0].len(), log_n + log_blowup - 1);
        // assert_eq!(f_hat_proofs[0][0].len(), 2);
        f_hat_proofs.iter().flatten().for_each(|p| {
            transcript.write_commitments(p);
        });
        // mmcs_proofs
        // assert_eq!(mmcs_proofs.len(), pp.num_verifier_queries);
        // assert_eq!(mmcs_proofs[0].len(), log_n + log_blowup - 1);
        mmcs_proofs.iter().flatten().for_each(|p| {
            transcript.write_commitment(*p);
        });
        // mmcs_openings
        // assert_eq!(mmcs_openings.len(), pp.num_verifier_queries);
        // assert_eq!(mmcs_openings[0].len(), log_n - 1);
        mmcs_openings.iter().for_each(|o| {
            transcript.write_field_elements(o);
        });
        // folding_neighbors
        // assert_eq!(folding_neighbors.len(), pp.num_verifier_queries);
        // assert_eq!(folding_neighbors[0].len(), log_n - 1);
        // assert_eq!(folding_neighbors[0][0].len(), 2);
        folding_neighbors.iter().flatten().for_each(|n| {
            transcript.write_field_elements(n);
        });
        // folding_proofs
        // assert_eq!(folding_proofs.len(), pp.num_verifier_queries);
        // for i in 0..pp.num_verifier_queries {
        //     assert_eq!(folding_proofs[i].len(), log_n - 1);
        //     for j in 0..log_n - 1 {
        //         assert_eq!(folding_proofs[i][j].len(), log_n + log_blowup - 2 - j);
        //     }
        // }
        folding_proofs.iter().flatten().flatten().for_each(|p| {
            transcript.write_commitments(p);
        });

        // let mut xi_powers = vec![xi];
        // for i in 0..log_n {
        //     xi_powers.push(xi_powers[i] * xi_powers[i]);
        // }

        // let mut expected_zero = xi_openings[0] - *f_eval * phi(log_n, xi);
        // for i in 0..log_n - 1 {
        //     expected_zero -=
        //         xi_openings[i + 1] * (xi_powers[i] * phi(i, xi) - point[i] * phi(i + 1, xi));
        // }
        // expected_zero -= quotient_prime_last[0]
        //     * (xi_powers[log_n - 1] * phi(log_n - 1, xi) - point[log_n - 1] * phi(log_n, xi));

        // assert_eq!(expected_zero, MyFr::ZERO);

        // let timer1_elapsed = timer1.elapsed();
        // println!("time1: {:?}", timer1_elapsed);

        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<MyFr, Self::Polynomial>],
        evals: &[Evaluation<MyFr>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error> {
        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();
        let num_vars = points.first().map(|point| point.len()).unwrap_or_default();

        for e in evals {
            let poly = polys[e.poly()];
            let comm = comms[e.poly()];
            let point = &points[e.point()];
            let eval = e.value();
            Self::open(pp, poly, comm, point, eval, transcript)?;
        }

        Ok(())
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        Fri::<MyFr, Blake2s>::read_commitments(vp, num_polys, transcript)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<MyFr, Self::Polynomial>,
        eval: &MyFr,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error> {
        let log_blowup = vp.log_rate;
        let log_n = vp.num_vars;
        let f_hat_root = comm.codeword_tree[comm.codeword_tree.len() - 1][0];

        // let timer0 = Instant::now();

        let quotient_prime_last = transcript.read_field_element()?;
        let quotient_prime_commitment = transcript.read_commitment()?;
        let alpha = transcript.squeeze_challenge();
        let xi = transcript.squeeze_challenge();

        let padding_lambdas = transcript.squeeze_challenges(log_n - 1);

        let xi_openings = transcript.read_field_elements(log_n)?;
        let _lambda = transcript.squeeze_challenge();

        let num_verifier_queries = vp.num_verifier_queries;

        let mut betas = Vec::with_capacity(log_n);
        let mut tree_roots = Vec::with_capacity(log_n - 1);
        betas.push(transcript.squeeze_challenge());
        for i in 0..(log_n - 1) {
            tree_roots.push(transcript.read_commitment()?);
            betas.push(transcript.squeeze_challenge());
        }
        let folded_last = transcript.read_field_element()?;
        let queries = transcript.squeeze_challenges(num_verifier_queries);

        let f_hat_openings = (0..num_verifier_queries)
            .map(|_| transcript.read_field_elements(2).unwrap())
            .collect_vec();
        let f_hat_proofs = (0..num_verifier_queries)
            .map(|_| {
                (0..log_n + log_blowup - 1)
                    .map(|_| transcript.read_commitments(2).unwrap())
                    .collect_vec()
            })
            .collect_vec();
        let mmcs_proofs = (0..num_verifier_queries)
            .map(|_| transcript.read_commitments(log_n + log_blowup - 1).unwrap())
            .collect_vec();
        let mmcs_openings = (0..num_verifier_queries)
            .map(|_| transcript.read_field_elements(log_n - 1).unwrap())
            .collect_vec();
        let folding_neighbors = (0..num_verifier_queries)
            .map(|_| {
                (0..log_n - 1)
                    .map(|_| transcript.read_field_elements(2).unwrap())
                    .collect_vec()
            })
            .collect_vec();
        let mut folding_proofs = Vec::with_capacity(num_verifier_queries);
        for i in 0..num_verifier_queries {
            let mut proofs = Vec::with_capacity(log_n - 1);
            for j in 0..log_n - 1 {
                proofs.push(
                    (0..log_n + log_blowup - 2 - j)
                        .map(|_| transcript.read_commitments(2).unwrap())
                        .collect_vec(),
                );
            }
            folding_proofs.push(proofs);
        }

        // let timer0_elapsed = timer0.elapsed();
        // println!("time0: {:?}", timer0_elapsed);

        // let timer1 = Instant::now();

        let mut xi_powers = Vec::with_capacity(log_n + 1);
        xi_powers.push(xi);
        for i in 0..log_n {
            xi_powers.push(xi_powers[i] * xi_powers[i]);
        }

        let mut padding_poly_at_xi = Vec::with_capacity(log_n);
        padding_poly_at_xi.push(MyFr::ONE);
        for i in 0..log_n - 1 {
            padding_poly_at_xi
                .push(padding_poly_at_xi[i] * (MyFr::ONE + padding_lambdas[i] * xi_powers[i]));
        }

        (0..num_verifier_queries).into_par_iter().for_each(|i| {
            // let timer1_0 = Instant::now();
            // for i in 0..num_verifier_queries {
            let q = queries[i].as_canonical_u32() as usize % (1 << (log_n + log_blowup));
            authenticate_merkle_path_root::<Blake2s, MyFr>(
                &f_hat_proofs[i],
                &(f_hat_openings[i][0], f_hat_openings[i][1]),
                q,
                &f_hat_root,
            );

            // let timer1_0_elapsed = timer1_0.elapsed();
            // println!("time1_0: {:?}", timer1_0_elapsed);

            // let timer1_1 = Instant::now();
            authenticate_merkle_path_mmcs::<Blake2s, MyFr>(
                &mmcs_proofs[i]
                    .iter()
                    .map(|p| Output::<Blake2s>::from_slice(p))
                    .collect::<Vec<&Output<Blake2s>>>(),
                &mmcs_openings[i],
                q >> 1,
                log_n + log_blowup - 1,
                &quotient_prime_commitment,
            );

            // let timer1_1_elapsed = timer1_1.elapsed();
            // println!("time1_1: {:?}", timer1_1_elapsed);

            // let timer1_2 = Instant::now();

            let t = vp.table_w_weights[log_n + log_blowup - 1][q >> 1].0;
            let mut xs = vec![t, -t];

            // let timer_power_1 = Instant::now();
            // let mut xs_powers_expected = Vec::with_capacity(log_n + 1);
            // xs_powers_expected.push(xs.clone());
            // for i in 0..log_n {
            //     xs_powers_expected.push(
            //         (0..2)
            //             .map(|k| xs_powers_expected[i][k] * xs_powers_expected[i][k])
            //             .collect_vec(),
            //     );
            // }
            // let timer_power_1_elapsed = timer_power_1.elapsed();
            // println!("time_power-1: {:?}", timer_power_1_elapsed);

            // let timer_power = Instant::now();
            let xs_powers = (0..log_n + 1)
                .map(|i| {
                    let q_idx = (q >> 1) << 1;
                    let positive =
                        power_of_element(q_idx, i, &vp.table_w_weights[log_n + log_blowup - 1]);
                    let negative =
                        power_of_element(q_idx + 1, i, &vp.table_w_weights[log_n + log_blowup - 1]);
                    vec![positive, negative]
                })
                .collect_vec();
            // let timer_power_elapsed = timer_power.elapsed();
            // println!(
            //     "time_power-1: {:?}, time_power-2: {:?}",
            //     timer_power_1_elapsed, timer_power_elapsed
            // );
            // assert_eq!(xs_powers_expected, xs_powers);

            let mut batched_quotient = (0..2)
                .map(|j| {
                    (f_hat_openings[i][j] - xi_openings[0]) * (MyFr::ONE + _lambda * xs[j])
                        / (xs[j] - xi)
                })
                .collect_vec();

            // let timer1_2_elapsed = timer1_2.elapsed();
            // println!("time1_2: {:?}", timer1_2_elapsed);

            // let timer1_3 = Instant::now();

            let mut base = alpha;

            // let timer1_3_0 = Instant::now();
            let mut denominator = (0..2).map(|k| xs[k] - xi).collect_vec();
            denominator.iter_mut().batch_invert();

            // let timer1_3_0_elapsed = timer1_3_0.elapsed();
            // println!("time1_3_0: {:?}", timer1_3_0_elapsed);

            // let timer1_3_1 = Instant::now();

            let mut padding_poly_at_xs = Vec::with_capacity(log_n);
            padding_poly_at_xs.push(vec![MyFr::ONE, MyFr::ONE]);
            for j in 0..log_n - 1 {
                padding_poly_at_xs.push(
                    (0..2)
                        .map(|k| {
                            padding_poly_at_xs[j][k]
                                * (MyFr::ONE + padding_lambdas[j] * xs_powers[j][k])
                        })
                        .collect_vec(),
                );
            }

            for j in 0..log_n - 1 {
                // let timer1_3_1_0 = Instant::now();

                let quotient_hat_code = (0..2)
                    .map(|k| mmcs_openings[i][j] * padding_poly_at_xs[j + 1][k])
                    .collect_vec();

                // let timer1_3_1_0_elapsed = timer1_3_1_0.elapsed();
                // println!("time1_3_1_0: {:?}", timer1_3_1_0_elapsed);
                // println!(
                //     "verifier quotient_hat_code-{}: {:?}",
                //     j + 1,
                //     quotient_hat_code
                // );

                // let timer1_3_1_1 = Instant::now();

                // let degree_n_poly_at_xi = xi_openings[j + 1] * eval_poly(&padding_coefs[j + 1], xi);
                let degree_n_poly_at_xi = xi_openings[j + 1] * padding_poly_at_xi[j + 1];

                // let timer1_3_1_1_elapsed = timer1_3_1_1.elapsed();
                // println!("time1_3_1_1: {:?}", timer1_3_1_1_elapsed);
                // println!(
                //     "verifier degree_n_poly_at_xi-{}: {}, xi_openings[j + 1]: {}, eval_poly(&padding_coefs[j + 1], xi): {:?}",
                //     j + 1,
                //     degree_n_poly_at_xi,
                //     xi_openings[j + 1],
                //     eval_poly(&padding_coefs[j + 1], xi)
                // );

                // let timer1_3_1_2 = Instant::now();

                let numerator = (0..2)
                    .map(|k| quotient_hat_code[k] - degree_n_poly_at_xi)
                    .collect_vec();

                // let timer1_3_1_2_elapsed = timer1_3_1_2.elapsed();
                // println!("time1_3_1_2: {:?}", timer1_3_1_2_elapsed);
                // println!("verifier numerator-{}: {:?}", j + 1, numerator);
                // println!("verifier denominator-{}: {:?}", j + 1, denominator);

                // let timer1_3_1_3 = Instant::now();
                for k in 0..2 {
                    batched_quotient[k] +=
                        base * (MyFr::ONE + _lambda * xs[k]) * numerator[k] * denominator[k];
                }

                base *= alpha;

                // let timer1_3_1_3_elapsed = timer1_3_1_3.elapsed();
                // println!("time1_3_1_3: {:?}", timer1_3_1_3_elapsed);

                // println!(
                //     "verifier batched_quotient-{}: {:?}",
                //     j + 1,
                //     batched_quotient
                // );
            }

            // let timer1_3_1_elapsed = timer1_3_1.elapsed();
            // println!("time1_3_1: {:?}", timer1_3_1_elapsed);

            // let timer1_3_elapsed = timer1_3.elapsed();
            // println!("time1_3: {:?}", timer1_3_elapsed);

            // let timer1_4 = Instant::now();

            // let minus_2_x = if q > 1 << (log_n + log_blowup - 1) {
            //     -vp.table_w_weights[log_n + log_blowup - 1]
            //         [((q >> 1) << 1) - (1 << (log_n + log_blowup - 1))]
            //         .1
            // } else {
            //     vp.table_w_weights[log_n + log_blowup - 1][(q >> 1) << 1].1
            // };
            let minus_2_x = vp.table_w_weights[log_n + log_blowup - 1][q >> 1].1;

            let mut f_even = (batched_quotient[0] + batched_quotient[1]) * MyFr::TWO_INV;
            let mut f_odd = (batched_quotient[1] - batched_quotient[0]) * minus_2_x;
            // assert_eq!(
            //     f_odd,
            //     (batched_quotient[0] - batched_quotient[1]) * MyFr::TWO_INV / xs[0]
            // );
            let mut folded = f_even + f_odd * betas[0];

            for j in 0..log_n - 1 {
                let neighbors = &folding_neighbors[i][j];
                assert_eq!(
                    neighbors[(q >> (j + 1)) & 1],
                    folded + mmcs_openings[i][j],
                    "j: {j}"
                );

                authenticate_merkle_path::<Blake2s, MyFr>(
                    &folding_proofs[i][j],
                    &(neighbors[0], neighbors[1]),
                    q >> (j + 1),
                );

                f_even = (neighbors[0] + neighbors[1]) * MyFr::TWO_INV;
                f_odd = (neighbors[1] - neighbors[0])
                    * vp.table_w_weights[log_n + log_blowup - j - 1][q >> (j + 2)].1;
                folded = f_even + f_odd * betas[j + 1];
            }

            assert_eq!(folded, folded_last, "i: {i}");

            // let timer1_4_elapsed = timer1_4.elapsed();
            // println!("time1_4: {:?}", timer1_4_elapsed);
            // }
        });

        let mut phi_vec = Vec::with_capacity(log_n + 1);
        let mut base = xi;
        let mut result = MyFr::ONE;
        phi_vec.push(result);
        for i in 1..log_n + 1 {
            for j in (1 << (i - 1))..(1 << i) {
                result += base;
                base *= xi;
            }
            phi_vec.push(result);
        }

        // let timer_expected_zero = Instant::now();
        let mut expected_zero = xi_openings[0] - *eval * phi_vec[log_n];
        for i in 0..log_n - 1 {
            expected_zero -=
                xi_openings[i + 1] * (xi_powers[i] * phi_vec[i] - point[i] * phi_vec[i + 1]);
        }
        expected_zero -= quotient_prime_last
            * (xi_powers[log_n - 1] * phi_vec[log_n - 1] - point[log_n - 1] * phi_vec[log_n]);

        // let timer_expected_zero_elapsed = timer_expected_zero.elapsed();
        // println!("time_expected_zero: {:?}", timer_expected_zero_elapsed);

        assert_eq!(expected_zero, MyFr::ZERO);

        // let timer1_elapsed = timer1.elapsed();
        // println!("time1: {:?}", timer1_elapsed);

        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<MyFr, Self::Polynomial>],
        evals: &[Evaluation<MyFr>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, MyFr>,
    ) -> Result<(), Error>
    where
        Self::Commitment: 'a,
    {
        let comms = comms.into_iter().collect_vec();
        for e in evals {
            let comm = &comms[e.poly()];
            let point = &points[e.point()];
            let eval = e.value();
            Self::verify(vp, comm, point, eval, transcript)?;
        }

        Ok(())
    }
}

fn authenticate_merkle_path<H: Hash, F: PrimeField>(
    path: &Vec<Vec<Output<H>>>,
    leaves: &(F, F),
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

fn even_code_op(code: &Vec<MyFr>) -> Vec<MyFr> {
    let n = code.len();
    let mut even_code = vec![MyFr::ZERO; n / 2];
    even_code
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, even_code_i)| {
            *even_code_i = (code[2 * i] + code[2 * i + 1]) * MyFr::TWO_INV;
        });
    return even_code;
}

fn odd_code_op(code: &Vec<MyFr>, table_w_weights: &Vec<(MyFr, MyFr)>) -> Vec<MyFr> {
    let n = code.len();
    assert_eq!(n, table_w_weights.len() * 2);
    let mut odd_code = vec![MyFr::ZERO; n / 2];
    odd_code
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, odd_code_i)| {
            *odd_code_i = (code[2 * i + 1] - code[2 * i]) * table_w_weights[i].1;
        });
    return odd_code;
}

fn quotient_op(code: &Vec<MyFr>, table_w_weights: &Vec<(MyFr, MyFr)>) -> Vec<MyFr> {
    let n = code.len();
    assert_eq!(n, table_w_weights.len() * 2);

    let even_code = even_code_op(code);
    let odd_code = odd_code_op(code, table_w_weights);
    let quotient = even_code
        .par_iter()
        .zip(odd_code.par_iter())
        .map(|(even_code_i, odd_code_i)| *odd_code_i - *even_code_i)
        .collect::<Vec<MyFr>>();
    return quotient;
}

fn quotient_op_coef(coef: &Vec<MyFr>) -> Vec<MyFr> {
    let n = coef.len();
    assert_eq!(n & 1, 0);

    let mut quotient = vec![MyFr::ZERO; n >> 1];
    quotient
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, quotient_i)| {
            *quotient_i = coef[(i << 1) + 1] - coef[i << 1];
        });
    quotient
}

fn remainder_op(code: &Vec<MyFr>, point: MyFr, table_w_weights: &Vec<(MyFr, MyFr)>) -> Vec<MyFr> {
    let n = code.len();
    assert_eq!(n, table_w_weights.len() * 2);

    let even_code = even_code_op(code);
    let odd_code = odd_code_op(code, table_w_weights);
    let remainder = even_code
        .par_iter()
        .zip(odd_code.par_iter())
        .map(|(even_code_i, odd_code_i)| (MyFr::ONE - point) * even_code_i + point * odd_code_i)
        .collect::<Vec<MyFr>>();
    return remainder;
}

fn remainder_op_coef(coef: &Vec<MyFr>, point: MyFr) -> Vec<MyFr> {
    let n = coef.len();
    assert_eq!(n & 1, 0);

    let mut remainder = vec![MyFr::ZERO; n >> 1];
    remainder
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, remainder_i)| {
            *remainder_i = coef[i << 1] + point * (coef[(i << 1) + 1] - coef[i << 1]);
        });
    remainder
}

fn phi(k: usize, x: MyFr) -> MyFr {
    let mut base = MyFr::ONE;
    let mut result = MyFr::ZERO;
    for i in 0..1 << k {
        result += base;
        base *= x;
    }
    return result;
}

fn fold(evals: Vec<MyFr>, alpha: MyFr, table_w_weights: &Vec<(MyFr, MyFr)>) -> Vec<MyFr> {
    let n = evals.len();
    assert_eq!(n, table_w_weights.len() * 2);

    let mut res = vec![MyFr::ZERO; n >> 1];
    res.par_iter_mut().enumerate().for_each(|(i, res_i)| {
        let f_even = (evals[i << 1] + evals[(i << 1) + 1]) * MyFr::TWO_INV;
        let f_odd = (evals[(i << 1) + 1] - evals[i << 1]) * table_w_weights[i].1;
        *res_i = f_even + alpha * f_odd;
    });
    return res;
}

fn precompute_e_vec(
    point: MyFr,
    weights: &Vec<MyFr>,
    table: &Vec<(MyFr, MyFr)>,
) -> (Vec<MyFr>, Vec<MyFr>, MyFr) {
    let n = table.len() * 2;
    assert_eq!(n, weights.len());

    let mut e_vec = vec![MyFr::ZERO; n];
    e_vec
        .par_chunks_exact_mut(2)
        .enumerate()
        .for_each(|(i, e_vec_i)| {
            let x = table[i].0;
            e_vec_i[0] = point - x;
            e_vec_i[1] = point + x;
        });

    e_vec.iter_mut().batch_invert();

    let raw_e_vec = e_vec.clone();

    e_vec.iter_mut().enumerate().for_each(|(i, e_i)| {
        *e_i *= weights[i];
    });

    let sum = e_vec.par_iter().sum::<MyFr>();

    (raw_e_vec, e_vec, sum)
}

// fn evaluate_from_evals(
//     evals: &Vec<MyFr>,
//     point: MyFr,
//     table: &Vec<(MyFr, MyFr)>,
//     weights: &Vec<MyFr>,
// ) -> MyFr {
//     let n = evals.len();
//     assert_eq!(n, table.len() * 2);

//     // let weights = barycentric_weights(table);
//     let timer0 = Instant::now();
//     let mut e_vec = vec![MyFr::ZERO; n];
//     // e_vec.par_iter_mut().enumerate().for_each(|(i, e_i)| {
//     //     let x = table[i >> 1].0;
//     //     let x = if i & 1 == 0 { x } else { -x };
//     //     *e_i = point - x;
//     // });
//     e_vec
//         .par_chunks_exact_mut(2)
//         .enumerate()
//         .for_each(|(i, e_vec_i)| {
//             let x = table[i].0;
//             e_vec_i[0] = point - x;
//             e_vec_i[1] = point + x;
//         });
//     let timer0_elapsed = timer0.elapsed();
//     println!("e_vec time0: {:?}", timer0_elapsed);

//     let timer1 = Instant::now();
//     e_vec.iter_mut().batch_invert();
//     let timer1_elapsed = timer1.elapsed();
//     println!("e_vec batch_invert time1: {:?}", timer1_elapsed);

//     let timer2 = Instant::now();
//     e_vec.iter_mut().enumerate().for_each(|(i, e_i)| {
//         *e_i *= weights[i];
//     });
//     let timer2_elapsed = timer2.elapsed();
//     println!("e_vec weights time2: {:?}", timer2_elapsed);

//     let timer3 = Instant::now();
//     let numerator = e_vec
//         .par_iter()
//         .zip(evals.par_iter())
//         .map(|(eval, e)| *e * *eval)
//         .sum::<MyFr>();
//     let denominator = e_vec.par_iter().sum::<MyFr>();
//     let timer3_elapsed = timer3.elapsed();
//     println!("e_vec numerator denominator time3: {:?}", timer3_elapsed);

//     return numerator / denominator;
// }

fn evaluate_from_evals(evals: &Vec<MyFr>, e_vec: &Vec<MyFr>, denominator: MyFr) -> MyFr {
    let n = evals.len();
    assert_eq!(n, e_vec.len());

    let numerator = e_vec
        .par_iter()
        .zip(evals.par_iter())
        .map(|(eval, e)| *e * *eval)
        .sum::<MyFr>();

    return numerator / denominator;
}

fn barycentric_weights(table: &Vec<(MyFr, MyFr)>) -> Vec<MyFr> {
    let n = table.len() * 2;
    let mut weights = vec![MyFr::ZERO; n];
    weights
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, weight_i)| {
            let first = table[i >> 1].0;
            let first = if i & 1 == 0 { first } else { -first };
            let mut t = MyFr::ONE;
            for j in 0..n >> 1 {
                let second = table[j].0;
                if i != j << 1 {
                    t *= first - second;
                }
                if i != (j << 1) + 1 {
                    t *= first + second;
                }
            }
            *weight_i = t;
        });

    weights.iter_mut().batch_invert();
    return weights;
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
    leaves: &(F, F),
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

pub fn evaluate_over_foldable_domain<F: PrimeField>(
    log_rate: usize,
    mut coeffs: Vec<F>,
    table: &Vec<Vec<F>>,
) -> Vec<F> {
    //iterate over array, replacing even indices with (evals[i] - evals[(i+1)])
    let k = coeffs.len();
    //    println!("k {:?}", k);
    let logk = log2_strict(k);
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

pub fn power_of_element(idx: usize, log_power: usize, table: &Vec<(MyFr, MyFr)>) -> MyFr {
    let new_idx = idx >> log_power;
    let x = table[new_idx >> 1].0;
    if new_idx & 1 == 0 {
        x
    } else {
        -x
    }
}

#[cfg(test)]
mod test {
    use crate::util::fake_extension::MyFr;
    use crate::{
        pcs::{
            multilinear::{
                test::{run_batch_commit_open_verify, run_commit_open_verify},
                zeromorph::Zeromorph,
                zeromorph_fri::ZeromorphFri,
                ZeromorphFriV4,
            },
            univariate::{Fri, UnivariateKzg},
        },
        util::{
            hash::{Blake2s, Hash, Keccak256, Output},
            transcript::Keccak256Transcript,
        },
    };
    use halo2_curves::bn256::Bn256;

    type Pcs = ZeromorphFriV4<Fri<MyFr, Blake2s>>;

    #[test]
    fn commit_open_verify() {
        run_commit_open_verify::<_, Pcs, Keccak256Transcript<_>>();
    }

    #[test]
    fn batch_commit_open_verify() {
        run_batch_commit_open_verify::<_, Pcs, Keccak256Transcript<_>>();
    }
}
