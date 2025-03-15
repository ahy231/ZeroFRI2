use benchmark::BasefoldParams::{
    BasefoldFri, Eighteen, Eleven, Fifteen, Fourteen, Nineteen, Seventeen, Sixteen, Ten, Thirteen,
    Twelve, Twenty, TwentyFive, TwentyFour, TwentyOne, TwentySix, TwentyThree, TwentyTwo,
};
use ff::{BatchInvert, Field, PrimeField};
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::halo2curves::secp256k1::Fp;
use itertools::{izip, Itertools as _};
use num_bigint::BigInt;
use p3_bn254_fr::{Bn254Fr, FFBn254Fr};
use p3_challenger::FieldChallenger;
use p3_matrix::Matrix;
use plonkish_backend::piop::sum_check::classic::{ClassicSumCheck, CoefficientsProver};
use plonkish_backend::piop::sum_check::{eq_xy_eval, SumCheck, VirtualPolynomial};
use plonkish_backend::poly::univariate::UnivariatePolynomial;
use plonkish_backend::util::arithmetic::{inner_product, squares};
use plonkish_backend::util::expression::{Expression, Query, Rotation};
use plonkish_backend::util::fake_extension::{FakeExtension, MyFr};
use plonkish_backend::util::transcript::FieldTranscript;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use plonkish_backend::pcs::mock_pcs::PcsOps;
use plonkish_backend::pcs::multilinear::deepfold::Deepfold;
use plonkish_backend::pcs::multilinear::{
    interpolate_over_boolean_hypercube_with_copy, Basefold, Gemini, MultilinearBrakedown,
    MultilinearHyrax, MultilinearKzg, Type2Polynomial, ZeromorphFriV2,
};
use plonkish_backend::pcs::univariate::UnivariateKzg;
use plonkish_backend::pcs::{Evaluation, PolynomialCommitmentScheme};
use plonkish_backend::poly::Polynomial;
use plonkish_backend::util::code::{BrakedownSpec1, BrakedownSpec6};
use plonkish_backend::util::goldilocksMont::GoldilocksMont;
use plonkish_backend::util::hash::{Blake2s, Keccak256};
use plonkish_backend::util::mersenne_61_mont::Mersenne61Mont;
use plonkish_backend::util::new_fields::Mersenne127;
use plonkish_backend::util::parallel::parallelize;
use plonkish_backend::util::poly_loader::loader::Loader;
use plonkish_backend::util::transcript::{
    Blake2sTranscript, InMemoryTranscript, Keccak256Transcript, TranscriptRead, TranscriptWrite,
};
use plonkish_backend::{
    halo2_curves::bn256::Fr,
    pcs::{multilinear::ZeromorphFri, univariate::Fri},
    poly::multilinear::MultilinearPolynomial,
    util::poly_loader::container::Field as CF,
};

use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use sha2::digest::Output;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::ops::{AddAssign, Deref as _, Range};
use std::ptr::addr_of;
use std::{
    env::args,
    fmt::Display,
    fs::File,
    time::{Duration, Instant},
};

const OUTPUT_DIR: &str = "./bench_data/mock";

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub method: PcsOps,
    pub poly_num: usize,
    pub poly_vars: usize,
    pub time: f64,
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub total_commit_time: f64,
    pub total_open_time: f64,
    pub total_verify_time: f64,
    pub total_time: f64,
    pub avg_commit_time: f64,
    pub avg_open_time: f64,
    pub avg_verify_time: f64,
    pub avg_commit_size: f64,
    pub avg_open_size: f64,
    pub avg_poly_vars: f64,
}

fn main() {
    let (systems, k_range) = parse_args(); // (1) parse CLI args
                                           // (2) For each exponent k in k_range, for each system, call system.bench(k).
    k_range.for_each(|k| systems.iter().for_each(|system| system.bench(k)));
}

pub trait FieldFromStr: DeserializeOwned + Clone + AddAssign + Copy + Debug {
    fn from_str(s: &str) -> Self;
    fn to_enum() -> CF;
}

impl FieldFromStr for Fr {
    fn from_str(s: &str) -> Self {
        let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
        let mut bytes = [0u8; 32];
        let bytes_le = bigint.to_bytes_le().1;
        bytes[..bytes_le.len()].copy_from_slice(&bytes_le);
        Fr::from_bytes(&bytes).unwrap()
    }

    fn to_enum() -> CF {
        CF::Bn254Fr
    }
}

impl FieldFromStr for Mersenne127 {
    fn from_str(s: &str) -> Self {
        let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
        let mut bytes = [0u8; 16];
        let bytes_vec = bigint.to_bytes_le().1;
        bytes[..bytes_vec.len()].copy_from_slice(&bytes_vec);
        Mersenne127::from_u128(u128::from_le_bytes(bytes))
    }

    fn to_enum() -> CF {
        CF::Mersenne127
    }
}

impl FieldFromStr for GoldilocksMont {
    fn from_str(s: &str) -> Self {
        let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
        let mut bytes = [0u8; 16];
        let bytes_vec = bigint.to_bytes_le().1;
        bytes[..bytes_vec.len()].copy_from_slice(&bytes_vec);
        GoldilocksMont::from_u128(u128::from_le_bytes(bytes))
    }

    fn to_enum() -> CF {
        CF::GoldilocksMont
    }
}

impl FieldFromStr for Fp {
    fn from_str(s: &str) -> Self {
        let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
        let mut bytes = [0u8; 32];
        let bytes_le = bigint.to_bytes_le().1;
        bytes[..bytes_le.len()].copy_from_slice(&bytes_le);
        Fp::from_bytes(&bytes).unwrap()
    }

    fn to_enum() -> CF {
        CF::Fp
    }
}

impl FieldFromStr for MyFr {
    fn from_str(s: &str) -> Self {
        let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
        let mut bytes = [0u8; 32];
        let bytes_le = bigint.to_bytes_le().1;
        bytes[..bytes_le.len()].copy_from_slice(&bytes_le);
        MyFr(Bn254Fr {
            value: FFBn254Fr::from_bytes(&bytes).unwrap(),
        })
    }

    fn to_enum() -> CF {
        CF::Bn254Fr
    }
}

impl FieldFromStr for FakeExtension {
    fn from_str(s: &str) -> Self {
        FakeExtension {
            value: MyFr::from_str(s),
        }
    }

    fn to_enum() -> CF {
        CF::Bn254Fr
    }
}

impl FieldFromStr for Mersenne61Mont {
    fn from_str(s: &str) -> Self {
        let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
        let mut bytes = [0u8; 16];
        let bytes_le = bigint.to_bytes_le().1;
        bytes[..bytes_le.len()].copy_from_slice(&bytes_le);
        Mersenne61Mont::from_u128(u128::from_le_bytes(bytes))
    }

    fn to_enum() -> CF {
        CF::Mersenne61
    }
}

fn bench_pcs<
    F: FieldFromStr + PrimeField,
    P: PolynomialCommitmentScheme<F, Polynomial = MultilinearPolynomial<F>>,
    T,
>(
    system: &System,
    k: usize,
) where
    T: TranscriptRead<P::CommitmentChunk, F>
        + TranscriptWrite<P::CommitmentChunk, F>
        + InMemoryTranscript<Param = ()>,
{
    let loader = Loader::new(F::to_enum());
    let commit_data = loader.load("mock_data.json");
    let mut commit_pointer = 0;
    let mut open_pointer = 0;
    let instructions: Vec<(PcsOps, usize)> =
        serde_json::from_reader(File::open("mock_pcs_recorder.json").unwrap()).unwrap();

    let mut poly_map: HashMap<
        Vec<String>,                                      // polynomial as string
        <P as PolynomialCommitmentScheme<F>>::Commitment, // commitment
    > = HashMap::new();
    let mut verify_data: Vec<(
        Vec<u8>,                                               // proof
        Vec<Vec<F>>,                                           // points
        Vec<F>,                                                // evals
        Vec<<P as PolynomialCommitmentScheme<F>>::Commitment>, // commitments
    )> = Vec::new();
    let mut records = Vec::new();

    // setup and trim
    let param = P::setup(
        commit_data.poly_size,
        commit_data.batch_size,
        &mut thread_rng(),
    )
    .unwrap();
    let (pp, vp) = P::trim(&param, commit_data.poly_size, commit_data.batch_size).unwrap();

    // commit and open
    for (ops, size) in instructions {
        match ops {
            PcsOps::Commit => {
                match commit_data.matrix_widths[0][commit_pointer] {
                    1 => {
                        let poly = MultilinearPolynomial::new(
                            commit_data.matrices[0][commit_pointer]
                                .clone()
                                .into_iter()
                                .map(|s| F::from_str(&s))
                                .collect_vec(),
                        );
                        let (comm, duration) =
                            sample(k, || (), |_| P::commit(&pp, &poly).unwrap(), |c| c);
                        poly_map.insert(
                            poly.coefficients()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec(),
                            comm.clone(),
                        );

                        let mut transcript = T::new(());
                        transcript.write_commitment(&comm.as_ref()[0]).unwrap();
                        let proof = transcript.into_proof();

                        records.push(Record {
                            method: ops,
                            poly_num: 1,
                            poly_vars: poly.num_vars(),
                            time: duration,
                            size: Some(proof.len()),
                        });
                    }
                    _ => {
                        let polys_str = &commit_data.matrices[0][commit_pointer];
                        let matrix_width = commit_data.matrix_widths[0][commit_pointer];
                        let matrix = polys_str
                            .chunks(matrix_width)
                            .map(|chunk| chunk.iter().map(|s| F::from_str(&s)).collect_vec())
                            .collect_vec();
                        let polys = (0..matrix_width)
                            .map(|i| {
                                MultilinearPolynomial::new(
                                    matrix.iter().map(|r| r[i]).collect_vec(),
                                )
                            })
                            .collect_vec();
                        let (comms, duration) = sample(
                            k,
                            || (),
                            |_| P::batch_commit(&pp, &polys).unwrap(),
                            |c: Vec<<P as PolynomialCommitmentScheme<F>>::Commitment>| c,
                        );

                        let measure_comm_size =
                            |c: &<P as PolynomialCommitmentScheme<F>>::Commitment| {
                                let mut transcript = T::new(());
                                transcript.write_commitment(&c.as_ref()[0]).unwrap();
                                transcript.into_proof().len()
                            };

                        let comms_size = comms.iter().map(measure_comm_size).sum::<usize>();
                        for (poly, comm) in polys.clone().into_iter().zip(comms.clone()) {
                            poly_map.insert(
                                poly.evals()
                                    .into_iter()
                                    .map(|f| format!("{:?}", f))
                                    .collect_vec(),
                                comm.clone(),
                            );
                        }
                        records.push(Record {
                            method: ops,
                            poly_num: polys.len(),
                            poly_vars: polys[0].num_vars(),
                            time: duration,
                            size: Some(comms_size), // size of commitment
                        });
                    }
                }
                commit_pointer += 1;
            }
            PcsOps::Open => match size {
                1 => {
                    let (poly, point, eval) = &commit_data.poly_points[open_pointer];
                    let poly = MultilinearPolynomial::new(
                        poly.iter().map(|s| F::from_str(&s)).collect_vec(),
                    );
                    let comm = poly_map
                        .get(
                            &poly
                                .evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec(),
                        )
                        .unwrap()
                        .clone();
                    let point = point
                        .clone()
                        .into_iter()
                        .map(|f| F::from_str(&f))
                        .collect_vec();
                    let eval = F::from_str(eval);

                    let (proof, duration) = sample(
                        k,
                        || T::new(()),
                        |mut transcript| {
                            P::open(&pp, &poly, &comm, point.as_ref(), &eval, &mut transcript)
                                .unwrap();
                            transcript
                        },
                        |transcript| transcript.into_proof(),
                    );

                    verify_data.push((
                        proof.clone(),
                        vec![point.clone()],
                        vec![eval.clone()],
                        vec![comm],
                    ));

                    records.push(Record {
                        method: ops,
                        poly_num: 1,
                        poly_vars: poly.num_vars(),
                        time: duration,
                        size: Some(proof.len()),
                    });

                    open_pointer += size;
                }
                _ => {
                    let (mut polys, mut points, mut evals, mut comms) = (
                        Vec::with_capacity(size),
                        Vec::with_capacity(size),
                        Vec::with_capacity(size),
                        Vec::with_capacity(size),
                    );

                    commit_data.poly_points[open_pointer..open_pointer + size]
                        .into_iter()
                        .for_each(|(poly, point, eval)| {
                            let point = point
                                .clone()
                                .into_iter()
                                .map(|f| F::from_str(&f))
                                .collect_vec();
                            let eval = F::from_str(eval);
                            let poly_str = poly
                                .iter()
                                .map(|f| format!("{:?}", F::from_str(f)))
                                .collect_vec();
                            let comm = poly_map.get(&poly_str).unwrap().clone();

                            polys.push(MultilinearPolynomial::new(
                                poly.iter().map(|s| F::from_str(&s)).collect_vec(),
                            ));
                            points.push(point);
                            evals.push(eval);
                            comms.push(comm);
                        });

                    let (proof, duration) = sample(
                        k,
                        || T::new(()),
                        |mut transcript| {
                            P::batch_open(
                                &pp,
                                &polys,
                                &comms,
                                &points,
                                evals
                                    .clone()
                                    .into_iter()
                                    .zip(0..polys.len())
                                    .map(|(e, i)| Evaluation::new(i, i, e))
                                    .collect_vec()
                                    .as_slice(),
                                &mut transcript,
                            )
                            .unwrap();
                            transcript
                        },
                        |transcript| transcript.into_proof(),
                    );

                    verify_data.push((proof.clone(), points.clone(), evals.clone(), comms.clone()));

                    records.push(Record {
                        method: ops,
                        poly_num: polys.len(),
                        poly_vars: polys[0].num_vars(),
                        time: duration,
                        size: Some(proof.len()),
                    });

                    open_pointer += size;
                }
            },
            PcsOps::Verify => {
                unreachable!("Verify should not be in the instructions");
            }
        }
    }

    // verify
    for (proof, points, evals, comms) in verify_data {
        let duration;
        match points.len() {
            1 => {
                (_, duration) = sample(
                    k,
                    || T::from_proof((), proof.as_slice()),
                    |mut transcript| {
                        P::verify(&vp, &comms[0], &points[0], &evals[0], &mut transcript).unwrap()
                    },
                    |_| (),
                );
            }
            _ => {
                let evals = evals
                    .into_iter()
                    .zip(0..points.len())
                    .map(|(e, i)| Evaluation::new(i, i, e))
                    .collect_vec();
                (_, duration) = sample(
                    k,
                    || T::from_proof((), proof.as_slice()),
                    |mut transcript| {
                        P::batch_verify(&vp, &comms, &points, &evals, &mut transcript).unwrap();
                        transcript
                    },
                    |_| (),
                );
            }
        }
        records.push(Record {
            method: PcsOps::Verify,
            poly_num: points.len(),
            poly_vars: points[0].len(),
            time: duration,
            size: None,
        });
    }

    let mut file = File::create(system.detail_output_path(k)).unwrap();
    serde_json::to_writer(&mut file, &records).unwrap();

    // analysis
    let total_commit_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.time)
        .sum::<f64>();
    let total_open_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Open)
        .map(|r| r.time)
        .sum::<f64>();
    let total_verify_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Verify)
        .map(|r| r.time)
        .sum::<f64>();
    let total_time = total_commit_time + total_open_time + total_verify_time;
    let total_commit_size = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.size.unwrap())
        .sum::<usize>();
    let total_open_size = records
        .iter()
        .filter(|r| r.method == PcsOps::Open)
        .map(|r| r.size.unwrap())
        .sum::<usize>();
    let avg_commit_time = total_commit_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_open_time = total_open_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Open)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_verify_time = total_verify_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Verify)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_commit_size = total_commit_size as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_open_size = total_open_size as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Open)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_poly_vars = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.poly_vars * r.poly_num)
        .sum::<usize>() as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let analysis = Analysis {
        total_commit_time,
        total_open_time,
        total_verify_time,
        total_time,
        avg_commit_time,
        avg_open_time,
        avg_verify_time,
        avg_commit_size,
        avg_open_size,
        avg_poly_vars,
    };
    let mut file = File::create(system.analysis_output_path(k)).unwrap();
    serde_json::to_writer(&mut file, &analysis).unwrap();
}

fn quotients<F: Field, T>(
    poly: &MultilinearPolynomial<F>,
    point: &[F],
    f: impl Fn(usize, Vec<F>) -> T,
) -> (Vec<T>, F) {
    assert_eq!(poly.num_vars(), point.len());

    let mut remainder = poly.evals().to_vec();
    let mut quotients = point
        .iter()
        .zip(0..poly.num_vars())
        .rev()
        .map(|(x_i, num_vars)| {
            let (remaimder_lo, remainder_hi) = remainder.split_at_mut(1 << num_vars);
            let mut quotient = vec![F::ZERO; remaimder_lo.len()];

            parallelize(&mut quotient, |(quotient, start)| {
                izip!(quotient, &remaimder_lo[start..], &remainder_hi[start..])
                    .for_each(|(q, r_lo, r_hi)| *q = *r_hi - r_lo);
            });
            parallelize(remaimder_lo, |(remaimder_lo, start)| {
                izip!(remaimder_lo, &remainder_hi[start..])
                    .for_each(|(r_lo, r_hi)| *r_lo += (*r_hi - r_lo as &_) * x_i);
            });

            remainder.truncate(1 << num_vars);

            f(num_vars, quotient)
        })
        .collect_vec();
    quotients.reverse();

    (quotients, remainder[0])
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

fn bench_fri(system: &System, k: usize) {
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

    let loader = Loader::new(Val::to_enum());
    let commit_data = loader.load("mock_data.json");
    let mut commit_pointer = 0;
    let mut open_pointer = 0;
    let instructions: Vec<(PcsOps, usize)> =
        serde_json::from_reader(File::open("mock_pcs_recorder.json").unwrap()).unwrap();

    let mut poly_map: HashMap<
        Vec<String>, // matrix as string
        (
            p3_symmetric::Hash<Val, u8, 32>,            // commitment
            p3_merkle_tree::MerkleTree<Val, u8, _, 32>, // prover data
        ),
    > = HashMap::new();
    let mut matrix_map: HashMap<
        Vec<String>, // polynomial as string
        Vec<String>, // matrix as string
    > = HashMap::new();
    let mut verifier_data = Vec::new();
    let mut records: Vec<Record> = Vec::new();

    // setup

    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_config = FriConfig {
        log_blowup: 3,
        log_final_poly_len: 0,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    let pcs = FriPcs::new(Dft::default(), val_mmcs, fri_config);

    let mut poly_len = 0;

    // commit and open
    for (ops, size) in instructions {
        match ops {
            PcsOps::Commit => {
                let matrix_str = commit_data.matrices[0][commit_pointer].clone();
                let degree = matrix_str.len() / commit_data.matrix_widths[0][commit_pointer];
                let domain =
                    <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                        &pcs, degree,
                    );
                let matrix_width = commit_data.matrix_widths[0][commit_pointer];
                let matrix = matrix_str
                    .chunks(matrix_width)
                    .map(|chunk| chunk.iter().map(|s| Val::from_str(&s)).collect_vec())
                    .collect_vec();
                let mle_evals = (0..matrix_width)
                    .map(|i| matrix.iter().map(|r| r[i]).collect_vec())
                    .collect_vec();

                let ((comm, prover_data), duration) = sample(
                    k,
                    || (),
                    |_| {
                        let uni_evals = mle_evals
                            .iter()
                            .map(|chunk| {
                                let poly = Type2Polynomial {
                                    poly: chunk.clone().to_vec(),
                                };
                                interpolate_over_boolean_hypercube_with_copy(&poly).0
                            })
                            .collect_vec();
                        let matrix = RowMajorMatrix::<Val>::new(
                            (0..uni_evals[0].poly.len())
                                .flat_map(|i| uni_evals.iter().map(|e| e.poly[i]).collect_vec())
                                .collect_vec(),
                            uni_evals.len(),
                        );
                        <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(
                            &pcs,
                            vec![(domain, matrix.clone())],
                        )
                    },
                    |res| res,
                );

                poly_map.insert(matrix_str.clone(), (comm, prover_data));
                mle_evals.iter().for_each(|chunk| {
                    let poly_str = chunk.iter().map(|s| format!("{:?}", s)).collect_vec();
                    matrix_map.insert(poly_str, matrix_str.clone());
                });

                records.push(Record {
                    method: ops,
                    poly_num: size,
                    poly_vars: log2_ceil_usize(degree),
                    time: duration,
                    size: Some(comm.into_iter().count()),
                });

                commit_pointer += 1;
            }
            PcsOps::Open => {
                let mut data_points: HashMap<_, HashSet<Vec<Challenge>>> = HashMap::new();
                let poly_vars = log2_strict_usize(commit_data.poly_points[open_pointer].1.len());

                commit_data.poly_points[open_pointer..open_pointer + size]
                    .into_iter()
                    .for_each(|(poly, point, _)| {
                        let matrix_str = matrix_map.get(poly).unwrap();

                        let point = point
                            .clone()
                            .into_iter()
                            .map(|f| Challenge::from_str(&f))
                            .collect_vec();

                        data_points
                            .entry(matrix_str)
                            .or_insert(HashSet::new())
                            .insert(point);
                    });

                let polys = commit_data.poly_points[open_pointer..open_pointer + size]
                    .into_iter()
                    .map(|(poly, _, _)| {
                        let poly = poly.iter().map(|s| Val::from_str(&s)).collect_vec();
                        MultilinearPolynomial::new(poly)
                    })
                    .collect_vec();
                let evals = commit_data.poly_points[open_pointer..open_pointer + size]
                    .into_iter()
                    .enumerate()
                    .map(|(i, (_, _, eval))| Evaluation::new(i, i, Val::from_str(eval)))
                    .collect_vec();
                let points = commit_data.poly_points[open_pointer..open_pointer + size]
                    .into_iter()
                    .map(|(_, point, _)| point.into_iter().map(|f| Val::from_str(&f)).collect_vec())
                    .collect_vec();
                let comm_point_evals = polys
                    .clone()
                    .iter()
                    .zip(points.iter())
                    .zip(evals.iter())
                    .map(|((p, point), eval)| {
                        (
                            p.evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec(),
                            point,
                            eval,
                        )
                    })
                    .fold(HashSet::new(), |mut acc, (poly, point, eval)| {
                        acc.insert((matrix_map.get(&poly).unwrap(), point, eval.value()));
                        acc
                    })
                    .into_iter()
                    .map(|(matrix_str, point, eval)| {
                        (
                            poly_map.get(&matrix_str.clone()).unwrap().0,
                            point.clone(),
                            eval.clone(),
                        )
                    })
                    .collect_vec();
                let mut num_vars = 0;

                let (proof, duration) = sample(
                    k,
                    || {
                        (
                            Blake2sTranscript::<std::io::Cursor<Vec<u8>>>::default(),
                            Challenger::from_hasher(vec![], byte_hash),
                        )
                    },
                    |(mut transcript, mut challenger)| {
                        num_vars = polys.first().map(|p| p.num_vars()).unwrap_or_default();
                        let t = (0..polys.len().next_power_of_two().ilog2() as usize)
                            .map(|_| challenger.sample_algebra_element::<Val>())
                            .collect_vec();

                        let eq_xt = MultilinearPolynomial::eq_xy(&t);
                        let merged_polys = evals.iter().zip(eq_xt.evals().iter()).fold(
                            vec![
                                (Val::ONE, Cow::<MultilinearPolynomial<_>>::default());
                                points.len()
                            ],
                            |mut merged_polys, (eval, eq_xt_i)| {
                                if merged_polys[eval.point()].1.is_zero() {
                                    merged_polys[eval.point()] =
                                        (*eq_xt_i, Cow::Borrowed(&polys[eval.poly()]));
                                } else {
                                    let coeff = merged_polys[eval.point()].0;
                                    if coeff != Val::ONE {
                                        merged_polys[eval.point()].0 = Val::ONE;
                                        *merged_polys[eval.point()].1.to_mut() *= &coeff;
                                    }
                                    *merged_polys[eval.point()].1.to_mut() +=
                                        (eq_xt_i, &polys[eval.poly()]);
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
                                Expression::<Val>::eq_xy(idx)
                                    * Expression::Polynomial(Query::new(poly, Rotation::cur()))
                                    * scalar
                            })
                            .sum();
                        let virtual_poly = VirtualPolynomial::new(
                            &expression,
                            unique_merged_polys.iter().map(|(_, poly)| poly.deref()),
                            &[],
                            &points,
                        );

                        let tilde_gs_sum =
                            inner_product(evals.iter().map(|e| e.value()), &eq_xt[..evals.len()]);

                        let (challenges, _) = ClassicSumCheck::<CoefficientsProver<Val>>::prove(
                            &(),
                            num_vars,
                            virtual_poly,
                            tilde_gs_sum,
                            &mut transcript,
                        )
                        .unwrap();
                        //	println!("sum check time {:?}", now.elapsed().as_millis());

                        let eq_xy_evals = points
                            .iter()
                            .map(|point| eq_xy_eval(&challenges, point))
                            .collect_vec();

                        let g_prime = merged_polys
                            .into_iter()
                            .zip(eq_xy_evals.iter())
                            .map(|((scalar, poly), eq_xy_eval)| {
                                (scalar * eq_xy_eval, poly.into_owned())
                            })
                            .sum::<MultilinearPolynomial<_>>();

                        let point = challenges;

                        //write batch queries

                        let poly = g_prime;

                        num_vars = poly.num_vars();

                        let (quotients, _) =
                            quotients(&poly, &point[..], |_, q| UnivariatePolynomial::new(q));

                        let mut tmp_vec = Vec::with_capacity(quotients.len() * (1 << poly_vars));
                        for j in 0..(1 << poly_vars) {
                            for i in 0..quotients.len() {
                                if j < quotients[i].coeffs().len() {
                                    tmp_vec.push(quotients[i].coeffs()[j]);
                                } else {
                                    tmp_vec.push(Val::ZERO);
                                }
                            }
                        }
                        let matrix = RowMajorMatrix::new(tmp_vec, quotients.len());
                        let dft = Dft::default();
                        let matrix = dft.dft_batch(matrix.clone()).to_row_major_matrix();
                        let domain = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                            &pcs,
                            1 << poly_vars,
                        );

                        let (q_comm, q_prover_data) =
                            <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(
                                &pcs,
                                vec![(domain, matrix)],
                            );

                        let x: Val = transcript.squeeze_challenge(); // Val == Challenge

                        let q_proof = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::open(
                            &pcs,
                            vec![(&q_prover_data, vec![vec![Challenge::from(x)]])],
                            &mut challenger,
                        );

                        let poly = poly.evals().to_vec();
                        poly_len = poly.len();
                        let domain = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                            &pcs,
                            poly.len(),
                        );
                        let matrix = RowMajorMatrix::new(poly, 1);

                        let (f_comm, f_prover_data) =
                            <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(
                                &pcs,
                                vec![(domain, matrix)],
                            );

                        let f_proof = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::open(
                            &pcs,
                            vec![(&f_prover_data, vec![vec![Challenge::from(x)]])],
                            &mut challenger,
                        );

                        let rounds = data_points
                            .clone()
                            .into_iter()
                            .map(|(k, _)| {
                                (&poly_map.get(k).unwrap().1, vec![vec![Challenge::from(x)]])
                            })
                            .collect_vec();
                        let p_proof = <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::open(
                            &pcs,
                            rounds,
                            &mut challenger,
                        );

                        (q_comm, q_proof, f_comm, f_proof, p_proof)
                    },
                    |proof| proof,
                );

                let proof_bytes = bincode::serialize(&proof).unwrap();

                records.push(Record {
                    method: ops,
                    poly_num: size,
                    poly_vars: num_vars,
                    time: duration,
                    size: Some(proof_bytes.len()),
                });

                verifier_data.push((proof, points, evals, comm_point_evals));

                open_pointer += size;
            }
            PcsOps::Verify => {
                unreachable!("Verify should not be in the instructions");
            }
        }
    }

    // verify
    for (proof, points, evals, comm_point_evals) in verifier_data {
        let mut num_vars = 0;
        let rounds = comm_point_evals
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, (comm, points, _))| {
                let domain =
                    <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << num_vars,
                    );
                (
                    comm,
                    vec![(
                        domain,
                        points
                            .into_iter()
                            .map(|f| Challenge::from(f))
                            .zip(proof.4 .0[0][i].clone())
                            .collect_vec(),
                    )],
                )
            })
            .collect_vec();

        let (_, duration) = sample(
            k,
            || {
                (
                    Blake2sTranscript::<std::io::Cursor<Vec<u8>>>::default(),
                    Challenger::from_hasher(vec![], byte_hash),
                )
            },
            |(mut transcript, mut challenger)| {
                num_vars = points.first().map(|point| point.len()).unwrap_or_default();

                let ell = evals.len().next_power_of_two().ilog2() as usize;
                let t = transcript.squeeze_challenges(ell);

                let eq_xt = MultilinearPolynomial::eq_xy(&t);
                let tilde_gs_sum =
                    inner_product(evals.iter().map(|e| e.value()), &eq_xt[..evals.len()]);

                let (g_prime_eval, verify_point) =
                    ClassicSumCheck::<CoefficientsProver<Val>>::verify(
                        &(),
                        num_vars,
                        2,
                        tilde_gs_sum,
                        &mut transcript,
                    )
                    .unwrap();

                let point = verify_point;
                let eval = g_prime_eval;

                let q_comm = proof.0;

                let x: Val = transcript.squeeze_challenge();
                // let x = Challenge::from(x);

                let domain =
                    <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << num_vars,
                    );
                let q_evals = proof.1 .0[0][0][0].clone();

                <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::verify(
                    &pcs,
                    vec![(
                        q_comm,
                        vec![(domain, vec![(Challenge::from(x), q_evals.clone())])],
                    )],
                    &proof.1 .1,
                    &mut challenger,
                )
                .unwrap();

                let (eval_scalar, q_scalars) = eval_and_quotient_scalars(x, &point[..]);
                let mut f_eval = eval_scalar * eval;
                let q_evals = q_evals.into_iter().map(|f| f.value).collect_vec();
                izip!(&q_evals, &q_scalars).for_each(|(q, scalar)| f_eval += *scalar * *q);

                let f_comm = proof.2;
                let f_evals = proof.3 .0[0][0][0].clone();

                let domain =
                    <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::natural_domain_for_degree(
                        &pcs, poly_len,
                    );

                <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::verify(
                    &pcs,
                    vec![(
                        f_comm,
                        vec![(domain, vec![(Challenge::from(x), f_evals.clone())])],
                    )],
                    &proof.3 .1,
                    &mut challenger,
                )
                .unwrap();

                <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::verify(
                    &pcs,
                    rounds.clone(),
                    &proof.4 .1,
                    &mut challenger,
                )
                .unwrap();
            },
            |_| (),
        );

        records.push(Record {
            method: PcsOps::Verify,
            poly_num: points.len(),
            poly_vars: num_vars,
            time: duration,
            size: None,
        });
    }

    let mut file = File::create(system.detail_output_path(k)).unwrap();
    serde_json::to_writer(&mut file, &records).unwrap();

    // analysis
    let total_commit_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.time)
        .sum::<f64>();
    let total_open_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Open)
        .map(|r| r.time)
        .sum::<f64>();
    let total_verify_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Verify)
        .map(|r| r.time)
        .sum::<f64>();
    let total_time = total_commit_time + total_open_time + total_verify_time;
    let total_commit_size = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.size.unwrap())
        .sum::<usize>();
    let total_open_size = records
        .iter()
        .filter(|r| r.method == PcsOps::Open)
        .map(|r| r.size.unwrap())
        .sum::<usize>();
    let avg_commit_time = total_commit_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_open_time = total_open_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Open)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_verify_time = total_verify_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Verify)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_commit_size = total_commit_size as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_open_size = total_open_size as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Open)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let avg_poly_vars = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.poly_vars * r.poly_num)
        .sum::<usize>() as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .map(|r| r.poly_num)
            .sum::<usize>() as f64;
    let analysis = Analysis {
        total_commit_time,
        total_open_time,
        total_verify_time,
        total_time,
        avg_commit_time,
        avg_open_time,
        avg_verify_time,
        avg_commit_size,
        avg_open_size,
        avg_poly_vars,
    };
    let mut file = File::create(system.analysis_output_path(k)).unwrap();
    serde_json::to_writer(&mut file, &analysis).unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    MultilinearKzg,
    Basefold256,
    Basefold61Mersenne,
    BasefoldBlake2s,
    Brakedown,
    BrakedownBlake2s,
    ZeromorphFri,
    ZeromorphFriV2,
    P3Fri,
    Circle,
    Gemini,
    Hyrax,
    Deepfold,
}

impl System {
    fn all() -> Vec<System> {
        vec![
            System::MultilinearKzg,
            System::Basefold256,
            System::Basefold61Mersenne,
            System::BasefoldBlake2s,
            System::Brakedown,
            System::BrakedownBlake2s,
            System::ZeromorphFri,
            System::ZeromorphFriV2,
            System::P3Fri,
            System::Circle,
            System::Gemini,
            System::Hyrax,
            System::Deepfold,
        ]
    }

    fn detail_output_path(&self, k: usize) -> String {
        format!("{OUTPUT_DIR}/{self}-{k}-detail.json")
    }

    fn analysis_output_path(&self, k: usize) -> String {
        format!("{OUTPUT_DIR}/{self}-{k}-analysis.json")
    }

    fn bench(&self, k: usize) {
        type Kzg = MultilinearKzg<Bn256>;
        type Brakedown = MultilinearBrakedown<Fp, Keccak256, BrakedownSpec6>;
        // type Brakedown127 = MultilinearBrakedown<Fp, Blake2s, BrakedownSpec6>;
        type BrakedownBlake2s = MultilinearBrakedown<GoldilocksMont, Blake2s, BrakedownSpec1>;

        match self {
            System::ZeromorphFri => {
                bench_pcs::<Fr, ZeromorphFri<Fri<_, Blake2s>>, Blake2sTranscript<_>>(self, k)
            }
            System::Basefold256 => {
                bench_pcs::<Fr, Basefold<_, Blake2s, BasefoldFri>, Blake2sTranscript<_>>(self, k)
            }
            System::MultilinearKzg => bench_pcs::<Fr, Kzg, Blake2sTranscript<_>>(self, k),
            System::Basefold61Mersenne => bench_pcs::<
                Mersenne127,
                Basefold<Mersenne127, Blake2s, BasefoldFri>,
                Blake2sTranscript<_>,
            >(self, k),
            System::BasefoldBlake2s => match k {
                10 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Ten>,
                    Blake2sTranscript<_>,
                >(self, k),
                11 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Eleven>,
                    Blake2sTranscript<_>,
                >(self, k),
                12 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Twelve>,
                    Blake2sTranscript<_>,
                >(self, k),
                13 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Thirteen>,
                    Blake2sTranscript<_>,
                >(self, k),
                14 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Fourteen>,
                    Blake2sTranscript<_>,
                >(self, k),
                15 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Fifteen>,
                    Blake2sTranscript<_>,
                >(self, k),
                16 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Sixteen>,
                    Blake2sTranscript<_>,
                >(self, k),
                17 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Seventeen>,
                    Blake2sTranscript<_>,
                >(self, k),
                18 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Eighteen>,
                    Blake2sTranscript<_>,
                >(self, k),
                19 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Nineteen>,
                    Blake2sTranscript<_>,
                >(self, k),
                20 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Twenty>,
                    Blake2sTranscript<_>,
                >(self, k),
                21 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyOne>,
                    Blake2sTranscript<_>,
                >(self, k),
                22 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyTwo>,
                    Blake2sTranscript<_>,
                >(self, k),
                23 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyThree>,
                    Blake2sTranscript<_>,
                >(self, k),
                24 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyFour>,
                    Blake2sTranscript<_>,
                >(self, k),
                25 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyFive>,
                    Blake2sTranscript<_>,
                >(self, k),
                26 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentySix>,
                    Blake2sTranscript<_>,
                >(self, k),
                _ => {}
            },
            System::Brakedown => bench_pcs::<Fp, Brakedown, Keccak256Transcript<_>>(self, k),
            System::BrakedownBlake2s => {
                bench_pcs::<GoldilocksMont, BrakedownBlake2s, Blake2sTranscript<_>>(self, k)
            }
            System::P3Fri => bench_fri(self, k),
            System::Circle => {
                unimplemented!("Circle is not implemented for mock proof system")
            }
            System::Gemini => {
                bench_pcs::<Fr, Gemini<UnivariateKzg<Bn256>>, Blake2sTranscript<_>>(self, k)
            }
            System::Hyrax => {
                bench_pcs::<Fr, MultilinearHyrax<G1Affine>, Blake2sTranscript<_>>(self, k)
            }
            System::Deepfold => {
                bench_pcs::<Mersenne61Mont, Deepfold, Blake2sTranscript<_>>(self, k)
            }
            System::ZeromorphFriV2 => {
                bench_pcs::<MyFr, ZeromorphFriV2<Fri<_, Blake2s>>, Blake2sTranscript<_>>(self, k)
            }
        }
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::ZeromorphFri => write!(f, "zeromorph_fri"),
            System::Basefold256 => write!(f, "basefold256"),
            System::MultilinearKzg => write!(f, "multilinear_kzg"),
            System::Basefold61Mersenne => write!(f, "basefold61mersenne"),
            System::BasefoldBlake2s => write!(f, "basefoldblake2s"),
            System::Brakedown => write!(f, "brakedown"),
            System::BrakedownBlake2s => write!(f, "brakedownblake2s"),
            System::Circle => write!(f, "circle"),
            System::Gemini => write!(f, "gemini"),
            System::Hyrax => write!(f, "hyrax"),
            System::P3Fri => write!(f, "fri"),
            System::ZeromorphFriV2 => write!(f, "zeromorph_fri_v2"),
            System::Deepfold => write!(f, "deepfold"),
        }
    }
}

fn parse_args() -> (Vec<System>, Range<usize>) {
    let (systems, k_range) = args().chain(Some("".to_string())).tuple_windows().fold(
        (Vec::new(), 10..24),
        |(mut systems, mut k_range), (key, value)| {
            match key.as_str() {
                "--system" => match value.as_str() {
                    "all" => systems = System::all(),
                    "zeromorph_fri" => systems.push(System::ZeromorphFri),
                    "basefold256" => systems.push(System::Basefold256),
                    "multilinear_kzg" => systems.push(System::MultilinearKzg),
                    "basefold61mersenne" => systems.push(System::Basefold61Mersenne),
                    "basefoldblake2s" => systems.push(System::BasefoldBlake2s),
                    "brakedown" => systems.push(System::Brakedown),
                    "brakedownblake2s" => systems.push(System::BrakedownBlake2s),
                    "circle" => systems.push(System::Circle),
                    "gemini" => systems.push(System::Gemini),
                    "hyrax" => systems.push(System::Hyrax),
                    "fri" => systems.push(System::P3Fri),
                    "zeromorph_fri_v2" => systems.push(System::ZeromorphFriV2),
                    _ => panic!(
                        "system should be one of {{all,zeromorph_fri,basefold256,multilinear_kzg,basefold61mersenne}}"
                    ),
                },
                "--k" => {
                    // Handle either "10..20" or a single integer "12".
                    if let Some((start, end)) = value.split_once("..") {
                        k_range = start.parse().expect("k range start to be usize")
                            ..end.parse().expect("k range end to be usize");
                    } else {
                        k_range.start = value.parse().expect("k to be usize");
                        k_range.end = k_range.start + 1;
                    }
                }
                _ => {}
            }
            (systems, k_range)
        },
    );

    // Sort/deduplicate systems. If none specified, we default to all systems.
    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = System::all();
    };

    (systems, k_range)
}

fn sample<T1, T2, T3>(
    k: usize,
    before: impl Fn() -> T1,
    mut prove: impl FnMut(T1) -> T2,
    after: impl Fn(T2) -> T3,
) -> (T3, f64) {
    let mut sum = Duration::from_millis(0);

    let pre_data = before();
    let start = Instant::now();
    let result = prove(pre_data);
    sum += start.elapsed();
    let output = after(result);

    for _ in 1..sample_size(k) {
        let pre_data = before();
        let start = Instant::now();
        prove(pre_data);
        sum += start.elapsed();
    }
    (output, sum.as_millis() as f64 / sample_size(k) as f64)
}

fn sample_size(k: usize) -> usize {
    if k < 16 {
        20
    } else if k < 20 {
        5
    } else {
        1
    }
}
