use benchmark::fake_extension::{FakeExtension, MyFr};
use benchmark::BasefoldParams::{
    BasefoldFri, Eighteen, Eleven, Fifteen, Fourteen, Nineteen, Seventeen, Sixteen, Ten, Thirteen,
    Twelve, Twenty, TwentyFive, TwentyFour, TwentyOne, TwentySix, TwentyThree, TwentyTwo,
};
use ff::PrimeField;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::halo2curves::secp256k1::Fp;
use itertools::{izip, Itertools as _};
use num_bigint::BigInt;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_bn254_fr::{Bn254Fr, FFBn254Fr};
use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_circle::CirclePcs;
use p3_commit::{Mmcs, Pcs, PolynomialSpace};

use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, TwoAdicMultiplicativeCoset};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, TwoAdicField};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation,
};
use p3_util::log2_ceil_usize;
use plonkish_backend::pcs::mock_pcs::PcsOps;
use plonkish_backend::pcs::multilinear::{
    Basefold, Gemini, MultilinearBrakedown, MultilinearHyrax, MultilinearKzg,
};
use plonkish_backend::pcs::univariate::UnivariateKzg;
use plonkish_backend::pcs::{Evaluation, PolynomialCommitmentScheme};
use plonkish_backend::poly::Polynomial;
use plonkish_backend::util::code::{BrakedownSpec1, BrakedownSpec6};
use plonkish_backend::util::goldilocksMont::GoldilocksMont;
use plonkish_backend::util::hash::{Blake2s, Keccak256, Output};
use plonkish_backend::util::new_fields::Mersenne127;
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
use rand_9::Rng;
use rand_9::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::from_str;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{AddAssign, Range};
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
                            commit_data.matrices[0][commit_pointer].clone(),
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
                    let poly = from_str::<MultilinearPolynomial<F>>(poly).unwrap();
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

                    // poly_map.insert(
                    //     poly.evals()
                    //         .into_iter()
                    //         .map(|f| format!("{:?}", f))
                    //         .collect_vec(),
                    //     comm.clone(),
                    // );

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
                            let poly_str = &from_str::<MultilinearPolynomial<F>>(poly)
                                .unwrap()
                                .evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec();
                            let comm = poly_map.get(poly_str).unwrap().clone();

                            // poly_map.insert(
                            //     from_str::<MultilinearPolynomial<F>>(poly)
                            //         .unwrap()
                            //         .evals()
                            //         .into_iter()
                            //         .map(|f| format!("{:?}", f))
                            //         .collect_vec(),
                            //     comm.clone(),
                            // );

                            polys.push(from_str(poly).unwrap());
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

    // type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
    type FriPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    let loader = Loader::new(Val::to_enum());
    let commit_data = loader.load("mock_data.json");
    let mut commit_pointer = 0;
    let mut open_pointer = 0;
    let instructions: Vec<(PcsOps, usize)> =
        serde_json::from_reader(File::open("mock_pcs_recorder.json").unwrap()).unwrap();

    let mut poly_map: HashMap<
        Vec<String>, // polynomial as string
        (
            p3_symmetric::Hash<Val, u8, 32>,            // commitment
            p3_merkle_tree::MerkleTree<Val, u8, _, 32>, // prover data
        ),
    > = HashMap::new();
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
                let matrix = RowMajorMatrix::<Val>::new(
                    matrix_str
                        .clone()
                        .into_iter()
                        .map(|s| Val::from_str(&s))
                        .collect_vec(),
                    commit_data.matrix_widths[0][commit_pointer],
                );

                let ((comm, prover_data), duration) = sample(
                    k,
                    || (),
                    |_| {
                        <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::commit(
                            &pcs,
                            vec![(domain, matrix.clone())],
                        )
                    },
                    |res| res,
                );

                poly_map.insert(matrix_str, (comm, prover_data));

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
                let (mut points, mut prover_datas) = (
                    Vec::<Vec<Vec<FakeExtension>>>::with_capacity(size),
                    Vec::with_capacity(size),
                );

                let mut last_poly = &String::new();
                commit_data.poly_points[open_pointer..open_pointer + size]
                    .into_iter()
                    .for_each(|(poly, point, _)| {
                        if poly != last_poly {
                            let poly_str = &from_str::<MultilinearPolynomial<Fr>>(poly)
                                .unwrap()
                                .coefficients()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec();
                            let (comm, prover_data) = poly_map.get(poly_str).unwrap();

                            prover_datas.push(prover_data);
                            points.push(Vec::new());
                            last_poly = poly;
                        }
                        let point = point
                            .clone()
                            .into_iter()
                            .map(|f| FakeExtension::from_str(&f))
                            .collect_vec();
                        points.last_mut().unwrap().push(point);
                    });

                let data_points = prover_datas
                    .iter()
                    .map(|p| *p)
                    .zip(points.iter().clone())
                    .map(|(p, q)| {
                        (
                            p,
                            q.iter()
                                .map(|r| r.iter().map(|s| *s).collect_vec())
                                .collect_vec(),
                        )
                    })
                    .collect_vec();

                let (proof, duration) = sample(
                    k,
                    || Challenger::from_hasher(vec![], byte_hash),
                    |mut transcript| {
                        <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::open(
                            &pcs,
                            data_points.clone(),
                            &mut transcript,
                        )
                    },
                    |proof| proof,
                );

                let proof_bytes = bincode::serialize(&proof).unwrap();

                records.push(Record {
                    method: ops,
                    poly_num: size,
                    poly_vars: log2_ceil_usize(last_poly.len()),
                    time: duration,
                    size: Some(proof_bytes.len()),
                });

                // let comm = poly_map.get().unwrap().0;

                // <FriPcs as p3_commit::Pcs<Challenge, Challenger>>::verify(
                //     &pcs,
                //     vec![()],
                //     &proof.1,
                //     &mut Challenger::from_hasher(vec![], byte_hash),
                // )
                // .unwrap();

                open_pointer += size;
            }
            PcsOps::Verify => {
                unreachable!("Verify should not be in the instructions");
            }
        }
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
    Fri,
    Circle,
    Gemini,
    Hyrax,
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
            System::Fri,
            System::Circle,
            System::Gemini,
            System::Hyrax,
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
            System::Fri => bench_fri(self, k),
            System::Circle => {
                unimplemented!("Circle is not implemented for mock proof system")
            }
            System::Gemini => {
                bench_pcs::<Fr, Gemini<UnivariateKzg<Bn256>>, Blake2sTranscript<_>>(self, k)
            }
            System::Hyrax => {
                bench_pcs::<Fr, MultilinearHyrax<G1Affine>, Blake2sTranscript<_>>(self, k)
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
            System::Fri => write!(f, "fri"),
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
                    "fri" => systems.push(System::Fri),
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
