use itertools::Itertools as _;
use num_bigint::BigInt;
use plonkish_backend::pcs::mock_pcs::PcsOps;
use plonkish_backend::pcs::{Evaluation, PolynomialCommitmentScheme};
use plonkish_backend::poly::Polynomial;
use plonkish_backend::util::hash::{Blake2s, Output};
use plonkish_backend::util::poly_loader::loader::Loader;
use plonkish_backend::util::transcript::{Blake2sTranscript, InMemoryTranscript};
use plonkish_backend::{
    halo2_curves::bn256::Fr,
    pcs::{multilinear::ZeromorphFri, univariate::Fri},
    poly::multilinear::MultilinearPolynomial,
    util::poly_loader::container::Field as CF,
};
use rand::thread_rng;
use serde::Serialize;
use serde_json::from_str;
use std::collections::HashMap;
use std::{
    env::args,
    fmt::Display,
    fs::{create_dir, File, OpenOptions},
    io::Write,
    iter,
    path::Path,
    time::{Duration, Instant},
};

const OUTPUT_DIR: &str = "./bench_data/kzg";

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub method: PcsOps,
    pub poly_num: usize,
    pub poly_vars: usize,
    pub time: u128,
    pub size: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub total_commit_time: u128,
    pub total_open_time: u128,
    pub total_verify_time: u128,
    pub total_time: u128,
    pub avg_commit_time: f64,
    pub avg_open_time: f64,
    pub avg_verify_time: f64,
    pub avg_commit_size: f64,
    pub avg_open_size: f64,
    pub avg_poly_vars: f64,
    pub avg_poly_num: f64,
}

fn main() {
    let systems = parse_args();
    create_output(&systems);
    systems.iter().for_each(|system| system.bench());
}

fn fr_from_str(s: &str) -> Fr {
    let bigint = BigInt::parse_bytes(s.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap();
    let mut bytes = [0u8; 32];
    let bytes_le = bigint.to_bytes_le().1;
    bytes[..bytes_le.len()].copy_from_slice(&bytes_le);
    Fr::from_bytes(&bytes).unwrap()
}

fn bench_mock_psys<
    P: PolynomialCommitmentScheme<
        Fr,
        Polynomial = MultilinearPolynomial<Fr>,
        CommitmentChunk = Output<Blake2s>,
    >,
>()
where
    <P as PolynomialCommitmentScheme<Fr>>::Commitment: AsRef<[Output<Blake2s>]>,
{
    let loader = Loader::new(CF::Bn254Fr);
    let commit_data = loader.load("mock_data.json");
    let mut commit_pointer = 0;
    let mut open_pointer = 0;
    let instructions: Vec<(PcsOps, usize)> =
        serde_json::from_reader(File::open("mock_pcs_recorder.json").unwrap()).unwrap();

    let mut poly_map: HashMap<
        Vec<String>, // polynomial as string
        (
            Option<Vec<u8>>,                                           // transcript as string
            Option<Vec<Fr>>,                                           // point as string
            Option<Fr>,                                                // eval as string
            Option<<P as PolynomialCommitmentScheme<Fr>>::Commitment>, // commitment
        ),
    > = HashMap::new();
    let mut verify_data: Vec<(
        Vec<u8>,                                                // proof
        Vec<Vec<Fr>>,                                           // points
        Vec<Fr>,                                                // evals
        Vec<<P as PolynomialCommitmentScheme<Fr>>::Commitment>, // commitments
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
        let duration;
        match ops {
            PcsOps::Commit => {
                match commit_data.matrix_widths[0][commit_pointer] {
                    1 => {
                        let poly = MultilinearPolynomial::new(
                            commit_data.matrices[0][commit_pointer]
                                .clone()
                                .into_iter()
                                .map(|s| fr_from_str(&s))
                                .collect_vec(),
                        );
                        let start = Instant::now();
                        let comm = P::commit(&pp, &poly).unwrap();
                        duration = start.elapsed();
                        poly_map.insert(
                            commit_data.matrices[0][commit_pointer].clone(),
                            (None, None, None, Some(comm.clone())),
                        );
                        records.push(Record {
                            method: ops,
                            poly_num: 1,
                            poly_vars: poly.num_vars(),
                            time: duration.as_millis(),
                            size: Some(comm.as_ref()[0].len()), // size of commitment, considering comm as [Output<H>] as [[u8]]
                        });
                    }
                    _ => {
                        let polys_str = &commit_data.matrices[0][commit_pointer];
                        let matrix_width = commit_data.matrix_widths[0][commit_pointer];
                        let matrix = polys_str
                            .chunks(matrix_width)
                            .map(|chunk| chunk.iter().map(|s| fr_from_str(&s)).collect_vec())
                            .collect_vec();
                        let polys = (0..matrix_width)
                            .map(|i| {
                                MultilinearPolynomial::new(
                                    matrix.iter().map(|r| r[i]).collect_vec(),
                                )
                            })
                            .collect_vec();
                        let start = Instant::now();
                        let comms = P::batch_commit(&pp, &polys).unwrap();
                        let comms_size = comms.iter().map(|c| c.as_ref()[0].len()).sum::<usize>();
                        // write_commitments(&mut transcript, &comms);
                        duration = start.elapsed();
                        for (poly, comm) in polys.clone().into_iter().zip(comms.clone()) {
                            poly_map.insert(
                                poly.evals()
                                    .into_iter()
                                    .map(|f| format!("{:?}", f))
                                    .collect_vec(),
                                (None, None, None, Some(comm)),
                            );
                        }
                        records.push(Record {
                            method: ops,
                            poly_num: polys.len(),
                            poly_vars: polys[0].num_vars(),
                            time: duration.as_millis(),
                            size: Some(comms_size), // size of commitment
                        });
                    }
                }
                commit_pointer += 1;
            }
            PcsOps::Open => match size {
                1 => {
                    let (poly, point, eval) = &commit_data.poly_points[open_pointer];
                    let poly = from_str::<MultilinearPolynomial<Fr>>(poly).unwrap();
                    let comm = poly_map
                        .get(
                            &poly
                                .evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec(),
                        )
                        .unwrap()
                        .3
                        .clone()
                        .unwrap();
                    let point = point
                        .clone()
                        .into_iter()
                        .map(|f| fr_from_str(&f))
                        .collect_vec();
                    let eval = fr_from_str(eval);
                    let mut transcript = Blake2sTranscript::default();

                    let start = Instant::now();
                    P::open(&pp, &poly, &comm, point.as_ref(), &eval, &mut transcript).unwrap();
                    duration = start.elapsed();

                    let proof = transcript.into_proof();

                    poly_map.insert(
                        poly.evals()
                            .into_iter()
                            .map(|f| format!("{:?}", f))
                            .collect_vec(),
                        (
                            Some(proof.clone()),
                            Some(point.clone()),
                            Some(eval.clone()),
                            Some(comm.clone()),
                        ),
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
                        time: duration.as_millis(),
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
                                .map(|f| fr_from_str(&f))
                                .collect_vec();
                            let eval = fr_from_str(eval);
                            let poly_str = &from_str::<MultilinearPolynomial<Fr>>(poly)
                                .unwrap()
                                .evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec();
                            let comm = poly_map.get(poly_str).unwrap().3.clone().unwrap();

                            poly_map.insert(
                                from_str::<MultilinearPolynomial<Fr>>(poly)
                                    .unwrap()
                                    .evals()
                                    .into_iter()
                                    .map(|f| format!("{:?}", f))
                                    .collect_vec(),
                                (None, Some(point.clone()), Some(eval), Some(comm.clone())),
                            );

                            polys.push(from_str(poly).unwrap());
                            points.push(point);
                            evals.push(eval);
                            comms.push(comm);
                        });

                    let mut transcript = Blake2sTranscript::default();

                    let start = Instant::now();
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
                    duration = start.elapsed();

                    let proof = transcript.into_proof();
                    verify_data.push((proof.clone(), points.clone(), evals.clone(), comms.clone()));

                    records.push(Record {
                        method: ops,
                        poly_num: polys.len(),
                        poly_vars: polys[0].num_vars(),
                        time: duration.as_millis(),
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
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        let duration;
        match points.len() {
            1 => {
                let start = Instant::now();
                P::verify(&vp, &comms[0], &points[0], &evals[0], &mut transcript).unwrap();
                duration = start.elapsed();
            }
            _ => {
                let evals = evals
                    .into_iter()
                    .zip(0..points.len())
                    .map(|(e, i)| Evaluation::new(i, i, e))
                    .collect_vec();
                let start = Instant::now();
                P::batch_verify(&vp, &comms, &points, &evals, &mut transcript).unwrap();
                duration = start.elapsed();
            }
        }
        records.push(Record {
            method: PcsOps::Verify,
            poly_num: points.len(),
            poly_vars: points[0].len(),
            time: duration.as_millis(),
            size: None,
        });
    }

    let mut file = File::create("benchmark_records.json").unwrap();
    serde_json::to_writer(&mut file, &records).unwrap();

    // analysis
    let total_commit_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.time)
        .sum::<u128>();
    let total_open_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Open)
        .map(|r| r.time)
        .sum::<u128>();
    let total_verify_time = records
        .iter()
        .filter(|r| r.method == PcsOps::Verify)
        .map(|r| r.time)
        .sum::<u128>();
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
            .count() as f64;
    let avg_open_time =
        total_open_time as f64 / records.iter().filter(|r| r.method == PcsOps::Open).count() as f64;
    let avg_verify_time = total_verify_time as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Verify)
            .count() as f64;
    let avg_commit_size = total_commit_size as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .count() as f64;
    let avg_open_size =
        total_open_size as f64 / records.iter().filter(|r| r.method == PcsOps::Open).count() as f64;
    let avg_poly_vars = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.poly_vars)
        .sum::<usize>() as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .count() as f64;
    let avg_poly_num = records
        .iter()
        .filter(|r| r.method == PcsOps::Commit)
        .map(|r| r.poly_num)
        .sum::<usize>() as f64
        / records
            .iter()
            .filter(|r| r.method == PcsOps::Commit)
            .count() as f64;
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
        avg_poly_num,
    };
    let mut file = File::create("benchmark_analysis.json").unwrap();
    serde_json::to_writer(&mut file, &analysis).unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    MockProofSystem,
}

impl System {
    fn all() -> Vec<System> {
        vec![System::MockProofSystem]
    }

    fn output_path(&self) -> String {
        format!("{OUTPUT_DIR}/{self}-kzg-prover")
    }

    fn verifier_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/{self}-kzg-verifier")
    }

    fn size_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/{self}-kzg-size")
    }

    fn output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.output_path())
            .unwrap()
    }
    fn verifier_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.verifier_output_path())
            .unwrap()
    }
    fn size_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.size_output_path())
            .unwrap()
    }

    fn bench(&self) {
        bench_mock_psys::<ZeromorphFri<Fri<Fr, Blake2s>>>();
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::MockProofSystem => write!(f, "mock_proof_system"),
        }
    }
}

fn parse_args() -> Vec<System> {
    let systems = args().chain(Some("".to_string())).tuple_windows().fold(
        Vec::new(),
        |mut systems, (key, value)| {
            match key.as_str() {
                "--system" => match value.as_str() {
                    "all" => systems = System::all(),
                    "mock_proof_system" => systems.push(System::MockProofSystem),
                    _ => panic!("system should be one of {{all,mock_proof_system}}"),
                },
                _ => {}
            }
            systems
        },
    );
    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = vec![System::MockProofSystem];
    };
    systems
}

fn create_output(systems: &[System]) {
    if !Path::new(OUTPUT_DIR).exists() {
        create_dir(OUTPUT_DIR).unwrap();
    }
    for system in systems {
        File::create(system.output_path()).unwrap();
        File::create(system.verifier_output_path()).unwrap();
        File::create(system.size_output_path()).unwrap();
    }
}

fn sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();
    let avg = sum / sample_size as u32;
    writeln!(&mut system.output(), "{k}, {}", avg.as_millis()).unwrap();
    proof.unwrap()
}

fn sample_verifier<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();
    let avg = sum / sample_size as u32;
    writeln!(&mut system.verifier_output(), "{k}, {}", avg.as_millis()).unwrap();
    proof.unwrap()
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
