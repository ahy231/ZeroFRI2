use benchmark::BasefoldParams::BasefoldFri;
use itertools::Itertools as _;
use num_bigint::BigInt;
use plonkish_backend::pcs::mock_pcs::PcsOps;
use plonkish_backend::pcs::multilinear::Basefold;
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
use std::ops::Range;
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
>(
    system: &System,
    k: usize,
) where
    <P as PolynomialCommitmentScheme<Fr>>::Commitment: AsRef<[Output<Blake2s>]>,
{
    let loader = Loader::new(CF::Bn254Fr);
    let commit_data = loader.load("mock_data.json");
    let mut commit_pointer = 0;
    let mut open_pointer = 0;
    let instructions: Vec<(PcsOps, usize)> =
        serde_json::from_reader(File::open("mock_pcs_recorder.json").unwrap()).unwrap();

    let mut poly_map: HashMap<
        Vec<String>,                                       // polynomial as string
        <P as PolynomialCommitmentScheme<Fr>>::Commitment, // commitment
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
                        let (comm, duration) =
                            sample(k, || (), |_| P::commit(&pp, &poly).unwrap(), |c| c);
                        poly_map.insert(
                            commit_data.matrices[0][commit_pointer].clone(),
                            comm.clone(),
                        );
                        records.push(Record {
                            method: ops,
                            poly_num: 1,
                            poly_vars: poly.num_vars(),
                            time: duration,
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
                        let (comms, duration) =
                            sample(k, || (), |_| P::batch_commit(&pp, &polys).unwrap(), |c| c);
                        let comms_size = comms.iter().map(|c| c.as_ref()[0].len()).sum::<usize>();
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
                        .clone();
                    let point = point
                        .clone()
                        .into_iter()
                        .map(|f| fr_from_str(&f))
                        .collect_vec();
                    let eval = fr_from_str(eval);

                    let (proof, duration) = sample(
                        k,
                        || Blake2sTranscript::default(),
                        |mut transcript| {
                            P::open(&pp, &poly, &comm, point.as_ref(), &eval, &mut transcript)
                                .unwrap();
                            transcript
                        },
                        |transcript| transcript.into_proof(),
                    );

                    poly_map.insert(
                        poly.evals()
                            .into_iter()
                            .map(|f| format!("{:?}", f))
                            .collect_vec(),
                        comm.clone(),
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
                                .map(|f| fr_from_str(&f))
                                .collect_vec();
                            let eval = fr_from_str(eval);
                            let poly_str = &from_str::<MultilinearPolynomial<Fr>>(poly)
                                .unwrap()
                                .evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec();
                            let comm = poly_map.get(poly_str).unwrap().clone();

                            poly_map.insert(
                                from_str::<MultilinearPolynomial<Fr>>(poly)
                                    .unwrap()
                                    .evals()
                                    .into_iter()
                                    .map(|f| format!("{:?}", f))
                                    .collect_vec(),
                                comm.clone(),
                            );

                            polys.push(from_str(poly).unwrap());
                            points.push(point);
                            evals.push(eval);
                            comms.push(comm);
                        });

                    let (proof, duration) = sample(
                        k,
                        || Blake2sTranscript::default(),
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
                    || Blake2sTranscript::from_proof((), proof.as_slice()),
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
                    || Blake2sTranscript::from_proof((), proof.as_slice()),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    ZeromorphFri,
    Basefold256,
}

impl System {
    fn all() -> Vec<System> {
        vec![System::ZeromorphFri, System::Basefold256]
    }

    fn detail_output_path(&self, k: usize) -> String {
        format!("{OUTPUT_DIR}/{self}-{k}-detail.json")
    }

    fn analysis_output_path(&self, k: usize) -> String {
        format!("{OUTPUT_DIR}/{self}-{k}-analysis.json")
    }

    fn bench(&self, k: usize) {
        match self {
            System::ZeromorphFri => bench_mock_psys::<ZeromorphFri<Fri<Fr, Blake2s>>>(self, k),
            System::Basefold256 => bench_mock_psys::<Basefold<Fr, Blake2s, BasefoldFri>>(self, k),
        }
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::ZeromorphFri => write!(f, "zeromorph_fri"),
            System::Basefold256 => write!(f, "basefold256"),
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
                    _ => panic!("system should be one of {{all,zeromorph_fri,basefold256}}"),
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
