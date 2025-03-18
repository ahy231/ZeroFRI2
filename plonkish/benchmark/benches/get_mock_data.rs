// Standard Halo2 PLONK + KZG references.
use halo2_proofs::{
    halo2curves::secp256k1::Fp,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::kzg::{
        commitment::ParamsKZG,
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer},
};

// For convenient iterator transformations (e.g., collect_vec, tuple_windows).
use itertools::Itertools;

// A custom "plonkish_backend" library with advanced functionalities/circuits.
use plonkish_backend::{
    backend::{self, PlonkishBackend, PlonkishCircuit},
    frontend::halo2::{circuit::VanillaPlonk, CircuitExt, Halo2Circuit},
    halo2_curves::bn256::{Bn256, Fr},
    pcs::mock_pcs::{MockPcs, CONTAINER, FIELD as MF, PCS_RECORDER},
    util::{
        end_timer,
        fake_extension::MyFr,
        goldilocksMont::GoldilocksMont,
        hash::Blake2s256,
        mersenne_61_mont::Mersenne61Mont,
        new_fields::{Mersenne127, Mersenne61},
        poly_loader::{container::Field as CF, dumper::Dumper},
        start_timer,
        test::std_rng,
        transcript::MockTranscript, // Transcript types for non-interactive proofs.
    },
};
use serde::Serialize;

// Std library imports for I/O, timing, etc.
use std::{
    env::args, // Command-line arg parsing.
    fmt::Display,
    fs::{create_dir, File, OpenOptions},
    io::Write,
    iter,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};

// The folder where benchmark data will be written.
const OUTPUT_DIR: &str = "./bench_data/mock";

/// Main entry point for running benchmarks.
/// 1) Parse CLI args to decide the system, circuit, and k range.
/// 2) Create output directories.
/// 3) For each k in the range, run each system's benchmark with the chosen circuit.
fn main() {
    let (systems, k_range) = parse_args(); // (1) parse CLI args

    systems.iter().for_each(|system| match system {
        System::Bn254Fr => {
            unsafe {
                MF = Some(CF::Bn254Fr);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<Fr, VanillaPlonk<Fr>>(k);
            });
        }
        System::Mersenne127 => {
            unsafe {
                MF = Some(CF::Mersenne127);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<Mersenne127, VanillaPlonk<Mersenne127>>(k);
            });
        }
        System::GoldilocksMont => {
            unsafe {
                MF = Some(CF::GoldilocksMont);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<GoldilocksMont, VanillaPlonk<GoldilocksMont>>(k);
            });
        }
        System::MyFr => {
            unsafe {
                MF = Some(CF::MyFr);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<MyFr, VanillaPlonk<MyFr>>(k);
            });
        }
        System::Mersenne61Mont => {
            unsafe {
                MF = Some(CF::Mersenne61Mont);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<Mersenne61Mont, VanillaPlonk<Mersenne61Mont>>(k);
            });
        }
        System::Mersenne61 => {
            unsafe {
                MF = Some(CF::Mersenne61);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<Mersenne61, VanillaPlonk<Mersenne61>>(k);
            });
        }
        System::Fr => {
            unsafe {
                MF = Some(CF::Fr);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<Fr, VanillaPlonk<Fr>>(k);
            });
        }
        System::Fp => {
            unsafe {
                MF = Some(CF::Fp);
            }
            k_range.clone().for_each(|k| {
                bench_hyperplonk::<Fp, VanillaPlonk<Fp>>(k);
            });
        }
    });
}

/// Benchmarks HyperPlonk for a given circuit size k and circuit type C.
fn bench_hyperplonk<
    F: ff::PrimeField + Serialize + std::hash::Hash + for<'de> serde::Deserialize<'de>,
    C: CircuitExt<F>,
>(
    k: usize,
) {
    // 1) Type definitions for the FRI-based PCS.
    type Mock<F> = MockPcs<F, Blake2s256>;
    // 2) Our HyperPlonk backend uses Gemini as the polynomial commitment scheme.
    type HyperPlonk<F> = backend::hyperplonk::HyperPlonk<Mock<F>>;

    // 3) Generate a random circuit of size k.
    let circuit = C::rand(k, std_rng());
    // 4) Convert the random circuit into a Halo2Circuit that HyperPlonk can understand.
    let circuit = Halo2Circuit::new::<HyperPlonk<F>>(k, circuit);

    // Additional data needed for setup/proof generation: circuit_info, instance arrays, etc.
    let circuit_info = circuit.circuit_info().unwrap();
    let instances = circuit.instances();

    // 5) Setup
    let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
    // 6) Produce universal params for HyperPlonk (contains cryptographic data).
    let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
    end_timer(timer);

    // 7) Preprocessing (split params into prover/verifier subsets, or do any polynomial prep).
    let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
    let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
    end_timer(timer);

    // 8) Proving phase, measured using the `sample` helper function.
    let proof = sample(k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        // 9) A transcript where proof data is recorded; used for non-interactive proofs.
        let mut transcript = MockTranscript::<F, Blake2s256>::default();
        // 10) Generate the proof with the prover parameters, circuit data, RNG, etc.
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        // Convert the transcript into a raw byte vector proof.
        let proof = transcript.into_proof();
        proof
    });

    unsafe {
        let dumper = Dumper::new();
        dumper.dump(&CONTAINER.clone().unwrap(), "mock_data.json");
        dumper.dump(&PCS_RECORDER.clone().unwrap(), "mock_pcs_recorder.json");
    }
}

/// Benchmarks Halo2's KZG scheme for a circuit of size k and circuit type C.
fn bench_halo2<C: CircuitExt<Fr>>(k: usize) {
    // 1) Random circuit of size k.
    let circuit = C::rand(k, std_rng());
    let circuits = &[circuit];

    // 2) Gather "instance" data (public inputs) and structure for Halo2's APIs.
    let instances = circuits[0].instances();
    let instances = instances.iter().map(Vec::as_slice).collect_vec();
    let instances = [instances.as_slice()];

    // Setup (produce KZG parameters) and measure the time.
    let timer = start_timer(|| format!("halo2_setup-{k}"));
    let param = ParamsKZG::<Bn256>::setup(k as u32, std_rng());
    end_timer(timer);

    // Generate verifying key (vk) and proving key (pk).
    let timer = start_timer(|| format!("halo2_preprocess-{k}"));
    let vk = keygen_vk::<_, _, _, false>(&param, &circuits[0]).unwrap();
    let pk = keygen_pk::<_, _, _, false>(&param, vk, &circuits[0]).unwrap();
    end_timer(timer);

    // 5) Helper closures for proof creation and verification.
    let create_proof = |c, d, e, mut f: Blake2bWrite<_, _, _>| {
        create_proof::<_, ProverGWC<_>, _, _, _, _, false>(&param, &pk, c, d, e, &mut f).unwrap();
        f.finalize()
    };
    let verify_proof =
        |c, d, e| verify_proof::<_, VerifierGWC<_>, _, _, _, false>(&param, pk.get_vk(), c, d, e);

    // 7) Proving step with repeated sampling for average time.
    let proof = sample(k, || {
        let _timer = start_timer(|| format!("halo2_prove-{k}"));
        let transcript = Blake2bWrite::init(Vec::new());
        create_proof(circuits, &instances, std_rng(), transcript)
    });

    // Verification step
    let _timer = start_timer(|| format!("halo2_verify-{k}"));
    let accept = {
        let mut transcript = Blake2bRead::init(proof.as_slice());
        let strategy = SingleStrategy::new(&param);
        verify_proof(strategy, &instances, &mut transcript).is_ok()
    };
    // Ensure it verifies successfully.
    assert!(accept);
}

/// Enum listing which system(s) can be benchmarked. Right now, only HyperPlonk is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    Bn254Fr,
    Mersenne127,
    GoldilocksMont,
    MyFr,
    Mersenne61Mont,
    Mersenne61,
    Fr,
    Fp,
}

impl System {
    /// Returns all possible systems (in this example, just HyperPlonk).
    fn all() -> Vec<System> {
        vec![
            System::Bn254Fr,
            System::Mersenne127,
            System::GoldilocksMont,
            System::MyFr,
            System::Mersenne61Mont,
            System::Fr,
        ]
    }

    /// Path to the "proving time" or general output file for this system.
    fn output_path(&self) -> String {
        format!("{OUTPUT_DIR}/hyperplonk-mock")
    }

    /// Path for the "verification time" output file.
    fn verifier_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/verifier-hyperplonk-mock")
    }

    /// Path for the "proof size" output file.
    fn size_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/size-hyperplonk-mock")
    }

    /// Opens the file for appending benchmark data (e.g., times).
    fn output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.output_path())
            .unwrap()
    }

    /// Similar file handle for verification times.
    fn verifier_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.verifier_output_path())
            .unwrap()
    }

    /// File handle for the proof size logs.
    fn size_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.size_output_path())
            .unwrap()
    }

    /// Whether this system can run a particular circuit variant. Currently everything is `true`.
    fn support(&self, circuit: Circuit) -> bool {
        match self {
            System::Bn254Fr
            | System::Mersenne127
            | System::GoldilocksMont
            | System::MyFr
            | System::Mersenne61Mont
            | System::Mersenne61
            | System::Fr
            | System::Fp => match circuit {
                Circuit::VanillaPlonk | Circuit::Aggregation | Circuit::Sha256 => true,
            },
        }
    }

    /// The main benchmark dispatcher. Decides which function to call based on system + circuit.
    fn bench<F: ff::PrimeField + Serialize + std::hash::Hash + for<'de> serde::Deserialize<'de>>(
        &self,
        k: usize,
        circuit: Circuit,
    ) {
        if !self.support(circuit) {
            println!("skip benchmark on {circuit} with {self} because it's not compatible");
            return;
        }

        println!("start benchmark on 2^{k} {circuit} with {self}");

        // Match on the system and circuit, calling the correct bench function.
        match self {
            System::Bn254Fr
            | System::Mersenne127
            | System::GoldilocksMont
            | System::MyFr
            | System::Mersenne61Mont
            | System::Mersenne61
            | System::Fr
            | System::Fp => match circuit {
                Circuit::VanillaPlonk => bench_hyperplonk::<F, VanillaPlonk<F>>(k),
                Circuit::Aggregation => {
                    // Example aggregator circuit commented out:
                    // bench_hyperplonk::<AggregationCircuit<Bn256>>(k)
                }
                Circuit::Sha256 => {
                    // Example Sha256 circuit commented out:
                    // bench_hyperplonk::<Sha256Circuit>(k)
                }
            },
        }
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::Bn254Fr => write!(f, "bn254fr"),
            System::Mersenne127 => write!(f, "mersenne127"),
            System::GoldilocksMont => write!(f, "goldilocksmont"),
            System::MyFr => write!(f, "myfr"),
            System::Mersenne61Mont => write!(f, "mersenne61mont"),
            System::Mersenne61 => write!(f, "mersenne61"),
            System::Fr => write!(f, "fr"),
            System::Fp => write!(f, "fp"),
        }
    }
}

/// Enum enumerating possible circuit types: VanillaPlonk, Aggregation, or Sha256.
#[derive(Debug, Clone, Copy)]
enum Circuit {
    VanillaPlonk,
    Aggregation,
    Sha256,
}

impl Circuit {
    /// Minimum k value for each circuit type. E.g., Aggregation requires larger k.
    fn min_k(&self) -> usize {
        match self {
            Circuit::VanillaPlonk => 4,
            Circuit::Aggregation => 20,
            Circuit::Sha256 => 17,
        }
    }
}

impl Display for Circuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Circuit::VanillaPlonk => write!(f, "vanilla_plonk"),
            Circuit::Aggregation => write!(f, "aggregation"),
            Circuit::Sha256 => write!(f, "sha256"),
        }
    }
}

/// Parse CLI arguments like `--system hyperplonk --circuit vanilla_plonk --k 10..20`.
/// Returns a tuple of (Vec<System>, Circuit, Range<usize>).
fn parse_args() -> (Vec<System>, Range<usize>) {
    let (systems, k_range) = args().chain(Some("".to_string())).tuple_windows().fold(
        (Vec::new(), 10..24),
        |(mut systems, mut k_range), (key, value)| {
            match key.as_str() {
                "--system" => match value.as_str() {
                    "all" => systems = System::all(),
                    "bn254fr" => systems.push(System::Bn254Fr),
                    "mersenne127" => systems.push(System::Mersenne127),
                    "goldilocksmont" => systems.push(System::GoldilocksMont),
                    "myfr" => systems.push(System::MyFr),
                    "mersenne61mont" => systems.push(System::Mersenne61Mont),
                    "mersenne61" => systems.push(System::Mersenne61),
                    "fr" => systems.push(System::Fr),
                    "fp" => systems.push(System::Fp),
                    _ => panic!(
                        "system should be one of {{all,bn254fr,mersenne127,goldilocksmont,myfr,mersenne61mont,mersenne61,fr,fp}}"
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

/// Creates output directory/files for each system's logs (proof times, verify times, proof size).
fn create_output(systems: &[System]) {
    if !Path::new(OUTPUT_DIR).exists() {
        create_dir(OUTPUT_DIR).unwrap();
    }
    // For each system, create 3 files: "output", "verifier_output", "size_output".
    for system in systems {
        File::create(system.output_path()).unwrap();
        File::create(system.verifier_output_path()).unwrap();
        File::create(system.size_output_path()).unwrap();
    }
}

/// Helper function for measuring the average prove time across multiple samples.
fn sample<T>(k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    // Decide how many times to repeat based on k. Smaller k => more repeats.
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove()); // actually run the prove closure
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();

    let avg = sum / sample_size as u32;
    // Write the average (in milliseconds) to the system's output file.
    // writeln!(&mut system.output(), "{}", avg.as_millis()).unwrap();
    println!("mock: {k}, {}", avg.as_millis());
    proof.unwrap()
}

/// Helper function for measuring the average verify time across multiple samples.
fn verifier_sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove()); // run the verify closure
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();

    let avg = sum / sample_size as u32;
    // Write the average verification time to the system's verifier output file.
    // writeln!(&mut system.verifier_output(), "{}", avg.as_millis()).unwrap();
    proof.unwrap()
}

/// Determines how many samples to run based on k. For small k, run more samples for stable timing.
fn sample_size(k: usize) -> usize {
    // if k < 16 {
    //     20
    // } else if k < 20 {
    //     5
    // } else {
    //     1
    // }
    1
}
