use benchmark::{
    espresso,
    halo2::{AggregationCircuit, Sha256Circuit},
};
// Imports from `espresso_hyperplonk` for certain proof systems or mocking circuits.
use espresso_hyperplonk::{prelude::MockCircuit, HyperPlonkSNARK};
// Additional subroutines (e.g., for multilinear KZG).
use espresso_subroutines::{MultilinearKzgPCS, PolyIOP, PolynomialCommitmentScheme};

// Standard Halo2 PLONK + KZG references.
use halo2_proofs::{
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
    halo2_curves::{bn256::{Bn256, Fr}, secp256k1::Fp},
    pcs::{
        // Possibly two different FRI implementations (multilinear vs. univariate).
        multilinear::ZeromorphFri,
        univariate::Fri
    },
    util::{
        end_timer, start_timer,        // Timer utilities for measuring performance.
        test::std_rng,                 // A standard RNG for testing.
        transcript::{InMemoryTranscript, Blake2sTranscript}, // Transcript types for non-interactive proofs.
        hash::{Blake2s256,Blake2s},    // Additional hashing utilities.
        code::BrakedownSpec6,          // Possibly special circuit specs.
        goldilocksMont::GoldilocksMont // Possibly a specialized field / curves.
    },
};

// Std library imports for I/O, timing, etc.
use std::{
    env::args,             // Command-line arg parsing.
    fmt::Display,
    fs::{create_dir, File, OpenOptions},
    io::Write,
    iter,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};

// The folder where benchmark data will be written.
const OUTPUT_DIR: &str = "./bench_data/zeromorph_fri_256_8";

/// Main entry point for running benchmarks.
/// 1) Parse CLI args to decide the system, circuit, and k range.
/// 2) Create output directories.
/// 3) For each k in the range, run each system's benchmark with the chosen circuit.
fn main() {
    let (systems, circuit, k_range) = parse_args();   // (1) parse CLI args
    create_output(&systems);                          // (2) ensure we have output files/folders
    // (3) For each exponent k in k_range, for each system, call system.bench(k, circuit).
    k_range.for_each(|k| systems.iter().for_each(|system| system.bench(k, circuit)));
}

/// Benchmarks HyperPlonk for a given circuit size k and circuit type C.
fn bench_hyperplonk<C: CircuitExt<Fr>>(k: usize) {
    // 1) Type definitions for the FRI-based PCS.
    type ZeromorphFriPcs = ZeromorphFri<Fri<Fr,Blake2s>>;
    // 2) Our HyperPlonk backend uses ZeromorphFri as the polynomial commitment scheme.
    type HyperPlonk = backend::hyperplonk::HyperPlonk<ZeromorphFriPcs>;

    // 3) Generate a random circuit of size k.
    let circuit = C::rand(k, std_rng());
    // 4) Convert the random circuit into a Halo2Circuit that HyperPlonk can understand.
    let circuit = Halo2Circuit::new::<HyperPlonk>(k, circuit);

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
    let proof = sample(System::HyperPlonk, k, || {
        let _timer = start_timer(|| format!("hyperplonk_prove-{k}"));
        // 9) A transcript where proof data is recorded; used for non-interactive proofs.
        let mut transcript = Blake2sTranscript::default();
        // 10) Generate the proof with the prover parameters, circuit data, RNG, etc.
        HyperPlonk::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        // Convert the transcript into a raw byte vector proof.
        let proof = transcript.into_proof();
        proof
    });

    // 11) Proof size in bits (assuming each byte is 8 bits).
    let size = proof.len() * 8;
    // Write the proof size into a file specific to this system.
    writeln!(&mut (System::HyperPlonk).size_output(), "{}", size).unwrap();	

    // 12) Verification, measured via `verifier_sample`.
    let _timer = start_timer(|| format!("hyperplonk_verify-{k}"));
    let accept = verifier_sample(System::HyperPlonk, k , || {
        // 13) Recreate a transcript from the proof bytes for verification.
        let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
        // 14) Attempt to verify the proof with the verifier params, instance data, etc.
        HyperPlonk::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    });
    // If verification fails, panic in debug mode.
    assert!(accept);
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
    let proof = sample(System::HyperPlonk, k, || {
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
    HyperPlonk
}

impl System {
    /// Returns all possible systems (in this example, just HyperPlonk).
    fn all() -> Vec<System> {
        vec![System::HyperPlonk]
    }

    /// Path to the "proving time" or general output file for this system.
    fn output_path(&self) -> String {
        format!("{OUTPUT_DIR}/hyperplonk-zeromorph_fri")
    }

    /// Path for the "verification time" output file.
    fn verifier_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/verifier-hyperplonk-zeromorph_fri")
    }

    /// Path for the "proof size" output file.
    fn size_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/size-hyperplonk-zeromorph_fri")
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
            System::HyperPlonk => match circuit {
                Circuit::VanillaPlonk | Circuit::Aggregation | Circuit::Sha256 => true,
            },
        }
    }

    /// The main benchmark dispatcher. Decides which function to call based on system + circuit.
    fn bench(&self, k: usize, circuit: Circuit) {
        if !self.support(circuit) {
            println!("skip benchmark on {circuit} with {self} because it's not compatible");
            return;
        }

        println!("start benchmark on 2^{k} {circuit} with {self}");

        // Match on the system and circuit, calling the correct bench function.
        match self {
            System::HyperPlonk => match circuit {
                Circuit::VanillaPlonk => bench_hyperplonk::<VanillaPlonk<Fr>>(k),
                Circuit::Aggregation => {
                    // Example aggregator circuit commented out:
                    // bench_hyperplonk::<AggregationCircuit<Bn256>>(k)
                },
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
            System::HyperPlonk => write!(f, "hyperplonk"),
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
fn parse_args() -> (Vec<System>, Circuit, Range<usize>) {
    let (systems, circuit, k_range) = args().chain(Some("".to_string())).tuple_windows().fold(
        (Vec::new(), Circuit::VanillaPlonk, 10..24),
        |(mut systems, mut circuit, mut k_range), (key, value)| {
            match key.as_str() {
                "--system" => match value.as_str() {
                    "all" => systems = System::all(),
                    "hyperplonk" => systems.push(System::HyperPlonk),
                    _ => panic!("system should be one of {{all,hyperplonk,halo2,espresso_hyperplonk}}"),
                },
                "--circuit" => match value.as_str() {
                    "vanilla_plonk" => circuit = Circuit::VanillaPlonk,
                    "aggregation" => circuit = Circuit::Aggregation,
                    "sha256" => circuit = Circuit::Sha256,
                    _ => panic!("circuit should be one of {{aggregation,vanilla_plonk,sha256}}"),
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
            (systems, circuit, k_range)
        },
    );

    // Ensure k >= the minimum required for this circuit.
    if k_range.start < circuit.min_k() {
        panic!("k should be at least {} for {circuit:?}", circuit.min_k());
    }

    // Sort/deduplicate systems. If none specified, we default to all systems.
    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = System::all();
    };

    (systems, circuit, k_range)
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
fn sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    // Decide how many times to repeat based on k. Smaller k => more repeats.
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());  // actually run the prove closure
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();

    let avg = sum / sample_size as u32;
    // Write the average (in milliseconds) to the system's output file.
    writeln!(&mut system.output(), "{}", avg.as_millis()).unwrap();
    println!("zeromorph: {k}, {}", avg.as_millis());
    proof.unwrap()
}

/// Helper function for measuring the average verify time across multiple samples.
fn verifier_sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());  // run the verify closure
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();

    let avg = sum / sample_size as u32;
    // Write the average verification time to the system's verifier output file.
    writeln!(&mut system.verifier_output(), "{}", avg.as_millis()).unwrap();
    proof.unwrap()
}

/// Determines how many samples to run based on k. For small k, run more samples for stable timing.
fn sample_size(k: usize) -> usize {
    if k < 16 {
        20
    } else if k < 20 {
        5
    } else {
        1
    }
}
