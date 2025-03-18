// use benchmark::{
//     espresso,
//     halo2::{AggregationCircuit, Sha256Circuit},
// };
// use halo2_proofs::transcript::{
//     Blake2bRead, Blake2bWrite, TranscriptReadBuffer, TranscriptWriterBuffer,
// };
// use itertools::Itertools;
// use plonkish_backend::{
//     backend::{self, PlonkishBackend, PlonkishCircuit},
//     frontend::halo2::{circuit::VanillaPlonk, CircuitExt, Halo2Circuit},
//     halo2_curves::bn256::{Bn256, Fr},
//     pcs::multilinear::virgo::VirgoPCS,
//     util::{
//         algebra::field::mersenne61_ext::Mersenne61Ext,
//         arithmetic::Field,
//         end_timer,
//         mersenne_61_mont::Mersenne61Mont,
//         start_timer,
//         test::std_rng,
//         transcript::{Blake2sTranscript, FiatShamirTranscript, InMemoryTranscript, TranscriptWrite, TranscriptRead},
//     },
// };

// use std::{
//     env::args,
//     fmt::Display,
//     fs::{create_dir, File, OpenOptions},
//     io::Write,
//     iter,
//     ops::Range,
//     path::Path,
//     time::{Duration, Instant},
// };

// // Output directory for benchmark data.
// const OUTPUT_DIR: &str = "./bench_data/virgo";

// // Type alias for the field.
// type F = Mersenne61Mont;

// /// Main entry point for running benchmarks.
// /// Parses CLI arguments, creates output directories, and runs benchmarks for each k.
// fn main() {
//     let (systems, circuit, k_range) = parse_args();
//     create_output(&systems);
//     k_range.for_each(|k| systems.iter().for_each(|system| system.bench(k, circuit)));
// }

// /// Benchmarks the Virgo backend for a given circuit size k and circuit type C.
// fn bench_virgo<C: CircuitExt<F>>(k: usize) {
//     // Type alias: use our VirgoPCS as the underlying polynomial commitment scheme.
//     type VirgoPcs = VirgoPCS;
//     // Define the backend that uses VirgoPCS.
//     type VirgoBackend = backend::hyperplonk::HyperPlonk<VirgoPcs>;

//     // (1) Generate a random circuit of size k.
//     let circuit = C::rand(k, std_rng());
//     // (2) Convert the random circuit into a Halo2Circuit that VirgoBackend can process.
//     let circuit = Halo2Circuit::new::<VirgoBackend>(k, circuit);
              
//     // (3) Obtain additional circuit info and instance data.
//     let circuit_info = circuit.circuit_info().unwrap();
//     let instances = circuit.instances();

//     // (4) Setup: produce universal parameters for VirgoBackend.
//     let timer = start_timer(|| format!("virgo_setup-{k}"));
//     let param = VirgoBackend::setup(&circuit_info, std_rng()).unwrap();
//     end_timer(timer);

//     // (5) Preprocess: derive prover and verifier parameters.
//     let timer = start_timer(|| format!("virgo_preprocess-{k}"));
//     let (pp, vp) = VirgoBackend::preprocess(&param, &circuit_info).unwrap();
//     end_timer(timer);

//     // (6) Proving phase.
//     let proof = sample(System::Virgo, k, || {
//         let _timer = start_timer(|| format!("virgo_prove-{k}"));
//         // Create a transcript (using Blake2sTranscript::default() makes the InMemoryTranscript methods available).
//         let mut transcript = Blake2sTranscript::default();
//         VirgoBackend::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
//         transcript.into_proof()
//     });

//     // (7) Record proof size (in bits).
// let size = proof.len() * 8;     
//     writeln!(&mut System::Virgo.size_output(), "{}", size).unwrap();

//     // (8) Verification phase.
//     let _timer = start_timer(|| format!("virgo_verify-{k}"));
//     let accept = verifier_sample(System::Virgo, k, || {
//         // Recreate a transcript from the proof bytes.
//         let mut transcript = Blake2sTranscript::from_proof((), proof.as_slice());
//         VirgoBackend::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
//     });
//     assert!(accept);
// }

// /// Enum representing the proof systems we benchmark; here we support Virgo.
// #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// enum System {
//     Virgo,
// }

// impl System {
//     /// Returns a vector of all systems we can benchmark.
//     fn all() -> Vec<System> {
//         vec![System::Virgo]
//     }

//     /// Returns the output file path for recording proving times.
//     fn output_path(&self) -> String {
//         format!("{OUTPUT_DIR}/virgo")
//     }

//     /// Returns the output file path for recording verification times.
//     fn verifier_output_path(&self) -> String {
//         format!("{OUTPUT_DIR}/verifier-virgo")
//     }

//     /// Returns the output file path for recording proof sizes.
//     fn size_output_path(&self) -> String {
//         format!("{OUTPUT_DIR}/size-virgo")
//     }

//     /// Opens the file for appending proving time benchmark data.
//     fn output(&self) -> File {
//         OpenOptions::new()
//             .append(true)
//             .open(self.output_path())
//             .unwrap()
//     }

//     /// Opens the file for appending verification time benchmark data.
//     fn verifier_output(&self) -> File {
//         OpenOptions::new()
//             .append(true)
//             .open(self.verifier_output_path())
//             .unwrap()
//     }

//     /// Opens the file for appending proof size data.
//     fn size_output(&self) -> File {
//         OpenOptions::new()
//             .append(true)
//             .open(self.size_output_path())
//             .unwrap()
//     }

//     /// Dispatches the benchmark for a given system and circuit.
//     fn bench(&self, k: usize, circuit: Circuit) {
//         if !self.support(circuit) {
//             println!("Skipping benchmark on {circuit} with {self} because it is not supported");
//             return;
//         }
//         println!("Starting benchmark on 2^{k} {circuit} with {self}");
//         match self {
//             System::Virgo => match circuit {
//                 Circuit::VanillaPlonk => bench_virgo::<VanillaPlonk<F>>(k),
//                 Circuit::Aggregation => {
//                     // If you have an aggregator circuit for Virgo, call its benchmark here.
//                 }
//                 Circuit::Sha256 => {
//                     // If you have a SHA256 circuit benchmark for Virgo, call it here.
//                 }
//             },
//         }
//     }

//     fn support(&self, circuit: Circuit) -> bool {
//         matches!((self, circuit), (System::Virgo, Circuit::VanillaPlonk))
//     }
// }

// impl Display for System {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             System::Virgo => write!(f, "virgo"),
//         }
//     }
// }

// /// Enum representing the circuit type.
// #[derive(Debug, Clone, Copy)]
// enum Circuit {
//     VanillaPlonk,
//     Aggregation,
//     Sha256,
// }

// impl Circuit {
//     /// Minimum k required for each circuit type.
//     fn min_k(&self) -> usize {
//         match self {
//             Circuit::VanillaPlonk => 4,
//             Circuit::Aggregation => 20,
//             Circuit::Sha256 => 17,
//         }
//     }
// }

// impl Display for Circuit {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             Circuit::VanillaPlonk => write!(f, "vanilla_plonk"),
//             Circuit::Aggregation => write!(f, "aggregation"),
//             Circuit::Sha256 => write!(f, "sha256"),
//         }
//     }
// }

// /// Parses CLI arguments to determine which systems, circuit type, and k range to benchmark.
// /// Example arguments: `--system virgo --circuit vanilla_plonk --k 10..20`
// fn parse_args() -> (Vec<System>, Circuit, Range<usize>) {
//     let (systems, circuit, k_range) = args().chain(Some("".to_string())).tuple_windows().fold(
//         (Vec::new(), Circuit::VanillaPlonk, 10..15),
//         |(mut systems, mut circuit, mut k_range), (key, value)| {
//             match key.as_str() {
//                 "--system" => match value.as_str() {
//                     "all" => systems = System::all(),
//                     "virgo" => systems.push(System::Virgo),
//                     _ => panic!("System must be one of {{all, virgo}}"),
//                 },
//                 "--circuit" => match value.as_str() {
//                     "vanilla_plonk" => circuit = Circuit::VanillaPlonk,
//                     "aggregation" => circuit = Circuit::Aggregation,
//                     "sha256" => circuit = Circuit::Sha256,
//                     _ => panic!("Circuit must be one of {{aggregation, vanilla_plonk, sha256}}"),
//                 },
//                 "--k" => {
//                     if let Some((start, end)) = value.split_once("..") {
//                         k_range = start.parse().expect("Start of k range must be usize")
//                             ..end.parse().expect("End of k range must be usize");
//                     } else {
//                         k_range.start = value.parse().expect("k must be usize");
//                         k_range.end = k_range.start + 1;
//                     }
//                 }
//                 _ => {}
//             }
//             (systems, circuit, k_range)
//         },
//     );

//     if k_range.start < circuit.min_k() {
//         panic!("k must be at least {} for {circuit:?}", circuit.min_k());
//     }

//     let mut systems = systems.into_iter().sorted().dedup().collect_vec();
//     if systems.is_empty() {
//         systems = System::all();
//     }
//     (systems, circuit, k_range)
// }

// /// Creates output directories and files for benchmark logs.
// fn create_output(systems: &[System]) {
//     if !Path::new(OUTPUT_DIR).exists() {
//         create_dir(OUTPUT_DIR).unwrap();
//     }
//     for system in systems {
//         File::create(system.output_path()).unwrap();
//         File::create(system.verifier_output_path()).unwrap();
//         File::create(system.size_output_path()).unwrap();
//     }
// }

// /// Helper function that runs the prove procedure multiple times and returns the average proof.
// fn sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
//     let mut proof = None;
//     let sample_size = sample_size(k);
//     let sum = iter::repeat_with(|| {
//         let start = Instant::now();
//         proof = Some(prove());
//         start.elapsed()
//     })
//     .take(sample_size)
//     .sum::<Duration>();
//     let avg = sum / sample_size as u32;
//     writeln!(&mut system.output(), "{}", avg.as_millis()).unwrap();
//     println!(
//         "virgo: k = {k}, avg proving time = {} ms",
//         avg.as_millis()
//     );
//     proof.unwrap()
// }

// /// Helper function that runs the verification procedure multiple times and returns the average time.
// fn verifier_sample<T>(system: System, k: usize, verify: impl Fn() -> T) -> T {
//     let mut res = None;
//     let sample_size = sample_size(k);
//     let sum = iter::repeat_with(|| {
//         let start = Instant::now();
//         res = Some(verify());
//         start.elapsed()
//     })
//     .take(sample_size)
//     .sum::<Duration>();
//     let avg = sum / sample_size as u32;
//     writeln!(&mut system.verifier_output(), "{}", avg.as_millis()).unwrap();
//     res.unwrap()
// }

// /// Determines the number of samples to run based on k.
// fn sample_size(k: usize) -> usize {
//     if k < 16 {
//         20
//     } else if k < 20 {
//         5
//     } else {
//         1
//     }
// }
