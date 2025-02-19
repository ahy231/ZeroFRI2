use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use itertools::Itertools;
use plonkish_backend::pcs::multilinear::combined_deepfold::{Proof, Prover, Verifier};
use plonkish_backend::util::{
    algebra::{
        coset::Coset,
        field::{mersenne61_ext::Mersenne61Ext, MyField},
        polynomial::MultilinearPolynomial,
        CODE_RATE, SECURITY_BITS, SIZE, STEP,
    },
    random_oracle::RandomOracle,
};

const OUTPUT_DIR: &str = "./bench_data/deepfold";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    Deepfold,
}

impl System {
    fn output_path(&self) -> String {
        match self {
            System::Deepfold => format!("{OUTPUT_DIR}/deepfold.log"),
        }
    }
    fn verifier_output_path(&self) -> String {
        match self {
            System::Deepfold => format!("{OUTPUT_DIR}/verifier-deepfold.log"),
        }
    }
    fn size_output_path(&self) -> String {
        match self {
            System::Deepfold => format!("{OUTPUT_DIR}/size-deepfold.log"),
        }
    }
    fn output(&self) -> BufWriter<File> {
        BufWriter::new(
            OpenOptions::new()
                .append(true)
                .open(self.output_path())
                .unwrap(),
        )
    }
    fn verifier_output(&self) -> BufWriter<File> {
        BufWriter::new(
            OpenOptions::new()
                .append(true)
                .open(self.verifier_output_path())
                .unwrap(),
        )
    }
    fn size_output(&self) -> BufWriter<File> {
        BufWriter::new(
            OpenOptions::new()
                .append(true)
                .open(self.size_output_path())
                .unwrap(),
        )
    }
    /// Run all deepfold benchmarks (commit, open, verify, and proof size) for a given k.
    fn bench(&self, k: usize) {
        println!("Benchmarking Deepfold for k = {}", k);
        bench_commit(*self, k);
        // bench_open returns both the proof and the verifier (constructed with the same parameters)
        let (proof, verifier) = bench_open(*self, k);
        bench_verify(*self, k, &proof, &verifier);
        bench_size(*self, k, &proof);
    }
}

/// Create output directory and log files.
fn create_output(systems: &[System]) {
    if !std::path::Path::new(OUTPUT_DIR).exists() {
        create_dir_all(OUTPUT_DIR).unwrap();
    }
    for system in systems {
        File::create(system.output_path()).unwrap();
        File::create(system.verifier_output_path()).unwrap();
        File::create(system.size_output_path()).unwrap();
    }
}

/// Repeatedly run the given closure, average the duration, and write the average in milliseconds.
/// The `label` parameter is used to print the phase (e.g. "commit", "open").
fn sample<T>(label: &str, system: System, k: usize, bench: impl Fn() -> T) -> T {
    let iterations = sample_size(k);
    let mut total = Duration::new(0, 0);
    let mut result = None;
    for _ in 0..iterations {
        let start = Instant::now();
        result = Some(bench());
        total += start.elapsed();
    }
    let avg = total / iterations as u32;
    let mut out = system.output();
    writeln!(&mut out, "{}", avg.as_millis()).unwrap();
    out.flush().unwrap();
    println!(
        "Deepfold {}: k = {}, avg = {} ms",
        label,
        k,
        avg.as_millis()
    );
    result.unwrap()
}

/// Similar to sample(), but for the verification phase.
fn verifier_sample<T>(label: &str, system: System, k: usize, bench: impl Fn() -> T) -> T {
    let iterations = sample_size(k);
    let mut total = Duration::new(0, 0);
    let mut result = None;
    for _ in 0..iterations {
        let start = Instant::now();
        result = Some(bench());
        total += start.elapsed();
    }
    let avg = total / iterations as u32;
    let mut out = system.verifier_output();
    writeln!(&mut out, "{}", avg.as_millis()).unwrap();
    out.flush().unwrap();
    println!(
        "Deepfold {}: k = {}, avg = {} ms",
        label,
        k,
        avg.as_millis()
    );
    result.unwrap()
}

/// Decide the number of iterations based on k.
fn sample_size(k: usize) -> usize {
    if k < 16 {
        20
    } else if k < 20 {
        5
    } else {
        1
    }
}

/// Benchmark the commit phase: generate a random polynomial and time the commit operation.
fn bench_commit(system: System, variable_num: usize) {
    let polynomial = MultilinearPolynomial::random_polynomial(variable_num);
    let mut interpolate_cosets = vec![Coset::new(
        1 << (variable_num + CODE_RATE),
        Mersenne61Ext::from_int(1),
    )];
    for i in 1..=variable_num {
        interpolate_cosets.push(interpolate_cosets[i - 1].pow(2));
    }
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    // Log commit time with label "commit"
    let _ = sample("commit", system, variable_num, || {
        let prover = Prover::new(
            variable_num,
            &interpolate_cosets,
            polynomial.clone(),
            &oracle,
            STEP,
        );
        prover.commit_polynomial()
    });
}

/// Benchmark the open phase: generate a proof by opening the commitment.
/// Returns a tuple of (proof, verifier) so that the same parameters can be used for verification.
fn bench_open(
    system: System,
    variable_num: usize,
) -> (Proof<Mersenne61Ext>, Verifier<Mersenne61Ext>) {
    let polynomial = MultilinearPolynomial::random_polynomial(variable_num);
    let mut interpolate_cosets = vec![Coset::new(
        1 << (variable_num + CODE_RATE),
        Mersenne61Ext::from_int(1),
    )];
    for i in 1..=variable_num {
        interpolate_cosets.push(interpolate_cosets[i - 1].pow(2));
    }
    let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
    let prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle, STEP);
    let commit = prover.commit_polynomial();
    let verifier = Verifier::new(variable_num, &interpolate_cosets, commit, &oracle, STEP);
    let point = verifier.get_open_point();
    // Log open (proof generation) time with label "open"
    let proof = sample("open", system, variable_num, || {
        prover.clone().generate_proof(point.clone())
    });
    (proof, verifier)
}

/// Benchmark the verification phase: verify the generated proof using the verifier constructed during the open phase.
fn bench_verify(
    system: System,
    variable_num: usize,
    proof: &Proof<Mersenne61Ext>,
    verifier: &Verifier<Mersenne61Ext>,
) {
    verifier_sample("verify", system, variable_num, || {
        assert!(verifier.clone().verify(proof.clone()));
    });
}

/// Benchmark the proof size: compute and log the size (in bits) of the generated proof.
fn bench_size(system: System, variable_num: usize, proof: &Proof<Mersenne61Ext>) {
    let size = proof.size() * 8; // Use the size() method from Proof
    let mut out = system.size_output();
    writeln!(&mut out, "{}", size).unwrap();
    out.flush().unwrap();
    println!(
        "Deepfold proof size: k = {}, size = {} bits",
        variable_num, size
    );
}

/// Main entry point: create output files, then for each k value, run all deepfold benchmarks.
fn main() {
    let systems = vec![System::Deepfold];
    create_output(&systems);
    println!("Starting Deepfold benchmarks...");
    for k in 10..SIZE {
        System::Deepfold.bench(k);
    }
}
