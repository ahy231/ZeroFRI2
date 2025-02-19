use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use itertools::Itertools;
use plonkish_backend::pcs::multilinear::combined_virgo::{FriProver, FriVerifier};
use plonkish_backend::util::{
    algebra::{
        coset::Coset,
        field::{mersenne61_ext::Mersenne61Ext, MyField},
        polynomial::MultilinearPolynomial,
        CODE_RATE, SECURITY_BITS, SIZE, STEP,
    },
    query_result::QueryResult,
    random_oracle::RandomOracle,
};

const OUTPUT_DIR: &str = "./bench_data/virgo";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    Virgo,
}

impl System {
    fn output_path(&self) -> String {
        match self {
            System::Virgo => format!("{OUTPUT_DIR}/virgo.log"),
        }
    }
    fn verifier_output_path(&self) -> String {
        match self {
            System::Virgo => format!("{OUTPUT_DIR}/verifier-virgo.log"),
        }
    }
    fn size_output_path(&self) -> String {
        match self {
            System::Virgo => format!("{OUTPUT_DIR}/size-virgo.log"),
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
    /// Run all Virgo benchmarks (commit, open, verify, and proof size) for a given k.
    fn bench(&self, k: usize) {
        println!("Benchmarking Virgo for k = {}", k);
        bench_commit(*self, k);
        let (proof, verifier) = bench_open(*self, k);
        bench_verify(*self, k, &proof, &verifier);
        bench_size(*self, k, &proof);
    }
}

/// Type alias for the Virgo proof
type VirgoProof = (
    Vec<QueryResult<Mersenne61Ext>>,
    Vec<QueryResult<Mersenne61Ext>>,
    HashMap<usize, Mersenne61Ext>,
);

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

/// Repeatedly run the given closure, average the duration, and write the average (in ms)
/// to the system's output file. The label parameter distinguishes the phase (e.g. "commit" or "open").
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
    println!("Virgo {}: k = {}, avg = {} ms", label, k, avg.as_millis());
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
    println!("Virgo {}: k = {}, avg = {} ms", label, k, avg.as_millis());
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

/// Benchmark the commit phase: generate a random polynomial and time the commit_first_polynomial operation.
fn bench_commit(system: System, variable_num: usize) {
    let total_round = variable_num;
    let polynomial = MultilinearPolynomial::random_polynomial(variable_num);
    let mut interpolate_cosets = vec![Coset::new(
        1 << (variable_num + CODE_RATE),
        Mersenne61Ext::random_element(),
    )];
    for i in 1..=variable_num {
        interpolate_cosets.push(interpolate_cosets[i - 1].pow(2));
    }
    let random_oracle = RandomOracle::new(total_round, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset = Coset::new(1 << variable_num, Mersenne61Ext::random_element());
    let _ = sample("commit", system, variable_num, || {
        let prover = FriProver::new(
            total_round,
            &interpolate_cosets,
            &vector_interpolation_coset,
            polynomial.clone(),
            &random_oracle,
            STEP,
        );
        prover.commit_first_polynomial();
    });
}

/// Benchmark the open phase: run the full proof generation procedure.
/// Returns a tuple of (proof, updated verifier) so that the same parameters are used for verification.
fn bench_open(system: System, variable_num: usize) -> (VirgoProof, FriVerifier<Mersenne61Ext>) {
    let total_round = variable_num;
    let polynomial = MultilinearPolynomial::random_polynomial(variable_num);
    let mut interpolate_cosets = vec![Coset::new(
        1 << (variable_num + CODE_RATE),
        Mersenne61Ext::random_element(),
    )];
    for i in 1..=variable_num {
        interpolate_cosets.push(interpolate_cosets[i - 1].pow(2));
    }
    let random_oracle = RandomOracle::new(total_round, SECURITY_BITS / CODE_RATE);
    let vector_interpolation_coset = Coset::new(1 << variable_num, Mersenne61Ext::random_element());
    let mut prover = FriProver::new(
        total_round,
        &interpolate_cosets,
        &vector_interpolation_coset,
        polynomial,
        &random_oracle,
        STEP,
    );
    let commit = prover.commit_first_polynomial();
    let mut verifier = FriVerifier::new(
        total_round,
        &interpolate_cosets,
        &vector_interpolation_coset,
        commit,
        &random_oracle,
        STEP,
    );
    let open_point = verifier.get_open_point();

    // Measure open phase timing on clones (so original remains unchanged)
    let _timed_proof: VirgoProof = sample("open", system, variable_num, || {
        let mut p_clone = prover.clone();
        let mut v_clone = verifier.clone();
        p_clone.commit_functions(&mut v_clone, &open_point);
        p_clone.prove();
        p_clone.commit_foldings(&mut v_clone);
        p_clone.query() // returns (folding_proofs, function_proofs, v_value)
    });

    // Now update the original verifier using the original prover to get the final state
    prover.commit_functions(&mut verifier, &open_point);
    prover.prove();
    prover.commit_foldings(&mut verifier);
    let proof: VirgoProof = prover.query();

    (proof, verifier)
}

/// Benchmark the verification phase: verify the generated proof using the updated verifier.
fn bench_verify(
    system: System,
    variable_num: usize,
    proof: &VirgoProof,
    verifier: &FriVerifier<Mersenne61Ext>,
) {
    verifier_sample("verify", system, variable_num, || {
        let (ref folding_proofs, ref function_proofs, ref v_value) = proof;
        assert!(verifier
            .clone()
            .verify(folding_proofs, v_value, function_proofs));
    });
}

/// Benchmark the proof size: compute and log the size (in bits) of the generated proof.
/// We assume the proof is a triple: (folding_proofs, function_proofs, v_value).
fn bench_size(system: System, variable_num: usize, proof: &VirgoProof) {
    let (ref folding_proofs, ref function_proofs, ref v_value) = proof;
    let folding_size = folding_proofs.len();
    let function_size = function_proofs.len();
    let v_value_size = std::mem::size_of_val(v_value);
    let total_bytes = folding_size + function_size + v_value_size;
    let size_bits = total_bytes * 8;
    let mut out = system.size_output();
    writeln!(&mut out, "{}", size_bits).unwrap();
    out.flush().unwrap();
    println!(
        "Virgo proof size: k = {}, size = {} bits",
        variable_num, size_bits
    );
}

/// Main entry point: create output files, then for each k value, run all Virgo benchmarks.
fn main() {
    let systems = vec![System::Virgo];
    create_output(&systems);
    println!("Starting Virgo benchmarks...");
    for k in 10..SIZE {
        System::Virgo.bench(k);
    }
}
