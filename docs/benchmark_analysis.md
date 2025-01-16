# Table Of Contents

<ul>
  <li><a href="#introduction">Introduction</a></li>
  <li>
    <a href="#overview-of-codebases">Overview of Codebases</a>
    <ul>
      <li><a href="#proof-system-benchmark">Proof System Benchmark</a></li>
      <li><a href="#pcs-benchmark">PCS Benchmark</a></li>
    </ul>
  </li>
  <li>
    <a href="#detailed-workflow">Detailed Workflow</a>
    <ul>
      <li><a href="#proof-system-benchmark-flow">Proof System Benchmark Flow</a></li>
      <li><a href="#pcs-benchmark-flow">PCS Benchmark Flow</a></li>
    </ul>
  </li>
  <li><a href="#time-measurement-methods">Time Measurement Methods</a></li>
  <li><a href="#proof-size-measurement-methods">Proof Size Measurement Methods</a></li>
  <li>
    <a href="#measurement-content">Measurement Content</a>
    <ul>
      <li><a href="#for-pcs-benchmark">For PCS benchmark</a></li>
      <li><a href="#for-proof-system-benchmark">For proof system benchmark</a></li>
    </ul>
  </li>
  <li><a href="#circuit-definitions-and-extensions">Circuit Definitions and Extensions</a></li>
  <li><a href="#troubleshooting-and-common-pitfalls">Troubleshooting and Common Pitfalls</a></li>
</ul>

# Introduction

This manual decribes two Rust benchmarking codebases focused on:

- **Proof systems** (e.g., HyperPlonk, Halo2, Espresso HyperPlonk)
- **Polynomial commitment schemes** (PCS) (e.g., MultilinearKzg, Basefold variants, Brakedown, ZeromorphFri)

The benchmarks measure performance (setup, proving, verification times) and proof sizes under different parameters, providing insights for developers and researchers comparing cryptographic proof systems and PCS implementations.

# Overview of Codebases

## Proof System Benchmark

- **File Location:** https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs
- **Purpose:**
  Benchmarks several proof systems (HyperPlonk, Halo2, Espresso HyperPlonk) across different circuits (VanillaPlonk, Aggregation, Sha256).

- Each system is associated with KZG as the underlying polynomial commitment scheme.
- Collects metrics on:

  - Setup time
  - Preprocessing time
  - Proving time
  - Verification time
  - Proof size

- **Key Components:**
- `System` enum: Lists supported systems: `HyperPlonk`, `Halo2`, `EspressoHyperPlonk`.
- `Circuit` enum: Lists supported circuits: `VanillaPlonk`, `Aggregation`, `Sha256`.
- `bench_hyperplonk()`, `bench_halo2()`, `bench_espresso_hyperplonk()`: Core benchmark functions for each proof system.
- `sample()` and `sample_verifier()`: Repeatedly runs proofs/verifications to compute average times.
- `parse_args()`: Parses command-line arguments such as `--system`, `--circuit`, and `--k` ranges.
- `create_output()`: Creates output files to store results.

---

## PCS Benchmark

- **File Location:** https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs

- **Purpose:**
  Benchmarks different polynomial commitment schemes (e.g., MultilinearKzg, Basefold variants, Brakedown, ZeromorphFri) on polynomials of size 2^k.

- Collects metrics on:

  - Setup and trim time
  - Commitment time
  - Proving time
  - Verification time
  - Proof size

- **Key Components:**
- `System` enum: Lists supported PCS implementations: `MultilinearKzg`, `Basefold256`, `Basefold61Mersenne`, etc.
- `bench_pcs<F, Pcs, T>()`: Core benchmark function templated over the field (`F`), the PCS type (`Pcs`), and the transcript type (`T`).
- `parse_args()`: Parses command-line arguments (e.g., `--system`, `--k`).
- `sample_size`: Determines how many times to repeat each operation based on `k`.
- `create_output()`: Creates the output directory and files for each PCS system.

# Detailed Workflow

## Proof System Benchmark Flow

1. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L42">`main()`</a>

   - Parses command line arguments via `parse_args()` to get:
     - `systems`: Vector of PCS systems to benchmark
     - `k_range`: Range of k values to test
   - Creates output directories via `create_output(&systems)`
   - For each k value and system, calls `system.bench(k)`

2. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L222">`System::bench(k, circuit)`</a>

   - Matches on system type to call appropriate `bench_pcs<F, Pcs, T>()` with correct type parameters
   - Different combinations of field type (F), PCS scheme (Pcs), and transcript (T) for each system (see `bench_pcs<F, Pcs, T>()`)

3. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L48">`bench_hyperplonk<C: CircuitExt<Fr>>()`</a>

   - main benchmark function
   - Setup phase:

     - Generates random circuit of size k
     - Creates Halo2Circuit wrapper
     - Gets circuit info and instances
     - Times HyperPlonk parameter generation via `HyperPlonk::setup()`

   - Preprocess phase:

     - Times preprocessing via `HyperPlonk::preprocess()`
     - Generates proving key (pp) and verification key (vp)

   - Prove phase:

     - Creates Blake2s transcript
     - Times proof generation via `HyperPlonk::prove()`
     - Uses `sample()` to average multiple proving runs

   - Verify phase:
     - Creates verification transcript from proof
     - Times verification via `HyperPlonk::verify()`
     - Uses `sample_verifier()` to average multiple verification runs
     - Records proof sizes
     - Asserts verification succeeds

4. Helper functions:
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L343">`sample()`</a>: Runs benchmark multiple times and averages results
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L373">`sample_size()`</a>: Determines number of iterations based on k
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L332">`create_output()`</a>: Sets up output files for results
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L287">`parse_args()`</a>: Processes command line arguments

The benchmark measures and records:

- Commitment time
- Proving time
- Verification time
- Proof sizes

For <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L164">different</a> proof systems including:

- HyperPlonk (using MultilinearKzg)
- Halo2 (using KZG)
- EspressoHyperPlonk (using MultilinearKzg)

For <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L261">different</a> circuit types including:

- VanillaPlonk
- Aggregation
- Sha256

Use only KZG for this benchmark.

## PCS Benchmark Flow

The PCS benchmark measures performance of different polynomial commitment schemes:

1. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L80">`bench_pcs<F, Pcs, T>()`</a>

   - main benchmark function
   - Setup phase:

     - Generates random polynomial of size 2^k
     - Times PCS parameter generation via `Pcs::setup()`
     - Times parameter trimming via `Pcs::trim()`

   - Commit phase:

     - Creates transcript
     - Generates random polynomial
     - Times multiple commitment generations
     - Records average commitment time

   - Prove phase:

     - Generates random evaluation point
     - Times proof generation multiple times
     - Records average proving time
     - Records proof sizes

   - Verify phase:

     - Creates verification transcript from proof
     - Times verification
     - Records verification time
     - Asserts verification succeeds

   - MultilinearKzg: KZG-based multilinear PCS

2. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L170">System enum</a> defines supported PCS schemes:

   - Basefold variants:
     - Basefold256: Using 256-bit field
     - Basefold61Mersenne: Using 61-bit Mersenne field
     - BasefoldBlake2s: Using Blake2s hash
   - Brakedown variants:
     - Brakedown: Original version
     - BrakedownBlake2s: Using Blake2s hash
   - ZeromorphFri: FRI-based PCS

3. Helper functions:
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L195">`output_path()`</a>: Generates output file paths
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L199">`output()`</a>, <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L218">`commit_output()`</a>, etc: Handle file I/O
   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L345">`sample()`</a>: Runs benchmark multiple times and averages

The benchmark measures and records:

- Setup time
- Proving time
- Verification time
- Proof sizes

For each PCS scheme, measurements are taken across different polynomial sizes (2^k) to analyze scaling behavior.

For different polynomial commitment schemes including:

- MultilinearKzg
- Basefold (various variants)
- Brakedown
- ZeromorphFri

# Time Measurement Methods

The benchmark uses two different timing measurement systems:

1. Arkworks Timer (Feature-gated)

   - Enabled via `timer` feature flag
   - Uses arkworks framework's timing tools
   - Measures total time across n iterations for:
     - "PCS setup and trim": Total setup time
     - "commit": Total commiting and proving time
     - "verify": Total verification time
   - Controlled by `start_timer()` and `end_timer()`
   - Example:
     ```rust
     let timer = start_timer(|| format!("PCS setup and trim -{k}"));
     // Setup operations...
     end_timer(timer);
     ```

2. Rust Built-in Timer
   - Uses std::time::{Duration, Instant}
   - Takes multiple samples and averages
   - Measures per-operation time for:
     - Commit: Single commitment generation time
     - Open: Single proof generation time
     - Verify: Single verification time
   - Example:
     ```rust
     let start = Instant::now();
     // Operation
     let duration = start.elapsed();
     ```

Key differences:

- Arkworks timer measures aggregate time across all iterations
- Built-in timer measures individual operations and averages
- Arkworks timer requires feature flag
- Built-in timer always enabled
- Arkworks provides structured timing data
- Built-in provides raw durations

# Proof Size Measurement Methods

For PCS benchmark:

The benchmark measures proof sizes by tracking commitments in the transcript:

1. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L138">Count Initial Commitments</a>

   ```rust
   let mut transcript = T::from_proof((), proof.as_slice());
   let mut start_size = 0;
   while (transcript.read_commitment().is_ok()) {
       start_size = start_size + 1;
   }
   ```

2. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L154">Count Remaining Commitments After Verification</a>

   ```rust
   let mut end_size = 0;
   while (transcript.read_commitment().is_ok()) {
       end_size = end_size + 1;
   }
   ```

3. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L158">Calculate Size Difference and Record</a>

   - Difference between start and end counts represents commitments used in proof
   - Multiply by 256 bits per commitment to get total size in bits

   ```rust
   writeln!(&mut pcs.size_output(), "{:?} {:?} : {:?}", pcs, k, (start_size - end_size)*256);
   ```

The size measurement is integrated into the verification flow to track actual proof sizes used during protocol execution.

For proof system benchmark:

The benchmark measures proof sizes by tracking the transcript size after verification:

1. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L73">Create Transcript and Verify</a>

   ```rust
   let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
   HyperPlonk::verify(&vp, instances, &mut t1, std_rng()).is_ok();
   let end_size = t1.into_proof().len();
   ```

2. <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L77">Record Size in Bits</a>

   ```rust
   writeln!(&mut (System::HyperPlonk).size_output(), "{:?}", (end_size)*8).unwrap();
   ```

The size measurement captures the total proof size in bits by:

- Converting the transcript to bytes after verification is complete
- Multiplying the byte length by 8 to get bits
- Writing the size to a dedicated output file for each proof system

This approach is used consistently across all proof systems (HyperPlonk, Halo2, Espresso HyperPlonk) to enable fair size comparisons.

The size measurement is integrated into the verification flow to track actual proof sizes used during protocol execution.

# Measurement Content

## For PCS benchmark

Sample size varies by k:

The benchmark measures the following operations:

1. Setup & Parameter Generation
   - `Pcs::setup()`: Generates initial PCS parameters
   - `Pcs::trim()`: Trims parameters to specific size
   - Measured via Arkworks Timer
2. Commitment Generation

   - `Pcs::commit_and_write()`:
     - Commits to polynomial
     - Writes commitment to transcript
   - Measured via rust built-in timer and arkworks timer

3. Proving

   - `transcript.squeeze_challenges()`: Generates random challenges
   - `poly.evaluate()`: Evaluates polynomial at challenge point
   - `transcript.write_field_element()`: Writes evaluation to transcript
   - `Pcs::open()`: Generates proof of evaluation
   - Measured via rust built-in timer and arkworks timer

4. Verification

   - `Pcs::read_commitment()`: Reads commitment from transcript
   - `transcript.squeeze_challenges()`: Regenerates challenges
   - `transcript.read_field_element()`: Reads claimed evaluation
   - `Pcs::verify()`: Verifies proof
   - Measured via rust built-in timer and arkworks timer

5. Quotients Computation

   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/plonkish_backend/src/pcs/multilinear.rs#L91">`quotients()`</a> in multilinear.rs
     - Computes quotient polynomials for multilinear PCS
     - Parallelizes computation across threads
     - Measures time via arkworks timer
     - Example timing output:
       ```
       Start:   quotients
       End:     quotients .............................................................12.208µs
       ```

6. Variable Base MSM

   - <a href="https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/plonkish_backend/src/util/arithmetic/msm.rs#L92">`variable_base_msm()`</a> in msm.rs
     - Multi-scalar multiplication with variable bases
     - Parallelizes across threads for large inputs
     - Measures time via arkworks timer
       ```
       Start:   variable_base_msm-32 (for 32 scalars)
       End:     variable_base_msm-32 ..................................................13.347ms
       ```
     - Time scales with number of scalars:
       - Small inputs (< num_threads): Serial computation
       - Large inputs: Parallel chunks across threads

7. Proof Size Measurement

   - Measured in `bench_pcs()` function for each PCS system
   - Key components:

     - Records initial transcript size before verification:
       ```rust
       let mut start_size = 0;
       while (transcript.read_commitment().is_ok()) {
           start_size = start_size + 1;
       }
       ```
     - Records final transcript size after verification:
       ```rust
       let mut end_size = 0;
       while (transcript.read_commitment().is_ok()) {
           end_size = end_size + 1;
       }
       ```
     - Calculates proof size as difference:
       ```rust
       writeln!(
           &mut pcs.size_output(),
           "{:?} {:?} : {:?}",
           pcs,
           k,
           (start_size - end_size) * 256
       );
       ```
     - Size is measured in bytes (each commitment chunk is 256 bits)
     - Results written to separate size output file for each PCS:
       ```rust
       fn size_output_path(&self) -> String {
           format!("{OUTPUT_DIR}/size_{self}")
       }
       ```

   - Example output format:

     ```
     basefold_blake 10 : 512  // For k=10, proof size is 512 bytes
     basefold_blake 11 : 768  // For k=11, proof size is 768 bytes
     ```

   - Size varies by PCS system:
     - KZG: Linear in number of variables
     - Basefold: Logarithmic in number of variables
     - Brakedown: Logarithmic with larger constants
     - ZeromorphFri: Logarithmic with different constants

The benchmark records:

- Commitment time
- Proving time
- Verification time
- Proof sizes
- Quotients computation time
- Variable base MSM time

For each operation, multiple samples are taken based on k value:

- k < 16: 20 samples
- 16 <= k < 20: 5 samples
- k >= 20: 1 sample

Results are written to separate files for each metric and PCS system.

## For proof system benchmark

The main measurements are:

1. Setup Time

   - Measured in `bench_hyperplonk()`, `bench_halo2()`, `bench_espresso_hyperplonk()`
   - Uses arkworks timer
   - Example timing:
     ```rust
     let timer = start_timer(|| format!("hyperplonk_setup-{k}"));
     let param = HyperPlonk::setup(&circuit_info, std_rng()).unwrap();
     end_timer(timer);
     ```

2. Preprocessing Time

   - Measured for parameter and verification key generation
   - Uses same timer mechanism
   - Example from HyperPlonk:
     ```rust
     let timer = start_timer(|| format!("hyperplonk_preprocess-{k}"));
     let (pp, vp) = HyperPlonk::preprocess(&param, &circuit_info).unwrap();
     end_timer(timer);
     ```

3. Proving Time

   - Measured via `sample()` function that takes multiple samples
   - Uses arkworks timer and rust built-in timer
   - Number of samples based on k value:
     ```rust
     fn sample_size(k: usize) -> usize {
         if k < 16 { 20 }
         else if k < 20 { 5 }
         else { 1 }
     }
     ```
   - Records average proving time to "{system}-kzg-prover" file

4. Verification Time

   - Measured via `sample_verifier()` similar to proving time
   - Uses rust built-in timer
   - Records average verification time to "{system}-kzg-verifier" file

5. Proof Size
   - Measured by tracking transcript size
   - For HyperPlonk example:
     ```rust
     let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());
     HyperPlonk::verify(&vp, instances, &mut t1, std_rng()).is_ok();
     let end_size = t1.into_proof().len();
     writeln!(&mut (System::HyperPlonk).size_output(), "{:?}", (end_size)*8).unwrap();
     ```
   - Records proof size in bits to "{system}-kzg-size" file

Results are written to separate files under "./bench_data/kzg/" directory:

- {system}-kzg-prover: Proving times
- {system}-kzg-verifier: Verification times
- {system}-kzg-size: Proof sizes

Where {system} is one of:

- hyperplonk
- halo2
- espresso_hyperplonk

The benchmark supports different circuit types:

- VanillaPlonk
- Aggregation
- Sha256

And measures performance across different k values specified via command line arguments.

# Circuit Definitions and Extensions

We intend to support Halo2 circuit, so we define trait `CircuitExt` to extend `Circuit` trait in Halo2.


For instance, this is how we define Sha256 circuit:

First, we define the circuit:

https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/src/halo2/circuit.rs#L422

```rust
    #[derive(Default)]
    pub struct Sha256Circuit {
        input_size: usize,
    }
```

Then we implement `Circuit` trait for `Sha256Circuit`:

https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/src/halo2/circuit.rs#L427

```rust
    impl Circuit<Fr> for Sha256Circuit {
        type Config = Table16Config;
        type FloorPlanner = SimpleFloorPlanner;
        // ...
    }
```

Then we again implement `CircuitExt` trait for `Sha256Circuit`:

https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/src/halo2/circuit.rs#L464

```rust
    impl CircuitExt<Fr> for Sha256Circuit {
        fn rand(k: usize, _: impl RngCore) -> Self {
            assert!(k > 16);
            let input_size = if k > 22 {
                1025
            } else {
                [33, 65, 129, 257, 513, 1025][k - 17]
            };
            Self { input_size }
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            Vec::new()
        }
    }
```

Finally, this circuit is proved and verified by HyperPlonk.
https://github.com/sec-bit/mle-pcs-benchmark/blob/main/plonkish/benchmark/benches/proof_system.rs#L53

# Troubleshooting and Common Pitfalls

- **Insufficient `k`:**
  - Some circuits require a minimum `k`. If `parse_args()` sees `k < circuit.min_k()`, it panics (e.g., `Aggregation` requires `k >= 20`).
  - **Solution:** Increase `k` to meet the circuit's constraints.

- **Missing or Misconfigured Dependencies:**
  - If the code fails to compile, ensure that all required crates (`arkworks`, `halo2_proofs`, `itertools`, etc.) are specified in `Cargo.toml`.
  - If using Arkworks timers, confirm `features = ["timer"]` are enabled where needed.

- **File Creation Errors:**
  - If the `./bench_data/` directory is missing or permissions are restricted, file creation can fail.
  - **Solution:** Check file system permissions or run `create_output()` manually.

- **Large `k` Values:**
  - For big polynomials (e.g., `k = 24` = 16,777,216 coefficients), memory usage and run times can become quite large.
  - **Solution:** Use caution on machines with limited RAM.

- **Conflicting Transcripts:**
  - Each system or PCS scheme uses specific transcript structures (`Blake2sTranscript`, `Blake2bWrite`, `Keccak256Transcript`, etc.).
  - **Solution:** Make sure the chosen transcript type matches the method calls for reading/writing commitments and field elements.