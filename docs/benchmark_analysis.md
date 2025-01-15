# Benchmark Analysis

proof system benchmark:
source1: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs

pcs benchmark:
source2: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs

## Main Function Flow

For proof system benchmark:

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L42
1. `main()`
   - Parses command line arguments via `parse_args()` to get:
     - `systems`: Vector of PCS systems to benchmark
     - `k_range`: Range of k values to test
   - Creates output directories via `create_output(&systems)`
   - For each k value and system, calls `system.bench(k)`

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L222
2. `bench()` method on `System` enum
   - Matches on system type to call appropriate `bench_pcs<F, Pcs, T>()` with correct type parameters
   - Different combinations of field type (F), PCS scheme (Pcs), and transcript (T) for each system (see `bench_pcs<F, Pcs, T>()`)

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L48
3. `bench_hyperplonk<C: CircuitExt<Fr>>()` main benchmark function
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
   - `sample()`: Runs benchmark multiple times and averages results: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L343
   - `sample_size()`: Determines number of iterations based on k: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L373
   - `create_output()`: Sets up output files for results: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L332
   - `parse_args()`: Processes command line arguments: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L287

The benchmark measures and records:
- Commitment time
- Proving time  
- Verification time
- Proof sizes

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L164
For different proof systems including:
- HyperPlonk (using MultilinearKzg)
- Halo2 (using KZG)
- EspressoHyperPlonk (using MultilinearKzg)

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L261
For different circuit types including:
- VanillaPlonk
- Aggregation
- Sha256

Use only KZG for this benchmark.

For PCS benchmark:

The PCS benchmark measures performance of different polynomial commitment schemes:
1. `bench_pcs<F, Pcs, T>()` main benchmark function
https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L80
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

2. System enum defines supported PCS schemes:
https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L170
   - MultilinearKzg: KZG-based multilinear PCS
   - Basefold variants:
     - Basefold256: Using 256-bit field
     - Basefold61Mersenne: Using 61-bit Mersenne field
     - BasefoldBlake2s: Using Blake2s hash
   - Brakedown variants:
     - Brakedown: Original version
     - BrakedownBlake2s: Using Blake2s hash
   - ZeromorphFri: FRI-based PCS

3. Helper functions:
   - `output_path()`: Generates output file paths https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L195
   - `output()`, `commit_output()`, etc: Handle file I/O https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L199 https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L218
   - `bench()`: Dispatches to appropriate benchmark based on system https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L242
   - `sample()`: Runs benchmark multiple times and averages https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L345

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

## Time Measurement Methods

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

## Proof Size Measurement Methods

For PCS benchmark:

The benchmark measures proof sizes by tracking commitments in the transcript:

1. Count Initial Commitments
   https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L138
   ```rust
   let mut transcript = T::from_proof((), proof.as_slice());
   let mut start_size = 0;
   while (transcript.read_commitment().is_ok()) {
       start_size = start_size + 1;
   }
   ```

2. Count Remaining Commitments After Verification
   https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L154
   ```rust 
   let mut end_size = 0;
   while (transcript.read_commitment().is_ok()) {
       end_size = end_size + 1;
   }
   ```

3. Calculate Size Difference and Record
   https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/pcs_bench.rs#L158
   - Difference between start and end counts represents commitments used in proof
   - Multiply by 256 bits per commitment to get total size in bits
   ```rust
   writeln!(&mut pcs.size_output(), "{:?} {:?} : {:?}", pcs, k, (start_size - end_size)*256);
   ```

The size measurement is integrated into the verification flow to track actual proof sizes used during protocol execution.

For proof system benchmark:

The benchmark measures proof sizes by tracking the transcript size after verification:

1. Create Transcript and Verify
https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L73
   ```rust
   let mut t1 = Blake2sTranscript::from_proof((),proof.as_slice());    
   HyperPlonk::verify(&vp, instances, &mut t1, std_rng()).is_ok();
   let end_size = t1.into_proof().len();
   ```

2. Record Size in Bits
https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L77
   ```rust
   writeln!(&mut (System::HyperPlonk).size_output(), "{:?}", (end_size)*8).unwrap();
   ```

The size measurement captures the total proof size in bits by:
- Converting the transcript to bytes after verification is complete
- Multiplying the byte length by 8 to get bits
- Writing the size to a dedicated output file for each proof system

This approach is used consistently across all proof systems (HyperPlonk, Halo2, Espresso HyperPlonk) to enable fair size comparisons.

The size measurement is integrated into the verification flow to track actual proof sizes used during protocol execution.

## Measurement Content

For PCS benchmark:

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
   - `quotients()` in multilinear.rs: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/plonkish_backend/src/pcs/multilinear.rs#L91
     - Computes quotient polynomials for multilinear PCS
     - Parallelizes computation across threads
     - Measures time via arkworks timer
     - Example timing output:
       ```
       Start:   quotients
       End:     quotients .............................................................12.208µs
       ```

6. Variable Base MSM
   - `variable_base_msm()` in msm.rs: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/plonkish_backend/src/util/arithmetic/msm.rs#L92
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


For proof system benchmark:

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
   - Uses arkworks timer and rust built-in timer: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L65 https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L343
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
   - Uses rust built-in timer: https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L358
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

## Circuit

We intend to support Halo2 circuit, so we define trait `CircuitExt` to extend `Circuit` trait in Halo2.

![circuit](./imgs/circuit.png)

For instance, this is how we define Sha256 circuit:

First, we define the circuit:

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/src/halo2/circuit.rs#L422
```rust
    #[derive(Default)]
    pub struct Sha256Circuit {
        input_size: usize,
    }
```

Then we implement `Circuit` trait for `Sha256Circuit`:

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/src/halo2/circuit.rs#L427
```rust
    impl Circuit<Fr> for Sha256Circuit {
        type Config = Table16Config;
        type FloorPlanner = SimpleFloorPlanner;
        // ...
    }
```

Then we again implement `CircuitExt` trait for `Sha256Circuit`:

https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/src/halo2/circuit.rs#L464
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
https://github.com/hadasz/plonkish_basefold/blob/main/plonkish/benchmark/benches/proof_system.rs#L53
