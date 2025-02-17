# Analysis of MLE-Polynomial Commitment Schemes

Welcome to our benchmarking project for various proving systems and polynomial commitment schemes.

## Overview

Our project provides comprehensive analysis of the different proving systems (Basefold, Brakedown, Gemini, Zeromorph-FRI, Hyrax) by running benchmarks across different circuit sizes, and measuring key metrics such as proof generation time, proof size, and verification time.

## Installation & Usage

1. **Clone the Repository:**

    ```bash
    git clone https://github.com/sec-bit/mle-pcs-benchmark
    cd mle-pcs-benchmark
    ```

2. **Build the Project:**

    ```bash
    cargo build --release
    ```

3. **Running Benchmarks:**

    Navigate to the `plonkish` directory and run:

    ```bash
    cargo run -p bench-cli
    ```

    Follow the prompts to select the proof system and set the desired parameters.

*For more detailed benchmark instructions and technical documentation, please refer to [docs/benchmark_analysis.md](docs/benchmark_analysis.md).*

# Benchmarking

Our benchmarks cover:

- **Proof Generation Time**: How quickly a proof can be generated.
- **Proof Size**: The size of the generated proofs.
- **Verification Time**: How fast a proof can be verified.

For a full analysis, including detailed measurement methods and workflow diagrams, please see [docs/bench_results.md](docs/bench_results.md).

---

# Testing Framework

We employ a robust testing framework that includes:

- Repeated sampling to average out measurements.
- Two timing methods (Arkworks timer for aggregate times and Rust’s built-in timer for individual operations).
- Automated data processing to record and analyze results.

For more in-depth details on our testing framework, please see [docs/benchmark_analysis.md](docs/benchmark_analysis.md).

# Acknowledgements

This project was originally forked from [hadasz/plonkish_basefold](https://github.com/hadasz/plonkish_basefold). Since the fork, we have made several improvements:

- Added comprehensive benchmarks for Polynomial Commitment Schemes (PCS).
- Collected and analyzed extensive bench-data.
- Integrated plonky3 and enabled benchmarks using P3.
- Developed a robust testing framework for accurate measurement of proof generation, proof size, and verification time.

We are grateful to the original authors for their foundational work.

---

# Future Work / Ongoing Refinements

We are continuously refining our testing framework, data processing, and analysis methods. Stay tuned for further updates as we enhance the project's performance and capabilities.