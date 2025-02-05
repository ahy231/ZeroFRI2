All benchmarks in p3 are about small components (like fft, poseidon etc), rather than whole pcs or proof system.

Let's take [fri/benches/fold_even_odd.rs](https://github.com/Plonky3/Plonky3/blob/main/fri/benches/fold_even_odd.rs) as example.

This file is a test case of function `fold_even_odd`, it chooses 3 fields (Babybear, Goldilocks and Complex\<Mersenne31\>) for testing.

https://github.com/Plonky3/Plonky3/blob/main/fri/benches/fold_even_odd.rs#L40

P3 tests it with 6 `log_sizes` (12, 14, 16, 18, 20, 22).

https://github.com/Plonky3/Plonky3/blob/main/fri/benches/fold_even_odd.rs#L38

By using popular benchmark crate `criterion`.

https://github.com/Plonky3/Plonky3/blob/main/fri/benches/fold_even_odd.rs#L45

Other benchmarks are almost the same as this case.
