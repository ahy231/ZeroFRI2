# Analysis of Proving Systems

Below is a step-by-step comparison of the different proving systems (Basefold, Brakedown, Gemini, Zeromorph-FRI, **Hyrax**) across three key metrics:

1. **Proof Generation Time**  
2. **Proof Size**  
3. **Verification Time**  

Because each system’s performance depends heavily on circuit/instance size (the “Polynomial Size” column, measured in \(\log_2\)), it is often most illuminating to compare them at the same polynomial size.

---

## High-Level Observations

1. **Proof Generation Time (“Prover Time”)**  
   - **Smaller polynomial sizes** (e.g., 10–12):  
     - **Basefold** often has the fastest proof generation time.  
     - **Hyrax** is slower than Basefold (e.g., 241 ms vs. 22 ms at size 10) but still in the same range as Gemini (228 ms at size 10).  
     - **Brakedown** has moderate times, depending on the spec.  
     - **Gemini** and **Zeromorph-FRI** can sometimes outpace Brakedown but are generally slower than Basefold for small circuits.  
   - **Larger polynomial sizes** (e.g., 19–22):  
     - **Brakedown** (especially **spec 3**) still shows comparatively better scaling in proof time and can become faster than Basefold.  
     - **Hyrax** remains slower than both Basefold and Brakedown for large circuits (e.g., 52,824 ms at size 20 vs. 16,292 ms for Basefold and 5,305 ms for Brakedown spec 3).  
     - **Gemini** becomes quite slow at large sizes (e.g., 74,933 ms at size 20).  
     - **Zeromorph-FRI** also ramps up at large sizes but sometimes can be faster than Gemini.

2. **Proof Size**  
   - **Gemini** has by far the smallest proof sizes (in the kilobits range).  
   - **Hyrax** is typically in the tens to hundreds of kilobits range, which is larger than Gemini but **much** smaller than Basefold/Brakedown, and even smaller than Zeromorph-FRI at many sizes.  
     - For instance, at size 20: Hyrax \(\sim\) 72 KB, whereas Zeromorph-FRI \(\sim\) 2.88 MB, Basefold \(\sim\) 14 MB, Brakedown (spec 3) \(\sim\) 133 MB.  
   - **Zeromorph-FRI** is in the low megabits range, so often bigger than Hyrax at large sizes.  
   - **Basefold** is typically in the tens of megabits range.  
   - **Brakedown** (all specs) tends to produce the largest proofs—often hundreds of megabits or more.

3. **Verification Time**  
   - **Gemini** stands out with the fastest verification times (often single-digit or tens of milliseconds).  
   - **Zeromorph-FRI** is second best (tens of milliseconds).  
   - **Basefold** is moderate (tens to ~100 ms).  
   - **Hyrax** has moderate to high verification times (e.g., 26 ms at size 10, 444 ms at size 20), which is faster than Brakedown but slower than Basefold at small sizes, and significantly slower than Gemini and Zeromorph-FRI for large sizes.  
   - **Brakedown** verifications are in the hundreds to thousands of milliseconds range, generally the slowest among these systems.

In short:

- If you want **tiny proof size and fastest verification**, **Gemini** is the clear winner.  
- If you want the **fastest proof generation time** for **small circuits**, **Basefold** is often best; for **large circuits**, **Brakedown spec 3** typically catches up or beats Basefold.  
- **Hyrax** has proof sizes much smaller than Basefold/Brakedown and sits in a moderate range for prover time at small scale—but its time grows significantly for large circuits; verification is also moderate to high.  
- **Zeromorph-FRI** is a “middle ground” system with smaller proofs (than Basefold/Brakedown) and faster verification (than Basefold), but typically bigger proofs than Hyrax (at least at large sizes) and somewhat lower verification time than Hyrax for big circuits.

---

## Detailed Comparisons by Example Polynomial Sizes

Below are a couple of detailed snapshots at small (log size=10) and larger (log size=20) circuit sizes.  
(All proof sizes below are quoted in **bits**; approximate bytes/MB are in parentheses.)

### Polynomial Size = 10

| System                | Proof Time (ms) | Proof Size (bits)     | Approx Size   | Verification (ms) |
|-----------------------|-----------------|------------------------|---------------|--------------------|
| **Basefold**          | **22**          | 48,085,760            | ~6 MB         | 72                 |
| **Brakedown** (spec 1)| 247            | 571,307,520           | ~68 MB        | 905                |
| **Brakedown** (spec 3)| 111            | 284,358,144           | ~34 MB        | 360                |
| **Brakedown** (spec 6)| 69             | 162,301,440           | ~20 MB        | 213                |
| **Gemini**            | 228            | **36,864**            | ~4.6 KB       | **10**             |
| **Zeromorph-FRI**     | 43             | 11,052,032            | ~1.38 MB      | 22                 |
| **Hyrax**             | 241            | 50,944                | ~6.4 KB       | 26                 |

- **Fastest proof generation time**: Basefold (22 ms).  
- **Smallest proof size**: Gemini (36,864 bits → ~4.6 KB). Hyrax is bigger than Gemini (~6.4 KB) but still **far** smaller than most others.  
- **Fastest verification**: Gemini (10 ms).  
- **Hyrax** is similar to Gemini’s proof generation time at size 10 (241 ms vs. 228 ms). It has a slightly larger proof than Gemini and a slightly slower verification (26 ms vs. 10 ms).

### Polynomial Size = 20

| System                | Proof Time (ms)   | Proof Size (bits)   | Approx Size    | Verification (ms) |
|-----------------------|-------------------|----------------------|----------------|--------------------|
| **Basefold**          | 16,292           | 110,739,200         | ~13.84 MB      | 101                |
| **Brakedown** (spec 1)| 5,981            | 1,854,126,080       | ~232 MB        | 3,746              |
| **Brakedown** (spec 3)| **5,305**        | 1,065,015,296       | ~133 MB        | 2,684              |
| **Brakedown** (spec 6)| 6,086            | 788,621,824         | ~98 MB         | 1,926              |
| **Gemini**            | 74,933           | **67,584**          | ~8.4 KB        | **21**             |
| **Zeromorph-FRI**     | 50,730           | 23,076,352          | ~2.88 MB       | 62                 |
| **Hyrax**             | 52,824           | 587,008             | ~72 KB         | 444                |

- **Fastest proof generation time**: Brakedown spec 3 (5,305 ms).  
- **Smallest proof size**: Gemini (67,584 bits → ~8.4 KB).  
- **Hyrax** proof size is 587,008 bits (~72 KB) — about an order of magnitude bigger than Gemini but still *far* smaller than Zeromorph-FRI (~2.88 MB), Basefold (~14 MB), or Brakedown (hundreds of MB).  
- **Verification times**: 
  - Hyrax is at 444 ms, which is larger than Basefold (101 ms), significantly larger than Gemini (21 ms) and Zeromorph-FRI (62 ms), but *much* lower than Brakedown’s thousands of ms.

---

## Summary of “Best” Systems by Metric

1. **Fastest Proof Generation**  
   - **Small/medium circuits**: **Basefold** typically leads at low polynomial sizes (10–13).  
   - **Large circuits**: **Brakedown** (particularly **spec 3**) has better scaling and overtakes Basefold around polynomial size 17–20+.  
   - **Hyrax** is not a leader in prover time at any size; it’s slower than Basefold or Brakedown.

2. **Smallest Proof Size**  
   - **Gemini** is consistently the smallest (in the kilobits range).  
   - **Hyrax** is next in line (tens to hundreds of kilobits), smaller than **Zeromorph-FRI** (megabits) and **Basefold/Brakedown** (tens to hundreds of MB).  
   - **Zeromorph-FRI** is typically a few MB, which is still large compared to Hyrax.  
   - **Basefold** is tens of MB, and **Brakedown** is largest (hundreds of MB or more).

3. **Fastest Verification**  
   - **Gemini** almost always has the smallest verification time (tens of ms or less).  
   - **Zeromorph-FRI** is usually the second fastest.  
   - **Basefold** is moderate.  
   - **Hyrax** is moderate-to-high (e.g., 26 ms at size 10, 444 ms at size 20).  
   - **Brakedown** is comparatively slower (hundreds to thousands of ms).

---

## Choosing a Proof System

- **If you need very small proofs (e.g., for bandwidth-restricted environments)**:  
  - **Gemini** is still the clear winner in proof size, with the added bonus of very fast verification. The main tradeoff is higher proving time for large circuits.  
  - **Hyrax** is also quite small in proof size (though larger than Gemini) and has moderate verification times. If proof size is crucial and you want something smaller than Zeromorph-FRI (and *much* smaller than Basefold/Brakedown), Hyrax is an option—especially if you can handle its longer prover time.

- **If you need extremely fast proof generation (e.g., you re-generate proofs frequently on large circuits)**:  
  - **Brakedown** under **spec 3** can outperform others at high polynomial sizes (e.g., \(\log_2 n = 20\)).  
  - For smaller polynomial sizes, **Basefold** is often the fastest.  
  - **Hyrax** doesn’t excel in prover speed at large scale—its times can grow significantly (e.g., ~52,824 ms at size 20).

- **If you want a balanced approach with moderate proof time, smaller proof size than Plonk-based “vanilla” solutions, and decent verification time**:  
  - **Zeromorph-FRI** often sits in a comfortable middle ground, but *Hyrax* might be attractive if you prioritize a smaller proof than Zeromorph-FRI (at the cost of somewhat larger verification time).  
  - **Hyrax** has a proof size in the tens–hundreds of KB range, which is smaller than Zeromorph-FRI (MB range).

---

### Final Takeaways

1. **Gemini**: Ultra-small proofs, ultra-fast verification; however, its prover time scales up quickly for large circuits.  
2. **Hyrax**: Small proofs (bigger than Gemini but smaller than others), moderate-to-high proving time, and moderate verification.  
3. **Zeromorph-FRI**: Middle-of-the-road, decent proof size (a few MB) and relatively fast verification.  
4. **Basefold**: Very fast prover for small-medium sizes, moderate proof size, moderate verification.  
5. **Brakedown**: Large proofs but, especially under **spec 3**, can have the fastest prover at large scales—tradeoff is bigger proof sizes and slower verification.

Depending on whether your application prioritizes **prover speed**, **proof size**, or **verifier speed**, you would select one of the above accordingly.
