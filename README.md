# Analysis of Proving Systems

Below is a step-by-step comparison of the different proving systems (Basefold, Brakedown, Gemini, Zeromorph-FRI) across three key metrics:

1. **Proof Generation Time**  
2. **Proof Size**  
3. **Verification Time**  

Because each system’s performance depends heavily on circuit/instance size (the “Polynomial Size” column, measured in \(\log_2\)), it is often most illuminating to compare them at the same polynomial size.

---

## High-Level Observations

1. **Proof Generation Time (“Prover Time”)**  
   - **Smaller polynomial sizes** (e.g., 10–12):  
     - **Basefold** often has the fastest proof generation time.  
     - **Brakedown** has moderate times.  
     - **Gemini** and **Zeromorph-FRI** are generally slower than Basefold but can sometimes outpace Brakedown, depending on the spec.  
   - **Larger polynomial sizes** (e.g., 19–22):  
     - **Brakedown** (especially **spec 3**) shows comparatively better scaling in proof time and can become faster than Basefold at higher degrees.  
     - **Gemini** becomes quite slow at large sizes (e.g., 74,933 ms at size 20).  
     - **Zeromorph-FRI** also ramps up at large sizes but can still be faster than Gemini for some sizes.

2. **Proof Size**  
   - **Gemini** has by far the smallest proof sizes (in the kilobits range).  
   - **Zeromorph-FRI** is the second smallest (megabit range).  
   - **Basefold** is typically in the tens of megabits range.  
   - **Brakedown** (all specs) tends to produce the largest proofs—often hundreds of megabits or more.

3. **Verification Time**  
   - **Gemini** stands out with the fastest verification times (often single-digit or tens of milliseconds).  
   - **Zeromorph-FRI** is second best (tens of milliseconds).  
   - **Basefold** verification is moderate (tens to ~100 ms).  
   - **Brakedown** verifications are in the hundreds to thousands of milliseconds range.

In short:
- If you want **tiny proof size and fastest verification**, **Gemini** is the clear winner.  
- If you want the **fastest proof generation time** for **small circuits**, **Basefold** is often best; for **large circuits**, **Brakedown spec 3** typically catches up or beats Basefold.  
- **Zeromorph-FRI** is often a “middle ground” system with smaller proofs (than Basefold/Brakedown) and faster verification (than Basefold), but slower proof generation than Basefold for small to medium circuits.

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

- **Fastest proof generation time**: Basefold (22 ms).  
- **Smallest proof size**: Gemini (36,864 bits → ~4.6 KB).  
- **Fastest verification**: Gemini (10 ms).  
- **Zeromorph-FRI** has a small proof (1.38 MB) and relatively fast verification (22 ms), but Basefold’s generation time is significantly lower for size=10.

### Polynomial Size = 20

| System                | Proof Time (ms)   | Proof Size (bits)   | Approx Size   | Verification (ms) |
|-----------------------|-------------------|----------------------|---------------|--------------------|
| **Basefold**          | 16,292           | 110,739,200         | ~13.84 MB     | 101                |
| **Brakedown** (spec 1)| 5,981            | 1,854,126,080       | ~232 MB       | 3,746              |
| **Brakedown** (spec 3)| **5,305**        | 1,065,015,296       | ~133 MB       | 2,684              |
| **Brakedown** (spec 6)| 6,086            | 788,621,824         | ~98 MB        | 1,926              |
| **Gemini**            | 74,933           | **67,584**          | ~8.4 KB       | **21**             |
| **Zeromorph-FRI**     | 50,730           | 23,076,352          | ~2.88 MB      | 62                 |

- **Fastest proof generation time** here: Brakedown spec 3 (5,305 ms). It outperforms Basefold (16,292 ms) at this circuit size.  
- **Smallest proof size**: Gemini (67,584 bits → ~8.4 KB).  
- **Fastest verification**: Gemini (21 ms).  
- **Second-place** in proof size is Zeromorph-FRI (~2.88 MB), which is still significantly larger than Gemini but much smaller than Basefold or Brakedown.  
- **Basefold** sits in the middle in proof size (~14 MB) and verification time (~100 ms).

---

## Summary of “Best” Systems by Metric

1. **Fastest Proof Generation**  
   - **Small/medium circuits**: **Basefold** typically leads at low polynomial sizes (e.g., 10–13).  
   - **Large circuits**: **Brakedown** (particularly **spec 3**) has better scaling and overtakes Basefold around polynomial size 17–20+.

2. **Smallest Proof Size**  
   - **Gemini** is consistently far smaller (in the kilobits range).  
   - **Zeromorph-FRI** is next smallest (in the low megabits range).  
   - **Basefold** is moderate (tens to ~100+ megabits for large sizes).  
   - **Brakedown** is largest (often hundreds of megabits or more).

3. **Fastest Verification**  
   - **Gemini** almost always has the smallest verification time.  
   - **Zeromorph-FRI** is usually 2nd place.  
   - **Basefold** is moderate.  
   - **Brakedown** is comparatively slower (hundreds to thousands of ms).

---

## Choosing a Proof System

- **If you need very small proofs (e.g., for bandwidth-restricted environments)**:  
  - **Gemini** is the clear winner in proof size, with the added bonus of very fast verification. The main tradeoff is higher proving time for large circuits.

- **If you need extremely fast proof generation (e.g., you re-generate proofs frequently on large circuits)**:  
  - **Brakedown** under **spec 3** can outperform others at high polynomial sizes (e.g., \(\log_2 n = 20\)).  
  - For smaller polynomial sizes, **Basefold** is often the fastest.

- **If you want a balanced approach with moderate proof time, smaller proof size than Plonk-based “vanilla” solutions, and decent verification time**:  
  - **Zeromorph-FRI** often sits in a comfortable middle ground: it doesn’t beat Gemini in size/verification or Basefold/Brakedown in prover speed at large scale, but it provides decent overall performance.

---

### Final Takeaways

1. **Gemini**: Ultra-small proofs, ultra-fast verification; however, its prover time scales up for large circuits.  
2. **Zeromorph-FRI**: Middle-of-the-road, decent proof size and verification time.  
3. **Basefold**: Very fast prover for small-medium sizes, moderate proof size, moderate verification time.  
4. **Brakedown**: Large proofs but, especially under **spec 3**, can have the fastest prover at large scales—tradeoff is bigger proof sizes and slower verification.

Depending on whether your application prioritizes **prover speed**, **proof size**, or **verifier speed**, you would select one of the above accordingly.