## batch_open

Code with explanation comments :

```rust
fn batch_open<'a>(
    // The KZG prover parameters (likely contains curve generator points, etc.)
    pp: &Self::ProverParam,
    // A collection of polynomials we want to prove evaluations for
    polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    // Corresponding KZG commitments for each polynomial
    comms: impl IntoIterator<Item = &'a Self::Commitment>,
    // The list of distinct points x_i at which polynomials are claimed to evaluate
    points: &[Point<M::Scalar, Self::Polynomial>],
    // The specific (poly_index, point_index, claimed_value) evaluations
    evals: &[Evaluation<M::Scalar>],
    // Fiat–Shamir transcript object to derive (and record) random challenges
    transcript: &mut impl TranscriptWrite<M::G1Affine, M::Scalar>,
) -> Result<(), Error> {
    // 1) Convert polynomials into a vector so we can index them directly
    let polys = polys.into_iter().collect_vec();

    // 2) Organize evals into 'sets'. Each set might group multiple polynomials
    //    if they share evaluation points, or group multiple points for a single polynomial, etc.
    //    'superset' is the union of all involved point indices.
    let (sets, superset) = eval_sets(evals);

    // 3) From the transcript, get two random challenges beta and gamma.
    let beta = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();

    // 4) Determine how many powers of beta and gamma we need:
    //    - beta is used to combine polynomials within each set,
    //    - gamma is used to combine the sets themselves.
    let max_set_len = sets.iter().map(|set| set.polys.len()).max().unwrap();
    let powers_of_beta = powers(beta).take(max_set_len).collect_vec();
    let powers_of_gamma = powers(gamma).take(sets.len()).collect_vec();

    // 5) For each set, do:
    //    - Compute a 'vanishing polynomial' that vanishes on the relevant points.
    //    - Build f_i = sum_{k in set.polys} [ (beta^k) * p_k ].
    //    - Divide f_i by that set's vanishing polynomial: f_i = q_i * V + r_i.
    //      (Here, V is the vanishing polynomial for that set.)
    let (fs, (qs, rs)) = sets
        .iter()
        .map(|set| {
            let vanishing_poly = set.vanishing_poly(points);   // ∏(x - x_j) or something similar

            // Combine polynomials with powers_of_beta:
            //    f = ∑ (beta^i * P_{set.polys[i]})
            let f = izip!(
                &powers_of_beta,
                set.polys.iter().map(|poly_index| polys[*poly_index])
            )
            .sum::<UnivariatePolynomial<_, _>>();

            // Divide f by the vanishing polynomial => f = q * V + r
            let (q, r) = f.div_rem(&vanishing_poly);

            (f, (q, r))
        })
        .unzip::<_, _, Vec<_>, (Vec<_>, Vec<_>)>();

    // 6) Combine all the q_i polynomials (one per set) into a single q using powers_of_gamma:
    //    q = ∑ (gamma^i * q_i)
    let q = izip_eq!(&powers_of_gamma, qs.iter()).sum::<UnivariatePolynomial<_, _>>();

    // 7) Commit to q and write the commitment to the transcript (binding it to gamma).
    let q_comm = Self::commit_and_write(pp, &q, transcript)?;

    // 8) Squeeze another challenge z from the transcript.
    //    We'll open the final aggregator polynomial f at x=z.
    let z = transcript.squeeze_challenge();

    // 9) Compute "normalized_scalars" used to combine all f_i polynomials,
    //    and a "normalizer" factor for the final combination.
    let (normalized_scalars, normalizer) = set_scalars(&sets, &powers_of_gamma, points, &z);

    // 10) Evaluate the “superset” vanishing polynomial at z:
    //     superset_eval = ∏(z - x_j) for all points in the superset.
    let superset_eval = vanishing_eval(superset.iter().map(|idx| &points[*idx]), &z);

    // 11) Compute q_scalar = -superset_eval * normalizer.
    //     This is used to scale q when building the final aggregator polynomial.
    let q_scalar = -superset_eval * normalizer;

    // 12) Build the final aggregator polynomial f:
    //     f = ∑(normalized_scalars[i] * f_i) + (q_scalar * q).
    let f = {
        let mut f = izip_eq!(&normalized_scalars, &fs).sum::<UnivariatePolynomial<_, _>>();
        f += (&q_scalar, &q);
        f
    };

    // 13) (Optional sanity-check) build the combined commitment for f,
    //     and also compute the combined remainder-evaluation.
    //     If not in "sanity-check" mode, just set defaults.
    let (comm, eval) = if cfg!(feature = "sanity-check") {
        // We gather the existing commitments
        let comms = comms.into_iter().map(|comm| &comm.0).collect_vec();

        // Build scalars for each original commitment
        let scalars = comm_scalars(comms.len(), &sets, &powers_of_beta, &normalized_scalars);

        // Combine them via multi-scalar multiplication (MSM),
        // plus the q commitment scaled by q_scalar
        let comm = UnivariateKzgCommitment(
            variable_base_msm(
                chain![&scalars, [&q_scalar]],
                chain![comms, [&q_comm.0]]
            ).into(),
        );

        // Evaluate the remainder polynomials r_i at z, then do an inner product
        // with normalized_scalars to get the final 'eval'.
        let r_evals = rs.iter().map(|r| r.evaluate(&z)).collect_vec();
        (comm, inner_product(&normalized_scalars, &r_evals))
    } else {
        (UnivariateKzgCommitment::default(), M::Scalar::ZERO)
    };

    // 14) Finally, open the combined polynomial f at z.
    //     This produces a single proof that suffices to verify all original evaluations.
    Self::open(pp, &f, &comm, &z, &eval, transcript)
}
```

Another important function being used inside `batch_verify` is `eval_sets` which works something like this : 
1. `eval_sets` scans all evaluations, grouping them first by **polynomial** (`poly_shifts`) and building a global **superset** of points.

2. Then it folds those groups into **EvaluationSets**. Each **EvaluationSet** is characterized by a unique set of points. Polynomials that share that exact point set end up together in the same **EvaluationSet**.

3. `points` in an **EvaluationSet** are the list of all points used by that group of polynomials.

4. `diffs` is just the leftover points in the global superset that this set does not use.

5. The final structure is then passed to the subsequent KZG steps to form vanishing polynomials, combine polynomials, and eventually create a single batched opening proof.


## A structured example for the working of `batch_open`

# 1. The Scenario: 4 Polynomials and 5 Points

Let's label our polynomials `P_0`, `P_1`, `P_2`, `P_3` (i.e., `poly = 0,1,2,3`) and our point indices as `{1, 2, 3, 4, 5}`. (We'll treat these point indices like `point: 1, 2, 3, 4, 5`—in actual code, these might be zero-based or something else, but the concept is the same.)

## 1.1. Example: Which Polynomials Are Evaluated Where?

Assume we have the following claims (`Evaluation<F>`) about these polynomials:

1. `P_0` is evaluated at points 1, 3, 5.
   - So we have `(poly=0, point=1, value=...)`, `(poly=0, point=3, value=...)`, `(poly=0, point=5, value=...)`.

2. `P_1` is evaluated at points 1, 3, 5 as well (the same set as `P_0`), plus it's also evaluated at point 2.
   - `(poly=1, point=1, value=...)`, `(poly=1, point=2, value=...)`, `(poly=1, point=3, value=...)`, `(poly=1, point=5, value=...)`.

3. `P_2` is evaluated at points 2, 5.
   - `(poly=2, point=2, value=...)`, `(poly=2, point=5, value=...)`.

4. `P_3` is evaluated at points 4, 5.
   - `(poly=3, point=4, value=...)`, `(poly=3, point=5, value=...)`.

Hence, we have a total of 11 evaluations in our `evals` array (3 for `P_0` + 4 for `P_1` + 2 for `P_2` + 2 for `P_3`)

```
evals = [
  // P0 @ {1,3,5}
  (poly=0, point=1, value=val_p0_1),
  (poly=0, point=3, value=val_p0_3),
  (poly=0, point=5, value=val_p0_5),

  // P1 @ {1,2,3,5}
  (poly=1, point=1, value=val_p1_1),
  (poly=1, point=2, value=val_p1_2),
  (poly=1, point=3, value=val_p1_3),
  (poly=1, point=5, value=val_p1_5),

  // P2 @ {2,5}
  (poly=2, point=2, value=val_p2_2),
  (poly=2, point=5, value=val_p2_5),

  // P3 @ {4,5}
  (poly=3, point=4, value=val_p3_4),
  (poly=3, point=5, value=val_p3_5),
];
```

# 2. Walking Through `eval_sets`

Recall the code has two major folds:

1. **First fold**: Build `(poly_shifts, superset)` by grouping all points for each polynomial.
2. **Second fold**: Build the final `Vec<EvaluationSet<F>>` from `poly_shifts`.

## 2.1. First Fold: `(poly_shifts, superset)`

`poly_shifts` is a vector of `(poly_index, Vec<point>, Vec<value>)`, grouping points by polynomial.

- **Start empty**.
- **Read each** `(poly=X, point=Y, value=Z)` in `evals`.
- If `poly_shifts` already has an entry for polynomial `X`, append `Y, Z`. Otherwise, create a new entry.
- Also insert `Y` into `superset`.

### At the end:

- For `P_0`: we’ll have `(0, [1,3,5], [val_p0_1, val_p0_3, val_p0_5])`.
- For `P_1`: `(1, [1,2,3,5], [val_p1_1, val_p1_2, val_p1_3, val_p1_5])`.
- For `P_2`: `(2, [2,5], [val_p2_2, val_p2_5])`.
- For `P_3`: `(3, [4,5], [val_p3_4, val_p3_5])`.

`superset` will contain all points we encountered: `{1, 2, 3, 4, 5}`.

So after the first fold, we have something like:

```
poly_shifts = [
  (0, [1, 3, 5], [val_p0_1, val_p0_3, val_p0_5]),
  (1, [1, 2, 3, 5], [val_p1_1, val_p1_2, val_p1_3, val_p1_5]),
  (2, [2, 5], [val_p2_2, val_p2_5]),
  (3, [4, 5], [val_p3_4, val_p3_5]),
]

superset = {1,2,3,4,5}
``` 
## 2.2. Second Fold: Build `sets (Vec<EvaluationSet<F>>)` 

Now we consume `poly_shifts`:

1. **Take** `(poly=0, points=[1,3,5], evals=[val_p0_1, val_p0_3, val_p0_5])`.
   - Initially, `sets` is empty, so we create a new `EvaluationSet`:
     - `polys = [0]`
     - `points = [1,3,5]`
     - `diffs = superset - {1,3,5} = {2,4}`
     - `evals = [val_p0_1, val_p0_3, val_p0_5]`

2. **Take** `(poly=1, points=[1,2,3,5], evals=[val_p1_1, val_p1_2, val_p1_3, val_p1_5])`.
   - Check if there is an existing `EvaluationSet` whose `points` exactly match `[1,2,3,5]`.
   - The only existing set has `points=[1,3,5]`; that is not identical, so we create a new set:
     - `polys = [1]`
     - `points = [1,2,3,5]`
     - `diffs = superset - {1,2,3,5} = {4}`
     - `evals = [val_p1_1, val_p1_2, val_p1_3, val_p1_5]`

3. **Take** `(poly=2, points=[2,5], evals=[val_p2_2, val_p2_5])`.
   - The existing sets have `points=[1,3,5]` and `[1,2,3,5]`; neither is `[2,5]`. So a new set:
     - `polys = [2]`
     - `points = [2,5]`
     - `diffs = superset - {2,5} = {1,3,4}`
     - `evals = [val_p2_2, val_p2_5]`

4. **Take** `(poly=3, points=[4,5], evals=[val_p3_4, val_p3_5])`.
   - Existing sets: `[1,3,5]`, `[1,2,3,5]`, `[2,5]`. None is `[4,5]`. So a new set:
     - `polys = [3]`
     - `points = [4,5]`
     - `diffs = superset - {4,5} = {1,2,3}`
     - `evals = [val_p3_4, val_p3_5]`

---

So we end up with 4 different `EvaluationSet`s. Each set has exactly one polynomial in this scenario, because no two polynomials share **exactly** the same set of points:

1. **Set 0**:
   - `polys = [0]`
   - `points = [1,3,5]`
   - `diffs = {2,4}`
   - `evals = [val_p0_1, val_p0_3, val_p0_5]`

2. **Set 1**:
   - `polys = [1]`
   - `points = [1,2,3,5]`
   - `diffs = {4}`
   - `evals = [val_p1_1, val_p1_2, val_p1_3, val_p1_5]`

3. **Set 2**:
   - `polys = [2]`
   - `points = [2,5]`
   - `diffs = {1,3,4}`
   - `evals = [val_p2_2, val_p2_5]`

4. **Set 3**:
   - `polys = [3]`
   - `points = [4,5]`
   - `diffs = {1,2,3}`
   - `evals = [val_p3_4, val_p3_5]`

---

And:

`superset = {1,2,3,4,5}
`

## 3. Understanding the "Set" and "Superset" Part

- Each `EvaluationSet` has a **unique set of points**.
- In this example, no two polynomials ended up in the same set because none had exactly the same set of points. (If two polynomials had shared exactly the same points, they would end up together in the same set.)
- `superset` is the **union of all points** that appear anywhere in `evals`: `{1, 2, 3, 4, 5}`.

### 3.1. Vanishing Polynomials per Set

When you do a **batch opening** later, each set can have a vanishing polynomial that zeroes out on its `points`. For instance:

- **Set 0** has points `{1, 3, 5}`. The vanishing polynomial could be $(x - 1)(x - 3)(x - 5)$.
- **Set 1**: $(x - 1)(x - 2)(x - 3)(x - 5)$.
- etc.

### 3.2. "Superset" for a Global Vanishing Polynomial

Sometimes the code also uses the **superset vanishing polynomial**, which would be $(x - 1)(x - 2)(x - 3)(x - 4)(x - 5)$ in this example to fold together all sets in a single aggregator polynomial.

---

## 4. How the Folding with $\beta$ and $\gamma$ Typically Works

After `eval_sets` organizes polynomials/evaluations into sets, the **batch opening procedure** (as shown in your original code snippet) uses **two random challenges** ($\beta$ and $\gamma$). Let’s give a high-level summary:

1. **Within Each Set: Combine Polynomials with $\beta$.**
   - Suppose a set has polynomials $\{P_0, P_1, P_2\}$ all evaluated at the same subset of points. You might form:

     
     $f_\text{set}(x) = \beta^0 P_0(x) + \beta^1 P_1(x) + \beta^2 P_2(x).$
     

   - Then you divide $f_\text{set}(x)$ by the set’s vanishing polynomial to get $f_\text{set}(x) = q_\text{set}(x) \cdot V_\text{set}(x) + r_\text{set}(x)$.

2. **Across Sets: Combine the Quotients with $\gamma$.**
   - For each set, you get a quotient polynomial $q_\text{set}$. Then you do:

     
      $q(x) = \sum_{\text{set}=0}^{s-1} \gamma^\text{set} q_\text{set}(x$
   

   - This yields one combined polynomial $q(x)$.

3. **Commit to $q$ and sample a new challenge $z$.**
   - The code commits to $q$ in the transcript, then extracts a new random point $z$.

4. **Form the Single Aggregator Polynomial \(f\).**
   - Combine $\{f_\text{set}(x)\}$ with certain “normalized scalars” and also fold in $\alpha \cdot q(x)$.
   - Finally, you just do one KZG open of $f$ at $z$.

---

### 4.1. Intuitive Reasoning

- The **$\beta$-folding** inside a set ensures you only need one remainder polynomial $r_\text{set}(x)$ for that set. If $f_\text{set}(x)$ is correct at the points in that set, it implies all those polynomials’ evaluations are correct at that subset.
- The **$\gamma$-folding** across sets merges all $\{q_\text{set}\}$ into a single polynomial $q(x)$. Later, in the aggregator polynomial $f$, that ensures you only produce one final KZG opening that covers all sets at once.