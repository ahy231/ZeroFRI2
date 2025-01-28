# Comparative Analysis of Hyrax Protocol Implementations

A comprehensive analysis of three different implementations of the **Hyrax** protocol for multilinear polynomial commitments:

1. **Arkworks** (Rust)  
2. **Hadasz** (Rust)  
3. **Python Reference** 

We begin with a brief recap of the Hyrax protocol itself, then compare how each of the three implementations handles the fundamental steps (commitment, opening/proof, and verification) and discuss their respective pros and cons.

---

## 1. Overview of the Hyrax Protocol

### 1.1. Multilinear Polynomials

A multilinear polynomial 
$$
f(X_0,\dots,X_{n-1})
$$ 
has degree at most 1 in each variable, and thus has 
$$
2^n
$$ 
coefficients:
$$
\{\,a_0,a_1,\dots,a_{2^n-1}\}.
$$
Often, these coefficients are arranged in a 
$$
\bigl(2^{n/2}\bigr) \times \bigl(2^{n/2}\bigr)
$$ 
matrix (assuming $n$ is even). For example, if $n=4$, we have 16 coefficients in a $4\times4$ matrix.

### 1.2. Row‐by‐Row Commitments

Hyrax uses **Pedersen multi‐commitments** to hide these coefficients. Each **row** of the coefficient matrix is committed separately:
$$
\mathrm{rowCom}_i 
= 
\sum_{j=0}^{2^{n/2}-1} a_{i,j}\,G_j \;+\; \rho_i\,H,
$$
where $\{G_j\}$ are group generators and $H$ is a blinding base. The set of $\mathrm{rowCom}_i$ for $i=0,\dots,2^{n/2}-1$ forms the total commitment to $f$.

### 1.3. Evaluation and Proof (Square‐Root Argument)

When we evaluate $f$ at a point 
$$
\mathbf{u}\in\mathbb{F}^n,
$$ 
we split $\mathbf{u}$ into two halves, $\mathbf{u}_L$ and $\mathbf{u}_R$. This induces two vectors $\vec{l}$ and $\vec{r}$, each of dimension $2^{n/2}$. Concretely:

- Multiply the matrix by $\vec{l}$ to get $\mathbf{lt}$.  
- Compute the final dot product 
$$
\mathrm{eval} = \langle \mathbf{lt},\,\vec{r}\rangle.
$$

Hyrax merges the row commits homomorphically according to $\vec{r}$, and then runs a **dot‐product argument** (mini‐IPA) to prove that 
$$
\langle \mathbf{lt}, \vec{r}\rangle = f(\mathbf{u})
$$ 
*without* revealing the entire matrix of coefficients.

---

## 2. Arkworks Implementation

### 2.1. Design & Traits

Arkworks defines a `PolynomialCommitment` interface with types like:
- **`PCUniversalParams`**  
- **`PCCommitterKey`**, **`PCVerifierKey`**  
- **`PCCommitment`**, **`PCProof`**  

For Hyrax, these are instantiated as:
- **`HyraxUniversalParams`**  
- **`HyraxCommitment`** (storing row commitments)  
- **`HyraxProof`** (containing the mini‐IPA artifacts)

### 2.2. Commits & Openings

1. **Commit**  
   - Reshapes $2^n$ evaluations into a $(2^{n/2})\times(2^{n/2})$ matrix.  
   - For each row, a Pedersen commitment is created using a random blinder.  
   - The final commitment is a list of row commits.

2. **Open**  
   - Explicitly implements the dot‐product argument in the code.  
   - Creates commitments to the partial fold $\mathbf{lt}$, the evaluation $\mathrm{eval}$, and uses random vectors $\mathbf{d}$ to blind the real vectors.  
   - Produces the proof data $(\mathbf{z}, z_d, z_b, \mathrm{com\_eval}, \mathrm{com\_d}, \mathrm{com\_b})$.

### 2.3. Pros & Cons

**Pros**  
- Clear, explicit square‐root argument in `open`.  
- Conforms to Arkworks’ trait ecosystem, making it easy to integrate if you already use Arkworks.

**Cons**  
- Restricted to **even $n$**.  
- Possibly large commitments for bigger $n$ (storing $2^{n/2}$ row commits).

---

## 3. Hadasz Implementation

### 3.1. Structure

- A `MultilinearHyraxParams` type storing `row_num_vars` and `num_chunks`.  
- A `MultilinearHyraxCommitment` storing multiple group elements.  
- The proof logic is delegated to `MultilinearIpa`, rather than coding the mini‐IPA directly in the Hyrax class.

### 3.2. Steps

1. **`setup`**  
   - Computes `num_vars = log2(poly_size)`.  
   - Chooses `row_num_vars = div_ceil(...)`, then calls `MultilinearIpa::setup(...)`.

2. **`commit`**  
   - Slices the polynomial’s evaluations into `num_chunks` blocks of size `row_len`.  
   - Each block is multi‐exponentiated with a fixed generator array, producing one element per chunk.

3. **`open`**  
   - Splits the point $\mathbf{u}$ into `(lo, hi)`.  
   - Partially folds the commitment with `hi` to get a single group element.  
   - Delegates the final check to `MultilinearIpa::open`.

### 3.3. Pros & Cons

**Pros**  
- More **modular**: the Hyrax code is mostly about chunking/folding, while `MultilinearIpa` does the IPA.  
- Potentially handles **odd** $n$ via `div_ceil`.

**Cons**  
- The underlying dot‐product proof is “hidden” in `MultilinearIpa`. You do not see the explicit Hyrax equations in the Hyrax code.  
- Still large commits for bigger dimension.

---

## 4. Python Reference Implementation

### 4.1. Overview

This code extends a `BULLETPROOF_IPA_PCS` for the final dot‐product argument, reusing the bulletproof style.  
- **`Hyrax_PCS.commit`**: Splits the polynomial’s coefficient vector into rows, commits each row with a random scalar.  
- **`prove_evaluation`** / **`verify_evaluation`**: Splits $\mathbf{u}$ into $(\mathbf{u}_L, \mathbf{u}_R)$, builds the partial multilinear eq vectors, folds one dimension, then calls an IPA method.

### 4.2. Pros & Cons

**Pros**  
- Very **readable**, clearly demonstrates how row $\times$ col dimension is used.  
- Great for **educational** or **prototyping** purposes.

**Cons**  
- We are using it purely as a reference.  
- Not using advancing param structures, just for small demos, which is fine for educational purposes though.

---

## 5. Comparative Summary

| **Aspect**                 | **Arkworks**                            | **Hadasz**                                     | **Python Reference**                                    |
|----------------------------|-----------------------------------------|------------------------------------------------|---------------------------------------------------------|
| **Language**              | Rust (Arkworks ecosystem)               | Rust (uses `MultilinearIpa`)                   | Python (research code)                                  |
| **Commit Structure**       | `HyraxCommitment { row_coms: Vec<G> }`  | `MultilinearHyraxCommitment(Vec<C>)`           | Plain `list[G1]` + `list[Field]` blinders               |
| **Dot‐Product Proof**      | Coded explicitly in `open`              | Delegated to `MultilinearIpa::open`            | Delegated to a bulletproof‐IPA library (`ipa.py`)       |
| **Flexibility**            | Requires even $n$                       | More general `div_ceil` approach               | Also expects power‐of‐2 size, but simpler to tweak      |
| **Performance**            | Production‐grade, parallel MSM in Arkworks  | Also parallel MSM (`variable_base_msm`)        | Python overhead, not optimized for speed                |
| **Security**              | Well‐typed, considered secure in Rust   | Also Rust, presumably can be production quality | Research code only     |
| **Pros**                   | Straightforward trait usage, explicit   | Modular design, good batch handling            | Excellent educational clarity                           |
| **Cons**                   | No partial dimension for odd $n$        | Dot‐product logic is hidden in separate module | Not suitable for real production                        |

---

## 6. Concluding Remarks

All three implementations follow the **same core** Hyrax design:

1. **Row commits** to a matrix of polynomial evaluations.  
2. **Partial fold** in one dimension using a vector derived from half the evaluation point $\mathbf{u}$.  
3. **Dot‐product argument** to prove the final evaluation matches the claimed value.

They differ mainly in **where** and **how** the argument is performed, **how** the code is structured (traits vs. direct calls), and **which** language ecosystem they integrate with.

- **Arkworks** is robust, with well‐structured Rust traits and a transparent Hyrax “open” procedure.  
- **Hadasz** offers a **modular** approach, letting `MultilinearIpa` handle the final proof. It may be more flexible with dimension splits (not strictly even).  
- **The Python code** stands out as an **educational reference**, demonstrating each step in a straightforward way, but it is explicitly **not** production‐grade.

**Recommendation**: For a secure, production environment in Rust, **Arkworks** is a strong choice if our dimension constraints are compatible. For custom or more flexible usage in Rust, **Hadasz**’s approach might be more adaptable. For learning or prototyping, the **Python reference** is an excellent demonstration of the Hyrax method.
