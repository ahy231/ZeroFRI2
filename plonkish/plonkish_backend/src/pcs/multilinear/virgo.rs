use crate::{
    Error,
    pcs::{Point, PolynomialCommitmentScheme, Evaluation},
    poly::{multilinear::MultilinearPolynomial, Polynomial},
    util::{
        algebra::{
            coset::Coset,
            field::MyField,
            CODE_RATE,
        },
        merkle_tree::{MerkleTreeProver, MerkleTreeVerifier, MERKLE_ROOT_SIZE},
        query_result::QueryResult,
        transcript::{TranscriptRead, TranscriptWrite},
    },
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, marker::PhantomData, iter, mem};

// ----------------------------------------------------------------
// Extension trait for MultilinearPolynomial needed by Virgo
// ----------------------------------------------------------------

impl<T: MyField + ff::Field> MultilinearPolynomial<T> {
    
    pub fn coefficients(&self) -> Vec<T> {
        self.evals().to_vec()
    }
    /// A helper method returning the polynomial’s degree.
    /// For a multilinear polynomial (degree ≤ 1 in each variable),
    /// we define degree = (1 << num_vars()) - 1.
    pub fn degree(&self) -> usize {
        (1 << self.num_vars()) - 1
    }
    /// Evaluate the polynomial at a given point.
    /// (For simplicity we assume the point is binary—adjust as needed.)
    pub fn evaluate_poly(&self, point: &[T]) -> T {
        // Interpret the point as bits: if an entry equals T::from_int(1), treat that bit as 1.
        let mut idx = 0;
        for (i, &val) in point.iter().enumerate() {
            if val == T::from_int(1) {
                idx |= 1 << i;
            }
        }
        self.evals()[idx]
    }
}

// Helper: Multiply two multilinear polynomials (placeholder)
fn mult_poly<T: MyField + ff::Field>(p1: &MultilinearPolynomial<T>, p2: &MultilinearPolynomial<T>) -> MultilinearPolynomial<T> {
    // For example, perform pointwise multiplication of evaluations.
    let evals: Vec<T> = p1.evals().iter().zip(p2.evals().iter()).map(|(a, b)| *a * *b).collect();
    MultilinearPolynomial::new(evals)
}

// ----------------------------------------------------------------
// Helper: Hash a proof into a fixed–size commitment.
fn hash_proof<T: MyField + serde::Serialize>(proof: &VirgoProof<T>) -> [u8; MERKLE_ROOT_SIZE] {
    let bytes = bincode::serialize(proof).expect("Proof serialization should work");
    let hash = Sha256::digest(&bytes);
    let mut arr = [0u8; MERKLE_ROOT_SIZE];
    arr.copy_from_slice(&hash[..MERKLE_ROOT_SIZE]);
    arr
}

// ----------------------------------------------------------------
// Extension trait for “over_vanish_polynomial”
// ----------------------------------------------------------------

pub trait VirgoPolyExt<T: MyField>: Sized {
    fn over_vanish_polynomial(self, vanish: &crate::util::algebra::polynomial::VanishingPolynomial<T>) -> Self;
}
impl<T: MyField> VirgoPolyExt<T> for MultilinearPolynomial<T> {
    fn over_vanish_polynomial(self, _vanish: &crate::util::algebra::polynomial::VanishingPolynomial<T>) -> Self {
        // Placeholder: return self.
        self
    }
}

// ----------------------------------------------------------------
// Virgo Commitment and Proof Types
// ----------------------------------------------------------------

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VirgoParams<T: MyField> {
    pub total_round: usize,
    pub fri_cosets: Vec<Coset<T>>,
    pub vector_interpolation_coset: Coset<T>,
    pub step: usize,
}
pub type VirgoProverParam<T> = VirgoParams<T>;
pub type VirgoVerifierParam<T> = VirgoParams<T>;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct VirgoCommitment<T: MyField> {
    pub u_root: [u8; MERKLE_ROOT_SIZE],
    #[serde(skip)]
    pub _marker: PhantomData<T>,
}

impl<T: MyField> AsRef<[[u8; MERKLE_ROOT_SIZE]]> for VirgoCommitment<T> {
    fn as_ref(&self) -> &[[u8; MERKLE_ROOT_SIZE]] {
        std::slice::from_ref(&self.u_root)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VirgoProof<T: MyField> {
    pub folding_proofs: Vec<QueryResult<T>>,
    pub function_proofs: Vec<QueryResult<T>>,
    pub v_values: HashMap<usize, T>,
}

// ----------------------------------------------------------------
// Internal Helper: InterpolateValue
// ----------------------------------------------------------------

#[derive(Clone)]
struct InterpolateValue<T: MyField> {
    value: Vec<T>,
    leaf_size: usize,
    merkle_tree: MerkleTreeProver,
}

impl<T: MyField> InterpolateValue<T> {
    fn new(value: Vec<T>, leaf_size: usize) -> Self {
        let len = value.len() / leaf_size;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| {
                    crate::util::algebra::field::as_bytes_vec(
                        &(0..leaf_size)
                            .map(|j| value[i + len * j])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect(),
        );
        Self { value, leaf_size, merkle_tree }
    }

    fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.commit()
    }

    fn query(&self, leaf_indices: &Vec<usize>) -> QueryResult<T> {
        let len = self.merkle_tree.leave_num();
        assert_eq!(len * self.leaf_size, self.value.len());
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j| {
                (0..self.leaf_size)
                    .map(|i| (j + len * i, self.value[j + len * i]))
                    .collect::<Vec<_>>()
            })
            .collect();
        let proof_bytes = self.merkle_tree.open(leaf_indices);
        QueryResult { proof_bytes, proof_values }
    }
}

// ----------------------------------------------------------------
// Virgo Prover Implementation
// ----------------------------------------------------------------

pub struct VirgoProver<T: MyField> {
    total_round: usize,
    vector_interpolation_coset: Coset<T>,
    fri_cosets: Vec<Coset<T>>,
    function_h: Option<InterpolateValue<T>>,
    function_u: InterpolateValue<T>,
    interpolation_v: Option<Vec<T>>,
    poly_u: MultilinearPolynomial<T>,
    polynomial: MultilinearPolynomial<T>,
    foldings: Vec<InterpolateValue<T>>,
    evaluation: Option<T>,
    final_poly: Option<MultilinearPolynomial<T>>,
    step: usize,
}

impl<T: MyField+ ff::Field> VirgoProver<T> {
    pub fn new(
        total_round: usize,
        fri_cosets: &Vec<Coset<T>>,
        vector_interpolation_coset: &Coset<T>,
        polynomial: MultilinearPolynomial<T>,
        step: usize,
    ) -> Self {
        assert_eq!(vector_interpolation_coset.size(), 1 << polynomial.num_vars());
        let interpolation = vector_interpolation_coset.ifft(polynomial.coefficients());
        Self {
            total_round,
            vector_interpolation_coset: vector_interpolation_coset.clone(),
            fri_cosets: fri_cosets.clone(),
            function_h: None,
            function_u: InterpolateValue::new(fri_cosets[0].fft(interpolation.clone()), 1 << step),
            interpolation_v: None,
            poly_u: MultilinearPolynomial::new(interpolation.clone()),
            polynomial,
            foldings: vec![],
            evaluation: None,
            final_poly: None,
            step,
        }
    }

    pub fn commit_first_polynomial(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.function_u.commit()
    }

    pub fn commit_functions(
        &mut self,
        verifier: &mut VirgoVerifier<T>,
        open_point: &Vec<T>,
        transcript: &mut impl TranscriptWrite<[u8; MERKLE_ROOT_SIZE], T>,
    ) {
        assert_eq!(open_point.len(), self.total_round);
        let mut public_vector = vec![T::from_int(1)];
        for i in open_point {
            let len = public_vector.len();
            for j in 0..len {
                public_vector.push(public_vector[j] * i.clone());
            }
        }
        let poly_v = MultilinearPolynomial::new(self.vector_interpolation_coset.ifft(public_vector));
        assert!(poly_v.degree() < self.vector_interpolation_coset.size());
        // Multiply poly_u and poly_v and then “divide” by the vanishing polynomial.
        let h = mult_poly(&self.poly_u, &poly_v)
            .over_vanish_polynomial(&crate::util::algebra::polynomial::VanishingPolynomial::new(&self.vector_interpolation_coset));
        assert!(h.degree() < self.vector_interpolation_coset.size());
        let function_h = InterpolateValue::new(self.fri_cosets[0].fft(h.coefficients()), 1 << self.step);
        verifier.set_h_root(function_h.commit());
        self.function_h = Some(function_h);
        self.interpolation_v = Some(self.fri_cosets[0].fft(poly_v.coefficients()));
        let evaluation = self.polynomial.evaluate_poly(open_point);
        self.evaluation = Some(evaluation);
        verifier.set_evaluation(evaluation);
    }

    pub fn commit_foldings(&self, verifier: &mut VirgoVerifier<T>) {
        for folding in &self.foldings {
            verifier.receive_folding_root(folding.leave_num(), folding.commit());
        }
        verifier.set_final_poly(self.final_poly.clone().unwrap());
    }

    fn initial_interpolation(&self) -> Vec<T> {
        let rlc = self.oracle_rlc();
        let u = &self.function_u.value;
        let h = &self.function_h.as_ref().unwrap().value;
        let mut res = u.clone();
        let mut acc = rlc;
        for i in 0..self.fri_cosets[0].size() {
            res[i] = res[i] + acc * h[i];
        }
        acc = acc * rlc;
        let vanish_size = T::from_int(self.vector_interpolation_coset.size() as u64);
        let v = self.interpolation_v.as_ref().unwrap();
        for i in 0..self.fri_cosets[0].size() {
            let x = self.fri_cosets[0].element_at(i);
            let x_inv = self.fri_cosets[0].element_inv_at(i);
            let vanish = crate::util::algebra::polynomial::VanishingPolynomial::new(&self.vector_interpolation_coset).evaluation_at(x);
            res[i] = res[i] + acc * (u[i] * v[i] * vanish_size - vanish * h[i] * vanish_size - self.evaluation.unwrap()) * x_inv;
        }
        res
    }

    fn oracle_rlc(&self) -> T {
        T::from_int(1)
    }

    fn evaluation_next_domain(&self, round: usize, challenge: Vec<T>) -> Vec<T> {
        if round == 0 {
            let mut function = self.initial_interpolation();
            for j in 0..self.step {
                let mut tmp = vec![];
                let coset = &self.fri_cosets[round * self.step + j];
                let len = coset.size();
                for i in 0..(len / 2) {
                    let x = function[i];
                    let nx = function[i + len / 2];
                    let new_val = (x + nx) + challenge[j] * (x - nx) * coset.element_inv_at(i);
                    tmp.push(new_val);
                }
                function = tmp;
            }
            function
        } else {
            let mut last = self.foldings.last().unwrap().value.clone();
            for j in 0..self.step {
                let mut tmp = vec![];
                let coset = &self.fri_cosets[round * self.step + j];
                let len = coset.size();
                for i in 0..(len / 2) {
                    let x = last[i];
                    let nx = last[i + len / 2];
                    let new_val = (x + nx) + challenge[j] * (x - nx) * coset.element_inv_at(i);
                    tmp.push(new_val);
                }
                last = tmp;
            }
            last
        }
    }

    pub fn prove(&mut self, transcript: &mut impl TranscriptWrite<[u8; MERKLE_ROOT_SIZE], T>) {
        for i in 0..(self.total_round / self.step) {
            let mut challenge = vec![];
            for _ in 0..self.step {
                challenge.push(transcript.squeeze_challenge());
            }
            let next_eval = self.evaluation_next_domain(i, challenge);
            let folding = InterpolateValue::new(next_eval.clone(), 1 << self.step);
            self.foldings.push(folding);
            if i == self.total_round / self.step - 1 {
                self.final_poly = Some(MultilinearPolynomial::new(
                    self.fri_cosets[(i + 1) * self.step].ifft(next_eval),
                ));
            }
        }
    }

    pub fn query(&self) -> (Vec<QueryResult<T>>, Vec<QueryResult<T>>, HashMap<usize, T>) {
        let mut folding_results = vec![];
        let mut function_results = None;
        let mut leaf_indices = self.oracle_query_list();
        let leaf_size = 1 << self.step;
        let mut v_value = HashMap::new();

        for i in 0..(self.total_round / self.step) {
            let len = self.fri_cosets[i * self.step].size() / (1 << self.step);
            leaf_indices = leaf_indices.iter().map(|v| v % len).collect();
            leaf_indices.sort();
            leaf_indices.dedup();
            if i == 0 {
                function_results = Some(vec![
                    self.function_u.query(&leaf_indices),
                    self.function_h.as_ref().unwrap().query(&leaf_indices),
                ]);
                if let Some(interpolation_v) = &self.interpolation_v {
                    for j in &leaf_indices {
                        for k in 0..leaf_size {
                            v_value.insert(j + k * len, interpolation_v[j + k * len]);
                        }
                    }
                }
            } else {
                let qr = self.foldings[i - 1].query(&leaf_indices);
                folding_results.push(qr);
            }
        }
        (folding_results, function_results.unwrap(), v_value)
    }

    fn oracle_query_list(&self) -> Vec<usize> {
        vec![0]
    }
}

// ----------------------------------------------------------------
// Virgo Verifier Implementation
// ----------------------------------------------------------------

pub struct VirgoVerifier<T: MyField> {
    total_round: usize,
    interpolate_cosets: Vec<Coset<T>>,
    vector_interpolation_coset: Coset<T>,
    u_root: MerkleTreeVerifier,
    h_root: Option<MerkleTreeVerifier>,
    folding_roots: Vec<MerkleTreeVerifier>,
    vanishing_polynomial: crate::util::algebra::polynomial::VanishingPolynomial<T>,
    final_poly: Option<MultilinearPolynomial<T>>,
    evaluation: Option<T>,
    open_point: Option<Vec<T>>,
    step: usize,
}

impl<T: MyField + ff::Field> VirgoVerifier<T> {
    pub fn new(
        total_round: usize,
        cosets: &Vec<Coset<T>>,
        vector_interpolation_coset: &Coset<T>,
        u_commitment: [u8; MERKLE_ROOT_SIZE],
        step: usize,
    ) -> Self {
        VirgoVerifier {
            total_round,
            interpolate_cosets: cosets.clone(),
            vector_interpolation_coset: vector_interpolation_coset.clone(),
            u_root: MerkleTreeVerifier {
                leave_number: cosets[0].size() / (1 << step),
                merkle_root: u_commitment,
            },
            h_root: None,
            folding_roots: vec![],
            vanishing_polynomial: crate::util::algebra::polynomial::VanishingPolynomial::new(vector_interpolation_coset),
            final_poly: None,
            evaluation: None,
            open_point: None,
            step,
        }
    }

    pub fn set_evaluation(&mut self, v: T) {
        self.evaluation = Some(v);
    }

    pub fn get_open_point(&mut self) -> Vec<T> {
        let pts: Vec<T> = (0..self.total_round).map(|_| T::random_element()).collect();
        self.open_point = Some(pts.clone());
        pts
    }

    pub fn set_h_root(&mut self, h_root: [u8; MERKLE_ROOT_SIZE]) {
        self.h_root = Some(MerkleTreeVerifier {
            merkle_root: h_root,
            leave_number: self.interpolate_cosets[0].size() / (1 << self.step),
        });
    }

    pub fn receive_folding_root(&mut self, leave_number: usize, folding_root: [u8; MERKLE_ROOT_SIZE]) {
        self.folding_roots.push(MerkleTreeVerifier { leave_number, merkle_root: folding_root });
    }

    pub fn set_final_poly(&mut self, poly: MultilinearPolynomial<T>) {
        self.final_poly = Some(poly);
    }

    pub fn verify(
        &self,
        folding_proofs: &Vec<QueryResult<T>>,
        v_values: &HashMap<usize, T>,
        function_proofs: &Vec<QueryResult<T>>,
        transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>,
    ) -> bool {
        let mut leaf_indices = self.oracle_query_list();
        let rlc = self.oracle_rlc();
        let vanish_size = T::from_int(self.vector_interpolation_coset.size() as u64);
        for i in 0..(self.total_round / self.step) {
            let len = self.interpolate_cosets[i * self.step].size() / (1 << self.step);
            leaf_indices = leaf_indices.iter().map(|v| v % len).collect();
            leaf_indices.sort();
            leaf_indices.dedup();
            if i == 0 {
                assert!(function_proofs[0].verify_merkle_tree(&leaf_indices, 1 << self.step, &self.u_root));
                assert!(function_proofs[1].verify_merkle_tree(&leaf_indices, 1 << self.step, &self.h_root.as_ref().unwrap()));
            } else {
                folding_proofs[i - 1].verify_merkle_tree(&leaf_indices, 1 << self.step, &self.folding_roots[i - 1]);
            }
            let get_folding_value = |index: &usize| {
                if i == 0 {
                    let u = function_proofs[0].proof_values[index];
                    let h = function_proofs[1].proof_values[index];
                    let v = v_values.get(index).unwrap();
                    let x = self.interpolate_cosets[i * self.step].element_at(*index);
                    let x_inv = self.interpolate_cosets[i * self.step].element_inv_at(*index);
                    let mut res = u;
                    let mut acc = rlc;
                    res = res + h * acc;
                    acc = acc * rlc;
                    res = res + acc * (u * (*v) * vanish_size - self.vanishing_polynomial.evaluation_at(x) * h * vanish_size - self.evaluation.unwrap()) * x_inv;
                    res
                } else {
                    folding_proofs[i - 1].proof_values[index]
                }
            };
            for k in &leaf_indices {
                let mut verify_values = vec![];
                let mut verify_inds = vec![];
                for j in 0..(1 << self.step) {
                    let ind = k + j * len;
                    verify_values.push(get_folding_value(&ind));
                    verify_inds.push(ind);
                }
                for j in 0..self.step {
                    let challenge = self.oracle_folding_challenge(i * self.step + j);
                    let size = verify_values.len();
                    let mut tmp = vec![];
                    let mut tmp_inds = vec![];
                    for l in 0..(size / 2) {
                        let x = verify_values[l];
                        let nx = verify_values[l + size/2];
                        tmp.push(x + nx + challenge * (x - nx) * self.interpolate_cosets[i * self.step + j].element_inv_at(verify_inds[l]));
                        tmp_inds.push(verify_inds[l]);
                    }
                    verify_values = tmp;
                    verify_inds = tmp_inds;
                }
                assert_eq!(verify_values.len(), 1);
                let v_val = verify_values[0];
                if i < self.total_round / self.step - 1 {
                    if v_val != folding_proofs[i].proof_values[k] {
                        return false;
                    }
                } else {
                    let point = self.interpolate_cosets[(i + 1) * self.step].element_at(*k);
                    if v_val != self.final_poly.as_ref().unwrap().evaluate_poly(&[point]) {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn oracle_rlc(&self) -> T {
        T::from_int(1)
    }
    fn oracle_folding_challenge(&self, _idx: usize) -> T {
        T::from_int(1)
    }
    fn oracle_query_list(&self) -> Vec<usize> {
        vec![0]
    }
}

// ----------------------------------------------------------------
// Virgo PCS Trait Implementation
// ----------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Virgo<T: MyField>(PhantomData<T>);

impl<T: MyField + ff::Field + Default + serde::Serialize + for<'de> serde::Deserialize<'de>>
    PolynomialCommitmentScheme<T> for Virgo<T>
{
    type Param = VirgoParams<T>;
    type ProverParam = VirgoProverParam<T>;
    type VerifierParam = VirgoVerifierParam<T>;
    type Polynomial = MultilinearPolynomial<T>;
    type Commitment = VirgoCommitment<T>;
    type CommitmentChunk = [u8; MERKLE_ROOT_SIZE];

    fn setup(poly_size: usize, _batch_size: usize, _rng: impl RngCore) -> Result<Self::Param, Error> {
        let total_round = poly_size;
        let first_coset = Coset::new(1 << (poly_size + CODE_RATE), T::from_int(1));
        let mut fri_cosets = vec![first_coset];
        for i in 1..=poly_size {
            let next = fri_cosets[i - 1].pow(2);
            fri_cosets.push(next);
        }
        let vector_interpolation_coset = Coset::new(1 << poly_size, T::from_int(1));
        let step = 1;
        Ok(VirgoParams { total_round, fri_cosets, vector_interpolation_coset, step })
    }

    fn trim(param: &Self::Param, _poly_size: usize, _batch_size: usize) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        Ok((param.clone(), param.clone()))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        let prover = VirgoProver::new(pp.total_round, &pp.fri_cosets, &pp.vector_interpolation_coset, poly.clone(), pp.step);
        Ok(VirgoCommitment { u_root: prover.commit_first_polynomial(), _marker: PhantomData })
    }

    fn batch_commit<'a>(pp: &Self::ProverParam, polys: impl IntoIterator<Item = &'a Self::Polynomial>) -> Result<Vec<Self::Commitment>, Error> {
        polys.into_iter().map(|poly| Self::commit(pp, poly)).collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        _comm: &Self::Commitment,
        point: &Point<T, Self::Polynomial>,
        _eval: &T,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, T>,
    ) -> Result<(), Error> {
        let mut prover = VirgoProver::new(pp.total_round, &pp.fri_cosets, &pp.vector_interpolation_coset, poly.clone(), pp.step);
        transcript.write_commitment(&prover.commit_first_polynomial())?;
        prover.prove(transcript);
        // Instead of writing an entire serialized proof, we hash the proof to obtain a fixed–size commitment.
        let (_folding, function, v_map) = prover.query();
        let proof = VirgoProof { folding_proofs: _folding, function_proofs: function, v_values: v_map };
        let proof_comm = hash_proof(&proof);
        transcript.write_commitment(&proof_comm)?;
        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        _comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<T, Self::Polynomial>],
        evals: &[Evaluation<T>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, T>,
    ) -> Result<(), Error> {
        for (poly, _comm, point, eval) in itertools::izip!(polys, _comms, points, evals) {
            Self::open(pp, poly, _comm, point, &eval.value, transcript)?;
        }
        Ok(())
    }

    fn read_commitments(_vp: &Self::VerifierParam, num_polys: usize, transcript: &mut impl TranscriptRead<Self::CommitmentChunk, T>) -> Result<Vec<Self::Commitment>, Error> {
        transcript.read_commitments(num_polys).map(|roots| {
            roots.into_iter()
                .map(|root| VirgoCommitment { u_root: root, _marker: PhantomData })
                .collect()
        })
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<T, Self::Polynomial>,
        _eval: &T,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, T>,
    ) -> Result<(), Error> {
        let mut verifier = VirgoVerifier::new(vp.total_round, &vp.fri_cosets, &vp.vector_interpolation_coset, comm.u_root, vp.step);
        let proof_comm = transcript.read_commitment()?;
        let proof: VirgoProof<T> = bincode::deserialize(&proof_comm)
            .map_err(|e| Error::VerificationError(e.to_string()))?;
        if verifier.verify(&proof.folding_proofs, &proof.v_values, &proof.function_proofs, transcript) {
            Ok(())
        } else {
            Err(Error::VerificationError("Virgo verification failed".to_string()))
        }
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<T, Self::Polynomial>],
        evals: &[Evaluation<T>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, T>,
    ) -> Result<(), Error> {
        for (comm, point) in comms.into_iter().zip(points) {
            Self::verify(vp, comm, point, &T::from_int(1), transcript)?;
        }
        Ok(())
    }
}

fn read_proof<T: MyField + serde::de::DeserializeOwned>(transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>) -> Result<VirgoProof<T>, Error> {
    let comm = transcript.read_commitment()?;
    let proof: VirgoProof<T> = bincode::deserialize(&comm)
        .map_err(|e| Error::VerificationError(e.to_string()))?;
    Ok(proof)
}
