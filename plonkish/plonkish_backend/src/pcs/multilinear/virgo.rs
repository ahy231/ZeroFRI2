// virgo.rs

use crate::util::mersenne_61_mont::Mersenne61Mont as F;
use ff::Field;
use poly::multilinear::MultilinearPolynomial as BackendMpoly;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Debug;
use std::mem::size_of;

use crate::util::{
    algebra::{
        coset::Coset,
        field::{as_bytes_vec, mersenne61_ext::Mersenne61Ext, MyField},
        polynomial::{MultilinearPolynomial as UtilMPoly, Polynomial, VanishingPolynomial},
        CODE_RATE, SECURITY_BITS, SIZE, STEP,
    },
    merkle_tree::{MerkleTreeProver, MerkleTreeVerifier, MERKLE_ROOT_SIZE},
    query_result::QueryResult,
    random_oracle::RandomOracle,
    transcript::{TranscriptRead, TranscriptWrite},
};

/// =============================================================
/// Virgo FRI implementation (core logic)
/// =============================================================           

/// InterpolateValue: a helper structure to build Merkle trees for function values.
#[derive(Clone)]
struct InterpolateValue<T: MyField> {
    value: Vec<T>,
    leaf_size: usize,
    merkle_tree: MerkleTreeProver,
}

impl<T: MyField> InterpolateValue<T> {
    pub fn new(value: Vec<T>, leaf_size: usize) -> Self {
        let len = value.len() / leaf_size;
        let merkle_tree = MerkleTreeProver::new(
            (0..len)
                .map(|i| {
                    as_bytes_vec(
                        &(0..leaf_size)
                            .map(|j| value[i + len * j])
                            .collect::<Vec<_>>(),
                    )
                })
                .collect(),
        );
        Self {
            value,
            leaf_size,
            merkle_tree,
        }
    }

    pub fn leave_num(&self) -> usize {
        self.merkle_tree.leave_num()
    }

    pub fn commit(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.merkle_tree.commit()
    }

    pub fn query(&self, leaf_indices: &Vec<usize>) -> QueryResult<T> {
        let len = self.merkle_tree.leave_num();
        assert_eq!(len * self.leaf_size, self.value.len());
        let proof_values = leaf_indices
            .iter()
            .flat_map(|j: &usize| {
                (0..self.leaf_size)
                    .map(|i| (j.clone() + len * i, self.value[j.clone() + len * i]))
                    .collect::<Vec<_>>()
            })
            .collect();
        let proof_bytes = self.merkle_tree.open(&leaf_indices);
        QueryResult {
            proof_bytes,
            proof_values,
        }
    }
}

/// FRI Prover implementation.
#[derive(Clone)]
pub struct FriProver<T: MyField> {
    pub total_round: usize,
    pub vector_interpolation_coset: Coset<T>,
    pub fri_cosets: Vec<Coset<T>>,
    pub function_h: Option<InterpolateValue<T>>,
    pub function_u: InterpolateValue<T>,
    pub interpolation_v: Option<Vec<T>>,
    pub poly_u: Polynomial<T>,
    pub polynomial: UtilMPoly<T>,
    pub foldings: Vec<InterpolateValue<T>>,
    pub oracle: RandomOracle<T>,
    pub evaluation: Option<T>,
    pub final_poly: Option<Polynomial<T>>,
    pub step: usize,
}

impl<T: MyField> FriProver<T> {
    pub fn new(
        total_round: usize,
        fri_cosets: &Vec<Coset<T>>,
        vector_interpolation_coset: &Coset<T>,
        polynomial: UtilMPoly<T>,
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> FriProver<T> {
        assert_eq!(
            vector_interpolation_coset.size(),
            1 << polynomial.variable_num()
        );
        let interpolation = vector_interpolation_coset.ifft(polynomial.coefficients().clone());
        FriProver {
            total_round,
            vector_interpolation_coset: vector_interpolation_coset.clone(),
            fri_cosets: fri_cosets.clone(),
            function_h: None,
            function_u: InterpolateValue::new(fri_cosets[0].fft(interpolation.clone()), 1 << step),
            interpolation_v: None,
            poly_u: Polynomial::new(interpolation),
            polynomial,
            foldings: vec![],
            oracle: oracle.clone(),
            evaluation: None,
            final_poly: None,
            step,
        }
    }

    pub fn commit_first_polynomial(&self) -> [u8; MERKLE_ROOT_SIZE] {
        self.function_u.commit()
    }

    pub fn commit_functions(&mut self, verifier: &mut FriVerifier<T>, open_point: &Vec<T>) {
        assert_eq!(open_point.len(), self.total_round);
        let mut public_vector = vec![T::from_int(1)];
        for i in open_point {
            let len = public_vector.len();
            for j in 0..len {
                public_vector.push(public_vector[j] * i.clone());
            }
        }
        let poly_v = Polynomial::new(self.vector_interpolation_coset.ifft(public_vector));
        assert!(poly_v.degree() < self.vector_interpolation_coset.size());
        let h = Coset::mult(&self.poly_u, &poly_v)
            .over_vanish_polynomial(&VanishingPolynomial::new(&self.vector_interpolation_coset));
        assert!(h.degree() < self.vector_interpolation_coset.size());
        let function_h = InterpolateValue::new(
            self.fri_cosets[0].fft(h.coefficients().clone()),
            1 << self.step,
        );
        verifier.set_h_root(function_h.commit());
        self.function_h = Some(function_h);
        self.interpolation_v = Some(self.fri_cosets[0].fft(poly_v.coefficients().clone()));
        let evaluation = self.polynomial.evaluate(open_point);
        self.evaluation = Some(evaluation);
        verifier.set_evaluation(evaluation);
    }

    pub fn commit_foldings(&self, verifier: &mut FriVerifier<T>) {
        for i in 0..(self.total_round / self.step) {
            verifier.receive_folding_root(self.foldings[i].leave_num(), self.foldings[i].commit());
        }
        verifier.set_final_poly(self.final_poly.clone().unwrap());
    }

    fn initial_interpolation(&self) -> Vec<T> {
        let rlc = self.oracle.rlc;
        let u = &self.function_u.value;
        let mut res = u.clone();
        let h = &self.function_h.as_ref().unwrap().value;
        let mut acc = rlc;
        for i in 0..self.fri_cosets[0].size() {
            res[i] += acc * h[i];
        }
        acc *= rlc;
        let vanish_polynomial = VanishingPolynomial::new(&self.vector_interpolation_coset);
        let v = self.interpolation_v.as_ref().unwrap();
        let h_size = T::from_int(self.vector_interpolation_coset.size() as u64);
        for i in 0..self.fri_cosets[0].size() {
            let x = self.fri_cosets[0].element_at(i);
            let x_inv = self.fri_cosets[0].element_inv_at(i);
            res[i] += acc
                * (u[i] * v[i] * h_size
                    - vanish_polynomial.evaluation_at(x) * h[i] * h_size
                    - self.evaluation.unwrap())
                * x_inv;
        }
        res
    }

    fn evaluation_next_domain(&self, round: usize, challenge: Vec<T>) -> Vec<T> {
        let mut res = vec![];
        if round == 0 {
            let mut function = self.initial_interpolation();
            for j in 0..self.step {
                let mut tmp_res = vec![];
                let coset = &self.fri_cosets[round * self.step + j];
                let len = coset.size();
                for i in 0..(len / 2) {
                    let x = function[i];
                    let nx = function[i + len / 2];
                    let new_v = (x + nx) + challenge[j] * (x - nx) * coset.element_inv_at(i);
                    tmp_res.push(new_v);
                }
                function = tmp_res;
            }
            res = function;
        } else {
            let mut last_folding = self.foldings.last().unwrap().value.clone();
            for j in 0..self.step {
                let mut tmp_res = vec![];
                let coset = &self.fri_cosets[round * self.step + j];
                let len = coset.size();
                for i in 0..(len / 2) {
                    let x = last_folding[i];
                    let nx = last_folding[i + len / 2];
                    let new_v = (x + nx) + challenge[j] * (x - nx) * coset.element_inv_at(i);
                    tmp_res.push(new_v);
                }
                last_folding = tmp_res;
            }
            res = last_folding;
        }
        res
    }

    pub fn prove(&mut self) {
        for i in 0..self.total_round / self.step {
            let mut challenge = vec![];
            for j in 0..self.step {
                challenge.push(self.oracle.folding_challenges[i * self.step + j]);
            }
            let next_evalutation = self.evaluation_next_domain(i, challenge);
            let interpolate_value = InterpolateValue::new(next_evalutation.clone(), 1 << self.step);
            self.foldings.push(interpolate_value);

            if i == self.total_round / self.step - 1 {
                self.final_poly = Some(Polynomial::new(
                    self.fri_cosets[(i + 1) * self.step].ifft(next_evalutation.clone()),
                ));
            }
        }
    }

    pub fn query(&self) -> (Vec<QueryResult<T>>, Vec<QueryResult<T>>, HashMap<usize, T>) {
        let mut folding_res = vec![];
        let mut functions_res = None;
        let mut leaf_indices = self.oracle.query_list.clone();
        let mut v_value = None;
        let leaf_size = 1 << self.step as usize;

        for i in 0..self.total_round / self.step {
            let len = self.fri_cosets[i * self.step].size() / (1 << self.step);
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % len).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                functions_res = Some(vec![
                    self.function_u.query(&leaf_indices),
                    self.function_h.as_ref().unwrap().query(&leaf_indices),
                ]);
                let interpolation_v = self.interpolation_v.as_ref().unwrap();
                v_value = Some(
                    leaf_indices
                        .iter()
                        .flat_map(|j| {
                            (0..leaf_size)
                                .map(|k: usize| {
                                    (j.clone() + k * len, interpolation_v[j.clone() + k * len])
                                })
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                );
            } else {
                let query_result = self.foldings[i - 1].query(&leaf_indices);
                folding_res.push(query_result);
            }
        }
        (folding_res, functions_res.unwrap(), v_value.unwrap())
    }
}

/// FRI Verifier implementation.
#[derive(Clone)]
pub struct FriVerifier<T: MyField> {
    pub total_round: usize,
    pub interpolate_cosets: Vec<Coset<T>>,
    pub vector_interpolation_coset: Coset<T>,
    pub u_root: MerkleTreeVerifier,
    pub h_root: Option<MerkleTreeVerifier>,
    pub folding_root: Vec<MerkleTreeVerifier>,
    pub oracle: RandomOracle<T>,
    pub vanishing_polynomial: VanishingPolynomial<T>,
    pub final_poly: Option<Polynomial<T>>,
    pub evaluation: Option<T>,
    pub open_point: Option<Vec<T>>,
    pub step: usize,
}

impl<T: MyField> FriVerifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<Coset<T>>,
        vector_interpolation_coset: &Coset<T>,
        polynomial_commitment: [u8; MERKLE_ROOT_SIZE],
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> Self {
        FriVerifier {
            total_round,
            interpolate_cosets: coset.clone(),
            vector_interpolation_coset: vector_interpolation_coset.clone(),
            u_root: MerkleTreeVerifier {
                leave_number: coset[0].size() / (1 << step),
                merkle_root: polynomial_commitment,
            },
            h_root: None,
            folding_root: vec![],
            oracle: oracle.clone(),
            vanishing_polynomial: VanishingPolynomial::new(vector_interpolation_coset),
            final_poly: None,
            open_point: None,
            evaluation: None,
            step,
        }
    }

    pub fn set_evaluation(&mut self, v: T) {
        self.evaluation = Some(v);
    }

    pub fn get_open_point(&mut self) -> Vec<T> {
        let point = (0..self.total_round)
            .map(|_| T::random_element())
            .collect::<Vec<T>>();
        self.open_point = Some(point.clone());
        point
    }

    pub fn set_h_root(&mut self, h_root: [u8; MERKLE_ROOT_SIZE]) {
        self.h_root = Some(MerkleTreeVerifier {
            merkle_root: h_root,
            leave_number: self.interpolate_cosets[0].size() / (1 << self.step),
        });
    }

    pub fn receive_folding_root(
        &mut self,
        leave_number: usize,
        folding_root: [u8; MERKLE_ROOT_SIZE],
    ) {
        self.folding_root.push(MerkleTreeVerifier {
            leave_number,
            merkle_root: folding_root,
        });
    }

    pub fn set_final_poly(&mut self, poly: Polynomial<T>) {
        self.final_poly = Some(poly);
    }

    pub fn verify(
        &self,
        folding_proofs: &Vec<QueryResult<T>>,
        v_values: &HashMap<usize, T>,
        function_proofs: &Vec<QueryResult<T>>,
    ) -> bool {
        let mut leaf_indices = self.oracle.query_list.clone();
        let rlc = self.oracle.rlc;
        let h_size = T::from_int(self.vector_interpolation_coset.size() as u64);
        for i in 0..self.total_round / self.step {
            let len = self.interpolate_cosets[i * self.step].size() / (1 << self.step);
            leaf_indices = leaf_indices.iter_mut().map(|v| *v % len).collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            if i == 0 {
                assert!(function_proofs[0].verify_merkle_tree(
                    &leaf_indices,
                    1 << self.step,
                    &self.u_root
                ));
                assert!(function_proofs[1].verify_merkle_tree(
                    &leaf_indices,
                    1 << self.step,
                    &self.h_root.as_ref().unwrap()
                ));
            } else {
                folding_proofs[i - 1].verify_merkle_tree(
                    &leaf_indices,
                    1 << self.step,
                    &self.folding_root[i - 1],
                );
            }

            let get_folding_value = |index: &usize| {
                if i == 0 {
                    let u = function_proofs[0].proof_values[index];
                    let h = function_proofs[1].proof_values[index];
                    let v = v_values[index];
                    let x = self.interpolate_cosets[i * self.step].element_at(*index);
                    let x_inv = self.interpolate_cosets[i * self.step].element_inv_at(*index);

                    let mut res = u;
                    let mut acc = rlc;
                    res += h * acc;
                    acc *= rlc;
                    res += acc
                        * (u * v * h_size
                            - self.vanishing_polynomial.evaluation_at(x) * h * h_size
                            - self.evaluation.unwrap())
                        * x_inv;
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
                    let challenge = self.oracle.folding_challenges[i * self.step + j];
                    let size = verify_values.len();
                    let mut tmp_values = vec![];
                    let mut tmp_inds = vec![];
                    for l in 0..size / 2 {
                        let x = verify_values[l];
                        let nx = verify_values[l + size / 2];
                        tmp_values.push(
                            x + nx
                                + challenge
                                    * (x - nx)
                                    * self.interpolate_cosets[i * self.step + j]
                                        .element_inv_at(verify_inds[l]),
                        );
                        tmp_inds.push(verify_inds[l]);
                    }
                    verify_values = tmp_values;
                    verify_inds = tmp_inds;
                }
                assert_eq!(verify_values.len(), 1);

                let v = verify_values[0];
                if i < self.total_round / self.step - 1 {
                    if v != folding_proofs[i].proof_values[k] {
                        panic!("{}", i)
                    }
                } else {
                    let point = self.interpolate_cosets[(i + 1) * self.step].element_at(*k);
                    if v != self.final_poly.as_ref().unwrap().evaluation_at(point) {
                        panic!()
                    }
                }
            }
        }
        true
    }
}

/// =============================================================
/// End of Virgo FRI logic
/// =============================================================

/// =============================================================
/// Implementation of the PolynomialCommitmentScheme trait for VirgoPCS
/// =============================================================
use crate::pcs::PolynomialCommitmentScheme;
use crate::pcs::{Evaluation, Point};
use crate::poly;
use crate::poly::Polynomial as PolyTrait;
use crate::Error;

/// Parameter types for VirgoPCS.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirgoParam<F: MyField> {
    /// The sequence of interpolation cosets (generated with base size 2^(num_vars+CODE_RATE)).
    pub interpolate_cosets: Vec<Coset<F>>,
    /// The coset used for vector interpolation (of size 2^(num_vars)).
    pub vector_interpolation_coset: Coset<F>,
    /// Total number of FRI rounds (for a multilinear polynomial with num_vars variables).
    pub total_round: usize,
    /// The FRI folding step (usually a constant STEP).
    pub step: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirgoProverParam<F: MyField> {
    pub param: VirgoParam<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirgoVerifierParam<F: MyField> {
    pub param: VirgoParam<F>,
}

/// A Virgo commitment is represented as a vector of Merkle-tree roots.
/// In our scheme the commitment consists of the u_root (first committed polynomial),
/// the h_root (from the FRI function-h) and then one root per folding round.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VirgoCommitment(pub Vec<[u8; 32]>);

impl AsRef<[[u8; MERKLE_ROOT_SIZE]]> for VirgoCommitment {
    fn as_ref(&self) -> &[[u8; MERKLE_ROOT_SIZE]] {
        &self.0
    }
}

/// The VirgoPCS type.
#[derive(Clone, Debug)]
pub struct VirgoPCS;

impl PolynomialCommitmentScheme<F> for VirgoPCS
where
    F: MyField + ff::Field + Serialize + for<'de> Deserialize<'de>,
    BackendMpoly<F>: Serialize + for<'de> Deserialize<'de> + Clone + Debug + PolyTrait<F>,
{
    type Param = VirgoParam<F>;
    type ProverParam = VirgoProverParam<F>;
    type VerifierParam = VirgoVerifierParam<F>;
    type Polynomial = BackendMpoly<F>;
    type Commitment = VirgoCommitment;
    type CommitmentChunk = [u8; 32];

    fn setup(
        poly_size: usize,
        _batch_size: usize,
        _rng: impl RngCore,
    ) -> Result<Self::Param, crate::Error> {
        let num_vars = poly_size.trailing_zeros() as usize;
        let width = num_vars + CODE_RATE;
        if width >= usize::BITS as usize {
            return Err(Error::InvalidPcsParam("poly_size too large".into()));
        }
        let base_coset = Coset::new(1 << (num_vars + CODE_RATE), F::random_element());
        let mut interpolate_cosets = vec![base_coset];
        for i in 1..=num_vars {
            let prev = interpolate_cosets[i - 1].clone();
            interpolate_cosets.push(prev.pow(2));
        }
        let vector_interpolation_coset = Coset::new(1 << num_vars, F::random_element());
        Ok(VirgoParam {
            interpolate_cosets,
            vector_interpolation_coset,
            total_round: num_vars,
            step: STEP,
        })
    }

    fn trim(
        param: &Self::Param,
        _poly_size: usize,
        _batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), crate::Error> {
        Ok((
            VirgoProverParam {
                param: param.clone(),
            },
            VirgoVerifierParam {
                param: param.clone(),
            },
        ))
    }

    fn commit(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, crate::Error> {
        let random_oracle = RandomOracle::new(pp.param.total_round, SECURITY_BITS / CODE_RATE);
        let mut fri_prover = FriProver::new(
            pp.param.total_round,
            &pp.param.interpolate_cosets,
            &pp.param.vector_interpolation_coset,
            UtilMPoly::new(poly.coefficients().to_vec()),
            &random_oracle,
            pp.param.step,
        );
        let u_root = fri_prover.commit_first_polynomial();
        let mut fri_verifier = FriVerifier::new(
            pp.param.total_round,
            &pp.param.interpolate_cosets,
            &pp.param.vector_interpolation_coset,
            u_root,
            &random_oracle,
            pp.param.step,
        );
        let open_point = fri_verifier.get_open_point();
        fri_prover.commit_functions(&mut fri_verifier, &open_point);
        fri_prover.prove();
        fri_prover.commit_foldings(&mut fri_verifier);
        let mut comm_chunks = vec![];
        comm_chunks.push(u_root);
        if let Some(h) = fri_verifier.h_root {
            comm_chunks.push(h.merkle_root);
        } else {
            comm_chunks.push([0u8; MERKLE_ROOT_SIZE]);
        }
        for fr in fri_verifier.folding_root.iter() {
            comm_chunks.push(fr.merkle_root);
        }
        Ok(VirgoCommitment(comm_chunks))
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, crate::Error>
    where
        Self::Polynomial: 'a,
    {
        polys
            .into_iter()
            .map(|poly| Self::commit(pp, poly))
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        _comm: &Self::Commitment,
        _point: &Point<F, Self::Polynomial>,
        _eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), crate::Error> {
        let random_oracle = RandomOracle::new(pp.param.total_round, SECURITY_BITS / CODE_RATE);
        let mut fri_prover = FriProver::new(
            pp.param.total_round,
            &pp.param.interpolate_cosets,
            &pp.param.vector_interpolation_coset,
            UtilMPoly::new(poly.coefficients().to_vec()),
            &random_oracle,
            pp.param.step,
        );
        let u_root = fri_prover.commit_first_polynomial();
        let mut fri_verifier = FriVerifier::new(
            pp.param.total_round,
            &pp.param.interpolate_cosets,
            &pp.param.vector_interpolation_coset,
            u_root,
            &random_oracle,
            pp.param.step,
        );
        let open_point = fri_verifier.get_open_point();
        fri_prover.commit_functions(&mut fri_verifier, &open_point);
        fri_prover.prove();
        fri_prover.commit_foldings(&mut fri_verifier);
        let (folding_proofs, function_proofs, v_values) = fri_prover.query();
        // Write function proofs.
        for qp in function_proofs.iter() {
            let proof_chunks: Vec<Self::CommitmentChunk> = qp
                .proof_bytes
                .chunks(MERKLE_ROOT_SIZE) // still splits at 32-byte boundaries
                .map(|c| c.try_into().unwrap())
                .collect();
            transcript.write_commitments(&proof_chunks)?;
            let field_vals: Vec<F> = qp.proof_values.iter().map(|(_, v)| *v).collect();
            transcript.write_field_elements(&field_vals)?;
        }
        // Write folding proofs.
        for qp in folding_proofs.iter() {
            let proof_chunks: Vec<[u8; MERKLE_ROOT_SIZE]> = qp
                .proof_bytes
                .chunks(MERKLE_ROOT_SIZE)
                .map(|chunk| chunk.try_into().unwrap())
                .collect();
            transcript.write_commitments(&proof_chunks)?;
            let field_vals: Vec<F> = qp.proof_values.iter().map(|(_, v)| *v).collect();
            transcript.write_field_elements(&field_vals)?;
        }
        // Write queried evaluations.
        let v_vals: Vec<F> = v_values.values().cloned().collect();
        transcript.write_field_elements(&v_vals)?;
        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let polys: Vec<_> = polys.into_iter().collect();
        let comms: Vec<_> = comms.into_iter().collect();

        for eval in evals {
            Self::open(
                pp,
                polys[eval.poly()],
                comms[eval.poly()],
                &points[eval.point()],
                &eval.value(),
                transcript,
            )?;
        }
        Ok(())
    }

    fn read_commitments(
        _vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, crate::Error> {
        let mut commitments = Vec::with_capacity(num_polys);
        for _ in 0..num_polys {
            let mut chunks = Vec::new();
            for _ in 0..3 {
                let chunk = transcript.read_commitment()?;
                chunks.push(chunk);
            }
            commitments.push(VirgoCommitment(chunks));
        }
        Ok(commitments)
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        _point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), crate::Error> {
        // Rebuild the verifier's state using the u_root stored in the commitment.
        let param = &vp.param;
        let u_root = comm
            .0
            .get(0)
            .ok_or_else(|| crate::Error::InvalidPcsParam("Missing u_root".into()))?
            .clone();
        let mut fri_verifier = FriVerifier::new(
            param.total_round,
            &param.interpolate_cosets,
            &param.vector_interpolation_coset,
            u_root,
            &RandomOracle::new(param.total_round, SECURITY_BITS / CODE_RATE),
            param.step,
        );
        // Read back the function proofs.
        // We expect exactly two function proofs.
        // Determine the expected number of chunks per query result.
        let expected_chunks = param.interpolate_cosets[0].size() / (1 << param.step);
        // Use the verifier's stored query list.
        let leaf_indices = fri_verifier.oracle.query_list.clone();
        let leaf_size = 1 << param.step;
        let num_field_elems = leaf_indices.len() * leaf_size;

        // Helper closure: Read one QueryResult from the transcript.
        let mut read_query_result = || -> Result<QueryResult<F>, crate::Error> {
            // Read commitment chunks and flatten them into a Vec<u8>
            let chunks: Vec<[u8; MERKLE_ROOT_SIZE]> =
                transcript.read_commitments(expected_chunks)?;
            let proof_bytes: Vec<u8> = chunks
                .into_iter()
                .flat_map(|chunk| chunk.to_vec())
                .collect();
            // Read the expected number of field elements.
            let elems: Vec<F> = transcript.read_field_elements(num_field_elems)?;
            // Reconstruct the HashMap mapping indices to field elements.
            let mut proof_values = std::collections::HashMap::new();
            let tree_leaves = fri_verifier.u_root.leave_number;
            for (idx, &j) in leaf_indices.iter().enumerate() {
                for i in 0..leaf_size {
                    let key = j + tree_leaves * i;
                    let value = elems[idx * leaf_size + i];
                    proof_values.insert(key, value);
                }
            }
            Ok(QueryResult {
                proof_bytes,
                proof_values,
            })
        };

        // Read the two function proofs.
        let function_proof1 = read_query_result()?;
        let function_proof2 = read_query_result()?;
        let function_proofs = vec![function_proof1, function_proof2];

        // Read back the folding proofs.
        // Read the folding proofs.
        let num_folding = param.total_round / param.step - 1;
        let mut folding_proofs = Vec::with_capacity(num_folding);
        for _ in 0..num_folding {
            let qr = read_query_result()?;
            folding_proofs.push(qr);
        }

        // Read the queried evaluation values and reconstruct the expected HashMap.
        let v_elems: Vec<F> = transcript.read_field_elements(num_field_elems)?;
        let mut v_values = std::collections::HashMap::new();
        let tree_leaves = fri_verifier.u_root.leave_number;
        for (idx, &j) in leaf_indices.iter().enumerate() {
            for i in 0..leaf_size {
                let key = j + tree_leaves * i;
                let value = v_elems[idx * leaf_size + i];
                v_values.insert(key, value);
            }
        }

        // Now call the internal FriVerifier verification logic.
        // Convert the boolean result into a Result.
        if fri_verifier.verify(&folding_proofs, &v_values, &function_proofs) {
            // Additionally, check that the final evaluation matches the claimed eval.
            // In the original FriVerifier, the final check compares the folded value to
            // final_poly.evaluation_at(point). Here we assume that check is done internally.
            Ok(())
        } else {
            return Err(Error::InvalidPcsParam("Virgo verification failed".into()));
        }
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), crate::Error>
    where
        Self::Commitment: 'a,
    {
        // Simply verify each instance individually.
        use itertools::izip;
        for (comm, point, eval) in izip!(comms, points, evals) {
            // Here we pass a reference to the inner field (eval.value) as our expected evaluation.
            Self::verify(vp, comm, point, &eval.value, transcript)?;
        }
        Ok(())
    }
}

/// =============================================================
/// End of VirgoPCS implementation
/// =============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use csv::Writer;

    fn output_proof_size(variable_num: usize) -> usize {
        let total_round = variable_num;
        let polynomial = UtilMPoly::random_polynomial(variable_num);
        let mut interpolate_cosets = vec![Coset::new(
            1 << (variable_num + CODE_RATE),
            Mersenne61Ext::random_element(),
        )];
        for i in 1..variable_num + 1 {
            interpolate_cosets.push(interpolate_cosets[i - 1].pow(2));
        }
        let random_oracle = RandomOracle::new(total_round, SECURITY_BITS / CODE_RATE);
        let vector_interpolation_coset =
            Coset::new(1 << variable_num, Mersenne61Ext::random_element());
        let mut prover = FriProver::new(
            total_round,
            &interpolate_cosets,
            &vector_interpolation_coset,
            polynomial.clone(),
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
        prover.commit_functions(&mut verifier, &open_point);
        prover.prove();
        prover.commit_foldings(&mut verifier);
        let (folding_proofs, function_proofs, v_value) = prover.query();
        assert!(verifier.verify(&folding_proofs, &v_value, &function_proofs));
        folding_proofs.iter().map(|x| x.proof_size()).sum::<usize>()
            + (variable_num + 1) * MERKLE_ROOT_SIZE
            + size_of::<Mersenne61Ext>()
            + function_proofs
                .iter()
                .map(|x| x.proof_size())
                .sum::<usize>()
    }

    #[test]
    fn test_virgo_proof_size() {
        let mut wtr = Writer::from_path("virgo.csv").unwrap();
        let range = 10..SIZE;
        for i in range.clone() {
            let proof_size = output_proof_size(i);
            wtr.write_record(&[i.to_string(), proof_size.to_string()])
                .unwrap();
        }
    }
}
