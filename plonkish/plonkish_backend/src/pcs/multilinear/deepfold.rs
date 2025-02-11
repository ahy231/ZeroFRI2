use crate::{
    Error,
    pcs::{Point, PolynomialCommitmentScheme},
    poly::{multilinear::MultilinearPolynomial, Polynomial},
    util::{
        algebra::{coset::Coset, field::MyField, CODE_RATE},
        merkle_tree::{MerkleTreeVerifier, MERKLE_ROOT_SIZE},
        query_result::QueryResult,
        transcript::{TranscriptRead, TranscriptWrite},
        Deserialize, DeserializeOwned, Itertools, Serialize,
    },
};
use rand::RngCore;
use std::{marker::PhantomData, ops::Neg, iter};

// ─────────────────────────────────────────────────────────────
// Deepfold Parameters and Types
// ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeepfoldParams<T: MyField> {
    pub total_round: usize,
    pub interpolate_cosets: Vec<Coset<T>>,
    pub step: usize,
}

pub type DeepfoldProverParam<T> = DeepfoldParams<T>;
pub type DeepfoldVerifierParam<T> = DeepfoldParams<T>;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DeepfoldCommitment<T: MyField> {
    pub merkle_root: [u8; MERKLE_ROOT_SIZE],
    pub deep: T,
}

impl<T: MyField> AsRef<[[u8; MERKLE_ROOT_SIZE]]> for DeepfoldCommitment<T> {
    fn as_ref(&self) -> &[[u8; MERKLE_ROOT_SIZE]] {
        std::slice::from_ref(&self.merkle_root)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeepfoldProof<T: MyField> {
    pub merkle_roots: Vec<[u8; MERKLE_ROOT_SIZE]>,
    pub query_result: Vec<QueryResult<T>>,
    pub deep_evals: Vec<(T, Vec<T>)>,
    pub shuffle_evals: Vec<T>,
    pub evaluation: T,
    pub final_value: T,
    // Use the concrete multilinear polynomial type.
    pub final_poly: MultilinearPolynomial<T>,
}

// ─────────────────────────────────────────────────────────────
// Internal Structures (Prover, Verifier, DeepEval)
// ─────────────────────────────────────────────────────────────

pub struct DeepfoldProver<T: MyField + ff::Field> {
    total_round: usize,
    interpolate_cosets: Vec<Coset<T>>,
    // Holds intermediate polynomials committed via a Merkle tree.
    interpolations: Vec<crate::util::interpolation::InterpolateValue<T>>,
    hypercube_interpolation: Vec<T>,
    deep_eval: Vec<DeepEval<T>>,
    shuffle_eval: Option<DeepEval<T>>,
    final_value: Option<T>,
    final_poly: Option<MultilinearPolynomial<T>>,
    step: usize,
}

pub struct DeepfoldVerifier<T: MyField + ff::Field + Default> {
    total_round: usize,
    interpolate_cosets: Vec<Coset<T>>,
    polynomial_roots: Vec<MerkleTreeVerifier>,
    first_deep: T,
    final_value: Option<T>,
    final_poly: Option<MultilinearPolynomial<T>>,
    shuffle_eval: Option<DeepEval<T>>,
    deep_evals: Vec<DeepEval<T>>,
    open_point: Vec<T>,
    step: usize,
}

#[derive(Clone)]
pub struct DeepEval<T: MyField> {
    point: Vec<T>,
    pub first_eval: T,
    pub else_evals: Vec<T>,
}

impl<T: MyField> DeepEval<T> {
    pub fn new(point: Vec<T>, poly_hypercube: Vec<T>) -> Self {
        DeepEval {
            point: point.clone(),
            first_eval: Self::evaluation_at(point, poly_hypercube),
            else_evals: vec![],
        }
    }

    fn evaluation_at(mut point: Vec<T>, mut poly_hypercube: Vec<T>) -> T {
        let mut len = poly_hypercube.len();
        assert_eq!(len, 1 << point.len());
        for v in point {
            len /= 2;
            for i in 0..len {
                poly_hypercube[i] = poly_hypercube[i] * (T::from_int(1) - v);
                let tmp = poly_hypercube[i + len] * v;
                poly_hypercube[i] = poly_hypercube[i] + tmp;
            }
        }
        poly_hypercube[0]
    }

    pub fn append_else_eval(&mut self, poly_hypercube: Vec<T>) {
        let mut point = self.point[self.else_evals.len()..].to_vec();
        point[0] = point[0] + T::from_int(1);
        self.else_evals.push(Self::evaluation_at(point, poly_hypercube));
    }

    pub fn verify(&self, challenges: &Vec<T>) -> T {
        let (_, challenges) = challenges.split_at(challenges.len() - self.point.len());
        let mut y_0 = self.first_eval;
        assert_eq!(self.point.len(), self.else_evals.len());
        for ((x, eval), challenge) in self.point.iter().zip(self.else_evals.iter()).zip(challenges.iter()) {
            y_0 = y_0 + (eval.clone() - y_0) * (challenge.clone() - x.clone());
        }
        y_0
    }
}

// ─────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────

fn inverse_two<T: ff::Field>() -> T {
    let two = T::ONE + T::ONE;
    two.invert().unwrap()
}

impl<T: MyField + ff::Field> MultilinearPolynomial<T> {
    /// Returns a vector of the evaluations (i.e. the hypercube values).
    pub fn evaluate_hypercube(&self) -> Vec<T> {
        self.evals().to_vec()
    }
    
}


// ─────────────────────────────────────────────────────────────
// DeepfoldProver Implementation (Transcript-based)
// ─────────────────────────────────────────────────────────────

impl<T: MyField + ff::Field> DeepfoldProver<T> {
    pub fn new(
        total_round: usize,
        interpolate_cosets: &Vec<Coset<T>>,
        polynomial: MultilinearPolynomial<T>,
        deep_challenge: T, // from transcript.squeeze_challenge()
        step: usize,
    ) -> Self {
        let point: Vec<T> = iter::successors(Some(deep_challenge), |&x| Some(x * x))
            .take(total_round)
            .collect();
        let hypercube_interpolation = polynomial.evaluate_hypercube();
        DeepfoldProver {
            total_round,
            interpolate_cosets: interpolate_cosets.clone(),
            interpolations: vec![crate::util::interpolation::InterpolateValue::new(
                interpolate_cosets[0].fft(MultilinearPolynomial::<T>::coefficients(&polynomial)),
                1 << step,
            )],
            hypercube_interpolation: hypercube_interpolation.clone(),
            deep_eval: vec![DeepEval::new(point, hypercube_interpolation.clone())],
            shuffle_eval: None,
            final_value: None,
            final_poly: None,
            step,
        }
    }

    pub fn commit_polynomial(&self) -> DeepfoldCommitment<T> {
        DeepfoldCommitment {
            merkle_root: self.interpolations[0].commit(),
            deep: self.deep_eval[0].first_eval,
        }
    }

    fn evaluation_next_domain(&self, round: usize, challenges: &Vec<T>) -> Vec<T> {
        let mut get_folding_value = self.interpolations[round].value.clone();
        for j in 0..self.step {
            if round * self.step + j == self.total_round {
                break;
            }
            let len = self.interpolate_cosets[round * self.step + j].size();
            let coset = &self.interpolate_cosets[round * self.step + j];
            let challenge = challenges[j];
            let mut tmp_folding_value = vec![];
            for i in 0..(len / 2) {
                let x = get_folding_value[i];
                let nx = get_folding_value[i + len / 2];
                let new_v = (x + nx) + challenge * (x - nx) * coset.element_inv_at(i);
                tmp_folding_value.push(new_v * inverse_two::<T>());
            }
            get_folding_value = tmp_folding_value;
        }
        get_folding_value
    }

    fn sumcheck_next_domain(hypercube_interpolation: &mut Vec<T>, m: usize, challenge: T) {
        for i in 0..m {
            hypercube_interpolation[i] = hypercube_interpolation[i] * (T::from_int(1) - challenge);
            let tmp = hypercube_interpolation[i + m] * challenge;
            hypercube_interpolation[i] = hypercube_interpolation[i] + tmp;
        }
        hypercube_interpolation.truncate(m);
    }

    pub fn prove(&mut self, point: Vec<T>, transcript: &mut impl TranscriptWrite<[u8; MERKLE_ROOT_SIZE], T>) {
        let mut hypercube_interpolation = self.hypercube_interpolation.clone();
        self.shuffle_eval = Some(DeepEval::new(point.clone(), hypercube_interpolation.clone()));
        for i in 0..(self.total_round / self.step + 1) {
            let mut challenges: Vec<T> = vec![];
            for j in 0..self.step {
                if i * self.step + j == self.total_round {
                    break;
                }
                challenges.push(transcript.squeeze_challenge());
            }
            for j in 0..self.step {
                if i * self.step + j == self.total_round {
                    break;
                }
                self.shuffle_eval.as_mut().unwrap().append_else_eval(hypercube_interpolation.clone());
                for deep in &mut self.deep_eval {
                    deep.append_else_eval(hypercube_interpolation.clone());
                }
                if i * self.step + j < self.total_round - 1 {
                    let m = 1 << (self.total_round - (i * self.step + j) - 1);
                    Self::sumcheck_next_domain(&mut hypercube_interpolation, m, challenges[j]);
                    let deep_point: Vec<T> = iter::successors(Some(transcript.squeeze_challenge()), |&x| Some(x * x))
                        .take(self.total_round - (i * self.step + j) - 1)
                        .collect();
                    self.deep_eval.push(DeepEval::new(deep_point, hypercube_interpolation.clone()));
                }
            }
            let next_evaluation = self.evaluation_next_domain(i, &challenges);
            if i < self.total_round / self.step - 1 {
                self.interpolations.push(crate::util::interpolation::InterpolateValue::new(
                    next_evaluation,
                    1 << self.step,
                ));
            } else if i == self.total_round / self.step - 1 {
                self.interpolations.push(crate::util::interpolation::InterpolateValue::new(
                    next_evaluation.clone(),
                    1 << self.step,
                ));
                self.final_poly = Some(MultilinearPolynomial::new(
                    self.interpolate_cosets[(i + 1) * self.step].ifft(next_evaluation),
                ));
            } else {
                assert_eq!(next_evaluation.len(), 1 << CODE_RATE);
                self.final_value = Some(next_evaluation[0]);
            }
        }
    }

    pub fn generate_proof(&mut self, point: Vec<T>, transcript: &mut impl TranscriptWrite<[u8; MERKLE_ROOT_SIZE], T>) -> DeepfoldProof<T> {
        self.prove(point, transcript);
        let query_result = self.interpolations.iter()
            .map(|interp| interp.query(&vec![])) // Placeholder for query indices.
            .collect();
        DeepfoldProof {
            merkle_roots: (1..(self.total_round / self.step))
                .map(|x| self.interpolations[x].commit())
                .collect(),
            query_result,
            deep_evals: self.deep_eval.iter().map(|d| (d.first_eval, d.else_evals.clone())).collect(),
            shuffle_evals: self.shuffle_eval.as_ref().unwrap().else_evals.clone(),
            final_value: self.final_value.unwrap(),
            final_poly: self.final_poly.clone().unwrap(),
            evaluation: self.shuffle_eval.as_ref().unwrap().first_eval,
        }
    }
}

impl<T: MyField + ff::Field + Default> DeepfoldVerifier<T> {
    pub fn new(
        total_round: usize,
        cosets: &Vec<Coset<T>>,
        commit: &DeepfoldCommitment<T>,
        transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>,
        step: usize,
    ) -> Self {
        let mut polynomial_roots = vec![];
        polynomial_roots.push(MerkleTreeVerifier::new(cosets[0].size() / (1 << step), &commit.merkle_root));
        let open_point: Vec<T> = (0..total_round)
            .map(|_| transcript.squeeze_challenge())
            .collect();
        DeepfoldVerifier {
            total_round,
            interpolate_cosets: cosets.clone(),
            polynomial_roots,
            first_deep: commit.deep,
            final_value: None,
            final_poly: None,
            shuffle_eval: None,
            deep_evals: vec![],
            open_point,
            step,
        }
    }

    pub fn get_open_point(&self) -> Vec<T> {
        self.open_point.clone()
    }

    pub fn verify(&mut self, proof: DeepfoldProof<T>, transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>) -> bool {
        self.final_value = Some(proof.final_value);
        self.final_poly = Some(proof.final_poly);
        let mut leave_number = self.interpolate_cosets[0].size() / (1 << self.step);
        for merkle_root in proof.merkle_roots {
            leave_number /= 1 << self.step;
            self.polynomial_roots.push(MerkleTreeVerifier {
                merkle_root,
                leave_number,
            });
        }
        self.shuffle_eval = Some(DeepEval {
            point: self.open_point.clone(),
            first_eval: proof.evaluation,
            else_evals: proof.shuffle_evals,
        });
        for (idx, (first_eval, else_evals)) in proof.deep_evals.into_iter().enumerate() {
            let deep_point: Vec<T> = iter::successors(Some(transcript.squeeze_challenge()), |&x| Some(x * x))
                .take(self.total_round - idx)
                .collect();
            self.deep_evals.push(DeepEval {
                point: deep_point,
                first_eval,
                else_evals,
            });
        }
        self._verify(&proof.query_result)
    }

    fn _verify(&self, polynomial_proof: &Vec<QueryResult<T>>) -> bool {
        let leaf_indices = vec![]; // Placeholder for query indices.
        for i in 0..(self.total_round / self.step) {
            let domain_size = self.interpolate_cosets[i * self.step].size();
            polynomial_proof[i].verify_merkle_tree(&leaf_indices, 1 << self.step, &self.polynomial_roots[i]);
            if i == self.total_round / self.step - 1 {
                let mut challenges = vec![];
                for _ in 0..self.total_round {
                    challenges.push(Default::default());
                }
                assert_eq!(self.shuffle_eval.as_ref().unwrap().verify(&challenges), self.final_value.unwrap());
                for de in &self.deep_evals {
                    assert_eq!(de.verify(&challenges), self.final_value.unwrap());
                }
            }
            let folding_value = &polynomial_proof[i].proof_values;
            let mut challenge = vec![];
            for _ in 0..self.step {
                challenge.push(<T as Default>::default());
            }
            for k in &leaf_indices {
                let mut verify_values = vec![];
                let mut verify_inds = vec![];
                for j in 0..(1 << self.step) {
                    let ind = k + j * domain_size / (1 << self.step);
                    verify_values.push(folding_value[&ind]);
                    verify_inds.push(ind);
                }
                for j in 0..self.step {
                    let size = verify_values.len();
                    let mut tmp_values = vec![];
                    let mut tmp_inds = vec![];
                    for l in 0..size/2 {
                        let x = verify_values[l];
                        let nx = verify_values[l + size/2];
                        tmp_values.push((x + nx + challenge[j] * (x - nx)
                            * self.interpolate_cosets[i * self.step + j].element_inv_at(verify_inds[l]))
                            * T::inverse_2());
                        tmp_inds.push(verify_inds[l]);
                    }
                    verify_values = tmp_values;
                    verify_inds = tmp_inds;
                }
                assert_eq!(verify_values[0], polynomial_proof[i + 1].proof_values[k]);
            }
        }
        true
    }
}

// ─────────────────────────────────────────────────────────────
// PolynomialCommitmentScheme Trait Implementation for Deepfold
// ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Deepfold<T: MyField>(PhantomData<T>);

impl<T: MyField + ff::Field + Default + serde::Serialize + for<'de> serde::Deserialize<'de>>
    PolynomialCommitmentScheme<T> for Deepfold<T>
{
    type Param = DeepfoldParams<T>;
    type ProverParam = DeepfoldProverParam<T>;
    type VerifierParam = DeepfoldVerifierParam<T>;
    type Polynomial = MultilinearPolynomial<T>;
    type Commitment = DeepfoldCommitment<T>;
    type CommitmentChunk = [u8; MERKLE_ROOT_SIZE];

    fn setup(
        poly_size: usize,
        _batch_size: usize,
        _rng: impl RngCore,
    ) -> Result<Self::Param, Error> {
        let total_round = poly_size;
        let first_coset = Coset::new(1 << (poly_size + CODE_RATE), T::from_int(1));
        let mut interpolate_cosets = vec![first_coset];
        for i in 1..=poly_size {
            let next = interpolate_cosets[i - 1].pow(2);
            interpolate_cosets.push(next);
        }
        let step = 1;
        Ok(DeepfoldParams {
            total_round,
            interpolate_cosets,
            step,
        })
    }

    fn trim(
        param: &Self::Param,
        _poly_size: usize,
        _batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        Ok((param.clone(), param.clone()))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        let deep_challenge = T::from_int(1); // Placeholder: ideally from the transcript.
        let prover = DeepfoldProver::new(pp.total_round, &pp.interpolate_cosets, poly.clone(), deep_challenge, pp.step);
        Ok(prover.commit_polynomial())
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        polys.into_iter().map(|poly| Self::commit(pp, poly)).collect()
    }

    // Here we change the open function to write the proof into the transcript
    // rather than returning it directly (to match our PCS trait).
    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        _comm: &Self::Commitment,
        point: &Point<T, Self::Polynomial>,
        _eval: &T,
        transcript: &mut impl TranscriptWrite<[u8; MERKLE_ROOT_SIZE], T>,
    ) -> Result<(), Error> {
        let mut prover = DeepfoldProver::new(pp.total_round, &pp.interpolate_cosets, poly.clone(), transcript.squeeze_challenge(), pp.step);
        let proof = prover.generate_proof(point.clone(), transcript);
        let proof_bytes = bincode::serialize(&proof).map_err(|e| Error::VerificationError(e.to_string()))?;
        let proof_arr: [u8; MERKLE_ROOT_SIZE] = proof_bytes.as_slice().try_into().expect("invalid length");
        transcript.write_commitment(&proof_arr);
        Ok(())
    }

    fn batch_open<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<T, Self::Polynomial>],
        evals: &[crate::pcs::Evaluation<T>],
        transcript: &mut impl TranscriptWrite<[u8; MERKLE_ROOT_SIZE], T>,
    ) -> Result<(), Error> {
        for (poly, comm, point, eval) in itertools::izip!(polys, comms, points, evals) {
            Self::open(pp, poly, comm, point, &eval.value, transcript)?;
        }
        Ok(())
    }

    fn read_commitments(
        _vp: &Self::VerifierParam,
        _num_polys: usize,
        _transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        unimplemented!()
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<T, Self::Polynomial>,
        _eval: &T,
        transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>,
    ) -> Result<(), Error> {
        let mut verifier = DeepfoldVerifier::new(vp.total_round, &vp.interpolate_cosets, comm, transcript, vp.step);
        let proof_bytes = transcript.read_commitment()?;
        let proof: DeepfoldProof<T> = bincode::deserialize(&proof_bytes)
            .map_err(|e| Error::VerificationError(e.to_string()))?;
        if verifier.verify(proof, transcript) {
            Ok(())
        } else {
            Err(Error::VerificationError("Deepfold verification failed".to_string()))
        }
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<T, Self::Polynomial>],
        evals: &[crate::pcs::Evaluation<T>],
        transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>,
    ) -> Result<(), Error> {
        // A simple (placeholder) implementation: verify each commitment individually.
        for (comm, point, eval) in itertools::izip!(comms, points, evals) {
            Self::verify(vp, comm, point, &eval.value, transcript)?;
        }
        Ok(())
    }
}

// fn read_proof<T: MyField>(transcript: &mut impl TranscriptRead<[u8; MERKLE_ROOT_SIZE], T>) -> Result<DeepfoldProof<T>, Error> {
//     // For now, simply unimplemented.
//     unimplemented!()
// }
