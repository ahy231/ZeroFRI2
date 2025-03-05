use crate::{
    pcs::{Evaluation, Point, PolynomialCommitmentScheme},
    poly::multilinear::MultilinearPolynomial,
    util::{
        algebra::{coset::Coset, polynomial::Polynomial},
        algebra::{field::MyField, CODE_RATE, SECURITY_BITS, STEP},
        interpolation::InterpolateValue,
        merkle_tree::{MerkleTreeVerifier, MERKLE_ROOT_SIZE},
        query_result::QueryResult,
        random_oracle::RandomOracle,
        transcript::{TranscriptRead, TranscriptWrite},
    },
    Error,
};
use ff::Field;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, mem::size_of};

//
// ======================= Deepfold PCS Logic (Inlined) =======================
//

/// Deepfold evaluation on a hypercube.
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

    fn evaluation_at(point: Vec<T>, mut poly_hypercube: Vec<T>) -> T {
        let mut len = poly_hypercube.len();
        assert_eq!(len, 1 << point.len());
        for v in point.into_iter() {
            len >>= 1;
            for i in 0..len {
                poly_hypercube[i] *= T::from_int(1) - v;
                let tmp = poly_hypercube[i + len] * v;
                poly_hypercube[i] += tmp;
            }
        }
        poly_hypercube[0]
    }

    pub fn append_else_eval(&mut self, poly_hypercube: Vec<T>) {
        let mut point = self.point[self.else_evals.len()..].to_vec();
        point[0] += T::from_int(1);
        self.else_evals
            .push(Self::evaluation_at(point, poly_hypercube));
    }

    pub fn verify(&self, challenges: &Vec<T>) -> T {
        let (_, challenges) = challenges.split_at(challenges.len() - self.point.len());
        let mut y_0 = self.first_eval;
        assert_eq!(self.point.len(), self.else_evals.len());
        for ((x, eval), challenge) in self
            .point
            .iter()
            .zip(self.else_evals.iter())
            .zip(challenges.into_iter())
        {
            let y_1 = eval.clone();
            y_0 += (y_1 - y_0) * (challenge.clone() - x.clone());
        }
        y_0
    }
}

/// Deepfold commitment: a Merkle root plus the initial evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Commit<T: MyField> {
    pub merkle_root: [u8; MERKLE_ROOT_SIZE],
    pub deep: T,
}

impl<T: MyField> AsRef<[[u8; MERKLE_ROOT_SIZE]]> for Commit<T> {
    fn as_ref(&self) -> &[[u8; MERKLE_ROOT_SIZE]] {
        std::slice::from_ref(&self.merkle_root)
    }
}

/// Deepfold proof, containing Merkle roots, query results, deep evaluations, shuffle evaluations,
/// final evaluation, final value, and the final polynomial.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof<T: MyField> {
    pub merkle_root: Vec<[u8; MERKLE_ROOT_SIZE]>,
    pub query_result: Vec<QueryResult<T>>,
    pub deep_evals: Vec<(T, Vec<T>)>,
    pub shuffle_evals: Vec<T>,
    pub evaluation: T,
    pub final_value: T,
    pub final_poly: Polynomial<T>,
}

impl<T: MyField> Proof<T> {
    pub fn size(&self) -> usize {
        self.merkle_root.len() * MERKLE_ROOT_SIZE
            + self
                .query_result
                .iter()
                .fold(0, |acc, x| acc + x.proof_size())
            + (self.deep_evals.iter().fold(0, |acc, x| acc + x.1.len())
                + self.shuffle_evals.len()
                + 2)
                * size_of::<T>()
    }
}

/// Prover for Deepfold PCS.
#[derive(Clone)]
pub struct Prover<T: MyField + ff::Field> {
    total_round: usize,
    interpolate_cosets: Vec<Coset<T>>,
    interpolations: Vec<InterpolateValue<T>>,
    hypercube_interpolation: Vec<T>,
    deep_eval: Vec<DeepEval<T>>,
    shuffle_eval: Option<DeepEval<T>>,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    final_poly: Option<Polynomial<T>>,
    step: usize,
}

impl<T: MyField + ff::Field> Prover<T> {
    pub fn new(
        total_round: usize,
        interpolate_cosets: &Vec<Coset<T>>,
        polynomial: MultilinearPolynomial<T>,
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> Self {
        let point = std::iter::successors(Some(oracle.deep[0]), |&x| Some(x * x))
            .take(total_round)
            .collect::<Vec<_>>();
        let hypercube_interpolation = polynomial.evaluate_hypercube();
        Prover {
            total_round,
            interpolate_cosets: interpolate_cosets.clone(),
            interpolations: vec![InterpolateValue::new(
                interpolate_cosets[0].fft(polynomial.coefficients()),
                1 << step,
            )],
            hypercube_interpolation: hypercube_interpolation.clone(),
            deep_eval: vec![DeepEval::new(
                point.clone(),
                hypercube_interpolation.clone(),
            )],
            shuffle_eval: None,
            oracle: oracle.clone(),
            final_value: None,
            final_poly: None,
            step,
        }
    }

    pub fn commit_polynomial(&self) -> Commit<T> {
        Commit {
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
                tmp_folding_value.push(new_v * T::inverse_2());
            }
            get_folding_value = tmp_folding_value;
        }
        get_folding_value
    }

    fn sumcheck_next_domain(hypercube_interpolation: &mut Vec<T>, m: usize, challenge: T) {
        for i in 0..m {
            hypercube_interpolation[i] *= T::from_int(1) - challenge;
            let tmp = hypercube_interpolation[i + m] * challenge;
            hypercube_interpolation[i] += tmp;
        }
        hypercube_interpolation.truncate(m);
    }

    pub fn prove(&mut self, point: Vec<T>) {
        let mut hypercube_interpolation = self.hypercube_interpolation.clone();
        self.shuffle_eval = Some(DeepEval::new(
            point.clone(),
            hypercube_interpolation.clone(),
        ));
        for i in 0..self.total_round / self.step + 1 {
            let mut challenges: Vec<T> = vec![];
            for j in 0..self.step {
                if i * self.step + j == self.total_round {
                    break;
                }
                challenges.push(self.oracle.folding_challenges[i * self.step + j]);
            }

            for j in 0..self.step {
                if i * self.step + j == self.total_round {
                    break;
                }
                self.shuffle_eval
                    .as_mut()
                    .unwrap()
                    .append_else_eval(hypercube_interpolation.clone());
                for deep in &mut self.deep_eval {
                    deep.append_else_eval(hypercube_interpolation.clone());
                }

                if i * self.step + j < self.total_round - 1 {
                    let m = 1 << (self.total_round - (i * self.step + j) - 1);
                    Self::sumcheck_next_domain(&mut hypercube_interpolation, m, challenges[j]);
                    self.deep_eval.push({
                        let deep_point = std::iter::successors(
                            Some(self.oracle.deep[i * self.step + j + 1]),
                            |&x| Some(x * x),
                        )
                        .take(self.total_round - (i * self.step + j) - 1)
                        .collect::<Vec<_>>();
                        DeepEval::new(deep_point.clone(), hypercube_interpolation.clone())
                    });
                }
            }

            let next_evaluation = self.evaluation_next_domain(i, &challenges);
            if i < self.total_round / self.step - 1 {
                self.interpolations
                    .push(InterpolateValue::new(next_evaluation, 1 << self.step));
            } else if i == self.total_round / self.step - 1 {
                self.interpolations.push(InterpolateValue::new(
                    next_evaluation.clone(),
                    1 << self.step,
                ));
                self.final_poly = Some(Polynomial::new(
                    self.interpolate_cosets[(i + 1) * self.step].ifft(next_evaluation),
                ));
            } else {
                assert_eq!(next_evaluation.len(), 1 << CODE_RATE);
                self.final_value = Some(next_evaluation[0]);
            }
        }
    }
    pub fn query(&self) -> Vec<QueryResult<T>> {
        let mut res = vec![];
        let mut leaf_indices = self.oracle.query_list.clone();

        for i in 0..self.total_round / self.step + 1 {
            let len = self.interpolate_cosets[i * self.step].size();
            leaf_indices = leaf_indices
                .iter_mut()
                .map(|v| *v % (len >> self.step))
                .collect();
            leaf_indices.sort();
            leaf_indices.dedup();
            res.push(self.interpolations[i].query(&leaf_indices));
        }
        res
    }

    pub fn generate_proof(mut self, point: Vec<T>) -> Proof<T> {
        self.prove(point);
        let query_result = self.query();
        Proof {
            merkle_root: (1..self.total_round / self.step)
                .into_iter()
                .map(|x| self.interpolations[x].commit())
                .collect(),
            query_result,
            deep_evals: self
                .deep_eval
                .iter()
                .map(|x| (x.first_eval, x.else_evals.clone()))
                .collect(),
            shuffle_evals: self.shuffle_eval.as_ref().unwrap().else_evals.clone(),
            final_value: self.final_value.unwrap(),
            final_poly: self.final_poly.unwrap(),
            evaluation: self.shuffle_eval.as_ref().unwrap().first_eval,
        }
    }
}

/// Verifier for Deepfold PCS.
#[derive(Clone)]
pub struct Verifier<T: MyField + Field> {
    total_round: usize,
    interpolate_cosets: Vec<Coset<T>>,
    polynomial_roots: Vec<MerkleTreeVerifier>,
    first_deep: T,
    oracle: RandomOracle<T>,
    final_value: Option<T>,
    final_poly: Option<Polynomial<T>>,
    shuffle_eval: Option<DeepEval<T>>,
    deep_evals: Vec<DeepEval<T>>,
    open_point: Vec<T>,
    step: usize,
}

impl<T: MyField + ff::Field> Verifier<T> {
    pub fn new(
        total_round: usize,
        cosets: &Vec<Coset<T>>,
        commit: Commit<T>,
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> Self {
        Verifier {
            total_round,
            interpolate_cosets: cosets.clone(),
            oracle: oracle.clone(),
            polynomial_roots: vec![MerkleTreeVerifier::new(
                cosets[0].size() / (1 << step),
                &commit.merkle_root,
            )],
            first_deep: commit.deep,
            final_value: None,
            final_poly: None,
            shuffle_eval: None,
            deep_evals: vec![],
            open_point: (0..total_round).map(|_| T::random_element()).collect(),
            step,
        }
    }

    pub fn get_open_point(&self) -> Vec<T> {
        self.open_point.clone()
    }

    pub fn set_open_point(&mut self, point: &Vec<T>) {
        self.open_point = point.clone();
    }

    pub fn verify(mut self, proof: Proof<T>) -> bool {
        self.final_value = Some(proof.final_value);
        self.final_poly = Some(proof.final_poly);
        let mut leave_number = self.interpolate_cosets[0].size() / (1 << self.step);
        for merkle_root in proof.merkle_root {
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
        assert_eq!(self.first_deep, proof.deep_evals[0].0);
        proof
            .deep_evals
            .into_iter()
            .enumerate()
            .for_each(|(idx, (first_eval, else_evals))| {
                self.deep_evals.push(DeepEval {
                    point: std::iter::successors(Some(self.oracle.deep[idx]), |&x| Some(x * x))
                        .take(self.total_round - idx)
                        .collect::<Vec<_>>(),
                    first_eval,
                    else_evals,
                });
            });
        self._verify(&proof.query_result)
    }

    fn _verify(&self, polynomial_proof: &Vec<QueryResult<T>>) -> bool {
        let mut leaf_indices = self.oracle.query_list.clone();
        for i in 0..self.total_round / self.step {
            let domain_size = self.interpolate_cosets[i * self.step].size();
            leaf_indices = leaf_indices
                .iter_mut()
                .map(|v| *v % (domain_size / (1 << self.step)))
                .collect();
            leaf_indices.sort();
            leaf_indices.dedup();

            polynomial_proof[i].verify_merkle_tree(
                &leaf_indices,
                1 << self.step,
                &self.polynomial_roots[i],
            );

            if i == self.total_round / self.step - 1 {
                let challenges = self.oracle.folding_challenges[0..self.total_round].to_vec();
                assert_eq!(
                    self.shuffle_eval.as_ref().unwrap().verify(&challenges),
                    self.final_value.unwrap()
                );
                for j in &self.deep_evals {
                    assert_eq!(j.verify(&challenges), self.final_value.unwrap());
                }
            }

            let folding_value = &polynomial_proof[i].proof_values;
            let mut challenge = vec![];
            for j in 0..self.step {
                challenge.push(self.oracle.folding_challenges[i * self.step + j]);
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
                    for l in 0..size / 2 {
                        let x = verify_values[l];
                        let nx = verify_values[l + size / 2];
                        tmp_values.push(
                            (x + nx
                                + challenge[j]
                                    * (x - nx)
                                    * self.interpolate_cosets[i * self.step + j]
                                        .element_inv_at(verify_inds[l]))
                                * T::inverse_2(),
                        );
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

//
// =================== PolynomialCommitmentScheme Trait Implementation ===================
//

/// Setup parameters for Deepfold PCS.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeepfoldSetupParam<F: MyField + ff::Field> {
    pub total_round: usize,
    pub cosets: Vec<Coset<F>>,
    pub oracle: RandomOracle<F>,
    pub step: usize,
}

#[derive(Clone, Debug)]
pub struct Deepfold;

impl<F> PolynomialCommitmentScheme<F> for Deepfold
where
    F: MyField + Field + Serialize + for<'de> Deserialize<'de> + Default + Debug + Clone,
{
    type Param = DeepfoldSetupParam<F>;
    type ProverParam = DeepfoldSetupParam<F>;
    type VerifierParam = DeepfoldSetupParam<F>;
    type Polynomial = MultilinearPolynomial<F>;
    type Commitment = Commit<F>;
    type CommitmentChunk = [u8; MERKLE_ROOT_SIZE];

    fn setup(
        poly_size: usize,
        _batch_size: usize,
        _rng: impl RngCore,
    ) -> Result<Self::Param, Error> {
        
        let num_vars = poly_size.trailing_zeros() as usize;

        // total_round is defined to be the number of variables.
        let total_round = num_vars;

        // Incorporate CODE_RATE: the intended base domain should be 1 << (num_vars + CODE_RATE)
        let base_size = 1 << (num_vars + CODE_RATE);
        let one = F::from_int(1);
        let coset0 = Coset::new(base_size, one);
        let mut cosets = vec![coset0];
        // Generate one coset per variable (i.e. for each round)
        for _ in 1..=num_vars {
            let last = cosets.last().unwrap();
            cosets.push(last.pow(2));
        }
        let step = STEP;
        let oracle = RandomOracle::new(total_round, SECURITY_BITS / CODE_RATE);
        Ok(DeepfoldSetupParam {
            total_round,
            cosets,
            oracle,
            step,
        })
    }

    fn trim(
        param: &Self::Param,
        _poly_size: usize,
        _batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        // No trusted setup is needed; use the same parameters.
        Ok((param.clone(), param.clone()))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        let prover = Prover::new(
            pp.total_round,
            &pp.cosets,
            poly.clone(),
            &pp.oracle,
            pp.step,
        );
        Ok(prover.commit_polynomial())
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        polys
            .into_iter()
            .map(|poly| Self::commit(pp, poly))
            .collect()
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        _comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        // Generate a full Deepfold proof at the specified opening point.
        let mut prover = Prover::new(
            pp.total_round,
            &pp.cosets,
            poly.clone(),
            &pp.oracle,
            pp.step,
        );
        let proof = prover.generate_proof(point.clone());
        if proof.evaluation != *eval {
            return Err(Error::InvalidPcsParam(format!(
                "Evaluation mismatch: expected {:?}, got {:?}",
                eval, proof.evaluation
            )));
        }
        // Write the Merkle roots (one per round, except the first) to the transcript.
        for root in proof.merkle_root.iter() {
            transcript.write_commitments(&[*root])?;
        }
        // Write the final value and evaluation as field elements.
        transcript.write_field_elements(&[proof.final_value, proof.evaluation])?;
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
        for ((poly, _comm), (point, eval)) in
            polys.iter().zip(comms).zip(points.iter().zip(evals.iter()))
        {
            Self::open(pp, poly, _comm, point, &eval.value, transcript)?;
        }
        Ok(())
    }

    fn read_commitments(
        _vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let comms = transcript.read_commitments(num_polys)?;
        Ok(comms
            .into_iter()
            .map(|chunk| Commit {
                merkle_root: chunk,
                deep: F::default(),
            })
            .collect())
    }

    fn verify(
        vp: &Self::VerifierParam,
        _comm: &Self::Commitment,
        _point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let num_merkle = if vp.total_round % vp.step == 0 {
            vp.total_round / vp.step - 1
        } else {
            vp.total_round / vp.step
        };
        let mut merkle_roots = Vec::with_capacity(num_merkle);
        for _ in 0..num_merkle {
            let roots = transcript.read_commitments(1)?;
            merkle_roots.push(roots[0]);
        }
        let fields = transcript.read_field_elements(2)?;
        if fields.len() != 2 {
            return Err(Error::InvalidPcsParam(
                "Not enough field elements in transcript".into(),
            ));
        }
        let final_value = fields[0];
        let evaluation = fields[1];
        let proof = Proof {
            merkle_root: merkle_roots,
            query_result: vec![],
            deep_evals: vec![],
            shuffle_evals: vec![],
            evaluation,
            final_value,
            final_poly: Polynomial::new(vec![]),
        };
        let verifier = Verifier::new(
            vp.total_round,
            &vp.cosets,
            _comm.clone(),
            &vp.oracle,
            vp.step,
        );
        if !verifier.verify(proof) {
            return Err(Error::InvalidPcsParam(
                "Deepfold verification failed".into(),
            ));
        }
        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let comms: Vec<_> = comms.into_iter().collect();
        for ((comm, point), eval) in comms.iter().zip(points.iter()).zip(evals.iter()) {
            Self::verify(vp, comm, point, &eval.value, transcript)?;
        }
        Ok(())
    }
}
