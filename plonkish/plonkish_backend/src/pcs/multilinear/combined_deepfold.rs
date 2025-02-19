use std::mem::size_of;

// Common imports
use crate::util::{
    algebra::CODE_RATE,
    algebra::{
        coset::Coset,
        field::MyField,
        polynomial::{MultilinearPolynomial, Polynomial},
    },
    interpolation::InterpolateValue,
    merkle_tree::{MerkleTreeVerifier, MERKLE_ROOT_SIZE},
    query_result::QueryResult,
    random_oracle::RandomOracle,
};

#[derive(Clone)]
pub struct DeepEval<T: MyField> {
    point: Vec<T>,
    first_eval: T,
    else_evals: Vec<T>,
}

impl<T: MyField> DeepEval<T> {
    pub fn new(point: Vec<T>, poly_hypercube: Vec<T>) -> Self {
        DeepEval {
            point: point.clone(),
            first_eval: Self::evaluatioin_at(point, poly_hypercube),
            else_evals: vec![],
        }
    }

    fn evaluatioin_at(point: Vec<T>, mut poly_hypercube: Vec<T>) -> T {
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
            .push(Self::evaluatioin_at(point, poly_hypercube));
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

pub struct Commit<T: MyField> {
    merkle_root: [u8; MERKLE_ROOT_SIZE],
    deep: T,
}

#[derive(Clone)]
pub struct Proof<T: MyField> {
    merkle_root: Vec<[u8; MERKLE_ROOT_SIZE]>,
    query_result: Vec<QueryResult<T>>,
    deep_evals: Vec<(T, Vec<T>)>,
    shuffle_evals: Vec<T>,
    evaluation: T,
    final_value: T,
    final_poly: Polynomial<T>,
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

#[derive(Clone)]
pub struct Prover<T: MyField> {
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

impl<T: MyField> Prover<T> {
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
                interpolate_cosets[0].fft(polynomial.coefficients().clone()),
                1 << step,
            )],
            hypercube_interpolation: hypercube_interpolation.clone(),
            deep_eval: vec![DeepEval::new(point.clone(), hypercube_interpolation)],
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

            let next_evalutation = self.evaluation_next_domain(i, &challenges);
            if i < self.total_round / self.step - 1 {
                self.interpolations
                    .push(InterpolateValue::new(next_evalutation, 1 << self.step));
            } else if i == self.total_round / self.step - 1 {
                self.interpolations.push(InterpolateValue::new(
                    next_evalutation.clone(),
                    1 << self.step,
                ));
                self.final_poly = Some(Polynomial::new(
                    self.interpolate_cosets[(i + 1) * self.step].ifft(next_evalutation),
                ));
            } else {
                assert_eq!(next_evalutation.len(), 1 << CODE_RATE);
                self.final_value = Some(next_evalutation[0]);
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

#[derive(Clone)]
pub struct Verifier<T: MyField> {
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

impl<T: MyField> Verifier<T> {
    pub fn new(
        total_round: usize,
        coset: &Vec<Coset<T>>,
        commit: Commit<T>,
        oracle: &RandomOracle<T>,
        step: usize,
    ) -> Self {
        Verifier {
            total_round,
            interpolate_cosets: coset.clone(),
            oracle: oracle.clone(),
            polynomial_roots: vec![MerkleTreeVerifier::new(
                coset[0].size() / (1 << step),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::algebra::{field::m31_ext::M31ext, CODE_RATE, SECURITY_BITS, SIZE, STEP};
    use csv::Writer;

    fn output_proof_size<T: MyField>(variable_num: usize) -> usize {
        let polynomial = MultilinearPolynomial::random_polynomial(variable_num);
        let mut interpolate_cosets =
            vec![Coset::new(1 << (variable_num + CODE_RATE), T::from_int(1))];
        for i in 1..variable_num + 1 {
            interpolate_cosets.push(interpolate_cosets[i - 1].pow(2));
        }
        let oracle = RandomOracle::new(variable_num, SECURITY_BITS / CODE_RATE);
        let prover = Prover::new(variable_num, &interpolate_cosets, polynomial, &oracle, STEP);
        let commit = prover.commit_polynomial();
        let verifier = Verifier::new(variable_num, &interpolate_cosets, commit, &oracle, STEP);
        let point = verifier.get_open_point();
        let proof = prover.generate_proof(point);
        let size = proof.size();
        assert!(verifier.verify(proof));
        size
    }

    #[test]
    fn test_proof_size() {
        let mut wtr = Writer::from_path("deepfold.csv").unwrap();
        let range = 10..SIZE;
        for i in range.clone() {
            let proof_size = output_proof_size::<M31ext>(i);
            wtr.write_record(&[i.to_string(), proof_size.to_string()])
                .unwrap();
        }
    }
}
