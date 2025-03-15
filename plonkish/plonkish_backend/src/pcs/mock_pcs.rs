use crate::poly::multilinear::MultilinearPolynomial;
use crate::poly::Polynomial;
use crate::util::hash::Blake2s;
use crate::util::poly_loader::container::MatrixContainer;
use crate::{
    pcs::{AdditiveCommitment, Evaluation, Point, PolynomialCommitmentScheme},
    util::{
        arithmetic::PrimeField,
        hash::Hash,
        poly_loader::container::Field as CF,
        transcript::{TranscriptRead, TranscriptWrite},
        DeserializeOwned, Itertools, Serialize,
    },
    Error,
};

use itertools::izip;
use rand_chacha::rand_core::RngCore;
use serde::Deserialize;
use serde_json::to_string;
use sha2::digest::{Output, OutputSizeUser};

use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockParams<F: PrimeField> {
    pub phantom: PhantomData<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockProverParams<F: PrimeField> {
    pub phantom: PhantomData<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MockVerifierParams<F: PrimeField> {
    pub phantom: PhantomData<F>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: DeserializeOwned"))]
pub struct MockCommitment<F: PrimeField, H: Hash> {
    pub phantom: PhantomData<H>,
    pub poly: MultilinearPolynomial<F>,
}

impl<F: PrimeField, H: Hash> AsRef<[Output<Blake2s>]> for MockCommitment<F, H> {
    fn as_ref(&self) -> &[Output<Blake2s>] {
        &[]
    }
}

impl<F: PrimeField, H: Hash> PartialEq for MockCommitment<F, H> {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

pub static mut FIELD: Option<CF> = None;
pub static mut CONTAINER: Option<MatrixContainer> = None;
pub static mut PCS_RECORDER: Option<Vec<(PcsOps, usize)>> = None;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum PcsOps {
    Commit,
    Open,
    Verify,
}

impl<F: PrimeField, H: Hash> Eq for MockCommitment<F, H> {}
#[derive(Debug)]
pub struct MockPcs<F: PrimeField, H: Hash> {
    phantom: PhantomData<(F, H)>,
}

impl<F: PrimeField, H: Hash> Clone for MockPcs<F, H> {
    fn clone(&self) -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<F: PrimeField, H: Hash> AsRef<[MockCommitment<F, H>]> for MockCommitment<F, H> {
    fn as_ref(&self) -> &[MockCommitment<F, H>] {
        std::slice::from_ref(self)
    }
}
impl<F: PrimeField, H: Hash> AdditiveCommitment<F> for MockCommitment<F, H> {
    fn sum_with_scalar<'a>(
        scalars: impl IntoIterator<Item = &'a F> + 'a,
        bases: impl IntoIterator<Item = &'a Self> + 'a,
    ) -> Self {
        let mut poly = MultilinearPolynomial::<F>::default();
        for (scalar, base) in scalars.into_iter().zip(bases) {
            poly += (scalar, &base.poly);
        }
        Self {
            phantom: PhantomData,
            poly,
        }
    }
}
impl<F, H> PolynomialCommitmentScheme<F> for MockPcs<F, H>
where
    F: PrimeField + Serialize + DeserializeOwned,
    H: Hash,
{
    type Param = MockParams<F>;
    type ProverParam = MockProverParams<F>;
    type VerifierParam = MockVerifierParams<F>;
    type Polynomial = MultilinearPolynomial<F>;
    type Commitment = MockCommitment<F, H>;
    type CommitmentChunk = MockCommitment<F, H>;

    fn setup(poly_size: usize, batch_size: usize, rng: impl RngCore) -> Result<Self::Param, Error> {
        unsafe {
            CONTAINER = Some(MatrixContainer::new(
                poly_size,
                batch_size,
                FIELD.unwrap().clone(),
            ));
            CONTAINER.as_mut().unwrap().new_round();
            PCS_RECORDER = Some(Vec::new());
        }

        Ok(MockParams {
            phantom: PhantomData,
        })
    }

    fn trim(
        param: &Self::Param,
        poly_size: usize,
        batch_size: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        Ok((
            MockProverParams {
                phantom: PhantomData,
            },
            MockVerifierParams {
                phantom: PhantomData,
            },
        ))
    }

    fn commit(pp: &Self::ProverParam, poly: &Self::Polynomial) -> Result<Self::Commitment, Error> {
        if poly.evals().len() > 0 {
            unsafe {
                CONTAINER.as_mut().unwrap().push_matrix(vec![poly
                    .clone()
                    .into_evals()
                    .into_iter()
                    .map(|f| format!("{:?}", f))
                    .collect_vec()]);
                PCS_RECORDER.as_mut().unwrap().push((PcsOps::Commit, 1));
            }
        }

        Ok(Self::Commitment {
            phantom: PhantomData,
            poly: poly.clone(),
        })
    }

    fn batch_commit<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        let polys = polys.into_iter().collect_vec();
        if polys.len() > 0 && polys[0].evals().len() > 0 {
            unsafe {
                CONTAINER.as_mut().unwrap().push_matrix(
                    polys
                        .clone()
                        .into_iter()
                        .map(|p| {
                            p.clone()
                                .into_evals()
                                .into_iter()
                                .map(|f| format!("{:?}", f))
                                .collect_vec()
                        })
                        .collect_vec(),
                );
                PCS_RECORDER
                    .as_mut()
                    .unwrap()
                    .push((PcsOps::Commit, polys.len()));
            }
        }
        Ok(polys
            .into_iter()
            .map(|p| Self::Commitment {
                phantom: PhantomData,
                poly: p.clone(),
            })
            .collect_vec())
    }

    fn open(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        if poly.evals().len() > 0 {
            unsafe {
                CONTAINER.as_mut().unwrap().poly_points.push((
                    poly.coefficients()
                        .into_iter()
                        .map(|f| format!("{:?}", f))
                        .collect_vec(),
                    point
                        .clone()
                        .into_iter()
                        .map(|f| format!("{:?}", f))
                        .collect_vec(),
                    format!("{:?}", eval),
                ));
                PCS_RECORDER.as_mut().unwrap().push((PcsOps::Open, 1));
            }
        }
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
        let polys = polys.into_iter().collect_vec();
        let comms = comms.into_iter().collect_vec();

        if polys.len() > 0 && polys[0].evals().len() > 0 {
            unsafe {
                for eval in evals {
                    CONTAINER.as_mut().unwrap().poly_points.push((
                        polys[eval.poly]
                            .clone()
                            .into_evals()
                            .into_iter()
                            .map(|f| format!("{:?}", f))
                            .collect_vec(),
                        points[eval.point]
                            .clone()
                            .into_iter()
                            .map(|f| format!("{:?}", f))
                            .collect_vec(),
                        format!("{:?}", eval.value),
                    ));
                }
                PCS_RECORDER
                    .as_mut()
                    .unwrap()
                    .push((PcsOps::Open, polys.len()));
            }
        }

        Ok(())
    }

    fn verify(
        vp: &Self::VerifierParam,
        comm: &Self::Commitment,
        point: &Point<F, Self::Polynomial>,
        eval: &F,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn batch_verify<'a>(
        vp: &Self::VerifierParam,
        comms: impl IntoIterator<Item = &'a Self::Commitment>,
        points: &[Point<F, Self::Polynomial>],
        evals: &[Evaluation<F>],
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<(), Error> {
        let comms = comms.into_iter().collect_vec();
        Ok(())
    }

    fn commit_and_write(
        pp: &Self::ProverParam,
        poly: &Self::Polynomial,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        let comm = Self::commit(pp, poly)?;

        transcript.write_commitment(&comm)?;

        Ok(comm)
    }

    fn batch_commit_and_write<'a>(
        pp: &Self::ProverParam,
        polys: impl IntoIterator<Item = &'a Self::Polynomial>,
        transcript: &mut impl TranscriptWrite<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error>
    where
        Self::Polynomial: 'a,
    {
        let comms = Self::batch_commit(pp, polys)?;
        transcript.write_commitments(comms.iter())?;
        Ok(comms)
    }

    fn read_commitment(
        vp: &Self::VerifierParam,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Self::Commitment, Error> {
        Ok(transcript.read_commitment()?)
    }

    fn read_commitments(
        vp: &Self::VerifierParam,
        num_polys: usize,
        transcript: &mut impl TranscriptRead<Self::CommitmentChunk, F>,
    ) -> Result<Vec<Self::Commitment>, Error> {
        Ok(transcript.read_commitments(num_polys)?)
    }
}
