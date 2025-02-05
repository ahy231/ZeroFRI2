use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
};

use ff::PrimeField;
use generic_array::{
    typenum::{UInt, UTerm, B0, B1},
    GenericArray,
};
use halo2_curves::bn256::Fr;
use halo2_proofs::transcript::TranscriptWrite;
use p3_baby_bear::{BabyBear, BabyBearParameters, Poseidon2BabyBear};
use p3_bn254_fr::{Bn254Fr, FakeExtension};
use p3_challenger::{
    CanObserve, DuplexChallenger, FieldChallenger, HashChallenger, SerializingChallenger64,
};
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::ExtensionField;
use p3_fri::{BatchOpening, FriConfig, FriProof, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use p3_merkle_tree::{MerkleTree, MerkleTreeMmcs};
use p3_monty_31::MontyField31;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher64, TruncatedPermutation,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::pcs::univariate::{FriCommitment, P3FriCommitment};

use super::{
    hash::Blake2s,
    transcript::{Blake2sTranscript, Transcript},
};

pub type Val = Bn254Fr;
pub type Challenge = FakeExtension;

pub type ByteHash = Keccak256Hash;
pub type FieldHash = SerializingHasher64<ByteHash>;

pub type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

pub type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;

pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

pub type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;

pub type Dft = Radix2DitParallel<Val>;

pub type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub const MAX_POLYS: usize = 10000;

pub struct Storage {
    // mock data
    pub recording: bool,
    pub recording_mutex: Mutex<[bool; 3]>,
    pub recording_comm: Option<Vec<Fr>>,

    pub commit_result: Option<P3FriCommitment<Fr, Blake2s>>,
    pub query_result: [Option<(Vec<(Vec<(Fr, Fr)>, Vec<usize>)>, Vec<usize>)>; MAX_POLYS],
    pub open_transcript: Option<Blake2sTranscript<Blake2s>>,

    // bench data
    pub proof_size: Mutex<usize>,
    pub counter: Mutex<u128>,
    pub pcs: Option<Arc<Mutex<MyPcs>>>,
    pub domains_and_polys_by_round: [Option<
        Vec<
            Vec<(
                TwoAdicMultiplicativeCoset<Bn254Fr>,
                DenseMatrix<Bn254Fr, Vec<Bn254Fr>>,
            )>,
        >,
    >; MAX_POLYS],
    pub commits_by_round: [Option<Vec<p3_symmetric::Hash<Bn254Fr, u8, 32>>>; MAX_POLYS],
    pub data_by_round:
        [Option<Vec<MerkleTree<Bn254Fr, u8, DenseMatrix<Bn254Fr, Vec<Bn254Fr>>, 32>>>; MAX_POLYS],
    pub opening_by_round: [Option<Vec<Vec<Vec<Vec<FakeExtension>>>>>; MAX_POLYS],
    pub challenger: [Option<
        SerializingChallenger64<Bn254Fr, HashChallenger<u8, Keccak256Hash, 32>>,
    >; MAX_POLYS],
    pub proof: [Option<
        FriProof<
            FakeExtension,
            ExtensionMmcs<
                Bn254Fr,
                FakeExtension,
                MerkleTreeMmcs<
                    Bn254Fr,
                    u8,
                    SerializingHasher64<Keccak256Hash>,
                    CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
                    32,
                >,
            >,
            Bn254Fr,
            Vec<
                BatchOpening<
                    Bn254Fr,
                    MerkleTreeMmcs<
                        Bn254Fr,
                        u8,
                        SerializingHasher64<Keccak256Hash>,
                        CompressionFunctionFromHasher<Keccak256Hash, 2, 32>,
                        32,
                    >,
                >,
            >,
        >,
    >; MAX_POLYS],
}

pub static mut STORAGE: Storage = Storage {
    recording: false,
    recording_mutex: Mutex::new([false; 3]),
    recording_comm: None,

    proof_size: Mutex::new(0),
    commit_result: None,
    query_result: [const { None }; MAX_POLYS],
    open_transcript: None,
    counter: Mutex::new(0),
    pcs: None,
    domains_and_polys_by_round: [const { None }; MAX_POLYS],
    commits_by_round: [const { None }; MAX_POLYS],
    data_by_round: [const { None }; MAX_POLYS],
    opening_by_round: [const { None }; MAX_POLYS],
    proof: [const { None }; MAX_POLYS],
    challenger: [const { None }; MAX_POLYS],
};

pub fn get_pcs(log_blowup: usize) -> MyPcs {
    let log_blowup = 4;

    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);
    let compress = MyCompress::new(byte_hash);

    let val_mmcs = ValMmcs::new(field_hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_config = FriConfig {
        log_blowup,
        log_final_poly_len: 0,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    MyPcs::new(Dft::default(), val_mmcs, fri_config)
}
