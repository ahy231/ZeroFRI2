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

#[derive(Clone)]
pub struct Storage {
    pub pcs: Option<MyPcs>,
    pub domains_and_polys_by_round: Option<
        Vec<
            Vec<(
                TwoAdicMultiplicativeCoset<Bn254Fr>,
                DenseMatrix<Bn254Fr, Vec<Bn254Fr>>,
            )>,
        >,
    >,
    pub commits_by_round: Option<Vec<p3_symmetric::Hash<Bn254Fr, u8, 32>>>,
    pub data_by_round: Option<Vec<MerkleTree<Bn254Fr, u8, DenseMatrix<Bn254Fr, Vec<Bn254Fr>>, 32>>>,
    pub opening_by_round: Option<Vec<Vec<Vec<Vec<FakeExtension>>>>>,
    pub challenger: Option<SerializingChallenger64<Bn254Fr, HashChallenger<u8, Keccak256Hash, 32>>>,
    pub proof: Option<
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
    >,
}

pub static mut STORAGE: Storage = Storage {
    pcs: None,
    domains_and_polys_by_round: None,
    commits_by_round: None,
    data_by_round: None,
    opening_by_round: None,
    proof: None,
    challenger: None,
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
