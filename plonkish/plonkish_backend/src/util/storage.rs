use p3_baby_bear::{BabyBear, BabyBearParameters, Poseidon2BabyBear};
use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger};
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::ExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use p3_merkle_tree::{MerkleTree, MerkleTreeMmcs};
use p3_monty_31::MontyField31;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

pub type Val = BabyBear;
pub type Challenge = BinomialExtensionField<Val, 4>;

pub type Perm = Poseidon2BabyBear<16>;
pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

pub type ValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MyHash,
    MyCompress,
    8,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

pub type Dft = Radix2DitParallel<Val>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub struct Storage {
    pub pcs: Option<MyPcs>,
    pub commits_by_round: Option<Vec<MyHash>>,
    pub data_by_round: Option<Vec<ValMmcs>>,
    pub perm: Option<Perm>,
}

pub static mut STORAGE: Storage = Storage {
    pcs: None,
    commits_by_round: None,
    data_by_round: None,
    perm: None,
};

pub fn get_pcs(perm: Perm, log_blowup: usize) -> MyPcs {
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());

    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_config = FriConfig {
        log_blowup: log_blowup,
        log_final_poly_len: 0,
        num_queries: 10,
        proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };

    MyPcs::new(Dft::default(), val_mmcs, fri_config)
}
