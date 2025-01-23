use p3_bn254_fr::{Bn254Fr, FakeExtension};
use p3_circle::CirclePcs;
use rand::rngs::OsRng;

use itertools::{izip, Itertools};
use plonkish_backend::util::{end_timer, start_timer, Serialize};

use std::{
    env::args,
    fmt::Display,
    fs::{create_dir, File, OpenOptions},
    io::Write,
    iter,
    marker::PhantomData,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::{CanObserve, DuplexChallenger, FieldChallenger, SerializingChallenger64};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field};
use p3_fri::{create_test_fri_config, FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32, SerializingHasher64};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use rand::distributions::{Distribution, Standard};
use rand::Rng;

const OUTPUT_DIR: &str = "./bench_data/plonky3_pcs";

fn main() {
    let (systems, k_range, rounds, repetition) = parse_args();
    create_output(&systems);
    k_range.for_each(|k| {
        systems
            .iter()
            .for_each(|system| system.bench(k, rounds, repetition))
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    Fri,
    Circle,
    BigFieldFri,
}

impl System {
    fn all() -> Vec<System> {
        vec![System::Fri, System::Circle]
    }

    fn output_path(&self) -> String {
        format!("{OUTPUT_DIR}/open_{self}")
    }

    fn output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.output_path())
            .unwrap()
    }

    fn commit_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/commit_{self}")
    }

    fn size_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/size_{self}")
    }

    fn verify_output_path(&self) -> String {
        format!("{OUTPUT_DIR}/verify_{self}")
    }

    fn commit_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.commit_output_path())
            .unwrap()
    }

    fn size_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.size_output_path())
            .unwrap()
    }

    fn verify_output(&self) -> File {
        OpenOptions::new()
            .append(true)
            .open(self.verify_output_path())
            .unwrap()
    }

    fn bench(&self, k: usize, rounds: usize, repetition: usize) {
        match self {
            System::Fri => {
                type Val = BabyBear;
                type Challenge = BinomialExtensionField<Val, 4>;

                type Perm = Poseidon2BabyBear<16>;
                type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
                type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

                type ValMmcs = MerkleTreeMmcs<
                    <Val as Field>::Packing,
                    <Val as Field>::Packing,
                    MyHash,
                    MyCompress,
                    8,
                >;
                type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

                type Dft = Radix2DitParallel<Val>;
                type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

                let log_blowup = 4;

                let perm = Perm::new_from_rng_128(&mut seeded_rng());
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());

                let val_mmcs = ValMmcs::new(hash, compress);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

                let fri_config = FriConfig {
                    log_blowup,
                    log_final_poly_len: 0,
                    num_queries: 10,
                    proof_of_work_bits: 8,
                    mmcs: challenge_mmcs,
                };
                let pcs = TwoAdicFriPcs::<Val, Dft, ValMmcs, ChallengeMmcs>::new(
                    Dft::default(),
                    val_mmcs,
                    fri_config,
                );

                do_bench_pcs(
                    k,
                    System::Fri,
                    &(pcs, Challenger::new(perm.clone())),
                    vec![vec![k; repetition]; rounds],
                );
            }
            System::Circle => {
                type Val = Mersenne31;
                type Challenge = BinomialExtensionField<Mersenne31, 3>;

                type ByteHash = Keccak256Hash;
                type FieldHash = SerializingHasher32<ByteHash>;
                let byte_hash = ByteHash {};
                let field_hash = FieldHash::new(byte_hash);

                type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
                let compress = MyCompress::new(byte_hash);

                type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
                let val_mmcs = ValMmcs::new(field_hash, compress);

                type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

                type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

                let fri_config = create_test_fri_config(challenge_mmcs);

                type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
                let pcs = Pcs {
                    mmcs: val_mmcs,
                    fri_config,
                    _phantom: PhantomData,
                };

                let byte_hash = ByteHash {};
                let chal = Challenger::from_hasher(vec![], byte_hash);

                do_bench_pcs(
                    k,
                    System::Circle,
                    &(pcs, chal),
                    vec![vec![k; repetition]; rounds],
                );
            }
            System::BigFieldFri => {
                type Val = Bn254Fr;
                type Challenge = FakeExtension;

                type ByteHash = Keccak256Hash;
                type FieldHash = SerializingHasher64<ByteHash>;

                type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

                type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;

                type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

                type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;

                type Dft = Radix2DitParallel<Val>;

                type MyPcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

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

                let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_config);

                do_bench_pcs(
                    k,
                    System::BigFieldFri,
                    &(pcs, Challenger::from_hasher(vec![], byte_hash)),
                    vec![vec![k; repetition]; rounds],
                );
            }
        }
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::Fri => write!(f, "fri"),
            System::Circle => write!(f, "circle"),
            System::BigFieldFri => write!(f, "big_field_fri"),
        }
    }
}

fn parse_args() -> (Vec<System>, Range<usize>, usize, usize) {
    let (systems, k_range, rounds, repetition) =
        args().chain(Some("".to_string())).tuple_windows().fold(
            (Vec::new(), 10..23, 1, 1),
            |(mut systems, mut k_range, mut rounds, mut repetition), (key, value)| {
                match key.as_str() {
                    "--system" => match value.as_str() {
                        "all" => systems = vec![System::Fri, System::Circle, System::BigFieldFri],
                        "fri" => systems.push(System::Fri),
                        "circle" => systems.push(System::Circle),
                        "big_field_fri" => systems.push(System::BigFieldFri),
                        _ => panic!("system should be one of {{all,fri}}"),
                    },
                    "--k" => {
                        if let Some((start, end)) = value.split_once("..") {
                            k_range = start.parse().expect("k range start to be usize")
                                ..end.parse().expect("k range end to be usize");
                        } else {
                            k_range.start = value.parse().expect("k to be usize");
                            k_range.end = k_range.start + 1;
                        }
                    }
                    "--rounds" => {
                        rounds = value.parse().expect("rounds to be usize");
                    }
                    "--repetition" => {
                        repetition = value.parse().expect("repetition to be usize");
                    }
                    _ => {}
                }
                (systems, k_range, rounds, repetition)
            },
        );

    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = System::all();
    };
    (systems, k_range, rounds, repetition)
}

fn create_output(systems: &[System]) {
    if !Path::new(OUTPUT_DIR).exists() {
        create_dir(OUTPUT_DIR).unwrap();
    }
    for system in systems {
        File::create(system.output_path()).unwrap();
        File::create(system.commit_output_path()).unwrap();
        File::create(system.size_output_path()).unwrap();
        File::create(system.verify_output_path()).unwrap();
    }
}

fn sample<T>(system: System, k: usize, prove: impl Fn() -> T) -> T {
    let mut proof = None;
    let sample_size = sample_size(k);
    let sum = iter::repeat_with(|| {
        let start = Instant::now();
        proof = Some(prove());
        start.elapsed()
    })
    .take(sample_size)
    .sum::<Duration>();
    let avg = sum / sample_size as u32;
    writeln!(&mut system.output(), "{k}, {}", avg.as_millis()).unwrap();
    proof.unwrap()
}

fn sample_size(k: usize) -> usize {
    if k < 16 {
        20
    } else if k < 20 {
        5
    } else {
        1
    }
}

fn seeded_rng() -> impl Rng {
    OsRng::default()
}

fn do_bench_pcs<Val, Challenge, Challenger, P>(
    k: usize,
    system: System,
    (pcs, challenger): &(P, Challenger),
    log_degrees_by_round: Vec<Vec<usize>>,
) where
    P: Pcs<Challenge, Challenger>,
    P::Domain: PolynomialSpace<Val = Val>,
    Val: Field,
    Standard: Distribution<Val>,
    Challenge: ExtensionField<Val>,
    Challenger: Clone + CanObserve<P::Commitment> + FieldChallenger<Val>,
{
    let num_rounds = log_degrees_by_round.len();
    let mut rng = seeded_rng();

    let mut p_challenger = challenger.clone();
    let sample_size = sample_size(k);

    let _timer = start_timer(|| format!("PCS setup -{k}"));

    let mut commit_times = Vec::new();
    let mut domains_and_polys_by_round = Vec::new();
    for _ in 0..sample_size {
        let start = Instant::now();
        domains_and_polys_by_round = log_degrees_by_round
            .iter()
            .map(|log_degrees| {
                log_degrees
                    .iter()
                    .map(|&log_degree| {
                        let d = 1 << log_degree;
                        // random width 5-15
                        let width = 5 + rng.gen_range(0..=10);
                        (
                            pcs.natural_domain_for_degree(d),
                            RowMajorMatrix::<Val>::rand(&mut rng, d, width),
                        )
                    })
                    .collect_vec()
            })
            .collect_vec();
        commit_times.push(start.elapsed());
    }
    let sum = commit_times.iter().sum::<Duration>();
    let avg = sum / sample_size as u32;
    writeln!(&mut system.commit_output(), "{k}, {}", avg.as_millis()).unwrap();
    println!(
        "Commit time for {:?}, k = {k} is {} ms",
        system,
        avg.as_millis()
    );

    // Start timing for commit phase
    let _timer = start_timer(|| format!("commit -{k}"));

    let (commits_by_round, data_by_round): (Vec<_>, Vec<_>) = domains_and_polys_by_round
        .iter()
        .map(|domains_and_polys| pcs.commit(domains_and_polys.clone()))
        .unzip();

    // Start timing for prove phase
    let _timer = start_timer(|| format!("prove -{k}"));

    assert_eq!(commits_by_round.len(), num_rounds);
    assert_eq!(data_by_round.len(), num_rounds);
    p_challenger.observe_slice(&commits_by_round);

    let zeta: Challenge = p_challenger.sample_ext_element();

    let points_by_round = log_degrees_by_round
        .iter()
        .map(|log_degrees| vec![vec![zeta]; log_degrees.len()])
        .collect_vec();
    let data_and_points: Vec<_> = data_by_round.iter().zip(points_by_round).collect();
    let (opening_by_round, proof) = sample(system, k, || {
        pcs.open(data_and_points.clone(), &mut p_challenger.clone())
    });
    assert_eq!(opening_by_round.len(), num_rounds);

    // Start timing for verify phase
    let timer = start_timer(|| format!("verify -{k}"));

    // Verify the proof
    let mut v_challenger = challenger.clone();
    v_challenger.observe_slice(&commits_by_round);
    let verifier_zeta: Challenge = v_challenger.sample_ext_element();
    assert_eq!(verifier_zeta, zeta);

    let commits_and_claims_by_round = izip!(
        commits_by_round,
        domains_and_polys_by_round,
        opening_by_round
    )
    .map(|(commit, domains_and_polys, openings)| {
        let claims = domains_and_polys
            .iter()
            .zip(openings)
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect_vec();
        (commit, claims)
    })
    .collect_vec();

    assert_eq!(commits_and_claims_by_round.len(), num_rounds);

    let now = Instant::now();
    let verify_result = pcs.verify(commits_and_claims_by_round, &proof, &mut v_challenger);
    writeln!(
        &mut system.verify_output(),
        "{:?}: {:?}",
        k,
        now.elapsed().as_millis()
    )
    .unwrap();

    end_timer(timer);

    // Calculate proof size
    let mut proof_vec = Vec::new();
    proof
        .serialize(&mut serde_json::Serializer::new(&mut proof_vec))
        .unwrap();
    let proof_size = proof_vec.len();
    // Log the results
    writeln!(
        &mut system.size_output(),
        "{:?} {:?} : {:?}",
        system,
        k,
        proof_size
    )
    .unwrap();

    assert!(verify_result.is_ok());
}
