use benchmark::BasefoldParams::*;
use halo2_proofs::halo2curves::bn256::G1Affine;
use itertools::{izip, Itertools};
use num_bigint::BigInt;
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_bn254_fr::{Bn254Fr, FakeExtension};
use p3_challenger::{
    CanObserve, DuplexChallenger, FieldChallenger, HashChallenger, SerializingChallenger32,
    SerializingChallenger64,
};
use p3_circle::CirclePcs;
use p3_commit::{ExtensionMmcs, Pcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, ExtensionField, Field};
use p3_fri::{create_test_fri_config, FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, SerializingHasher64,
    TruncatedPermutation,
};
use p3_util::log2_strict_usize;
use plonkish_backend::{
    halo2_curves::{
        bn256::{Bn256, Fr},
        secp256k1::Fp,
    },
    pcs::{
        multilinear::{
            Basefold, BasefoldExtParams, Gemini, MultilinearBrakedown, MultilinearHyrax,
            MultilinearKzg, ZeromorphFri,
        },
        univariate::{Fri, UnivariateKzg},
        PolynomialCommitmentScheme,
    },
    poly::multilinear::MultilinearPolynomial,
    util::{
        arithmetic::PrimeField,
        code::{BrakedownSpec1, BrakedownSpec6},
        end_timer,
        goldilocksMont::GoldilocksMont,
        hash::{Blake2s, Blake2s256, Keccak256},
        new_fields::Mersenne127,
        poly_loader::{container::Field as CF, dumper::Dumper, loader::Loader},
        start_timer,
        transcript::{
            Blake2s256Transcript, Blake2sTranscript, InMemoryTranscript, Keccak256Transcript,
            TranscriptRead, TranscriptWrite,
        },
    },
};
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use rand::{rngs::OsRng, thread_rng};
use serde::Serialize as _;

use std::marker::PhantomData;
use std::{
    env::args,
    fmt::Display,
    fs::{create_dir, File, OpenOptions},
    io::Write,
    iter,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};

const OUTPUT_DIR: &str = "./bench_data/pcs";

#[derive(Debug)]
struct P {}

impl BasefoldExtParams for P {
    fn get_rate() -> usize {
        return 2;
    }

    fn get_basecode_rounds() -> usize {
        return 2;
    }

    fn get_reps() -> usize {
        return 1000;
    }

    fn get_rs_basecode() -> bool {
        true
    }
}
fn main() {
    let (systems, k_range, repetition, rounds) = parse_args();
    create_output(&systems);
    k_range.for_each(|k| {
        systems
            .iter()
            .for_each(|system| system.bench(k, repetition, rounds))
    });
}

fn bench_pcs<F, Pcs, T>(k: usize, pcs: System)
where
    F: PrimeField,
    Pcs: PolynomialCommitmentScheme<F, Polynomial = MultilinearPolynomial<F>>,
    T: TranscriptRead<Pcs::CommitmentChunk, F>
        + TranscriptWrite<Pcs::CommitmentChunk, F>
        + InMemoryTranscript<Param = ()>,
{
    let _ = start_timer(|| format!("PCS setup and trim -{k}"));
    let mut rng = OsRng;
    let poly_size = 1 << k;
    // let _ = Instant::now();
    let param = Pcs::setup(poly_size, 1, &mut rng).unwrap();
    let (pp, vp) = Pcs::trim(&param, poly_size, 1).unwrap();

    let _ = start_timer(|| format!("commit -{k}"));
    let mut transcript = T::new(());

    let poly = MultilinearPolynomial::rand(k, OsRng);

    let sample_size = sample_size(k);

    let mut commit_times = Vec::new();
    let mut times = Vec::new();
    for _ in 0..sample_size {
        let cstart = Instant::now();
        let comm = Pcs::commit_and_write(&pp, &poly, &mut transcript).unwrap();

        commit_times.push(cstart.elapsed());

        let start = Instant::now();
        let point = transcript.squeeze_challenges(k);
        let eval = poly.evaluate(point.as_slice());
        transcript.write_field_element(&eval).unwrap();
        Pcs::open(&pp, &poly, &comm, &point, &eval, &mut transcript).unwrap();
        times.push(start.elapsed());
    }
    let sum = times.iter().sum::<Duration>();
    let csum = commit_times.iter().sum::<Duration>();

    let avg = sum / sample_size as u32;
    let cavg = csum / sample_size as u32;

    writeln!(&mut pcs.commit_output(), "{k}, {}", cavg.as_millis()).unwrap();
    writeln!(&mut pcs.output(), "{k}, {}", avg.as_millis()).unwrap();

    let proof = transcript.into_proof();

    let timer = start_timer(|| format!("verify-{k}"));
    let result = {
        let mut transcript = T::from_proof((), proof.as_slice());
        let mut start_size = 0;
        while transcript.read_commitment().is_ok() {
            start_size = start_size + 1;
        }

        let mut transcript = T::from_proof((), proof.as_slice());
        let now = Instant::now();
        let b = Pcs::verify(
            &vp,
            &Pcs::read_commitment(&vp, &mut transcript).unwrap(),
            &transcript.squeeze_challenges(k),
            &transcript.read_field_element().unwrap(),
            &mut transcript,
        );
        writeln!(
            &mut pcs.verify_output(),
            "{:?}: {:?}",
            k,
            now.elapsed().as_millis()
        )
        .unwrap();
        let mut end_size = 0;
        while transcript.read_commitment().is_ok() {
            end_size = end_size + 1;
        }
        writeln!(
            &mut pcs.size_output(),
            "{:?} {:?} : {:?}",
            pcs,
            k,
            (start_size - end_size) * 256
        )
        .unwrap();
        b
    };

    end_timer(timer);
    assert_eq!(result, Ok(()));
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
    let mut rng = thread_rng();

    let mut p_challenger = challenger.clone();
    let sample_size = sample_size(k);

    let _timer = start_timer(|| format!("PCS setup -{k}"));

    let mut commit_times = Vec::new();
    let mut domains_and_polys_by_round = Vec::new();
    let mut matrix_by_round = Vec::new();
    for _ in 0..sample_size {
        let width = 5 + rng.gen_range(0..=10);
        matrix_by_round.push(RowMajorMatrix::<Val>::rand(&mut rng, 1 << k, width));
    }
    for i in 0..sample_size {
        let start = Instant::now();
        domains_and_polys_by_round = log_degrees_by_round
            .iter()
            .map(|log_degrees| {
                log_degrees
                    .iter()
                    .map(|&log_degree| {
                        let d = 1 << log_degree;
                        // random width 5-15
                        (pcs.natural_domain_for_degree(d), matrix_by_round[i].clone())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum System {
    MultilinearKzg,
    Basefold256,
    Basefold61Mersenne,
    BasefoldBlake2s,
    Brakedown,
    BrakedownBlake2s,
    ZeromorphFri,
    Fri,
    Circle,
    BigFieldFri,
    Gemini,
    Hyrax,
}

impl System {
    fn all() -> Vec<System> {
        vec![
            System::MultilinearKzg,
            System::Basefold61Mersenne,
            System::Basefold256,
            System::Brakedown,
            System::BasefoldBlake2s,
            System::BrakedownBlake2s,
            System::ZeromorphFri,
            System::Fri,
            System::Circle,
            System::BigFieldFri,
            System::Gemini,
            System::Hyrax,
        ]
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

    fn bench(&self, k: usize, repetition: usize, rounds: usize) {
        type Kzg = MultilinearKzg<Bn256>;
        type Brakedown = MultilinearBrakedown<Fp, Keccak256, BrakedownSpec6>;
        // type Brakedown127 = MultilinearBrakedown<Fp, Blake2s, BrakedownSpec6>;
        type BrakedownBlake2s = MultilinearBrakedown<GoldilocksMont, Blake2s, BrakedownSpec1>;

        match self {
            System::MultilinearKzg => {
                bench_pcs::<_, Kzg, Blake2sTranscript<_>>(k, System::MultilinearKzg)
            }
            System::Basefold61Mersenne => bench_pcs::<
                Mersenne127,
                Basefold<Mersenne127, Blake2s, P>,
                Blake2sTranscript<_>,
            >(k, System::Basefold61Mersenne),
            System::Basefold256 => bench_pcs::<
                Fr,
                Basefold<Fr, Blake2s256, BasefoldFri>,
                Blake2s256Transcript<_>,
            >(k, System::Basefold256),
            System::Brakedown => {
                bench_pcs::<Fp, Brakedown, Keccak256Transcript<_>>(k, System::Brakedown)
            }
            System::BasefoldBlake2s => match k {
                10 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Ten>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                11 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Eleven>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                12 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Twelve>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                13 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Thirteen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                14 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Fourteen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                15 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Fifteen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                16 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Sixteen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                17 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Seventeen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                18 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Eighteen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                19 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Nineteen>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                20 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, Twenty>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                21 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyOne>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                22 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyTwo>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                23 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyThree>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                24 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyFour>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                25 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentyFive>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                26 => bench_pcs::<
                    GoldilocksMont,
                    Basefold<GoldilocksMont, Blake2s, TwentySix>,
                    Blake2sTranscript<_>,
                >(k, System::BasefoldBlake2s),
                _ => {}
            },
            System::BrakedownBlake2s => bench_pcs::<
                GoldilocksMont,
                BrakedownBlake2s,
                Blake2sTranscript<_>,
            >(k, System::BrakedownBlake2s),
            System::ZeromorphFri => bench_pcs::<
                Fr,
                ZeromorphFri<Fri<Fr, Blake2s>>,
                Blake2sTranscript<_>,
            >(k, System::ZeromorphFri),
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

                let perm = Perm::new_from_rng_128(&mut OsRng::default());
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
            System::Gemini => {
                bench_pcs::<Fr, Gemini<UnivariateKzg<Bn256>>, Blake2sTranscript<_>>(
                    k,
                    System::Gemini,
                );
            }
            System::Hyrax => {
                bench_pcs::<Fr, MultilinearHyrax<G1Affine>, Blake2sTranscript<_>>(k, System::Hyrax);
            }
        }
    }
}

impl Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            System::Basefold256 => write!(f, "basefold256"),
            System::Basefold61Mersenne => write!(f, "basefold61Mersenne"),
            System::MultilinearKzg => write!(f, "kzg"),
            System::Brakedown => write!(f, "brakedown"),
            System::BrakedownBlake2s => write!(f, "brakedown_blake"),
            System::BasefoldBlake2s => write!(f, "basefold_blake"),
            System::ZeromorphFri => write!(f, "zeromorph_fri"),
            System::Fri => write!(f, "fri"),
            System::Circle => write!(f, "circle"),
            System::BigFieldFri => write!(f, "bigfield_fri"),
            System::Gemini => write!(f, "gemini"),
            System::Hyrax => write!(f, "hyrax"),
        }
    }
}

fn parse_args() -> (Vec<System>, Range<usize>, usize, usize) {
    let (systems, k_range, repetition, rounds) =
        args().chain(Some("".to_string())).tuple_windows().fold(
            (Vec::new(), 10..24, 1, 1),
            |(mut systems, mut k_range, mut repetition, mut rounds), (key, value)| {
                match key.as_str() {
                    "--system" => match value.as_str() {
                        "all" => {
                            systems = vec![
                                System::MultilinearKzg,
                                System::Basefold256,
                                System::Basefold61Mersenne,
                                System::BasefoldBlake2s,
                                System::Brakedown,
                                System::BrakedownBlake2s,
                                System::ZeromorphFri,
                            ]
                        }
                        "basefold256" => systems.push(System::Basefold256),
                        "multilinearkzg" => systems.push(System::MultilinearKzg),
                        _ => panic!(
                            "system should be one of {{all,hyperplonk,halo2,espresso_hyperplonk}}"
                        ),
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
                    "--repetition" => {
                        repetition = value.parse().expect("repetition to be usize");
                    }
                    "--rounds" => {
                        rounds = value.parse().expect("rounds to be usize");
                    }
                    _ => {}
                }
                (systems, k_range, repetition, rounds)
            },
        );

    let mut systems = systems.into_iter().sorted().dedup().collect_vec();
    if systems.is_empty() {
        systems = System::all();
    };
    (systems, k_range, repetition, rounds)
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
