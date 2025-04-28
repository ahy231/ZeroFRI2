use dialoguer::{theme::ColorfulTheme, Input, Select};
use regex::Regex;
use std::{fs, io, process::Command};

/// Three things the user can do from one executable.
enum Action {
    /// old: plonkish/benchmark “performance” benches
    PerfBench,
    /// new: generate polynomial test-vectors
    GetMockData,
    /// new: run the MLE-PCS comparison bench
    TestMockPCS,
}

fn main() -> io::Result<()> {
    // ──────────────────────────────────── 1. top-level menu
    let actions = [
        "Run performance benchmarks",
        "Generate polynomial mock data",
        "Test MLE-PCS",
    ];
    let action = match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What would you like to do?")
        .items(&actions)
        .default(0)
        .interact()?
    {
        0 => Action::PerfBench,
        1 => Action::GetMockData,
        _ => Action::TestMockPCS,
    };

    // ──────────────────────────────────── collect common input: k
    let k_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter k (single int like 12 **or** range like 10..18)")
        .default("10..27".into())
        .interact_text()?;

    match action {
        // ──────────────────────────────── 2A.  old path – performance benches
        Action::PerfBench => run_perf_bench(&k_input)?,

        // ──────────────────────────────── 2B.  new path – get_mock_data
        Action::GetMockData => {
            let field = ask_choice(
                "Which finite-field implementation?",
                &[
                    "bn254fr",
                    "mersenne127",
                    "goldilocksmont",
                    "myfr",
                    "mersenne61mont",
                    "mersenne61",
                    "fr",
                    "fp",
                ],
            )?;
            run_test_bench("get_mock_data", &k_input, &field)?;
        }

        // ──────────────────────────────── 2C.  new path – mock_proof_system
        Action::TestMockPCS => {
            let pcs = ask_choice(
                "Which PCS/back-end?",
                &[
                    "multilinearkzg",
                    "basefold256",
                    "basefold61mersenne",
                    "basefoldblake2s",
                    "brakedown",
                    "brakedownblake2s",
                    "zeromorphfri",
                    "zeromorphfriv2",
                    "zeromorphfriv3",
                    "gemini",
                    "hyrax",
                    "deepfold",
                ],
            )?;
            run_test_bench("mock_proof_system", &k_input, &pcs)?;
        }
    };
    Ok(())
}

// ───────────────────────────────────────── helpers ──────────────────────────

/// Interactive single-choice helper
fn ask_choice(prompt: &str, items: &[&str]) -> io::Result<String> {
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact()?;
    Ok(items[idx].to_string())
}

/// MODE 1  – choose which perf-bench, edit Cargo.toml + (optionally) patch k, then run `cargo bench`
fn run_perf_bench(k_input: &str) -> io::Result<()> {
    // pick which bench target
    let benches = [
        "brakedown_proof_system",
        "zeromorph_fri_proof_system",
        "gemini_proof_system",
        "basefold_proof_system",
        "hyrax_proof_system",
        "plonky3_pcs_bench",
        "p3_proof_system",
    ];
    let idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the proof-system bench to run")
        .items(&benches)
        .default(0)
        .interact()?;
    let chosen = benches[idx];

    // a) patch default-k inside that bench file  (regex unchanged)
    let bench_src = format!("benchmark/benches/{chosen}.rs");
    let bench_bak = format!("{bench_src}.bak");
    fs::copy(&bench_src, &bench_bak)?;
    patch_k_in_file(&bench_src, k_input)?;

    // b) toggle [[bench]] blocks so *only* this one is active
    let cargo_toml = "benchmark/Cargo.toml";
    let cargo_bak = "benchmark/Cargo.toml.bak";
    fs::copy(cargo_toml, cargo_bak)?;
    toggle_bench_blocks(cargo_toml, chosen)?;

    // c) run cargo bench
    let ok = Command::new("rustup")
        .args(&["run", "nightly", "cargo", "bench"])
        .current_dir("benchmark")
        .status()?
        .success();

    // d) restore files
    fs::copy(cargo_bak, cargo_toml)?;
    fs::remove_file(cargo_bak)?;
    fs::copy(&bench_bak, &bench_src)?;
    fs::remove_file(bench_bak)?;
    if !ok {
        eprintln!("Benchmark failed");
    }
    Ok(())
}

/// MODE 2 & 3 – run a “cargo test --bench …” with `--k` and `--system`
fn run_test_bench(bench_name: &str, k: &str, system: &str) -> io::Result<()> {
    let ok = Command::new("rustup")
        .args(&[
            "run", "nightly", "cargo", "test", "--bench", bench_name, "--", "--k", k,  "--system",
            system,
        ])
        .status()?
        .success();
    if !ok {
        eprintln!("Test bench failed");
    }
    Ok(())
}

/// Regex-replace the `(Vec::new(), Circuit::<…>, 10..27)` tuple
fn patch_k_in_file(path: &str, new_k: &str) -> io::Result<()> {
    let txt = fs::read_to_string(path)?;
    let re = Regex::new(r"(\(Vec::new\(\),\s*Circuit::[A-Za-z0-9_]+\s*,\s*)(\d+\.\.\d+|\d+)(\))")
        .unwrap();
    let patched = re.replace(&txt, |cap: &regex::Captures| {
        format!("{}{}{}", &cap[1], new_k, &cap[3])
    });
    fs::write(path, patched.as_ref())
}

/// comment / uncomment bench blocks (same logic you already had)
fn toggle_bench_blocks(path: &str, bench: &str) -> io::Result<()> {
    let src = fs::read_to_string(path)?;
    let mut out = String::new();
    let mut blk: Vec<String> = Vec::new();
    let mut in_blk = false;
    let hdr = |l: &str| {
        let t = l.trim_start();
        t.starts_with("[[bench]]") || t.starts_with("# [[bench]]")
    };
    let finish = |b: &[String], name: &str| -> Vec<String> {
        let match_ = b.iter().any(|l| l.contains("name =") && l.contains(name));
        b.iter()
            .map(|l| {
                let com = l.trim_start().starts_with('#');
                match (match_, com) {
                    (true, true) => l.trim_start_matches('#').trim_start().to_string(),
                    (false, false) => format!("# {l}"),
                    _ => l.clone(),
                }
            })
            .collect()
    };
    for ln in src.lines() {
        if hdr(ln) {
            if in_blk {
                for l in finish(&blk, bench) {
                    out.push_str(&l);
                    out.push('\n');
                }
                blk.clear();
            }
            in_blk = true;
            blk.push(ln.into());
        } else if in_blk {
            blk.push(ln.into());
        } else {
            out.push_str(ln);
            out.push('\n');
        }
    }
    if in_blk {
        for l in finish(&blk, bench) {
            out.push_str(&l);
            out.push('\n');
        }
    }
    fs::write(path, out)
}
