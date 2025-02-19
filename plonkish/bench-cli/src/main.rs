use dialoguer::{Input, Select, theme::ColorfulTheme};
use regex::Regex;
use std::fs;
use std::io;
use std::process::Command;

fn main() -> io::Result<()> {
    // Define the available benchmark names. They correspond to the bench file names
    // (without the .rs extension) in benchmark/benches/.
    let benchmarks = vec![
        "brakedown_proof_system",
        "zeromorph_fri_proof_system",
        "gemini_proof_system",
        "basefold_proof_system",
        "hyrax_proof_system",
        "plonky3_pcs_bench",
        "p3_proof_system",
        "deepfold_proof_system",
        "virgo_proof_system",
    ];

    // Prompt the user to select a proof system bench.
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the proof system benchmark to run")
        .default(0)
        .items(&benchmarks)
        .interact()
        .unwrap();
    let chosen_bench = benchmarks[selection];
    println!("Running benchmark: {}", chosen_bench);

    // Prompt the user for the parameter k value or range.
    // The default is "10..27" (which matches the default in your bench file).
    let k_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter the parameter k value ( e.g. 10..15)")
        .default("default 10..24".into())
        .interact_text()?;
    println!("Parameter k: {}", k_input);

    // --- STEP 1: Adjust the bench file to update the default k range ---
    // The bench file for the chosen system is assumed to be located at:
    // "benchmark/benches/<chosen_bench>.rs"
    let bench_file_path = format!("benchmark/benches/{}.rs", chosen_bench);
    let bench_file_backup_path = format!("{}.bak", &bench_file_path);
    fs::copy(&bench_file_path, &bench_file_backup_path)?;
    adjust_k_range_in_bench_file(&bench_file_path, &k_input)?;

    // --- STEP 2: Adjust the Cargo.toml so that only the chosen bench is active ---
    // The benchmark package has its own Cargo.toml in the "benchmark" folder.
    let cargo_file_path = "benchmark/Cargo.toml";
    let cargo_backup_path = "benchmark/Cargo.toml.bak";
    fs::copy(cargo_file_path, cargo_backup_path)?;
    adjust_cargo_toml(cargo_file_path, chosen_bench)?;

    // --- STEP 3: Run the benchmark ---
    // Change directory into "benchmark" (so that relative paths in the bench code resolve)
    // and run the benchmark command.
    let status = Command::new("rustup")
        .args(&["run", "nightly", "cargo", "bench"])
        .current_dir("benchmark")
        .status()?;

    if !status.success() {
        eprintln!("Benchmark command failed.");
    }

    // --- STEP 4: Restore the original configuration files ---
    // Restore the Cargo.toml file.
    fs::copy(cargo_backup_path, cargo_file_path)?;
    fs::remove_file(cargo_backup_path)?;
    // Restore the bench file.
    fs::copy(&bench_file_backup_path, &bench_file_path)?;
    fs::remove_file(&bench_file_backup_path)?;

    Ok(())
}

/// Adjusts the Cargo.toml file in the benchmark directory so that only the bench block
/// matching the chosen bench is active (uncommented) while all other bench blocks remain commented.
fn adjust_cargo_toml(path: &str, bench_name: &str) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    let mut new_content = String::new();

    // Helper: Check if a line starts a bench block.
    fn is_bench_header(line: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("[[bench]]") || trimmed.starts_with("# [[bench]]")
    }

    // Helper: Process a block of lines representing one bench entry.
    // If any line in the block contains the chosen bench name, then the block is uncommented.
    // Otherwise, every line in the block is commented.
    fn process_block(block: &[String], bench_name: &str) -> Vec<String> {
        let matches = block.iter().any(|line| {
            line.contains("name =") && line.contains(bench_name)
        });
        if matches {
            block.iter()
                .map(|line| {
                    if line.trim_start().starts_with('#') {
                        line.trim_start_matches('#').trim_start().to_string()
                    } else {
                        line.clone()
                    }
                })
                .collect()
        } else {
            block.iter()
                .map(|line| {
                    if line.trim_start().starts_with('#') {
                        line.clone()
                    } else {
                        format!("# {}", line)
                    }
                })
                .collect()
        }
    }

    let mut current_block: Vec<String> = Vec::new();
    let mut in_block = false;

    for line in content.lines() {
        if is_bench_header(line) {
            if in_block && !current_block.is_empty() {
                let processed = process_block(&current_block, bench_name);
                for processed_line in processed {
                    new_content.push_str(&processed_line);
                    new_content.push('\n');
                }
                current_block.clear();
            }
            in_block = true;
            current_block.push(line.to_string());
        } else if in_block {
            current_block.push(line.to_string());
        } else {
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    if in_block && !current_block.is_empty() {
        let processed = process_block(&current_block, bench_name);
        for processed_line in processed {
            new_content.push_str(&processed_line);
            new_content.push('\n');
        }
    }

    fs::write(path, new_content)
}

/// Updates the default k range in the chosen bench file.
/// It searches for a pattern in the file that looks like:
///   (Vec::new(), Circuit::<...>, 10..27)
/// and replaces the k range (here "10..27") with the new_k_range provided by the user.
fn adjust_k_range_in_bench_file(file_path: &str, new_k_range: &str) -> io::Result<()> {
    let content = fs::read_to_string(file_path)?;
    // This regex looks for a pattern starting with "(Vec::new(),", then a Circuit identifier,
    // then a comma and whitespace, then a k range (e.g. 10..27), and finally a closing ")".
    let re = Regex::new(r"(\(Vec::new\(\),\s*Circuit::[A-Za-z0-9_]+\s*,\s*)(\d+\.\.\d+)(\))")
        .expect("failed to compile regex");
    let new_content = re.replace(&content, |caps: &regex::Captures| {
        format!("{}{}{}", &caps[1], new_k_range, &caps[3])
    });
    fs::write(file_path, new_content.as_ref())
}
