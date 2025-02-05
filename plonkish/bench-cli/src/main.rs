use dialoguer::{theme::ColorfulTheme, Select};
use std::fs;
use std::io::{self, Write};
use std::process::Command;

fn main() -> io::Result<()> {
    // Define the available benchmark names, including the new ones.
    let benchmarks = vec![
        "brakedown_proof_system",
        "zeromorph_fri_proof_system",
        "gemini_proof_system",
        "basefold_proof_system",
        "hyrax_proof_system",
        "plonky3_pcs_bench",
        "p3_proof_system",
    ];

    // Present an interactive selection menu.
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select the proof system benchmark to run")
        .default(0)
        .items(&benchmarks)
        .interact()
        .unwrap();
    let chosen_bench = benchmarks[selection];
    println!("Running benchmark: {}", chosen_bench);

    // Define paths relative to the repository root.
    let cargo_file_path = "benchmark/Cargo.toml";
    let backup_file_path = "benchmark/Cargo.toml.bak";

    // Backup the original Cargo.toml.
    fs::copy(cargo_file_path, backup_file_path)?;

    // Adjust the Cargo.toml to activate only the chosen bench block.
    adjust_cargo_toml(cargo_file_path, chosen_bench)?;

    // Run the benchmark by changing into the benchmark directory.
    let status = Command::new("rustup")
        .args(&["run", "nightly", "cargo", "bench"])
        .current_dir("benchmark")
        .status()?;

    if !status.success() {
        eprintln!("Benchmark command failed.");
    }

    // Restore the original Cargo.toml.
    fs::copy(backup_file_path, cargo_file_path)?;
    fs::remove_file(backup_file_path)?;

    Ok(())
}

/// Processes the entire Cargo.toml file for the benchmark package.
/// It splits the file into bench blocks and non-bench parts. For each bench block:
/// - If it contains the chosen bench name (in a `name =` line), the entire block is uncommented.
/// - Otherwise, every line in the block is commented out.
///
/// Lines outside any bench block are left unchanged.
fn adjust_cargo_toml(path: &str, bench_name: &str) -> io::Result<()> {
    let content = fs::read_to_string(path)?;
    let mut new_content = String::new();

    // Helper: Determine if a line is a bench block header.
    fn is_bench_header(line: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("[[bench]]") || trimmed.starts_with("# [[bench]]")
    }

    // Helper: Process a collected bench block.
    // If any line in the block contains `name = ...` with the chosen bench name,
    // then return the block with every line uncommented.
    // Otherwise, return the block with every line commented.
    fn process_block(block: &[String], bench_name: &str) -> Vec<String> {
        let matches = block.iter().any(|line| {
            line.contains("name =") && line.contains(bench_name)
        });
        if matches {
            // Uncomment every line (remove leading '#' and any following space).
            block
                .iter()
                .map(|line| {
                    if line.trim_start().starts_with('#') {
                        line.trim_start_matches('#').trim_start().to_string()
                    } else {
                        line.clone()
                    }
                })
                .collect()
        } else {
            // Ensure every line is commented.
            block
                .iter()
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

    // Process the file line by line.
    for line in content.lines() {
        if is_bench_header(line) {
            // If already inside a bench block, process the collected block.
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
            // Continue collecting lines for the current bench block.
            // We assume bench blocks are contiguous until the next bench header.
            current_block.push(line.to_string());
        } else {
            // Lines outside of bench blocks are copied directly.
            new_content.push_str(line);
            new_content.push('\n');
        }
    }

    // Process any remaining block.
    if in_block && !current_block.is_empty() {
        let processed = process_block(&current_block, bench_name);
        for processed_line in processed {
            new_content.push_str(&processed_line);
            new_content.push('\n');
        }
    }

    fs::write(path, new_content)
}
