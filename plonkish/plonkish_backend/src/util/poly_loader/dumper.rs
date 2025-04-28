use serde::Serialize;
use serde_json::to_string;
use std::fs::{self, File};
use std::io::{self, Write};

use std::path::Path;

/// Ensures path exists: if path doesn't exist, automatically creates parent directories and creates file/directory as needed.
///
/// # Arguments
/// - `path`: The path to check/create (can point to file or directory).
///
/// # Rules
/// - If path ends with directory separator → creates directory.
/// - Otherwise → creates file.
///
/// # Errors
/// Returns `std::io::Error` type errors (e.g., insufficient permissions, invalid path).
pub fn ensure_path_exists(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }

    // get parent directory (handle special cases like root directory)
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path has no parent directory (e.g., root)",
        )
    })?;

    // recursively create parent directory
    fs::create_dir_all(parent)?;

    // create file, handle possible race conditions
    match File::create(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_file() {
        let file_path = Path::new("subdir/test.txt");

        // ensure file creation succeeds
        ensure_path_exists(&file_path).unwrap();
        assert!(file_path.is_file());
    }

    #[test]
    fn test_existing_path() {
        let existing_path = Path::new("subdir/test.txt");

        // path already exists, no operation needed
        ensure_path_exists(existing_path).unwrap();
    }
}

pub struct Dumper;

impl Dumper {
    pub fn new() -> Self {
        Self {}
    }

    pub fn dump<T: Serialize>(&self, data: &T, file_path: &str) {
        let mut result = to_string(data).unwrap();

        let path = Path::new(file_path);
        ensure_path_exists(path).unwrap();

        let mut file = File::create(path).unwrap();
        write!(file, "{}", result).unwrap();
        file.flush().unwrap();
    }
}

mod test {
    use std::collections::HashMap;
    use std::fmt::Debug;

    use super::*;

    use crate::util::poly_loader::container::{Field, MatrixContainer};
    use num_bigint::BigInt;
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_bn254_fr::FFBn254Fr as Fr;
    use rand::{thread_rng, Rng};

    #[test]
    fn babybear_dump() {
        let mut rng = thread_rng();
        let dumper = Dumper::new();
        let matrix_num = 2;
        let widths = vec![2, 3];
        let heights = vec![16, 8];
        let multi_polys: Vec<Vec<Vec<String>>> = (0..matrix_num)
            .map(|i| {
                (0..widths[i])
                    .map(|_| {
                        (0..heights[i])
                            .map(|_| rng.gen::<u32>().to_string())
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let mut container =
            MatrixContainer::new(multi_polys.len(), multi_polys[0].len(), Field::Babybear);
        container.new_round();
        container.push_matrix(multi_polys[0].clone());
        container.push_matrix(multi_polys[1].clone());
        dumper.dump(&container, "test.json");
    }
}
