use p3_matrix::{
    dense::{DenseStorage, RowMajorMatrix},
    Matrix,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::from_str;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;

use crate::util::matrix::container::{Field, MatrixContainer};

pub struct Loader<T> {
    pub field: Field,
    pub phantom: PhantomData<T>,
}

impl<T: DeserializeOwned + Clone + Send + Sync> Loader<T> {
    pub fn new(field: Field) -> Self {
        Self {
            field,
            phantom: PhantomData,
        }
    }

    pub fn load<F: Fn(&str) -> T>(&self, file_path: &str, parse: F) -> Vec<RowMajorMatrix<T>> {
        // Read the file content
        let mut file = File::open(file_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        // Parse the JSON into MatrixContainer
        let container: MatrixContainer = from_str(&content).unwrap();
        assert_eq!(self.field, container.field, "Field mismatch in loaded data");

        // Convert the flat matrices back into multi_polys structure
        (0..container.matrices_num)
            .map(|i| {
                RowMajorMatrix::new(
                    container.matrices[i]
                        .clone()
                        .iter()
                        .map(|s| parse(s))
                        .collect(),
                    container.matrix_widths[i],
                )
            })
            .collect()
    }
}

mod test {
    use super::*;

    use num_bigint::BigInt;
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_bn254_fr::FFBn254Fr as Fr;

    #[test]
    fn babybear_load() {
        let loader = Loader::new(Field::Babybear);
        let matrices = loader.load("test.json", |s| {
            BabyBear::new(u32::from_str_radix(s, 16).unwrap())
        });
        println!("{:?}", matrices);
    }

    #[test]
    fn bn254_load() {
        let loader = Loader::new(Field::Bn254Fr);
        let matrices = loader.load("test.json", |s| {
            let mut bytes = [0u8; 32];
            let num = BigInt::parse_bytes(s.as_bytes(), 16)
                .unwrap()
                .to_bytes_le()
                .1;
            bytes[..num.len()].copy_from_slice(&num);
            Bn254Fr {
                value: Fr::from_bytes(&bytes).unwrap(),
            }
        });
        println!("{:?}", matrices);
    }
}
