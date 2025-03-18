use p3_matrix::{
    dense::{DenseStorage, RowMajorMatrix},
    Matrix,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::from_str;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;

use crate::util::poly_loader::container::{Field, MatrixContainer};

pub struct Loader {
    pub field: Field,
}

impl Loader {
    pub fn new(field: Field) -> Self {
        Self { field }
    }

    pub fn load(&self, file_path: &str) -> MatrixContainer {
        // Read the file content
        let mut file = File::open(file_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        // Parse the JSON into MatrixContainer
        let container: MatrixContainer = from_str(&content).unwrap();
        assert_eq!(
            self.field, container.field,
            "Field mismatch in loaded data, expected {:?}, got {:?} in file {:?}",
            self.field, container.field, file_path
        );

        container
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
        let matrices = loader.load("test.json");
        println!("{:?}", matrices);
    }
}
