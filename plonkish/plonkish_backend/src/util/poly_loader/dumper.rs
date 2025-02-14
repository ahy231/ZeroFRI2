use serde_json::to_string;
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;

use crate::util::poly_loader::container::{Field, MatrixContainer};

pub struct Dumper {
    pub field: Field,
}

impl Dumper {
    pub fn new(field: Field) -> Self {
        Self { field }
    }

    pub fn dump(&self, container: &MatrixContainer, file_path: &str) {
        let mut result = to_string(container).unwrap();

        let mut file = File::create(file_path).unwrap();
        write!(file, "{}", result).unwrap();
        file.flush().unwrap();
    }
}

mod test {
    use std::collections::HashMap;
    use std::fmt::Debug;

    use super::*;

    use num_bigint::BigInt;
    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_bn254_fr::FFBn254Fr as Fr;
    use rand::{thread_rng, Rng};

    #[test]
    fn babybear_dump() {
        let mut rng = thread_rng();
        let dumper = Dumper::new(Field::Babybear);
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
        let container = MatrixContainer::new(
            multi_polys.len(),
            multi_polys[0].len(),
            Field::Babybear,
            1,
            vec![matrix_num],
            vec![widths],
            multi_polys,
            HashMap::new(),
        );
        dumper.dump(&container, "test.json");
    }
}
