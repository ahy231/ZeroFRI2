use serde_json::to_string;
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;

use crate::util::matrix::container::{Field, MatrixContainer};

pub struct Dumper<T> {
    pub field: Field,
    pub phantom: PhantomData<T>,
}

impl<T> Dumper<T> {
    pub fn new(field: Field) -> Self {
        Self {
            field,
            phantom: PhantomData,
        }
    }

    pub fn dump<F: Fn(&T) -> String>(
        &self,
        multi_polys: &Vec<Vec<Vec<T>>>,
        file_path: &str,
        stringify: F,
    ) {
        let matrices_num = multi_polys.len();
        let matrix_widths = multi_polys.iter().map(|m| m.len()).collect::<Vec<_>>();
        let matrices = multi_polys
            .iter()
            .map(|m| {
                assert!(m.len() > 0);
                (0..m[0].len())
                    .flat_map(|i| m.iter().map(|p| stringify(&p[i])).collect::<Vec<_>>())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut result = to_string(&MatrixContainer::new(
            self.field,
            matrices_num,
            matrix_widths,
            matrices,
        ))
        .unwrap();

        let mut file = File::create(file_path).unwrap();
        write!(file, "{}", result).unwrap();
        file.flush().unwrap();
    }
}

mod test {
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
        let multi_polys = (0..matrix_num)
            .map(|i| {
                (0..widths[i])
                    .map(|_| {
                        (0..heights[i])
                            .map(|_| BabyBear::new(rng.gen::<u32>()))
                            .collect()
                    })
                    .collect()
            })
            .collect();
        dumper.dump(&multi_polys, "test.json", |x: &BabyBear| {
            let x = x.clone().to_string();
            let buf = x.as_bytes();
            let num = BigInt::parse_bytes(buf, 10).unwrap();
            let hex = num
                .to_radix_be(16)
                .1
                .iter()
                .map(|e| format!("{:x}", e))
                .collect::<Vec<_>>()
                .join("");
            format!("{:0>8}", hex)
        });
    }

    #[test]
    fn bn254_dump() {
        let mut rng = thread_rng();
        let dumper = Dumper::new(Field::Bn254Fr);
        let matrix_num = 2;
        let widths = vec![2, 3];
        let heights = vec![16, 8];
        let multi_polys = (0..matrix_num)
            .map(|i| {
                (0..widths[i])
                    .map(|_| {
                        (0..heights[i])
                            .map(|_| {
                                let mut tmp = [0u8; 32];
                                rng.fill(&mut tmp);
                                while Fr::from_bytes(&tmp).is_none().into() {
                                    rng.fill(&mut tmp);
                                }
                                Bn254Fr {
                                    value: Fr::from_bytes(&tmp).unwrap(),
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        dumper.dump(&multi_polys, "test.json", |x: &Bn254Fr| {
            format!("{:?}", x.value).replace("0x", "")
        });
    }
}
