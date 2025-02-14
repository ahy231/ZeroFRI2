use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum Field {
    Babybear,
    Goldilocks,
    Mersenne61,
    Bn254Fr,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct MatrixContainer {
    pub poly_size: usize,
    pub batch_size: usize,
    pub field: Field,
    pub rounds: usize,
    pub matrices_num: Vec<usize>,
    pub matrix_widths: Vec<Vec<usize>>,
    pub matrices: Vec<Vec<Vec<String>>>,
    pub matrix_points: HashMap<String, Vec<String>>,
}

impl MatrixContainer {
    pub fn new(
        poly_size: usize,
        batch_size: usize,
        field: Field,
        rounds: usize,
        matrices_num: Vec<usize>,
        matrix_widths: Vec<Vec<usize>>,
        matrices: Vec<Vec<Vec<String>>>,
        matrix_points: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            poly_size,
            batch_size,
            field,
            rounds,
            matrices_num,
            matrix_widths,
            matrices,
            matrix_points,
        }
    }

    pub fn push_matrix(&mut self, matrix: Vec<Vec<String>>) {
        *self.matrices_num.last_mut().unwrap() += 1;
        self.matrices.push(matrix);
    }
}

mod test {
    use super::*;
    use serde_json::{from_str, to_string};

    #[test]
    fn test_matrix_container() {
        let matrix_container = MatrixContainer::new(
            1,
            1,
            Field::Babybear,
            1,
            vec![2],
            vec![vec![3, 4]],
            vec![vec![
                vec![
                    "1".to_string(),
                    "2".to_string(),
                    "3".to_string(),
                    "4".to_string(),
                    "5".to_string(),
                    "6".to_string(),
                ],
                vec![
                    "4".to_string(),
                    "5".to_string(),
                    "6".to_string(),
                    "7".to_string(),
                ],
            ]],
            HashMap::new(),
        );
        let json = to_string(&matrix_container).unwrap();
        println!("{}", json);
        let matrix_container_deserialized: MatrixContainer = from_str(&json).unwrap();
        println!("{:?}", matrix_container_deserialized);
        assert_eq!(matrix_container, matrix_container_deserialized);
    }
}
