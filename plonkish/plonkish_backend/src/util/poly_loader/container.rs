use std::collections::HashMap;

use itertools::Itertools as _;
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
    pub matrices_num: Vec<usize>,        // rounds[1, 2, (matrices_num)]
    pub matrix_widths: Vec<Vec<usize>>,  // rounds[matrices[1, 2, (matrix_widths)]]
    pub matrices: Vec<Vec<Vec<String>>>, // rounds[matrices[elements[1, 2, 3, 4, 5, 6]]], according to p3 matrix format
    pub poly_points: HashMap<String, Vec<String>>, // map(commitment => [points])
}

impl MatrixContainer {
    pub fn new(poly_size: usize, batch_size: usize, field: Field) -> Self {
        Self {
            poly_size,
            batch_size,
            field,
            rounds: 0,
            matrices_num: vec![],
            matrix_widths: vec![],
            matrices: vec![],
            poly_points: HashMap::new(),
        }
    }

    pub fn new_round(&mut self) {
        self.matrices_num.push(0);
        self.matrix_widths.push(vec![]);
        self.matrices.push(vec![]);
    }

    /// Push a matrix to the last round.
    ///
    /// # Arguments
    ///
    /// * `matrix` - Each vector is a column of matrix, there is a vector of columns
    ///
    /// # Returns
    ///
    pub fn push_matrix(&mut self, matrix: Vec<Vec<String>>) {
        assert!(matrix.len() > 0);
        assert!(matrix[0].len() > 0);

        *self.matrices_num.last_mut().unwrap() += 1;
        self.matrix_widths.last_mut().unwrap().push(matrix.len());
        let matrix = (0..matrix[0].len())
            .flat_map(|i| {
                (0..matrix.len())
                    .map(|j| matrix[j][i].clone())
                    .collect_vec()
            })
            .collect_vec();
        self.matrices.last_mut().unwrap().push(matrix);
    }
}

mod test {
    use super::*;
    use serde_json::{from_str, to_string};

    #[test]
    fn test_matrix_container() {
        let mut matrix_container = MatrixContainer::new(1, 1, Field::Babybear);
        matrix_container.new_round();
        matrix_container.push_matrix(vec![vec!["1".to_string(), "2".to_string()]]);
        let json = to_string(&matrix_container).unwrap();
        println!("{}", json);
        let matrix_container_deserialized: MatrixContainer = from_str(&json).unwrap();
        println!("{:?}", matrix_container_deserialized);
        assert_eq!(matrix_container, matrix_container_deserialized);
    }
}
