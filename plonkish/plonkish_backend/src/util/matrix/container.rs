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
    pub field: Field,
    pub matrices_num: usize,
    pub matrix_widths: Vec<usize>,
    pub matrices: Vec<Vec<String>>,
}

impl MatrixContainer {
    pub fn new(
        field: Field,
        matrices_num: usize,
        matrix_widths: Vec<usize>,
        matrices: Vec<Vec<String>>,
    ) -> Self {
        Self {
            field,
            matrices_num,
            matrix_widths,
            matrices,
        }
    }
}

mod test {
    use super::*;
    use serde_json::{from_str, to_string};

    #[test]
    fn test_matrix_container() {
        let matrix_container = MatrixContainer::new(
            Field::Babybear,
            2,
            vec![3, 4],
            vec![
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
            ],
        );
        let json = to_string(&matrix_container).unwrap();
        println!("{}", json);
        let matrix_container_deserialized: MatrixContainer = from_str(&json).unwrap();
        println!("{:?}", matrix_container_deserialized);
        assert_eq!(matrix_container, matrix_container_deserialized);
    }
}
