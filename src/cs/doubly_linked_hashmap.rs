use super::constraint_system::Variable;
use algebra::fields::PrimeField;
use num_traits::{One, Zero};
use std::collections::HashMap;
// DoublyHashMap ensures that if the user inserts the same scalar `F`
// He is returned the same variable. ie DoublyHashMap ensures that there is a one-to-one mapping
// from Variable to Scalars
pub struct DoublyHashMap<F: PrimeField> {
    variables_to_scalar: HashMap<Variable, F>,
    scalar_to_variables: HashMap<F, Variable>,
}

impl<F: PrimeField> DoublyHashMap<F> {
    pub fn with_capacity(n: usize) -> Self {
        Self {
            variables_to_scalar: HashMap::with_capacity(n),
            scalar_to_variables: HashMap::with_capacity(n),
        }
    }
    pub fn len(&self) -> usize {
        self.variables_to_scalar.keys().len()
    }
    // Insert checks if we have the scalar saved already
    // If we do, then we return the same Variable, if we do not then we return a new Variable
    pub fn insert(&mut self, n: F) -> Variable {
        match self.scalar_to_variables.get(&n) {
            Some(&variable) => variable,
            _ => {
                let var = Variable(self.len());
                self.variables_to_scalar.insert(var, n);
                self.scalar_to_variables.insert(n, var);
                var
            }
        }
    }
    pub fn contains_key(&self, var: &Variable) -> bool {
        self.variables_to_scalar.contains_key(var)
    }
}
use std::ops::Index;
impl<F: PrimeField> Index<&Variable> for DoublyHashMap<F> {
    type Output = F;

    fn index(&self, v: &Variable) -> &Self::Output {
        &self.variables_to_scalar[v]
    }
}
#[test]
fn test_same_variable() {
    use algebra::fields::bls12_381::Fr;
    use algebra::fields::Field;
    let mut map = DoublyHashMap::with_capacity(2);
    let var_a = map.insert(Fr::one());
    let var_b = map.insert(Fr::one());
    let var_c = map.insert(Fr::one());
    assert_eq!(var_a, var_b);
    assert_eq!(var_a, var_c);
}
#[test]
fn test_key_len() {
    use algebra::fields::bls12_381::Fr;
    use algebra::fields::Field;
    let mut map = DoublyHashMap::with_capacity(2);
    map.insert(Fr::one());
    map.insert(Fr::from(2u8));
    map.insert(Fr::from(3u8));
    map.insert(Fr::one());
    map.insert(Fr::from(2u8));
    map.insert(Fr::zero());
    map.insert(-Fr::from(2u8));
    assert_eq!(5, map.len());
}

#[test]
fn test_correct_indices() {
    use algebra::fields::bls12_381::Fr;
    use algebra::fields::Field;
    let mut map = DoublyHashMap::with_capacity(10);
    for i in 0u8..100u8 {
        let var = map.insert(Fr::from(i));
        assert_eq!(var.0, i as usize);
    }
}
