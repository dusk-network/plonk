use bls12_381::Scalar;

pub struct StandardComposer {
    // n represents the number of arithmetic gates in the circuit
    n: usize,

    // Selector vectors
    //
    // Multiplier selector
    q_m: Vec<Scalar>,
    // Left wire selector
    q_l: Vec<Scalar>,
    // Right wire selector
    q_r: Vec<Scalar>,
    // output wire selector
    q_o: Vec<Scalar>,
    // constant wire selector
    q_c: Vec<Scalar>,

    // witness vectors
    w_l: Vec<Variable>,
    w_r: Vec<Variable>,
    w_o: Vec<Variable>,

    // These are the actual variable values
    // N.B. They should not be exposed to the end user once added into the composer
    variables: Vec<Scalar>,

    // maps variables to the wire metadata that they are assosciated with
    // To then later create the necessary permutations
    // XXX: the index will be the Variable reference, so it may be better to use a map to be more explicit here
    variable_map: Vec<Vec<WireMetadata>>,

    sigmas: Vec<Vec<usize>>,
}

// Stores the metadata for a specific wire
// This data is the gate index and the type of wire
struct WireMetadata {
    gate_index: usize,
    wire_type: WireType,
}

impl WireMetadata {
    fn new(index: usize, wire_type: WireType) -> Self {
        WireMetadata {
            gate_index: index,
            wire_type: wire_type,
        }
    }
}

// Encoding for different wire types
#[derive(Copy, Clone)]
enum WireType {
    Left = 0,
    Right = (1 << 30),
    Output = (1 << 31),
}

/// Represents a variable in a constraint system.
/// The value is a reference to the position of the value in the variables vector
#[derive(Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(usize);

impl StandardComposer {
    pub fn new() -> Self {
        StandardComposer::with_expected_size(0)
    }

    // Creates a new circuit with an expected circuit size
    // This will allow for less reallocations when building the circuit
    pub fn with_expected_size(expected_size: usize) -> Self {
        StandardComposer {
            n: 0,

            q_m: Vec::with_capacity(expected_size),
            q_l: Vec::with_capacity(expected_size),
            q_r: Vec::with_capacity(expected_size),
            q_o: Vec::with_capacity(expected_size),
            q_c: Vec::with_capacity(expected_size),

            w_l: Vec::with_capacity(expected_size),
            w_r: Vec::with_capacity(expected_size),
            w_o: Vec::with_capacity(expected_size),

            variables: Vec::with_capacity(expected_size),
            variable_map: Vec::new(),

            sigmas: Vec::new(),
        }
    }

    // Computes the pre-processed polynomials
    // So the verifier can verify a proof made using this circuit
    pub fn preprocess() {}

    // Prove will compute the pre-processed polynomials and
    // produce a proof
    pub fn prove(&self) {}

    // Adds a value to the circuit and returns its
    // index reference
    fn add_input(&mut self, s: Scalar) -> Variable {
        self.variables.push(s);

        self.variable_map.push(Vec::new());

        Variable(self.variables.len() - 1)
    }
    // Circuit size is the amount of gates in the circuit
    fn circuit_size(&self) -> usize {
        self.n
    }

    fn add_variable_to_map(&mut self, a: Variable, b: Variable, c: Variable) {
        
        let num_variables = self.variable_map.len();
        assert!(num_variables > a.0);
        assert!(num_variables > b.0);
        assert!(num_variables > c.0);


        let left: WireMetadata = WireMetadata::new(self.n, WireType::Left);
        let right: WireMetadata = WireMetadata::new(self.n, WireType::Right);
        let output: WireMetadata = WireMetadata::new(self.n, WireType::Output);

        // Map each variable to the wires it is assosciated with
        self.variable_map[a.0].push(left);
        self.variable_map[b.0].push(right);
        self.variable_map[c.0].push(output);
    }

    // Adds an add gate to the circuit
    // This API is not great for the average user, what we can do is make separate functions for r1cs format
    pub fn add_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_l: Scalar,
        q_r: Scalar,
        q_o: Scalar,
        q_c: Scalar,
    ) {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);

        // For an add gate, q_m is zero
        self.q_m.push(Scalar::zero());

        // Add selector vectors
        self.q_l.push(q_l);
        self.q_r.push(q_r);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.add_variable_to_map(a, b, c);

        self.n = self.n + 1;
    }
    
    pub fn mul_gate(
        &mut self,
        a: Variable,
        b: Variable,
        c: Variable,
        q_m: Scalar,
        q_o: Scalar,
        q_c: Scalar,
    ) {
        self.w_l.push(a);
        self.w_r.push(b);
        self.w_o.push(c);
    
        // For a mul gate q_L and q_R is zero
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        
        // Add selector vectors
        self.q_m.push(q_m);
        self.q_o.push(q_o);
        self.q_c.push(q_c);

        self.add_variable_to_map(a, b, c);

        self.n = self.n + 1;
    }

    pub fn bool_gate(
        &mut self,
        a: Variable,
    ) {
        self.w_l.push(a);
        self.w_r.push(a);
        self.w_o.push(a);
    
        self.q_m.push(Scalar::one());
        self.q_l.push(Scalar::zero());
        self.q_r.push(Scalar::zero());
        self.q_o.push(-Scalar::one());
        self.q_c.push(Scalar::zero());

        self.add_variable_to_map(a, a, a);

        self.n = self.n + 1;
    }
    // Computes sigma_1, sigma_2 and sigma_3 permutations
    fn compute_sigma_permutations(&mut self) {
        let sigma_1: Vec<_> =
            (0 + WireType::Left as usize..self.n + WireType::Left as usize).collect();
        let sigma_2: Vec<_> =
            (0 + WireType::Right as usize..self.n + WireType::Right as usize).collect();
        let sigma_3: Vec<_> =
            (0 + WireType::Output as usize..self.n + WireType::Output as usize).collect();

        self.sigmas = vec![sigma_1, sigma_2, sigma_3];

        for (v_index, variable) in self.variable_map.iter().enumerate() {
            // Gets the metadata for each wire assosciated with this variable
            for current_wire in variable {
                // Fetch index of the next wire, if it is the last element
                // We loop back around to the beginning
                let next_index = match v_index == self.variable_map.len() - 1 {
                    true => 0,
                    false => v_index + 1,
                };

                // Fetch the next wire
                let next_wire = &variable[next_index];

                // Map current wire to the next wire
                // XXX: We could probably split up sigmas and do a match statement here
                // Or even better, to avoid the allocations when defining sigma_1,sigma_2 and sigma_3 we can use a better more explicit encoding
                self.sigmas[current_wire.wire_type as usize >> 30][current_wire.gate_index] =
                    next_wire.gate_index + next_wire.wire_type as usize;
            }
        }
    }
}

mod tests {

    use super::*;

    // Ensures a + b - c = 0
    fn simple_add_gadget(composer: &mut StandardComposer, a: Variable, b: Variable, c: Variable) {
        let q_l = Scalar::one();
        let q_r = Scalar::one();
        let q_o = -Scalar::one();
        let q_c = Scalar::zero();
    
    
        composer.add_gate(a, b, c, q_l, q_r, q_o, q_c);
    }

    #[test]
    fn test_add_gate() {
        let mut composer = StandardComposer::new();

        let one = Scalar::one();
        let two = Scalar::one() + Scalar::one();

        let var_one = composer.add_input(one);
        let var_two = composer.add_input(two);

        simple_add_gadget(&mut composer, var_one, var_one, var_two);

        composer.compute_sigma_permutations();
        let proof = composer.prove();
    }

    #[test]
    fn test_circuit_size() {
        let mut composer = StandardComposer::new();

        let one = Scalar::one();
        let two = Scalar::one() + Scalar::one();

        let var_one = composer.add_input(one);
        let var_two = composer.add_input(two);

        let n = 20;

        for _ in 0..n {
            simple_add_gadget(&mut composer, var_one, var_one, var_two);
        }

        assert_eq!(n, composer.circuit_size())
    }
}