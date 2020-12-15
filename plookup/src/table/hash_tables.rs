// In circuit hashing can be conducted using table lookups from the
// tables defined in this file

use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;
use dusk_plonk::prelude::BlsScalar;


// For Bls and BN254 we have different values of p (and therefore of
// the s_i, etc.)
// These are the required constants for Bls
// Currently making the s_i usize, but in reality I think they should be BlsScalars
const p: usize = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
const v: usize = 643;
const n: usize = 27;
// Note this is currently backwards, e.g. S[0] should = 673. But doesn't matter for now
const S: Vec<usize; n> = vec![651,658,656,666,663,654,668,677,681,683,669,681,680,677,675,
                                668,675,683,681,683,683,655,680,683,667,678,673];
const t_s: usize = 4;

// f is a polynomial; we will represent it as a vector of coefficients.
// We will make f the simple bijection that adds 3 to each element for now.
// The first entry represents the coefficient of the highest power, the 
// last entry is the constant in the polynomial.
// But this approach also seems to require knowing beforehand the degree of f.
// Perhaps we could find a max degree D for f and then always input f as D-sized vector
let f: Vec<usize> = vec![1, 3];

// A vector x in (F_p)^t goes through r rounds of some round function R.
// The result is another vector y in (F_p)^t.

pub struct hash_table(Vec<[BlsScalar; t_s]>);

// The whole lookup table will be constructed in 3 parts: the first rows where the third
// entry is derived from the function f, i.e. the rows are of the form (_, _, f(i), ...).
// The middle rows are where the first entries are between v+1 and s_i for some i.
// The binary rows are at the bottom of the table, and they enumerate all binary possibilities
// on t_s bits.
// Perhaps the function f can be entered as a vector of its coefficients; I think this would
// require knowing the degree of f before hand though in order to be able to evaluate it.
impl hash_table {
    pub fn first_rows(v: usize, f: function) -> self {
        let mut f_rows: Vec<[BlsScalar; t_s]> = Vec::with_capacity(v+1);

        // Have to make sure types of the same, right now v and are usize and BlsScalars.
        // Also need to figure out what this function f is, and how to give it to this
        // table creator
        for i in 0..(v+1) {
            let eval = f.0 * i + f.1;
            let perm_eval = BlsScalar::from(eval);
            let mut row = [BlsScalar::from(i), BlsScalar::zero(), BlsScalar::from(f(i))];

            // Need to push t_s-3 lots of -1 to the end of each vector
            for j in 0..(t_s - 3) {
                row.push(-BlsScalar::one());
            }

            f_rows.push(row);
        }

        f_rows
    }

    // The middle rows can be created iteratively too by taking in a vector S = (s_1,..., s_n)
    // in (F_p)^n, and v and n.
    // Will have to do the same thing as in the first rows to append t_s-3 lots of -1 to the end
    // of each row.
    pub fn middle_rows(S: Vec<usize; n>, n: usize, v: usize) -> self {
        // Calculate the number of middle rows
        cap = 0;
        for i in 0..n {
            cap += S[i] - v;
        }

        // Initialise the middle rows
        let mut m_rows: Vec<[BlsScalar; t_s]> = Vec::with_capacity(cap);

        // Iteratively build each row; the first loop determines which section (v+1 to s_{i+1}),
        // the second determines which row in the section (i.e. (v+j, i+1, ...)), and the third
        // loop iteratively appends all the -1's.
        for i in 0..n {
            let distance = S[i] - v;

            for j in 1..(distance + 1) {
                let mut row = [BlsScalar::from(v + j), BlsScalar::from(i + 1), BlsScalar::from(v + j)];

                for k in 0..(t_s - 3) {
                    row.push(-BlsScalar::one());
                }

                m_rows.push(row);
            }
        }

        m_rows        
    }

    // A function that creates all binary values of word of length t_s,
    // i.e. this is the bottom part of the end hash table we want.
    // It does this in a recursive manner.
    pub fn binary_rows(t_s: usize) -> self {
        let mut table: Vec<[BlsScalar; t_s]> = Vec.with_capacity(2.pow(t_s));
        let mut row: [BlsScalar] = [BlsScalar::zero()];

        for i in 1..t_s {
            row.push(BlsScalar::zero());
        }

        table.push(row);

        for i in 1..(2.pow(t_s)) {
            let mut j = 0;
            row = iterator(&mut row, &mut j, t_s);
            table.push(row);
        }

        table
    }
}

pub fn iterator(&mut row: [BlsScalar; t_s], &mut j: u8, t_s) -> [BlsScalar; t_s] {
    let pos = (t_s - 1) - j;
    if row[pos] == BlsScalar::zero() {
        row[pos] = BlsScalar::one();
    } else {
        row[pos] = BlsScalar::one();
        iterator(&mut row, &mut j, t_s);
    }

    row
}


fn main() {
    binary_rows(t_s);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_first() {
        let ans = first_rows(v, f);
        println!("{:?}", ans);
    }
}