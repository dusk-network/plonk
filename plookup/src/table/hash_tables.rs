// In circuit hashing can be conducted using table lookups from the
// tables defined in this file

use dusk_plonk::constraint_system::StandardComposer;
use dusk_plonk::constraint_system::Variable;
use dusk_plonk::prelude::BlsScalar;


// For Bls and BN254 we have different values of p (and therefore of
// the s_i, etc.)
// These are the required constants for Bls
// Currently making the s_i usize, but in reality I think they should be BlsScalars
// const p: usize = 52435875175126190479447740508185965837690552500527637822603658699938581184513;
const V: usize = 643;
const N: u64 = 27;
// Note this is currently backwards, e.g. S[0] should = 673. But doesn't matter for now
const S: [u64; 27] = [651,658,656,666,663,654,668,
                        677,681,683,669,681,680,677,675,
                        668,675,683,681,683,683,655,680,
                        683,667,678,673];
const T_S: usize = 4;

/// F is a polynomial; we will represent it as a vector of coefficients.
/// We will make F the simple bijection that adds 3 to each element for now.
/// The first entry represents the coefficient of the highest power, the 
/// last entry is the constant in the polynomial.
/// But this approach also seems to require knowing beforehand the degree of F.
/// Perhaps we could find a max degree D for F and then always input F as D-sized vector
const F: [u64; 2] = [1, 3];

// A vector x in (F_p)^t goes through r rounds of some round function R.
// The result is another vector y in (F_p)^t.
#[derive(Debug)]
pub struct HashTable(pub Vec<[BlsScalar; 4]>);

// The whole lookup table will be constructed in 3 parts: the first rows where the third
// entry is derived from the function F, i.e. the rows are of the form (_, _, F(i), ...).
// The middle rows are where the first entries are between V+1 and s_i for some i.
// The binary rows are at the bottom of the table, and they enumerate all binary possibilities
// on T_S bits.
// Perhaps the function F can be entered as a vector of its coefficients; I think this would
// require knowing the degree of F before hand though in order to be able to evaluate it.
impl HashTable {
    pub fn first_rows() -> Self {
        let mut f_rows: Vec<[BlsScalar; T_S]> = Vec::with_capacity(V+1);

        // Have to make sure types of the same, right now V and are usize and BlsScalars.
        // Also need to figure out what this function F is, and how to give it to this
        // table creator
        for i in 0..(V+1) {
            // println!("i: {}", i);
            let eval: u64 = F[0] * i as u64 + F[1];
            // println!("eval: {}", eval);
            let perm_eval = BlsScalar::from(eval);
            let row = [BlsScalar::from(i as u64), BlsScalar::zero(), perm_eval, -BlsScalar::one()];

            // Need to push T_S-3 lots of -1 to the end of each vector
            // for j in 0..(T_S - 3) {
            //     row.push(-BlsScalar::one());
            // }

            f_rows.push(row);
        }
        // println!("f_rows: {:?}", f_rows);
        HashTable(f_rows)
    }

    // The middle rows can be created iteratively too by taking in a vector S = (s_1,..., s_n)
    // in (F_p)^N, and V and N.
    // Will have to do the same thing as in the first rows to append T_S-3 lots of -1 to the end
    // of each row.
    pub fn middle_rows() -> Self {
        // Calculate the number of middle rows
        let mut cap = 0;
        for i in 0..N {
            cap += S[i as usize] as usize - V;
        }

        // Initialise the middle rows
        let mut m_rows: Vec<[BlsScalar; T_S]> = Vec::with_capacity(cap);

        // Iteratively build each row; the first loop determines which section (V+1 to s_{i+1}),
        // the second determines which row in the section (i.e. (V+j, i+1, ...)), and the third
        // loop iteratively appends all the -1's.
        for i in 0..N {
            let distance = S[i as usize] - V as u64;

            for j in 1..(distance + 1) {
                let mut row = [BlsScalar::from(V as u64 + j), BlsScalar::from(i as u64 + 1), BlsScalar::from(V as u64 + j), -BlsScalar::one()];

                // for k in 0..(T_S - 3) {
                //     row.push(-BlsScalar::one());
                // }

                m_rows.push(row);
            }
        }

        HashTable(m_rows)        
    }

    // A function that creates all binary values of word of length T_S,
    // i.e. this is the bottom part of the end hash table we want.
    // It does this in a recursive manner.
    // pub fn binary_rows(T_S: u64) -> Self {
    //     let mut table: Vec<[BlsScalar; T_S]> = Vec.with_capacity(2i32.pow(T_S.try_into().unwrap()));
    //     let mut row = [BlsScalar::zero()];

    //     for i in 1..T_S {
    //         row.push(BlsScalar::zero());
    //     }

    //     table.push(row);

    //     for i in 1..(2i32.pow(T_S)) {
    //         let mut j = 0;
    //         row = iterator(&mut row, &mut j, T_S);
    //         table.push(row);
    //     }

    //     HashTable(table)
    // }
}

// pub fn iterator(&mut row: [BlsScalar; 4], &mut j: usize, T_S) -> [BlsScalar; T_S] {
//     let pos = (T_S - 1) - j;
//     if row[pos] == BlsScalar::zero() {
//         row[pos] = BlsScalar::one();
//     } else {
//         row[pos] = BlsScalar::one();
//         iterator(&mut row, mut j, T_S);
//     }

//     HashTable(row)
// }



#[cfg(test)]
mod tests {
    use crate::table::hash_tables::HashTable;

    #[test]
    fn test_first() {
        let ans = HashTable::first_rows();
        println!("The values are: {:?}", ans);
    }
}