// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::{check_satisfied_circuit, check_unsatisfied_circuit};

#[test]
fn component_add_point() {
    pub struct TestCircuit {
        p1: JubJubExtended,
        p2: JubJubExtended,
        sum: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            p1: JubJubExtended,
            p2: JubJubExtended,
            sum: JubJubExtended,
        ) -> Self {
            Self { p1, p2, sum }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            let p1 = JubJubExtended::identity();
            let p2 = JubJubExtended::identity();
            let sum = JubJubExtended::identity();
            Self::new(p1, p2, sum)
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_p1 = composer.append_point(self.p1)?;
            let w_p2 = composer.append_point(self.p2)?;
            let w_sum = composer.append_point(self.sum)?;

            // The test inputs are multiples of the prime-order generator or
            // the identity, so subgroup membership holds by construction.
            let w_p1 = TorsionFreeWitnessPoint::new_unchecked(w_p1);
            let w_p2 = TorsionFreeWitnessPoint::new_unchecked(w_p2);

            let sum_circuit = composer.component_add_point(w_p1, w_p2);

            composer.assert_equal_point(w_sum, sum_circuit.into());

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_add_point";
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let capacity = 1 << 4;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test identity works:
    let msg = "Adding identity should not change the point";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let p2 = JubJubExtended::identity();
    let sum = p1;
    let circuit = TestCircuit::new(p1, p2, sum);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test distributivity:
    // a * GENERATOR + b * GENERATOR = (a + b) * GENERATOR
    let msg = "Random point addition should satisfy the circuit";
    let a = JubJubScalar::random(&mut rng);
    let b = JubJubScalar::random(&mut rng);
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * a;
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * b;
    let sum = dusk_jubjub::GENERATOR_EXTENDED * (a + b);
    let circuit = TestCircuit::new(p1, p2, sum);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test random works:
    let msg = "Random point addition should satisfy the circuit";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let sum = p1 + p2;
    let circuit = TestCircuit::new(p1, p2, sum);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Unsatisfied circuit
    let msg = "Unsatisfied circuit should not pass";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdecafu64);
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xcafeu64);
    let sum = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xcabu64);
    let circuit = TestCircuit::new(p1, p2, sum);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);
}

#[test]
fn component_sub_point() {
    pub struct TestCircuit {
        p1: JubJubExtended,
        p2: JubJubExtended,
        sub: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            p1: JubJubExtended,
            p2: JubJubExtended,
            sub: JubJubExtended,
        ) -> Self {
            Self { p1, p2, sub }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            let p1 = JubJubExtended::identity();
            let p2 = JubJubExtended::identity();
            let sub = JubJubExtended::identity();
            Self::new(p1, p2, sub)
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_p1 = composer.append_point(self.p1)?;
            let w_p2 = composer.append_point(self.p2)?;
            let w_sub = composer.append_point(self.sub)?;

            // The test inputs are multiples of the prime-order generator or
            // the identity, so subgroup membership holds by construction.
            let w_p1 = TorsionFreeWitnessPoint::new_unchecked(w_p1);
            let w_p2 = TorsionFreeWitnessPoint::new_unchecked(w_p2);

            let sub_circuit = composer.component_sub_point(w_p1, w_p2);

            composer.assert_equal_point(w_sub, sub_circuit.into());

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_sub_point";
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let capacity = 1 << 4;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test identity works:
    let msg = "Subtracting identity should not change the point";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let p2 = JubJubExtended::identity();
    let sub = p1;
    let circuit = TestCircuit::new(p1, p2, sub);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test identity works (second case):
    let msg = "Subtracting point from identity should negate the point";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let p2 = JubJubExtended::identity();
    let sub = -p1;
    let circuit = TestCircuit::new(p2, p1, sub);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test random works:
    let msg = "Random point subtraction should satisfy the circuit";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let sub = p1 - p2;
    let circuit = TestCircuit::new(p1, p2, sub);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Unsatisfied circuit
    let msg = "Unsatisfied circuit should not pass";
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdecafu64);
    let p2 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xcafeu64);
    let sub = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xcabu64);
    let circuit = TestCircuit::new(p1, p2, sub);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);
}

#[test]
fn component_neg_point() {
    pub struct TestCircuit {
        p: JubJubExtended,
        neg_p: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(p: JubJubExtended, neg_p: JubJubExtended) -> Self {
            Self { p, neg_p }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            let p = JubJubExtended::identity();
            let neg_p = JubJubExtended::identity();
            Self::new(p, neg_p)
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_p = composer.append_point(self.p)?;
            let w_neg_p = composer.append_point(self.neg_p)?;

            // The test inputs are multiples of the prime-order generator or
            // the identity, so subgroup membership holds by construction.
            let w_p = TorsionFreeWitnessPoint::new_unchecked(w_p);

            let neg_circuit = composer.component_neg_point(w_p);

            composer.assert_equal_point(neg_circuit.into(), w_neg_p);

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_neg_point";
    let mut rng = StdRng::seed_from_u64(0xcafe);
    let capacity = 1 << 4;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test identity works:
    let msg = "Negating the identity should not change it";
    let p = JubJubExtended::identity();
    let neg_p = -p;
    assert_eq!(p, neg_p);
    let circuit = TestCircuit::new(p, neg_p);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test random works:
    let msg = "Random point negation should satisfy the circuit";
    let p = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let neg_p = -p;
    let circuit = TestCircuit::new(p, neg_p);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Unsatisfied circuit
    let msg = "Unsatisfied circuit should not pass";
    let p = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdecafu64);
    let neg_p = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xcafeu64);
    let circuit = TestCircuit::new(p, neg_p);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);
}

#[test]
fn component_mul_generator() {
    pub struct TestCircuit {
        scalar: JubJubScalar,
        generator: JubJubExtended,
        result: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            scalar: JubJubScalar,
            generator: JubJubExtended,
            result: JubJubExtended,
        ) -> Self {
            Self {
                scalar,
                generator,
                result,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::new(
                JubJubScalar::zero(),
                dusk_jubjub::GENERATOR_EXTENDED,
                JubJubExtended::identity(),
            )
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_scalar = composer.append_witness(self.scalar);
            let w_result = composer.append_point(self.result)?;

            let circuit_result =
                composer.component_mul_generator(w_scalar, self.generator)?;

            composer.assert_equal_point(w_result, circuit_result.into());

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_mul_generator";
    let mut rng = StdRng::seed_from_u64(0xbead);
    let capacity = 1 << 9;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // generator point and pi are the same for all tests
    let generator = dusk_jubjub::GENERATOR_EXTENDED;
    let pi = vec![];

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test:
    // GENERATOR * 1 = GENERATOR
    let msg = "Circuit with generator multiplied by one should pass";
    let scalar = JubJubScalar::one();
    let result = dusk_jubjub::GENERATOR_EXTENDED;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test sanity:
    // GENERATOR * random
    let msg = "Circuit with random scalar should pass";
    let scalar = JubJubScalar::random(&mut rng);
    let result = generator * scalar;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test the canonical upper boundary. In the scalar field this is also
    // `-1`; its width-2 NAF carries into digit 252, so it pins the highest
    // signed digit the fixed-base gadget must retain.
    let msg = "Circuit with scalar -1 (r - 1) should pass";
    let scalar = -JubJubScalar::one();
    let result = generator * scalar;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Exercise signed-digit carries at the low end and around the highest
    // ordinary bit of a canonical Jubjub scalar.
    let two_to_251 = JubJubScalar::from_raw([0, 0, 0, 1 << 59]);
    let carry_boundaries = [
        ("low carry at 3", JubJubScalar::from(3u64)),
        (
            "carry into bit 251",
            JubJubScalar::from_raw([
                u64::MAX,
                u64::MAX,
                u64::MAX,
                (1 << 59) - 1,
            ]),
        ),
        ("exact bit 251", two_to_251),
        ("bit 251 plus one", two_to_251 + JubJubScalar::one()),
    ];
    for (case, scalar) in carry_boundaries {
        let result = generator * scalar;
        let circuit = TestCircuit::new(scalar, generator, result);
        check_satisfied_circuit(
            &prover,
            &verifier,
            &pi,
            &circuit,
            &mut rng,
            &format!("Circuit with {case} should pass"),
        );
    }

    // Verify multiple scalars, then perturb result by +G
    // and ensure proving fails for the same scalar.
    for s in 0u64..16 {
        let scalar = JubJubScalar::from(s);
        let result = generator * scalar;
        let ok_msg = format!("Circuit with scalar {s} should pass");
        let circuit = TestCircuit::new(scalar, generator, result);
        check_satisfied_circuit(
            &prover, &verifier, &pi, &circuit, &mut rng, &ok_msg,
        );

        let bad_result = result + generator;
        let bad_msg =
            format!("Circuit with scalar {s} and shifted result should fail");
        let bad_circuit = TestCircuit::new(scalar, generator, bad_result);
        check_unsatisfied_circuit(&prover, &bad_circuit, &mut rng, &bad_msg);
    }

    // Test unsatisfied:
    // GENERATOR * 7 != GENERATOR * 8
    let msg = "Unsatisfied circuit should not pass";
    let scalar = JubJubScalar::from(7u64);
    let result = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(8u64);
    let circuit = TestCircuit::new(scalar, generator, result);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);

    // Test unsatisfied:
    // invalid jubjub scalar panics
    let msg = "Unsatisfied circuit with invalid scalar should panic";
    let scalar = JubJubScalar::from_raw(*(-BlsScalar::one()).internal_repr());
    let result = dusk_jubjub::GENERATOR_EXTENDED;
    let circuit = TestCircuit::new(scalar, generator, result);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);
}

#[test]
fn component_mul_generator_rejects_non_prime_order_generator() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::one());

    let result =
        composer.component_mul_generator(scalar, JubJubExtended::identity());

    assert!(matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)));
}

#[test]
fn component_mul_generator_rejects_zero_z_generator() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::one());
    let generator = JubJubExtended::from_raw_unchecked(
        BlsScalar::zero(),
        BlsScalar::one(),
        BlsScalar::zero(),
        BlsScalar::zero(),
        BlsScalar::zero(),
    );

    let result = composer.component_mul_generator(scalar, generator);

    assert!(matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)));
}

/// Torsion points of the embedded curve, raw coordinates from dusk-jubjub's
/// (private) `EIGHT_TORSION` table. Their claimed orders are pinned by
/// `torsion_points_have_claimed_orders`.
fn torsion_points() -> [(u32, JubJubAffine); 3] {
    let order_8 = JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xd92e_6a79_2720_0d43,
            0x7aa4_1ac4_3dae_8582,
            0xeaaa_e086_a166_18d1,
            0x71d4_df38_ba9e_7973,
        ]),
        BlsScalar::from_raw([
            0xff0d_2068_eff4_96dd,
            0x9106_ee90_f384_a4a1,
            0x16a1_3035_ad4d_7266,
            0x4958_bdb2_1966_982e,
        ]),
    );
    let order_4 = JubJubAffine::from_raw_unchecked(
        BlsScalar::from_raw([
            0xfffe_ffff_0000_0001,
            0x67ba_a400_89fb_5bfe,
            0xa5e8_0b39_939e_d334,
            0x73ed_a753_299d_7d47,
        ]),
        BlsScalar::zero(),
    );
    let order_2 =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), -BlsScalar::one());

    [(8, order_8), (4, order_4), (2, order_2)]
}

#[test]
fn torsion_points_have_claimed_orders() {
    // The guard predicates separate torsion points from prime-order ones but
    // not the torsion orders from each other, so nothing else in these tests
    // would notice a mis-transcribed row of the source table. Pin each claimed
    // order by its doubling chain: the point reaches the identity after
    // exactly `log2(order)` doublings and not before.
    for (order, point) in torsion_points() {
        let mut accumulator = JubJubExtended::from(point);
        assert!(!bool::from(accumulator.is_identity()), "order {order}");

        for _ in 1..order.ilog2() {
            accumulator = accumulator.double();
            assert!(!bool::from(accumulator.is_identity()), "order {order}");
        }

        assert!(
            bool::from(accumulator.double().is_identity()),
            "order {order}"
        );
    }
}

#[test]
fn component_mul_generator_rejects_off_curve_generator() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::one());
    // `(0, 0)` does not satisfy the curve equation. As an extended point it
    // carries `Z = 1`, so the guard has to reject it through `is_on_curve`
    // rather than through the leading `Z = 0` check.
    let generator: JubJubExtended =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::zero())
            .into();
    assert_ne!(generator.get_z(), BlsScalar::zero());
    // The affine projection itself is off-curve, which separates this case
    // from the extended-coordinate one below.
    assert!(!bool::from(JubJubAffine::from(generator).is_on_curve()));
    assert!(!bool::from(generator.is_on_curve()));

    let result = composer.component_mul_generator(scalar, generator);

    assert!(matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)));
}

#[test]
fn component_mul_generator_rejects_inconsistent_extended_coordinates() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::one());
    // `is_on_curve` on an extended point also ties the two halves of the
    // extended coordinate to the affine ones: `u * v * z == t1 * t2`. Build a
    // generator whose affine projection is the honest `GENERATOR` — on-curve
    // and of prime order — but whose `t1`/`t2` break that identity, so this
    // conjunct is the only thing left to reject it.
    let affine = JubJubAffine::from(dusk_jubjub::GENERATOR_EXTENDED);
    let generator = JubJubExtended::from_raw_unchecked(
        affine.get_u(),
        affine.get_v(),
        BlsScalar::one(),
        affine.get_u(),
        affine.get_v() + BlsScalar::one(),
    );
    assert_ne!(generator.get_z(), BlsScalar::zero());
    assert!(bool::from(JubJubAffine::from(generator).is_on_curve()));
    assert!(!bool::from(generator.is_on_curve()));

    let result = composer.component_mul_generator(scalar, generator);

    assert!(matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)));
}

#[test]
fn component_mul_generator_rejects_on_curve_torsion_generator() {
    for (order, point) in torsion_points() {
        let generator: JubJubExtended = point.into();

        // Isolate the `is_torsion_free` branch: the point has to clear the
        // `Z = 0` and on-curve checks and differ from the identity, otherwise
        // an earlier condition rejects it and this branch is never reached.
        assert_ne!(generator.get_z(), BlsScalar::zero(), "order {order}");
        assert!(bool::from(generator.is_on_curve()), "order {order}");
        assert!(!bool::from(generator.is_identity()), "order {order}");
        assert!(bool::from(generator.is_small_order()), "order {order}");

        let mut composer = Composer::initialized();
        let scalar = composer.append_witness(JubJubScalar::one());

        let result = composer.component_mul_generator(scalar, generator);

        assert!(
            matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)),
            "order {order}"
        );
    }
}

#[test]
fn component_mul_generator_rejects_mixed_order_generator() {
    // A base of order `2r`, `4r` or `8r`: a prime-order point plus a torsion
    // component. Unlike the small-order cases it survives the doubling chain
    // `is_small_order` runs, so only the `r`-multiplication in
    // `is_torsion_free` separates it from an honest generator.
    let prime_order_part =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdead_beef_u64);

    for (order, torsion) in torsion_points() {
        let generator = prime_order_part + JubJubExtended::from(torsion);

        assert_ne!(generator.get_z(), BlsScalar::zero(), "order {order}");
        assert!(bool::from(generator.is_on_curve()), "order {order}");
        assert!(!bool::from(generator.is_identity()), "order {order}");
        assert!(!bool::from(generator.is_small_order()), "order {order}");

        let mut composer = Composer::initialized();
        let scalar = composer.append_witness(JubJubScalar::one());

        let result = composer.component_mul_generator(scalar, generator);

        assert!(
            matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)),
            "order {order}"
        );
    }
}

#[test]
fn component_mul_generator_rejects_non_canonical_scalar() {
    let mut composer = Composer::initialized();
    // A BLS scalar at or above the Jubjub scalar modulus: the witness has no
    // canonical Jubjub encoding, so the scalar guard rejects it. The generator
    // is honest, so it cannot be what rejects the call.
    let scalar = composer.append_witness(-BlsScalar::one());

    let result = composer
        .component_mul_generator(scalar, dusk_jubjub::GENERATOR_EXTENDED);

    assert!(matches!(result, Err(Error::JubJubScalarMalformed)));
}

#[test]
fn component_mul_generator_accepts_prime_order_generator() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::one());
    // An honest base other than `GENERATOR`, so the rejection tests above
    // cannot pass by refusing every generator.
    let generator =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdead_beef_u64);
    assert!(bool::from(generator.is_prime_order()));

    assert!(composer.component_mul_generator(scalar, generator).is_ok());
}

/// The generators of a double signature, which `component_mul_generator_pair`
/// is exercised with.
fn pair_generators() -> [JubJubExtended; 2] {
    [
        dusk_jubjub::GENERATOR_EXTENDED,
        dusk_jubjub::GENERATOR_NUMS_EXTENDED,
    ]
}

#[test]
fn component_mul_generator_pair() {
    pub struct TestCircuit {
        scalar: JubJubScalar,
        results: [JubJubExtended; 2],
    }

    impl TestCircuit {
        pub fn new(scalar: JubJubScalar, results: [JubJubExtended; 2]) -> Self {
            Self { scalar, results }
        }

        pub fn honest(scalar: JubJubScalar) -> Self {
            Self::new(scalar, pair_generators().map(|g| g * scalar))
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            Self::honest(JubJubScalar::zero())
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_scalar = composer.append_witness(self.scalar);
            let w_result_a = composer.append_point(self.results[0])?;
            let w_result_b = composer.append_point(self.results[1])?;

            let [generator_a, generator_b] = pair_generators();
            let (result_a, result_b) = composer.component_mul_generator_pair(
                w_scalar,
                generator_a,
                generator_b,
            )?;

            composer.assert_equal_point(w_result_a, result_a.into());
            composer.assert_equal_point(w_result_b, result_b.into());

            Ok(())
        }
    }

    let label = b"component_mul_generator_pair";
    let mut rng = StdRng::seed_from_u64(0xbea2);
    let capacity = 1 << 11;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");
    let pi = vec![];

    // The scalars `component_mul_generator` is tested at: the edges, `r - 1`
    // with its width-2 NAF carry into digit 252, and the carries around the
    // highest ordinary bit of a canonical Jubjub scalar.
    let two_to_251 = JubJubScalar::from_raw([0, 0, 0, 1 << 59]);
    let scalars = [
        ("zero", JubJubScalar::zero()),
        ("one", JubJubScalar::one()),
        ("a random scalar", JubJubScalar::random(&mut rng)),
        ("scalar -1 (r - 1)", -JubJubScalar::one()),
        ("low carry at 3", JubJubScalar::from(3u64)),
        (
            "carry into bit 251",
            JubJubScalar::from_raw([
                u64::MAX,
                u64::MAX,
                u64::MAX,
                (1 << 59) - 1,
            ]),
        ),
        ("exact bit 251", two_to_251),
        ("bit 251 plus one", two_to_251 + JubJubScalar::one()),
    ];
    for (case, scalar) in scalars {
        check_satisfied_circuit(
            &prover,
            &verifier,
            &pi,
            &TestCircuit::honest(scalar),
            &mut rng,
            &format!("Circuit with {case} should pass"),
        );
    }

    // Each result is bound on its own: shifting either, or swapping them,
    // fails.
    let [generator_a, generator_b] = pair_generators();
    let scalar = JubJubScalar::from(0xc0ffee_u64);
    let [result_a, result_b] = TestCircuit::honest(scalar).results;
    let wrong_results = [
        (
            "the first result shifted",
            [result_a + generator_a, result_b],
        ),
        (
            "the second result shifted",
            [result_a, result_b + generator_b],
        ),
        ("the results swapped", [result_b, result_a]),
    ];
    for (case, results) in wrong_results {
        check_unsatisfied_circuit(
            &prover,
            &TestCircuit::new(scalar, results),
            &mut rng,
            &format!("Circuit with {case} should fail"),
        );
    }
}

#[test]
fn component_mul_generator_pair_rejects_either_invalid_generator() {
    // The guard of `component_mul_generator`, applied to each generator before
    // any gate is appended.
    let off_curve: JubJubExtended =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::zero())
            .into();
    let prime_order_part =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdead_beef_u64);
    let mut invalid = vec![
        ("the identity".to_string(), JubJubExtended::identity()),
        ("a zero-Z point".to_string(), zero_z_point()),
        ("an off-curve point".to_string(), off_curve),
    ];
    for (order, torsion) in torsion_points() {
        invalid.push((format!("an order-{order} point"), torsion.into()));
        invalid.push((
            format!("a point of order {order}r"),
            prime_order_part + JubJubExtended::from(torsion),
        ));
    }

    let honest = dusk_jubjub::GENERATOR_EXTENDED;
    for (case, generator) in invalid {
        for (position, [a, b]) in [
            ("first", [generator, honest]),
            ("second", [honest, generator]),
        ] {
            let mut composer = Composer::initialized();
            let scalar = composer.append_witness(JubJubScalar::one());
            let constraints = composer.constraints();

            let result = composer.component_mul_generator_pair(scalar, a, b);

            assert!(
                matches!(result, Err(Error::JubJubGeneratorNotPrimeOrder)),
                "{case} as the {position} generator"
            );
            assert_eq!(
                composer.constraints(),
                constraints,
                "{case} as the {position} generator: no gate appended"
            );
        }
    }
}

#[test]
fn component_mul_generator_pair_rejects_non_canonical_scalar() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(-BlsScalar::one());
    let constraints = composer.constraints();
    let [generator_a, generator_b] = pair_generators();

    let result =
        composer.component_mul_generator_pair(scalar, generator_a, generator_b);

    assert!(matches!(result, Err(Error::JubJubScalarMalformed)));
    assert_eq!(composer.constraints(), constraints, "no gate appended");
}

#[test]
fn component_mul_generator_pair_accepts_prime_order_generators() {
    let mut composer = Composer::initialized();
    let scalar = composer.append_witness(JubJubScalar::one());
    // An honest base other than `GENERATOR`, in both accepted input forms.
    let generator =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdead_beef_u64);

    assert!(
        composer
            .component_mul_generator_pair(
                scalar,
                generator,
                JubJubAffine::from(generator),
            )
            .is_ok()
    );
}

/// An extended point with `Z = 0` and the honest generator's numerators, so
/// only the `Z` guard separates it from a valid point.
fn zero_z_point() -> JubJubExtended {
    let generator = JubJubAffine::from(dusk_jubjub::GENERATOR_EXTENDED);

    JubJubExtended::from_raw_unchecked(
        generator.get_u(),
        generator.get_v(),
        BlsScalar::zero(),
        generator.get_u(),
        generator.get_v(),
    )
}

#[test]
fn append_point_rejects_zero_z_point() {
    let mut composer = Composer::initialized();

    let result = composer.append_point(zero_z_point());

    assert!(matches!(result, Err(Error::JubJubPointDegenerate)));
}

#[test]
fn append_public_point_rejects_zero_z_point() {
    let mut composer = Composer::initialized();

    let result = composer.append_public_point(zero_z_point());

    assert!(matches!(result, Err(Error::JubJubPointDegenerate)));
}

#[test]
fn assert_equal_public_point_rejects_zero_z_point() {
    let mut composer = Composer::initialized();
    let point = composer
        .append_point(dusk_jubjub::GENERATOR)
        .expect("an honest generator should be appendable");

    let result = composer.assert_equal_public_point(point, zero_z_point());

    assert!(matches!(result, Err(Error::JubJubPointDegenerate)));
}

#[test]
fn append_constant_point_separates_its_rejection_branches() {
    let mut composer = Composer::initialized();

    // Degenerate representation: refused before the membership check.
    assert!(matches!(
        composer.append_constant_point(zero_z_point()),
        Err(Error::JubJubPointDegenerate)
    ));

    // Representable but outside the prime-order subgroup: the native
    // membership check rejects it, and keeps its own error.
    for (order, point) in torsion_points() {
        assert_eq!(
            composer.append_constant_point(point).unwrap_err(),
            Error::JubJubPointNotTorsionFree,
            "order {order}"
        );
    }
}

#[test]
fn append_constant_point_rejects_inconsistent_extended_coordinates() {
    let mut composer = Composer::initialized();
    // The affine projection is the honest generator — on-curve and of prime
    // order — while `T1 · T2 != U · V · Z`. Validating the extended point
    // catches that; validating its projection, as the guard did while it sat
    // after the conversion, would accept it.
    let affine = JubJubAffine::from(dusk_jubjub::GENERATOR_EXTENDED);
    let point = JubJubExtended::from_raw_unchecked(
        affine.get_u(),
        affine.get_v(),
        BlsScalar::one(),
        affine.get_u(),
        affine.get_v() + BlsScalar::one(),
    );
    assert!(bool::from(JubJubAffine::from(point).is_on_curve()));
    assert!(!bool::from(point.is_on_curve()));

    let result = composer.append_constant_point(point);

    assert!(matches!(result, Err(Error::JubJubPointNotTorsionFree)));
}

#[test]
fn point_entry_points_accept_honest_points() {
    let mut composer = Composer::initialized();
    // An honest base other than `GENERATOR`, in both accepted input forms, so
    // the rejection tests above cannot pass against entry points that refuse
    // every point.
    let extended =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdead_beef_u64);
    let affine = JubJubAffine::from(extended);

    let point = composer
        .append_point(extended)
        .expect("an honest point should be appendable");
    assert!(composer.append_point(affine).is_ok());
    assert!(composer.append_constant_point(extended).is_ok());
    assert!(composer.append_constant_point(affine).is_ok());
    assert!(composer.append_public_point(extended).is_ok());
    assert!(composer.append_public_point(affine).is_ok());
    assert!(composer.assert_equal_public_point(point, extended).is_ok());
    assert!(composer.assert_equal_public_point(point, affine).is_ok());
}

#[test]
fn component_mul_point() {
    pub struct TestCircuit {
        scalar: JubJubScalar,
        point: JubJubExtended,
        result: JubJubExtended,
    }

    impl TestCircuit {
        pub fn new(
            scalar: JubJubScalar,
            point: JubJubExtended,
            result: JubJubExtended,
        ) -> Self {
            Self {
                scalar,
                point,
                result,
            }
        }
    }

    impl Default for TestCircuit {
        fn default() -> Self {
            let scalar = JubJubScalar::from(0u64);
            let point = dusk_jubjub::GENERATOR_EXTENDED;
            let result = JubJubAffine::from_raw_unchecked(
                BlsScalar::zero(),
                BlsScalar::one(),
            )
            .into();

            Self::new(scalar, point, result)
        }
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let w_scalar = composer.append_witness(self.scalar);
            let w_point = composer.append_point(self.point)?;
            let w_result = composer.append_point(self.result)?;

            // The test base is a multiple of the prime-order generator, so
            // subgroup membership holds by construction.
            let w_point = TorsionFreeWitnessPoint::new_unchecked(w_point);

            let result_circuit =
                composer.component_mul_point(w_scalar, w_point);

            composer.assert_equal_point(w_result, result_circuit.into());

            Ok(())
        }
    }

    // Compile common circuit descriptions for the prover and verifier to be
    // used by all tests
    let label = b"component_mul_point";
    let mut rng = StdRng::seed_from_u64(0xdeed);
    let capacity = 1 << 11;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) = Compiler::compile::<TestCircuit>(&pp, label)
        .expect("Circuit should compile");

    // Test default works:
    let msg = "Default circuit verification should pass";
    let circuit = TestCircuit::default();
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test:
    // GENERATOR * 1 = GENERATOR
    let msg = "Circuit with generator multiplied by one should pass";
    let scalar = JubJubScalar::one();
    let point = dusk_jubjub::GENERATOR_EXTENDED;
    let result = dusk_jubjub::GENERATOR_EXTENDED;
    let circuit = TestCircuit::new(scalar, point, result);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test:
    // random * 0 = (0, 1)
    let msg =
        "Circuit with random point multiplied by zero should be the o = (0,1)";
    let scalar = JubJubScalar::zero();
    let point =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let result: JubJubExtended =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::one())
            .into();
    let circuit = TestCircuit::new(scalar, point, result);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Test: random works
    let msg = "Circuit with random point multiplication should pass";
    let scalar = JubJubScalar::random(&mut rng);
    let point =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let result = point * scalar;
    let circuit = TestCircuit::new(scalar, point, result);
    let pi = vec![];
    check_satisfied_circuit(&prover, &verifier, &pi, &circuit, &mut rng, msg);

    // Unsatisfied circuit
    let msg = "Unsatisfied circuit should not pass";
    let scalar = JubJubScalar::random(&mut rng);
    let point =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let result =
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
    let circuit = TestCircuit::new(scalar, point, result);
    check_unsatisfied_circuit(&prover, &circuit, &mut rng, msg);
}

/// `[k]point` for the integer `k` that the low 252 bits of `scalar` encode:
/// the product of the ladder in `component_mul_point`, and `[scalar]point`
/// whenever `scalar < 2^252`.
fn ladder_multiple(point: JubJubExtended, scalar: BlsScalar) -> JubJubExtended {
    scalar.to_bits()[..252].iter().rev().fold(
        JubJubExtended::identity(),
        |product, bit| match bit {
            1 => product.double() + point,
            _ => product.double(),
        },
    )
}

/// The bases `component_mul_point_pair` is exercised with.
fn pair_points() -> [JubJubExtended; 2] {
    [
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xdead_u64),
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(0xbeef_u64),
    ]
}

/// Multiplies both bases by one scalar with `component_mul_point_pair`.
struct MulPointPairCircuit {
    scalar: BlsScalar,
    points: [JubJubExtended; 2],
    results: [JubJubExtended; 2],
}

impl MulPointPairCircuit {
    fn new(
        scalar: BlsScalar,
        points: [JubJubExtended; 2],
        results: [JubJubExtended; 2],
    ) -> Self {
        Self {
            scalar,
            points,
            results,
        }
    }

    /// The circuit claiming the products of the ladder.
    fn honest(scalar: BlsScalar, points: [JubJubExtended; 2]) -> Self {
        Self::new(scalar, points, points.map(|p| ladder_multiple(p, scalar)))
    }
}

impl Default for MulPointPairCircuit {
    fn default() -> Self {
        Self::honest(BlsScalar::zero(), pair_points())
    }
}

impl Circuit for MulPointPairCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let w_scalar = composer.append_witness(self.scalar);
        let w_point_a = composer.append_point(self.points[0])?;
        let w_point_b = composer.append_point(self.points[1])?;
        let w_result_a = composer.append_point(self.results[0])?;
        let w_result_b = composer.append_point(self.results[1])?;

        // The test bases are multiples of the prime-order generator, so
        // subgroup membership holds by construction.
        let w_point_a = TorsionFreeWitnessPoint::new_unchecked(w_point_a);
        let w_point_b = TorsionFreeWitnessPoint::new_unchecked(w_point_b);

        let (result_a, result_b) =
            composer.component_mul_point_pair(w_scalar, w_point_a, w_point_b);

        composer.assert_equal_point(w_result_a, result_a.into());
        composer.assert_equal_point(w_result_b, result_b.into());

        Ok(())
    }
}

/// Multiplies one base by a scalar with `component_mul_point`, as the
/// reference for the scalar bound of the pair.
struct MulPointCircuit {
    scalar: BlsScalar,
    point: JubJubExtended,
    result: JubJubExtended,
}

impl Default for MulPointCircuit {
    fn default() -> Self {
        let [point, _] = pair_points();

        Self {
            scalar: BlsScalar::zero(),
            point,
            result: JubJubExtended::identity(),
        }
    }
}

impl Circuit for MulPointCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let w_scalar = composer.append_witness(self.scalar);
        let w_point = composer.append_point(self.point)?;
        let w_result = composer.append_point(self.result)?;

        // A multiple of the prime-order generator.
        let w_point = TorsionFreeWitnessPoint::new_unchecked(w_point);
        let result = composer.component_mul_point(w_scalar, w_point);

        composer.assert_equal_point(w_result, result.into());

        Ok(())
    }
}

#[test]
fn component_mul_point_pair() {
    let label = b"component_mul_point_pair";
    let mut rng = StdRng::seed_from_u64(0xdee2);
    let capacity = 1 << 13;
    let pp = PublicParameters::setup(capacity, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (prover, verifier) =
        Compiler::compile::<MulPointPairCircuit>(&pp, label)
            .expect("Circuit should compile");
    let pi = vec![];

    let random_points = [(); 2].map(|_| {
        dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::random(&mut rng)
    });
    let cases = [
        ("zero", BlsScalar::zero(), pair_points()),
        ("one", BlsScalar::one(), pair_points()),
        (
            "a random scalar and random points",
            JubJubScalar::random(&mut rng).into(),
            random_points,
        ),
        (
            "scalar -1 (r - 1)",
            (-JubJubScalar::one()).into(),
            pair_points(),
        ),
        (
            "the same point twice",
            JubJubScalar::random(&mut rng).into(),
            [pair_points()[0]; 2],
        ),
    ];
    for (case, scalar, points) in cases {
        let circuit = MulPointPairCircuit::honest(scalar, points);
        assert_eq!(
            circuit.results,
            points.map(|point| point
                * JubJubScalar::from_bytes(&scalar.to_bytes()).unwrap()),
            "{case}: the ladder must compute the true multiples"
        );
        check_satisfied_circuit(
            &prover,
            &verifier,
            &pi,
            &circuit,
            &mut rng,
            &format!("Circuit with {case} should pass"),
        );
    }

    // Each result is bound on its own: shifting either, or swapping them,
    // fails.
    let scalar = BlsScalar::from(0xc0ffee_u64);
    let points = pair_points();
    let [result_a, result_b] =
        MulPointPairCircuit::honest(scalar, points).results;
    let wrong_results = [
        ("the first result shifted", [result_a + points[0], result_b]),
        (
            "the second result shifted",
            [result_a, result_b + points[1]],
        ),
        ("the results swapped", [result_b, result_a]),
    ];
    for (case, results) in wrong_results {
        check_unsatisfied_circuit(
            &prover,
            &MulPointPairCircuit::new(scalar, points, results),
            &mut rng,
            &format!("Circuit with {case} should fail"),
        );
    }
}

#[test]
fn component_mul_point_pair_keeps_the_scalar_bound_of_component_mul_point() {
    let mut rng = StdRng::seed_from_u64(0xb0d);
    let pp = PublicParameters::setup(1 << 13, &mut rng)
        .expect("Creation of public parameter shouldn't fail");
    let (single_prover, _) =
        Compiler::compile::<MulPointCircuit>(&pp, b"mul_point_bound")
            .expect("Circuit should compile");
    let (pair_prover, _) =
        Compiler::compile::<MulPointPairCircuit>(&pp, b"mul_point_pair_bound")
            .expect("Circuit should compile");

    // Both gadgets bound the scalar below `2^252`, not to the canonical Jubjub
    // interval: `r` and the scalars above it up to `2^252 - 1` multiply as
    // integers, and from `2^252` the decomposition fails. Each circuit claims
    // the products of its ladder, so only the bound can reject it.
    let r = BlsScalar::from(-JubJubScalar::one()) + BlsScalar::one();
    let two_to_252 = BlsScalar::pow_of_2(252);
    let cases = [
        ("r", r, true),
        ("r + 1", r + BlsScalar::one(), true),
        ("2^252 - 1", two_to_252 - BlsScalar::one(), true),
        ("2^252", two_to_252, false),
        ("q - 1", -BlsScalar::one(), false),
    ];
    for (case, scalar, accepted) in cases {
        let pair = MulPointPairCircuit::honest(scalar, pair_points());
        let single = MulPointCircuit {
            scalar,
            point: pair.points[0],
            result: pair.results[0],
        };

        for (gadget, outcome) in [
            (
                "component_mul_point",
                single_prover.prove(&mut rng, &single),
            ),
            (
                "component_mul_point_pair",
                pair_prover.prove(&mut rng, &pair),
            ),
        ] {
            match outcome {
                Ok(_) => assert!(accepted, "{gadget} must reject {case}"),
                Err(Error::CircuitUnsatisfied) => {
                    assert!(!accepted, "{gadget} must accept {case}")
                }
                Err(other) => panic!("{gadget} with {case}: {other:?}"),
            }
        }
    }
}
