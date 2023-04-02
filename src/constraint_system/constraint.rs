// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::composer::{Builder, Composer};
use crate::constraint_system::Witness;
use dusk_bls12_381::BlsScalar;

/// Selectors used to address a coefficient inside of a [`Constraint`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selector {
    /// Multiplication coefficient `q_m`
    Multiplication = 0x00,
    /// Left coefficient `q_l`
    Left = 0x01,
    /// Right coefficient `q_r`
    Right = 0x02,
    /// Output coefficient `q_o`
    Output = 0x03,
    /// Fourth advice coefficient `q_4`
    Fourth = 0x04,
    /// Constant expression `q_c`
    Constant = 0x05,
    /// Public input `pi`
    PublicInput = 0x06,

    /// Arithmetic coefficient (internal use)
    Arithmetic = 0x07,
    /// Range coefficient (internal use)
    Range = 0x08,
    /// Logic coefficient (internal use)
    Logic = 0x09,
    /// Curve addition with fixed base coefficient (internal use)
    GroupAddFixedBase = 0x0a,
    /// Curve addition with variable base coefficient (internal use)
    GroupAddVariableBase = 0x0b,
}

/// Wire used to address a witness inside of a [`Constraint`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WiredWitness {
    /// `A` witness
    A = 0x00,
    /// `B` witness
    B = 0x01,
    /// `O` witness
    O = 0x02,
    /// `D` witness
    D = 0x03,
}

/// Constraint representation containing the coefficients of a polynomial
/// evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraint {
    coefficients: [BlsScalar; Self::COEFFICIENTS],
    witnesses: [Witness; Self::WITNESSES],

    // TODO Workaround solution to keep the sparse public input indexes in the
    // composer
    //
    // The indexes are needed to build the `VerifierData` so it won't contain
    // all the constraints of the circuit.
    //
    // However, the composer uses a dense instance of the public inputs to
    // prove statements. This way, it will need to keep the vector of
    // indexes internally so the `VerifierData` can be properly generated.
    //
    // Whenever `Constraint::public` is called and appended to a composer, the
    // composer must include this constraint index into the sparse set of
    // public input indexes.
    //
    // This workaround can be removed only after the composer replaces the
    // internal `Vec<BlsScalar>` of the selectors by a single
    // `Vec<Constraint>`.
    //
    // Related issue: https://github.com/dusk-network/plonk/issues/607
    has_public_input: bool,
}

impl Default for Constraint {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[BlsScalar]> for Constraint {
    fn as_ref(&self) -> &[BlsScalar] {
        &self.coefficients
    }
}

impl Constraint {
    /// Internal coefficients count.
    pub const COEFFICIENTS: usize = 12;

    /// Internal witnesses count.
    pub const WITNESSES: usize = 4;

    /// Initiate the composition of a new selector description of a circuit.
    pub const fn new() -> Self {
        Self {
            coefficients: [BlsScalar::zero(); Self::COEFFICIENTS],
            witnesses: [Builder::ZERO; Self::WITNESSES],
            has_public_input: false,
        }
    }

    fn from_external(constraint: &Self) -> Self {
        const EXTERNAL: usize = Selector::Arithmetic as usize;

        let mut s = Self::default();

        let src = &constraint.coefficients[..EXTERNAL];
        let dst = &mut s.coefficients[..EXTERNAL];

        dst.copy_from_slice(src);

        s.has_public_input = constraint.has_public_input();
        s.witnesses.copy_from_slice(&constraint.witnesses);

        s
    }

    /// Replace the value of a polynomial selector
    pub(crate) fn set<T: Into<BlsScalar>>(mut self, r: Selector, s: T) -> Self {
        self.coefficients[r as usize] = s.into();

        self
    }

    /// Replace the value of an indexed witness
    pub(crate) fn set_witness(&mut self, index: WiredWitness, w: Witness) {
        self.witnesses[index as usize] = w;
    }

    /// Return a reference to the specified selector of a circuit constraint.
    pub(crate) const fn coeff(&self, r: Selector) -> &BlsScalar {
        &self.coefficients[r as usize]
    }

    /// Return the wired witness in the constraint
    pub(crate) const fn witness(&self, w: WiredWitness) -> Witness {
        self.witnesses[w as usize]
    }

    /// Set `s` as the polynomial selector for the multiplication coefficient.
    pub fn mult<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Multiplication, s)
    }

    /// Set `s` as the polynomial selector for the left coefficient.
    pub fn left<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Left, s)
    }

    /// Set `s` as the polynomial selector for the right coefficient.
    pub fn right<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Right, s)
    }

    /// Set `s` as the polynomial selector for the output coefficient.
    pub fn output<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Output, s)
    }

    /// Set `s` as the polynomial selector for the fourth (advice) coefficient.
    pub fn fourth<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Fourth, s)
    }

    /// Set `s` as the polynomial selector for the constant of the constraint.
    pub fn constant<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Constant, s)
    }

    /// Set `s` as the public input of the constraint evaluation.
    pub fn public<T: Into<BlsScalar>>(mut self, s: T) -> Self {
        self.has_public_input = true;

        self.set(Selector::PublicInput, s)
    }

    /// Set witness `a` wired to `qM` and `qL`
    pub fn a(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::A, w);

        self
    }

    /// Set witness `b` wired to `qM` and `qR`
    pub fn b(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::B, w);

        self
    }

    /// Set witness `o` wired to `qO`
    pub fn o(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::O, w);

        self
    }

    /// Set witness `d` wired to the fourth/advice `q4` coefficient
    pub fn d(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::D, w);

        self
    }

    pub(crate) const fn has_public_input(&self) -> bool {
        self.has_public_input
    }

    pub(crate) fn arithmetic(s: &Self) -> Self {
        Self::from_external(s).set(Selector::Arithmetic, 1)
    }

    #[allow(dead_code)]
    // TODO to be used when `ComposerBackend` replaces internal selectors
    // with this struct
    pub(crate) fn range(s: &Self) -> Self {
        Self::from_external(s).set(Selector::Range, 1)
    }

    #[allow(dead_code)]
    // TODO to be used when `ComposerBackend` replaces internal selectors
    // with this struct
    pub(crate) fn logic(s: &Self) -> Self {
        Self::from_external(s)
            .set(Selector::Constant, 1)
            .set(Selector::Logic, 1)
    }

    #[allow(dead_code)]
    // TODO to be used when `ComposerBackend` replaces internal selectors
    // with this struct
    pub(crate) fn logic_xor(s: &Self) -> Self {
        Self::from_external(s)
            .set(Selector::Constant, -BlsScalar::one())
            .set(Selector::Logic, -BlsScalar::one())
    }

    #[allow(dead_code)]
    // TODO to be used when `ComposerBackend` replaces internal selectors
    // with this struct
    pub(crate) fn group_add_fixed_base(s: &Self) -> Self {
        Self::from_external(s).set(Selector::GroupAddFixedBase, 1)
    }

    #[allow(dead_code)]
    // TODO to be used when `ComposerBackend` replaces internal selectors
    // with this struct
    pub(crate) fn group_add_variable_base(s: &Self) -> Self {
        Self::from_external(s).set(Selector::GroupAddVariableBase, 1)
    }
}
