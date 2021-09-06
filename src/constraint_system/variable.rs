// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module holds the components needed in the Constraint System.
//! The components used are Variables, AllocatedScalars and Wires.
use core::ops::{Add, Mul, Sub};
use dusk_bls12_381::BlsScalar;

/// The value is a reference to the actual value that was added to the
/// constraint system
#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(pub(crate) usize);

/// Stores the data for a specific wire in an arithmetic circuit
/// This data is the gate index and the type of wire
/// Left(1) signifies that this wire belongs to the first gate and is the left
/// wire
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum WireData {
    /// Left Wire of n'th gate
    Left(usize),
    /// Right Wire of n'th gate
    Right(usize),
    /// Output Wire of n'th gate
    Output(usize),
    /// Fourth Wire of n'th gate
    Fourth(usize),
}

/// A struct which pairs a
/// [`Variable`](crate::constraint_system::variable::Variable) and the
/// underlying [`BlsScalar`] it's linked to in the `ConstraintSystem`.
///
/// An allocated scalar holds the underlying witness assignment for the Prover
/// and a dummy value for the verifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AllocatedScalar {
    /// Variable linked to the `Scalar` in the `ConstraintSystem`.
    var: Variable,
    /// Scalar associated to the `Variable`
    scalar: BlsScalar,
}

impl From<AllocatedScalar> for Variable {
    fn from(alloc: AllocatedScalar) -> Self {
        alloc.var
    }
}

impl From<&AllocatedScalar> for BlsScalar {
    fn from(alloc: &AllocatedScalar) -> Self {
        alloc.scalar
    }
}

impl From<AllocatedScalar> for BlsScalar {
    fn from(alloc: AllocatedScalar) -> Self {
        alloc.scalar
    }
}

impl From<&AllocatedScalar> for Variable {
    fn from(alloc: &AllocatedScalar) -> Self {
        alloc.var
    }
}

impl AllocatedScalar {
    /// Generate a new [`AllocatedScalar`] from a
    /// [`Variable`](crate::constraint_system::variable::Variable) &
    /// [`BlsScalar`].
    pub(crate) const fn new(scalar: BlsScalar, var: Variable) -> Self {
        Self { var, scalar }
    }
    /// Return the underlying [`BlsScalar`] tight to this `AllocatedScalar`
    /// instance.
    pub fn scalar(&self) -> BlsScalar {
        self.scalar
    }
}

impl Add<BlsScalar> for AllocatedScalar {
    type Output = BlsScalar;
    fn add(self, rhs: BlsScalar) -> Self::Output {
        self.scalar() + rhs
    }
}

impl Add<&BlsScalar> for &AllocatedScalar {
    type Output = BlsScalar;
    fn add(self, rhs: &BlsScalar) -> Self::Output {
        self.scalar() + rhs
    }
}

impl Add<AllocatedScalar> for BlsScalar {
    type Output = BlsScalar;
    fn add(self, rhs: AllocatedScalar) -> Self::Output {
        self + rhs.scalar()
    }
}

impl Add<&AllocatedScalar> for &BlsScalar {
    type Output = BlsScalar;
    fn add(self, rhs: &AllocatedScalar) -> Self::Output {
        self + rhs.scalar()
    }
}

impl Sub<BlsScalar> for AllocatedScalar {
    type Output = BlsScalar;
    fn sub(self, rhs: BlsScalar) -> Self::Output {
        self.scalar() - rhs
    }
}

impl Sub<&BlsScalar> for &AllocatedScalar {
    type Output = BlsScalar;
    fn sub(self, rhs: &BlsScalar) -> Self::Output {
        self.scalar() - rhs
    }
}

impl Sub<AllocatedScalar> for BlsScalar {
    type Output = BlsScalar;
    fn sub(self, rhs: AllocatedScalar) -> Self::Output {
        self - rhs.scalar()
    }
}

impl Sub<&AllocatedScalar> for &BlsScalar {
    type Output = BlsScalar;
    fn sub(self, rhs: &AllocatedScalar) -> Self::Output {
        self - rhs.scalar()
    }
}

impl Mul<BlsScalar> for AllocatedScalar {
    type Output = BlsScalar;
    fn mul(self, rhs: BlsScalar) -> Self::Output {
        self.scalar() * rhs
    }
}

impl Mul<&BlsScalar> for &AllocatedScalar {
    type Output = BlsScalar;
    fn mul(self, rhs: &BlsScalar) -> Self::Output {
        self.scalar() * rhs
    }
}

impl Mul<AllocatedScalar> for BlsScalar {
    type Output = BlsScalar;
    fn mul(self, rhs: AllocatedScalar) -> Self::Output {
        self * rhs.scalar()
    }
}

impl Mul<&AllocatedScalar> for &BlsScalar {
    type Output = BlsScalar;
    fn mul(self, rhs: &AllocatedScalar) -> Self::Output {
        self * rhs.scalar()
    }
}

impl Add<AllocatedScalar> for AllocatedScalar {
    type Output = BlsScalar;
    fn add(self, rhs: AllocatedScalar) -> Self::Output {
        self.scalar() + rhs.scalar()
    }
}

impl Sub<AllocatedScalar> for AllocatedScalar {
    type Output = BlsScalar;
    fn sub(self, rhs: AllocatedScalar) -> Self::Output {
        self.scalar() - rhs.scalar()
    }
}

impl Mul<AllocatedScalar> for AllocatedScalar {
    type Output = BlsScalar;
    fn mul(self, rhs: AllocatedScalar) -> Self::Output {
        self.scalar() * rhs.scalar()
    }
}
