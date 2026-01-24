// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK runtime controller

use dusk_bls12_381::BlsScalar;

use crate::prelude::{Constraint, Witness};

#[cfg(feature = "debug")]
use crate::debugger::Debugger;

/// Runtime events
#[derive(Debug, Clone, Copy)]
#[allow(clippy::large_enum_variant)]
pub enum RuntimeEvent {
    /// A witness was appended to the constraint system
    WitnessAppended {
        /// Appended witness
        w: Witness,
        /// Witness value
        v: BlsScalar,
    },

    /// A constraint was appended
    ConstraintAppended {
        /// Appended constraint
        c: Constraint,
    },

    /// The proof construction was finished
    ProofFinished,
}

/// Runtime structure with debugger
#[derive(Debug, Clone)]
pub struct Runtime {
    #[cfg(feature = "debug")]
    debugger: Debugger,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    /// Create a new PLONK runtime
    #[allow(unused_variables)]
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "debug")]
            debugger: Debugger::new(),
        }
    }

    #[allow(unused_variables)]
    pub(crate) fn event(&mut self, event: RuntimeEvent) {
        #[cfg(feature = "debug")]
        self.debugger.event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_new_default_and_events_do_not_panic() {
        let mut rt = Runtime::new();

        rt.event(RuntimeEvent::WitnessAppended {
            w: Witness::ZERO,
            v: BlsScalar::from(42u64),
        });

        rt.event(RuntimeEvent::ConstraintAppended {
            c: Constraint::new(),
        });
        rt.event(RuntimeEvent::ProofFinished);

        // `Default` delegates to `new()`.
        let mut rt2 = Runtime::default();
        rt2.event(RuntimeEvent::ProofFinished);
    }
}
