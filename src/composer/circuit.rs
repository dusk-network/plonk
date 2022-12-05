// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::error::Error;

use super::Composer;

/// Circuit implementation that can be proved by a Composer
///
/// The default implementation will be used to generate the proving arguments.
pub trait Circuit {
    /// Circuit definition
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer;
}
