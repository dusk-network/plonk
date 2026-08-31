// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Write;

pub(crate) struct BufferWriter<'a> {
    buffer: &'a mut [u8],
}

impl<'a> BufferWriter<'a> {
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) {
        self.buffer
            .write(bytes)
            .expect("serialization buffer is too small");
    }

    pub(crate) fn finish(self) {
        assert!(
            self.buffer.is_empty(),
            "serialization buffer was not fully written"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "serialization buffer is too small")]
    fn oversized_write_panics() {
        BufferWriter::new(&mut [0u8; 1]).write(&[0u8; 2]);
    }

    #[test]
    #[should_panic(expected = "serialization buffer was not fully written")]
    fn incomplete_write_panics() {
        let mut buffer = [0u8; 2];
        let mut writer = BufferWriter::new(&mut buffer);
        writer.write(&[0u8; 1]);
        writer.finish();
    }
}
