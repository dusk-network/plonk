/// Represents a variable in a constraint system.
/// The value is a reference to the actual value that was added to the constraint system
#[derive(Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(pub(super) usize);

/// Stores the data for a specific wire in an arithmetic circuit
/// This data is the gate index and the type of wire
/// (1,Left) signifies that this wire belongs to the first gate and is the left wire
pub(crate) struct WireData {
    pub(super) gate_index: usize,
    pub(super) wire_type: WireType,
}

impl WireData {
    /// Creates a new WireData instance
    pub fn new(index: usize, wire_type: WireType) -> Self {
        WireData {
            gate_index: index,
            wire_type: wire_type,
        }
    }
}

const MASK: usize = (1 << 29) - 1;

impl From<&usize> for WireData {
    fn from(n: &usize) -> WireData {
        let wire_idx = n & MASK;
        WireData {
            gate_index: wire_idx,
            wire_type: n.into(),
        }
    }
}
/// Encoding for different wire types
/// // XXX: Something like Right(10) would look like a better encoding
#[derive(Copy, Clone)]
pub enum WireType {
    Left = 0,
    Right = (1 << 30),
    Output = (1 << 31),
}

impl From<&usize> for WireType {
    fn from(n: &usize) -> WireType {
        match ((n >> 30) as usize) & (3 as usize) {
            2 => WireType::Output,
            1 => WireType::Right,
            _ => WireType::Left,
        }
    }
}
