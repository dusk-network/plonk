/// Represents a variable in a constraint system.
/// The value is a reference to the position of the value in the variables vector
#[derive(Eq, PartialEq, Clone, Copy, Hash)]
pub struct Variable(pub(super) usize);

// Stores the data for a specific wire
// This data is the gate index and the type of wire
pub struct WireData {
    pub(super) gate_index: usize,
    pub(super) wire_type: WireType,
}

impl WireData {
    pub fn new(index: usize, wire_type: WireType) -> Self {
        WireData {
            gate_index: index,
            wire_type: wire_type,
        }
    }
}

// Encoding for different wire types
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
