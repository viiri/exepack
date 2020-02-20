use std::cmp;
use std::fmt;

/// A segment:offset far pointer.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Pointer {
    pub segment: u16,
    pub offset: u16,
}

impl Pointer {
    pub fn abs(&self) -> u32 {
        self.segment as u32 * 16 + self.offset as u32
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.segment, self.offset)
    }
}

impl Ord for Pointer {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.abs().cmp(&other.abs())
    }
}

impl PartialOrd for Pointer {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Pointer {
    fn eq(&self, other: &Self) -> bool {
        self.abs() == other.abs()
    }
}
