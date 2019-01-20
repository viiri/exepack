use std::cmp;
use std::fmt;

#[derive(Debug, Copy, Clone)]
/// A segment:offset far pointer.
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

impl cmp::Ord for Pointer {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.abs().cmp(&other.abs())
    }
}

impl cmp::PartialOrd for Pointer {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::PartialEq for Pointer {
    fn eq(&self, other: &Self) -> bool {
        self.abs() == other.abs()
    }
}

impl cmp::Eq for Pointer {}
