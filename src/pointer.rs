//! A segment:offset far pointer type.

use std::cmp;
use std::fmt;

/// A segment:offset far pointer.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Pointer {
    pub segment: u16,
    pub offset: u16,
}

impl Pointer {
    /// Get's the pointer's absolute linear address according to the formula
    /// `segment`*16 + `offset`.
    pub fn abs(self) -> u32 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abs() {
        assert_eq!(Pointer{ segment: 0x0000, offset: 0x0000 }.abs(), 0x000000);
        assert_eq!(Pointer{ segment: 0x1111, offset: 0x1234 }.abs(), 0x012344);
        assert_eq!(Pointer{ segment: 0xffff, offset: 0xffff }.abs(), 0x10ffef);
    }

    #[test]
    fn test_ord() {
        assert!(Pointer{ segment: 0x0123, offset: 0x0000 } < Pointer { segment: 0x0000, offset: 0x1231 });
        assert!(Pointer{ segment: 0x0123, offset: 0x0000 } == Pointer { segment: 0x0000, offset: 0x1230 });
        assert!(Pointer{ segment: 0x0000, offset: 0x1234 } > Pointer { segment: 0x0123, offset: 0x0003 });
    }
}
