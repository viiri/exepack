use std::convert::TryFrom;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path;

use exe;

pub fn save_exe<P: AsRef<path::Path>>(path: P, exe: &exe::Exe) -> Result<(), Box<dyn std::error::Error>> {
    let f = fs::File::create(path)?;
    let mut w = io::BufWriter::new(f);
    exe.write(&mut w)?;
    w.flush()?;
    Ok(())
}

// call save_exe if the environment variable EXEPACK_TEST_SAVE_EXE is set.
pub fn maybe_save_exe<P: AsRef<path::Path>>(path: P, exe: &exe::Exe) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(_) = env::var_os("EXEPACK_TEST_SAVE_EXE") {
        save_exe(path, exe)?;
    }
    Ok(())
}

/// Panics if two `Exe`s are not equivalent.
///
/// We don't ask for perfect identity. The packing/unpacking roundtrip may
/// change the size of the header, and may add padding to the end of the body.
/// The location of the relocation table may change.
pub fn assert_exes_equivalent(a: &exe::Exe, b: &exe::Exe) {
    // Let a be the one with the shorter body.
    let (a, b) = if a.body.len() <= b.body.len() {
        (a, b)
    } else {
        (b, a)
    };

    assert_eq!(a.e_minalloc, b.e_minalloc);
    assert_eq!(a.e_maxalloc, b.e_maxalloc);
    assert_eq!(a.e_ss, b.e_ss);
    assert_eq!(a.e_sp, b.e_sp);
    assert_eq!(a.e_ip, b.e_ip);
    assert_eq!(a.e_cs, b.e_cs);
    assert_eq!(a.e_ovno, b.e_ovno);

    let diff = (isize::try_from(b.body.len()).unwrap())
        .checked_sub(isize::try_from(a.body.len()).unwrap()).unwrap();
    // should not add more than 15 bytes of padding
    assert!(0 <= diff && diff < 16, "{} {}", a.body.len(), b.body.len());
    let (b_body, b_padding) = b.body.split_at(a.body.len());
    // body up to padding must be identical
    assert_eq!(a.body, b_body);
    // padding must be zeroed
    for c in b_padding {
        assert_eq!(*c, 0x00, "{:?}", b_padding);
    }

    // relocations must be identical up to order
    let mut a_relocs = a.relocs.clone();
    a_relocs.sort();
    let mut b_relocs = a.relocs.clone();
    b_relocs.sort();
    assert_eq!(a_relocs, b_relocs);
}
