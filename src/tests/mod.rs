use std::convert::TryInto;
use std::env;
use std::fs;
use std::io::{self, prelude::*};
use std::path;

mod pack;
mod unpack;

use exe;
use exepack;

pub fn store_u16le(buf: &mut [u8], i: usize, v: u16) {
    buf[i..i+2].clone_from_slice(&u16::to_le_bytes(v));
}

pub fn fetch_u16le(buf: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(buf[i..i+2].try_into().unwrap())
}

pub fn unpacked_sample() -> exe::Exe {
    let mut f = fs::File::open("tests/hello.exe").unwrap();
    exe::Exe::read(&mut f, None).unwrap()
}

pub fn packed_sample() -> exe::Exe {
    let mut f = fs::File::open("tests/hello.exe").unwrap();
    let exe = exe::Exe::read(&mut f, None).unwrap();
    exepack::pack(&exe).unwrap()
}

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
