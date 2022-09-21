//! Extracts the EXEPACK decompression stub from a file and writes it to stdout.

extern crate exepack as exepack_crate;
use exepack_crate::exe;

extern crate lexopt;

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process;

fn locate_end_of_stub(stub: &[u8]) -> Option<usize> {
    const SUFFIX: &[u8] = b"\xcd\x21\xb8\xff\x4c\xcd\x21";
    const MESSAGE: &[u8] = b"Packed file is corrupt";
    // First try looking for the error exit code as in the main exepack
    // executable.
    for (i, window) in stub.windows(SUFFIX.len()).enumerate() {
        if window == SUFFIX {
            return Some(i + SUFFIX.len() + MESSAGE.len());
        }
    }
    // As a fallback, look for English "Packed file is corrupt".
    for (i, window) in stub.windows(MESSAGE.len()).enumerate() {
        if window == MESSAGE {
            return Some(i + MESSAGE.len());
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut path: Option<std::path::PathBuf> = None;
    {
        use lexopt::prelude::*;
        let mut parser = lexopt::Parser::from_env();
        while let Some(arg) = parser.next()? {
            match arg {
                Value(val) if path.is_none() => path = Some(val.into()),
                _ => Err(arg.unexpected())?,
            }
        }
    }
    let path = path.unwrap_or_else(|| {
        eprintln!("usage: {} INPUT.EXE", env::args().next().unwrap());
        process::exit(1);
    });

    let mut f = File::open(&path)?;
    let exe = exe::Exe::read(&mut f)?;
    let stub = &exe.body[usize::from(exe.e_cs)*16 + usize::from(exe.e_ip)..];
    let end = locate_end_of_stub(&stub).ok_or_else(|| "no EXEPACK decompression stub found")?;
    let stub = &stub[..end];
    io::stdout().write(&stub)?;

    Ok(())
}
