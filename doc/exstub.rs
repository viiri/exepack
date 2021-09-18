extern crate exepack as exepack_crate;
use exepack_crate::exe;

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process;

fn locate_end_of_stub(stub: &[u8]) -> Option<usize> {
    const SUFFIX: &[u8] = b"Packed file is corrupt";
    for (i, window) in stub.windows(SUFFIX.len()).enumerate() {
        if window == SUFFIX {
            return Some(i + SUFFIX.len());
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = getopts::Options::new();
    let matches = opts.parse(env::args().skip(1))?;

    if matches.free.len() != 1 {
        eprintln!("Need INPUT.EXE argument");
        process::exit(1);
    }
    let path = &matches.free[0];

    let mut f = File::open(&path)?;
    let exe = exe::Exe::read(&mut f, None)?;
    let stub = &exe.body[usize::from(exe.e_cs)*16 + usize::from(exe.e_ip)..];
    let stub = &stub[..locate_end_of_stub(&stub).unwrap()];
    io::stdout().write(&stub)?;

    Ok(())
}
