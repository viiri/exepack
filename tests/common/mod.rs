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
