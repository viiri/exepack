//! Tests that actually run the exepack binary, rather than calling its library
//! functions.

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path;
use std::process;

extern crate exepack as exepack_crate;
use exepack_crate::exe;

pub mod common;

/// Returns a path to the exepack binary.
fn exepack_path() -> path::PathBuf {
    // https://github.com/rust-lang/cargo/issues/5758
    let mut target_path = env::current_exe().unwrap()
        .parent().unwrap()
        .to_path_buf();
    if target_path.ends_with("deps") {
        target_path.pop();
    }
    target_path.join(format!("exepack{}", env::consts::EXE_SUFFIX))
}

/// Runs the exepack binary with the given options and input/output files.
fn exepack_run<I, S, P, Q>(options: I, input_path: P, output_path: Q) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
    P: AsRef<path::Path>,
    Q: AsRef<path::Path>,
{
    let status = process::Command::new(exepack_path())
        .args(options)
        .arg("--")
        .arg(input_path.as_ref().as_os_str())
        .arg(output_path.as_ref().as_os_str())
        .stdin(process::Stdio::null())
        .status()?;
    // Can use exit_ok in a future version of Rust: https://github.com/rust-lang/rust/issues/84908
    if status.success() {
        Ok(())
    } else {
        Err(From::from("non-success exit status"))
    }
}

/// Runs the exepack binary to compress a named file to a temporary file.
fn exepack_compress<P: AsRef<path::Path>>(input_path: P) -> Result<tempfile::NamedTempFile, Box<dyn Error>> {
    let output_file = tempfile::NamedTempFile::new()?;
    exepack_run(&([] as [&str; 0]), input_path, output_file.path())?;
    Ok(output_file)
}

/// Runs the exepack binary to decompress a named file to a temporary file.
fn exepack_decompress<P: AsRef<path::Path>>(input_path: P) -> Result<tempfile::NamedTempFile, Box<dyn Error>> {
    let output_file = tempfile::NamedTempFile::new()?;
    exepack_run(&["-d"], input_path, output_file.path())?;
    Ok(output_file)
}

/// Reads an exe::Exe and its trailing data.
fn read_exe_and_trailing<R: io::Read>(r: &mut R) -> Result<(exe::Exe, Vec<u8>), Box<dyn Error>> {
    let mut r = io::BufReader::new(r);
    let exe = exe::Exe::read(&mut r, None)?;
    let mut trailing = Vec::new();
    io::copy(&mut r, &mut trailing)?;
    Ok((exe, trailing))
}

/// Reads an exe::Exe and its trailing data from a file.
fn read_exe_and_trailing_from_file<P: AsRef<path::Path>>(path: P) -> Result<(exe::Exe, Vec<u8>), Box<dyn Error>> {
    read_exe_and_trailing(&mut fs::File::open(&path)?)
}

/// Copies the file `from` to the file `to` if the if the environment variable
/// `EXEPACK_TEST_SAVE_EXE` is set.
fn maybe_copy_file<P, Q>(from: P, to: Q) -> Result<(), Box<dyn Error>>
where
    P: AsRef<path::Path>,
    Q: AsRef<path::Path>,
{
    if let Some(_) = env::var_os("EXEPACK_TEST_SAVE_EXE") {
        fs::copy(from, to)?;
    }
    Ok(())
}

fn roundtrip_count<P: AsRef<path::Path>>(count: usize, max: usize, basename: &str, orig_path: P) -> Option<tempfile::NamedTempFile> {
    if count + 1 > max {
        return None;
    }

    let (orig_exe, _orig_trailing) = read_exe_and_trailing_from_file(&orig_path).unwrap();

    let mut compressed_file = exepack_compress(&orig_path).unwrap();
    let (_compressed_exe, compressed_trailing) = read_exe_and_trailing(&mut compressed_file).unwrap();
    maybe_copy_file(compressed_file.path(), format!("tests/{}_roundtrip_{}.compressed.exe", basename, count + 1)).unwrap();
    // Check that trailing data in compression input is discarded.
    assert_eq!(compressed_trailing.as_slice(), &[]);

    let roundtripped_file = roundtrip_count(count + 1, max, basename, compressed_file.path());

    let mut decompressed_file = exepack_decompress(roundtripped_file.unwrap_or(compressed_file).path()).unwrap();
    let (decompressed_exe, decompressed_trailing) = read_exe_and_trailing(&mut decompressed_file).unwrap();
    maybe_copy_file(decompressed_file.path(), format!("tests/{}_roundtrip_{}.decompressed.exe", basename, count)).unwrap();
    // Check that trailing data in decompression input is discarded.
    assert_eq!(decompressed_trailing.as_slice(), &[]);

    if std::panic::catch_unwind(|| {
        common::assert_exes_equivalent(&orig_exe, &decompressed_exe);
    }).is_err() {
        panic!("unequal at depth {}", count);
    }

    Some(decompressed_file)
}

/// Tests that compressing and re-compressing, then decompressing and
/// re-decompressing, gives equivalent results all the way down and up the chain.
#[test]
fn test_roundtrip() {
    roundtrip_count(0, 9, "hello", "tests/hello.exe");
    roundtrip_count(0, 9, "hello+trailing", "tests/hello+trailing.exe");
}
