//! Tests that actually run the exepack binary, rather than calling its library
//! functions.

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read};
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

/// Runs the exepack binary with the given options and input file, and a
/// temporary output file.
fn exepack_run_tempfile<I, S, P>(options: I, input_path: P) -> Result<tempfile::NamedTempFile, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
    P: AsRef<path::Path>,
{
    let output_file = tempfile::NamedTempFile::new()?;
    exepack_run(options, input_path, output_file.path())?;
    Ok(output_file)
}

/// Reads an exe::Exe and its trailing data.
fn read_exe_and_trailing<R: io::Read>(r: &mut R) -> Result<(exe::Exe, Vec<u8>), Box<dyn Error>> {
    let mut r = io::BufReader::new(r);
    let exe = exe::Exe::read(&mut r)?;
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

/// Tests that the -d and --decompress options are equivalent.
#[test]
fn test_decompress_options() {
    let compressed_file = exepack_run_tempfile(&[] as &[&str; 0], "tests/hello.exe").unwrap();

    let mut d_file = exepack_run_tempfile(&["-d"], compressed_file.path()).unwrap();
    let mut d_buf = Vec::new();
    d_file.read_to_end(&mut d_buf).unwrap();

    let mut decompress_file = exepack_run_tempfile(&["--decompress"], compressed_file.path()).unwrap();
    let mut decompress_buf = Vec::new();
    decompress_file.read_to_end(&mut decompress_buf).unwrap();

    assert_eq!(d_buf, decompress_buf);
}

fn roundtrip_count<P: AsRef<path::Path>>(count: usize, max: usize, basename: &str, orig_path: P) -> Option<tempfile::NamedTempFile> {
    if count + 1 > max {
        return None;
    }

    let (orig_exe, _orig_trailing) = read_exe_and_trailing_from_file(&orig_path).unwrap();

    let mut compressed_file = exepack_run_tempfile(&[] as &[&str; 0], &orig_path).unwrap();
    let (_compressed_exe, compressed_trailing) = read_exe_and_trailing(&mut compressed_file).unwrap();
    maybe_copy_file(compressed_file.path(), format!("tests/{}_roundtrip_{}.compressed.exe", basename, count + 1)).unwrap();
    // Check that trailing data in compression input is discarded.
    assert_eq!(compressed_trailing.as_slice(), &[]);

    let roundtripped_file = roundtrip_count(count + 1, max, basename, compressed_file.path());

    let mut decompressed_file = exepack_run_tempfile(&["-d"], roundtripped_file.unwrap_or(compressed_file).path()).unwrap();
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

#[cfg(unix)]
fn non_utf8_osstring() -> std::ffi::OsString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(b"exepack-non-utf8-\x80-").to_owned()
}

#[cfg(windows)]
fn non_utf8_osstring() -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    let mut s = std::ffi::OsString::from("exepack-non-utf8-");
    s.push(std::ffi::OsString::from_wide(&[0xd800]));
    s.push("-");
    s
}

/// Tests that the program accepts paths that are not representable as UTF-8.
#[test]
fn test_non_utf8_paths() {
    let mut input_tempfile = tempfile::Builder::new()
        .prefix(&non_utf8_osstring())
        .tempfile().unwrap();
    let output_tempfile = tempfile::Builder::new()
        .prefix(&non_utf8_osstring())
        .tempfile().unwrap();
    // Ensure the paths are not representable as str.
    assert!(input_tempfile.path().to_str().is_none());
    assert!(output_tempfile.path().to_str().is_none());

    {
        let mut f = fs::File::open("tests/hello.exe").unwrap();
        io::copy(&mut f, &mut input_tempfile).unwrap();
    }
    exepack_run(&[] as &[&str; 0], input_tempfile.path(), output_tempfile.path()).unwrap();
}
