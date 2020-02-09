//! exepack does compression and decompression of DOS executables with Microsoft
//! EXEPACK.
//!
//! For information about the format, see
//! <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK>.
//!
//! # Compression
//!
//! ```ignore
//! exepack input.exe packed.exe
//! ```
//!
//! # Decompression
//!
//! ```ignore
//! exepack -d input.exe unpacked.exe
//! ```
//!
//! # Exit status
//!
//! Exit status is 0 if there was no error, or 1 if there was any kind of error
//! (e.g., I/O, EXE parsing, EXEPACK decompression).

extern crate getopts;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str;
use std::sync::atomic;

#[macro_use]
mod debug;
mod exe;
mod exepack;
mod pointer;

#[derive(Debug)]
enum Error {
    Io(io::Error),
    Exe(exe::FormatError),
    Exepack(exepack::FormatError),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(err) => err.fmt(f),
            Error::Exe(err) => err.fmt(f),
            Error::Exepack(err) => err.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<exe::Error> for Error {
    fn from(err: exe::Error) -> Self {
        match err {
            exe::Error::Io(err) => Error::Io(err),
            exe::Error::Format(err) => Error::Exe(err),
        }
    }
}

impl From<exepack::FormatError> for Error {
    fn from(err: exepack::FormatError) -> Self {
        Error::Exepack(err)
    }
}

#[derive(Debug)]
struct TopLevelError {
    path: Option<PathBuf>,
    err: Error,
}

impl std::error::Error for TopLevelError {}

impl fmt::Display for TopLevelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TopLevelError { path: None, err } => err.fmt(f),
            TopLevelError { path: Some(path), err } => write!(f, "{}: {}", path.display(), err),
        }
    }
}

fn write_exe_file<P: AsRef<Path>>(path: P, exe: &exe::Exe) -> Result<u64, Error> {
    let f = File::create(&path)?;
    let mut f = io::BufWriter::new(f);
    let n = exe.write(&mut f)?;
    f.flush()?;
    Ok(n)
}

fn pack_file<P: AsRef<Path>>(path: P) -> Result<exe::Exe, Error> {
    let f = File::open(&path)?;
    let file_len = f.metadata()?.len();
    let mut f = io::BufReader::new(f);
    let exe = exe::Exe::read(&mut f, Some(file_len))?;
    exepack::pack(&exe)?;
    Ok(exe)
}

fn compress_mode<P: AsRef<Path>>(input_path: P, output_path: P) -> Result<(), TopLevelError> {
    let exe = match pack_file(&input_path) {
        Err(err) => return Err(TopLevelError {
            path: Some(input_path.as_ref().to_path_buf()),
            err: err,
        }),
        Ok(f) => f,
    };

    if let Err(err) = write_exe_file(&output_path, &exe) {
        return Err(TopLevelError {
            path: Some(output_path.as_ref().to_path_buf()),
            err: err,
        });
    }

    Ok(())
}

fn unpack_file<P: AsRef<Path>>(path: P) -> Result<exe::Exe, Error> {
    let f = File::open(&path)?;
    let file_len = f.metadata()?.len();
    let mut f = io::BufReader::new(f);
    let exe = exe::Exe::read(&mut f, Some(file_len))?;
    exepack::unpack(&exe).or_else(|err| Err(From::from(err)))
}

fn decompress_mode<P: AsRef<Path>>(input_path: P, output_path: P) -> Result<(), TopLevelError> {
    let exe = match unpack_file(&input_path) {
        Err(err) => return Err(TopLevelError {
            path: Some(input_path.as_ref().to_path_buf()),
            err: err,
        }),
        Ok(f) => f,
    };

    if let Err(err) = write_exe_file(&output_path, &exe) {
        return Err(TopLevelError {
            path: Some(output_path.as_ref().to_path_buf()),
            err: err,
        });
    }

    Ok(())
}

const EXEPACK_ERRMSG: &[u8] = b"Packed file is corrupt";

// Return whether the given slice contains EXEPACK_ERRMSG, and is therefore
// likely an EXEPACK decompression stub.
fn stub_resembles_exepack(stub: &[u8]) -> bool {
    // No equivalent of str::contains for &[u8]...
    for window in stub.windows(EXEPACK_ERRMSG.len()) {
        if window == EXEPACK_ERRMSG {
            return true;
        }
    }
    false
}

#[test]
fn test_stub_resembles_exepack() {
    assert_eq!(stub_resembles_exepack(b""), false);
    assert_eq!(stub_resembles_exepack(b"XXPacked XXPacked file is corrup"), false);
    assert_eq!(stub_resembles_exepack(b"Packed file is corrupt"), true);
    assert_eq!(stub_resembles_exepack(b"XXPacked file is corrupt"), true);
    assert_eq!(stub_resembles_exepack(b"XXPacked file is corruptXXPacked file is corruptXX"), true);
}

fn escape(buf: &[u8]) -> String {
    let mut s = String::new();
    for c in buf.iter() {
        if c.is_ascii_alphanumeric() {
            s.push(*c as char)
        } else {
            s.push_str(&format!("\\x{:02x}", *c))
        }
    }
    s
}

fn write_escaped_stub_for_submission<W: Write>(
    w: &mut W,
    exepack_header_buffer: &[u8],
    stub: &[u8]
) -> io::Result<()> {
    let mut buf = Vec::new();
    buf.extend_from_slice(exepack_header_buffer);
    buf.extend_from_slice(stub);
    for (i, chunk) in escape(&buf).as_bytes()
        .chunks(64)
        .enumerate()
    {
        writeln!(w, "={:02}={}==", i, str::from_utf8(chunk).unwrap())?;
    }
    Ok(())
}

fn display_unknown_stub<W: Write>(
    w: &mut W,
    exepack_header_buffer: &[u8],
    stub: &[u8]
) -> io::Result<()> {
    if stub_resembles_exepack(stub) {
        write!(w, "\
The input contains {:?}, but does not match a\n\
format that this program knows about. Please send the below listing to\n\
\tdavid@bamsoftware.com\n\
ideally with a link to or copy of the executable, so that a future\n\
version can support it.\n\
\n",
            str::from_utf8(EXEPACK_ERRMSG).unwrap()
        )?;
        write_escaped_stub_for_submission(w, exepack_header_buffer, stub)?;
    } else {
        write!(w, "\
The input does not contain {:?} within the first\n\
page of code. Is it really EXEPACK?\n",
            str::from_utf8(EXEPACK_ERRMSG).unwrap()
        )?;
    }
    Ok(())
}

fn print_usage<W: Write>(w: &mut W, opts: getopts::Options) -> io::Result<()> {
    let brief = format!("\
Usage: {} [OPTION]... INPUT.EXE OUTPUT.EXE\n\
Compress or decompress a DOS EXE executable with EXEPACK.",
        env::args().next().unwrap()
    );
    write!(w, "{}", opts.usage(&brief))
}

fn main() {
    let mut opts = getopts::Options::new();
    opts.optflag("", "debug", "show debugging output on stderr");
    opts.optflag("d", "decompress", "decompress");
    opts.optflag("h", "help", "show this help");
    let matches = match opts.parse(env::args().skip(1)) {
        Ok(matches) => matches,
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&mut io::stdout(), opts).unwrap();
        return;
    }

    if matches.opt_present("debug") {
        debug::DEBUG.store(true, atomic::Ordering::Relaxed);
    }

    if matches.free.len() != 2 {
        print_usage(&mut io::stderr(), opts).unwrap();
        eprintln!("\nNeed INPUT.EXE and OUTPUT.EXE arguments");
        process::exit(1);
    }
    let input_path = &matches.free[0];
    let output_path = &matches.free[1];

    if let Err(err) = if matches.opt_present("d") {
        decompress_mode(&input_path, &output_path)
    } else {
        compress_mode(&input_path, &output_path)
    } {
        match err.err {
            Error::Exepack(exepack::FormatError::UnknownStub(ref exepack_header_buffer, ref stub)) => {
                // UnknownStub gets special treatment. We search for "Packed
                // file is corrupt" and display the stub if it is found, or warn
                // that the input may not be EXEPACK if it is not.
                eprintln!("{}", err);
                eprintln!();
                display_unknown_stub(&mut io::stderr(), &exepack_header_buffer, &stub).unwrap();
            }
            _ => eprintln!("{}", err),
        }
        process::exit(1);
    }
}
