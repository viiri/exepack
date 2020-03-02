//! exepack does compression and decompression of DOS executables in the
//! Microsoft EXEPACK format.
//!
//! # Compression
//!
//! ```sh
//! exepack input.exe packed.exe
//! ```
//!
//! # Decompression
//!
//! ```sh
//! exepack -d input.exe unpacked.exe
//! ```
//!
//! # Exit status
//!
//! Exit status is 0 if there was no error, or 1 if there was any kind of error
//! (I/O error, EXE file format error, or EXEPACK format error).
//!
//! # References
//!
//! * <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK>.

use std::env;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str;

extern crate exepack as exepack_crate;
use exepack_crate::exe;
use exepack_crate::exepack;

/// An error that may occur while manipulating an EXE file.
#[derive(Debug)]
enum Error {
    /// An I/O error.
    Io(io::Error),
    /// An EXE file format error.
    Exe(exe::FormatError),
    /// An EXEPATK format error.
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

/// An `Error` annotated with a `Path`.
#[derive(Debug)]
struct PathError {
    path: Option<PathBuf>,
    err: Error,
}

impl PathError {
    fn new<P: AsRef<Path>>(path: P, err: Error) -> Self {
        let path = path.as_ref().to_owned();
        Self { path: Some(path), err }
    }
}

impl std::error::Error for PathError {}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PathError { path: None, err } => err.fmt(f),
            PathError { path: Some(path), err } => write!(f, "{}: {}", path.display(), err),
        }
    }
}

/// Calls `exepack::pack` on the EXE file named by `path`.
fn pack_file<P: AsRef<Path>>(path: P) -> Result<exe::Exe, Error> {
    let f = File::open(&path)?;
    let file_len = f.metadata()?.len();
    let mut f = io::BufReader::new(f);
    let exe = exe::Exe::read(&mut f, Some(file_len))?;
    exepack::pack(&exe)?;
    Ok(exe)
}

/// Calls `exepack::unpack` on the EXE file named by `path`.
fn unpack_file<P: AsRef<Path>>(path: P) -> Result<exe::Exe, Error> {
    let f = File::open(&path)?;
    let file_len = f.metadata()?.len();
    let mut f = io::BufReader::new(f);
    let exe = exe::Exe::read(&mut f, Some(file_len))?;
    exepack::unpack(&exe).map_err(|err| From::from(err))
}

/// Writes an EXE to a file named by `path`.
fn write_exe_file<P: AsRef<Path>>(path: P, exe: &exe::Exe) -> Result<u64, Error> {
    let f = File::create(&path)?;
    let mut f = io::BufWriter::new(f);
    let n = exe.write(&mut f)?;
    f.flush()?;
    Ok(n)
}

/// Reads an EXE from `input_path`, compresses it, and writes the compressed EXE
/// to `output_path`.
fn compress_mode<P, Q>(input_path: P, output_path: Q) -> Result<(), PathError>
    where P: AsRef<Path>, Q: AsRef<Path>,
{
    let exe = pack_file(&input_path)
        .map_err(|err| PathError::new(&input_path, err))?;
    write_exe_file(&output_path, &exe)
        .map_err(|err| PathError::new(&output_path, err))?;
    Ok(())
}

/// Reads an EXE from `input_path`, decompresses it, and writes the decompressed
/// EXE to `output_path`.
fn decompress_mode<P, Q>(input_path: P, output_path: Q) -> Result<(), PathError>
    where P: AsRef<Path>, Q: AsRef<Path>,
{
    let exe = unpack_file(&input_path)
        .map_err(|err| PathError::new(&input_path, err))?;
    write_exe_file(&output_path, &exe)
        .map_err(|err| PathError::new(&output_path, err))?;
    Ok(())
}

/// A byte string found in most EXEPACK decompression stubs.
const EXEPACK_ERRMSG: &[u8] = b"Packed file is corrupt";

/// Returns whether the given slice contains `EXEPACK_ERRMSG`, and is therefore
/// likely to be an EXEPACK decompression stub.
fn stub_resembles_exepack(stub: &[u8]) -> bool {
    // No equivalent of str::contains for &[u8]...
    stub.windows(EXEPACK_ERRMSG.len()).any(|window| window == EXEPACK_ERRMSG)
}

#[test]
fn test_stub_resembles_exepack() {
    assert_eq!(stub_resembles_exepack(b""), false);
    assert_eq!(stub_resembles_exepack(b"XXPacked XXPacked file is corrup"), false);
    assert_eq!(stub_resembles_exepack(b"Packed file is corrupt"), true);
    assert_eq!(stub_resembles_exepack(b"XXPacked file is corrupt"), true);
    assert_eq!(stub_resembles_exepack(b"XXPacked file is corruptXXPacked file is corruptXX"), true);
}

/// Converts `buf` into a backslash-escaped ASCII-safe string without
/// whitespace.
fn escape(buf: &[u8]) -> String {
    let mut s = String::new();
    for &c in buf {
        if c.is_ascii_alphanumeric() {
            s.push(c.into())
        } else {
            write!(s, "\\x{:02x}", c).unwrap()
        }
    }
    s
}

/// Writes `exepack_header_buffer` and `stub` to `w` in an ASCII-safe,
/// reversible format.
fn write_escaped_stub_for_submission<W: Write + ?Sized>(
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

/// Display an error message for an unknown decompression stub, including an
/// invitation to submit it if it really appears to be EXEPACK.
fn display_unknown_stub<W: Write + ?Sized>(
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

/// Print a usage message to `w`.
fn print_usage<W: Write + ?Sized>(w: &mut W, opts: getopts::Options) -> io::Result<()> {
    let brief = format!("\
Usage: {} [OPTION]... INPUT.EXE OUTPUT.EXE\n\
Compress or decompress a DOS EXE executable with EXEPACK.",
        env::args().next().unwrap()
    );
    write!(w, "{}", opts.usage(&brief))
}

fn main() {
    let mut opts = getopts::Options::new();
    opts.optflag("", "debug", "does nothing (formerly showed debugging output)");
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
        // Does nothing; removed --debug functionality after version 0.6.0.
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
            Error::Exepack(exepack::FormatError::UnknownStub { ref exepack_header, ref stub }) => {
                // UnknownStub gets special treatment. We search for "Packed
                // file is corrupt" and display the stub if it is found, or warn
                // that the input may not be EXEPACK if it is not.
                eprintln!("{}", err);
                eprintln!();
                display_unknown_stub(&mut io::stderr(), &exepack_header, &stub).unwrap();
            }
            _ => eprintln!("{}", err),
        }
        process::exit(1);
    }
}
