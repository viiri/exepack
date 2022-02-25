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
use std::fmt;
use std::fs::File;
use std::io::{self, Seek, Write};
use std::path::{Path, PathBuf};
use std::process;

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
    /// An EXEPACK format error.
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

/// Reads an EXE from `input_path`, runs `op` on it, and writes the transformed
/// EXE to `output_path`.
fn process<P, Q>(
    input_path: P, output_path: Q,
    op: fn(exe: &exe::Exe) -> Result<exe::Exe, exepack::FormatError>,
) -> Result<(), PathError>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    // Read and run op on the input. Any error here gets annotated with
    // input_path.
    let output_exe = (|| -> Result<_, Error> {
        let input = File::open(&input_path)?;
        let mut input = io::BufReader::new(input);
        let input_exe = exe::Exe::read(&mut input)?;

        let pos = input.seek(io::SeekFrom::Current(0))?;
        let len = input.seek(io::SeekFrom::End(0))?;
        if pos < len {
            eprintln!("{}: warning: EXE file size is {}; ignoring {} trailing bytes",
                input_path.as_ref().display(), pos, len - pos);
        }

        let output_exe = op(&input_exe)?;
        Ok(output_exe)
    })()
        .map_err(|err| PathError::new(&input_path, err))?;

    // Save output_exe to a file. Any error here gets annotated with
    // output_path.
    (|| -> Result<_, Error> {
        let output  = File::create(&output_path)?;
        let mut output = io::BufWriter::new(output);
        output_exe.write(&mut output)?;
        output.flush()?;
        Ok(())
    })()
        .map_err(|err| PathError::new(&output_path, err))?;

    Ok(())
}

/// Prints a usage message to `w`.
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

    let op = if matches.opt_present("d") {
        exepack::unpack
    } else {
        exepack::pack
    };

    if let Err(err) = process(&input_path, &output_path, op) {
        eprintln!("{}", err);
        process::exit(1);
    }
}
