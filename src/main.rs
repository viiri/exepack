extern crate exepack;
extern crate getopts;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::str;
use std::path::{Path, PathBuf};
use std::process;

struct TopLevelError {
    path: Option<PathBuf>,
    kind: exepack::Error,
}

impl fmt::Display for TopLevelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &TopLevelError { path: None, ref kind } => kind.fmt(f),
            &TopLevelError { path: Some(ref path), ref kind } => write!(f, "{}: {}", path.display(), kind),
        }
    }
}

fn unpack_file<P: AsRef<Path>>(path: P) -> Result<exepack::EXE, exepack::Error> {
    let mut f = File::open(&path)?;
    let file_len = f.metadata()?.len();
    exepack::unpack(&mut f, Some(file_len))
}

fn write_exe_file<P: AsRef<Path>>(path: P, exe: &exepack::EXE) -> io::Result<usize> {
    let f = File::create(&path)?;
    let mut f = io::BufWriter::new(f);
    let n = exepack::write_exe(&mut f, exe)?;
    f.flush()?;
    Ok(n)
}

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#File_Format
fn decompress_mode<P: AsRef<Path>>(input_path: P, output_path: P) -> Result<(), TopLevelError> {
    let exe = match unpack_file(&input_path) {
        Err(err) => return Err(TopLevelError {
            path: Some(input_path.as_ref().to_path_buf()),
            kind: err,
        }),
        Ok(f) => f,
    };

    if let Err(err) = write_exe_file(&output_path, &exe) {
        return Err(TopLevelError {
            path: Some(output_path.as_ref().to_path_buf()),
            kind: exepack::Error::Io(err),
        });
    }

    Ok(())
}

const EXEPACK_ERRMSG: &[u8] = b"Packed file is corrupt";

// Return whether the given slice contains EXEPACK_ERRMSG, and is therefore
// likely an EXEPACK decompression stub.
fn stub_resembles_exepack(stub: &[u8]) -> bool {
    // No equivalent of str::contains for &[u8]...
    for i in 0.. {
        if i + EXEPACK_ERRMSG.len() > stub.len() {
            break;
        }
        if &stub[i..i+EXEPACK_ERRMSG.len()] == EXEPACK_ERRMSG {
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

fn escape_u8(c: u8) -> String {
    format!("\\x{:02x}", c)
}

fn escape(buf: &[u8]) -> String {
    let mut s = String::new();
    for c in buf.iter() {
        if c.is_ascii_alphanumeric() {
            s.push(*c as char)
        } else {
            s.push_str(&escape_u8(*c))
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
\n\
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
\n\
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
        env::args().next().unwrap());
    write!(w, "{}", opts.usage(&brief))
}

fn main() {
    let mut opts = getopts::Options::new();
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
        unimplemented!("compress")
    } {
        eprintln!("{}", err);
        if let exepack::Error::EXEPACK(exepack::EXEPACKFormatError::UnknownStub(ref exepack_header_buffer, ref stub)) = err.kind {
            // UnknownStub gets special treatment. We search for "Packed
            // file is corrupt" and display the stub if it is found, or warn
            // that the input may not be EXEPACK if it is not.
            display_unknown_stub(&mut io::stderr(), &exepack_header_buffer, &stub).unwrap();
        }
        process::exit(match err.kind {
            exepack::Error::Io(_) | exepack::Error::EXE(_) => 1,
            // EXEPACK returns 255 on a "Packed file is corrupt" error.
            exepack::Error::EXEPACK(_) => 255,
        });
    }
}
