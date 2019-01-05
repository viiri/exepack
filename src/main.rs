extern crate getopts;

use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;

mod stubs;

const DEBUG: bool = true;

macro_rules! debug {
    ($($x:tt)*) => {
        if DEBUG {
            eprintln!($($x)*);
        }
    };
}

fn parse_u16le(buf: &[u8], i: usize) -> u16 {
    (buf[i] as u16) | ((buf[i+1] as u16) << 8)
}

fn read_u16le<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok((buf[0] as u16) | ((buf[1] as u16) << 8))
}

#[test]
fn test_read_u16le() {
    fn expect_unexpectedeof(x: io::Result<u16>) {
        match x {
            Err(ref err) if err.kind() == io::ErrorKind::UnexpectedEof => (),
            _ => panic!("expected UnexpectedEof, got {:?}", x),
        }
    }
    expect_unexpectedeof(read_u16le(&mut io::Cursor::new([])));
    expect_unexpectedeof(read_u16le(&mut io::Cursor::new([0x12])));
    assert_eq!(0x3412, read_u16le(&mut io::Cursor::new([0x12, 0x34])).unwrap());
    assert_eq!(0x3412, read_u16le(&mut io::Cursor::new([0x12, 0x34, 0x56, 0x78])).unwrap());
}

const MZ_SIGNATURE: u16 = 0x5a4d; // "MZ"

// http://www.delorie.com/djgpp/doc/exe/
// This is a form of IMAGE_DOS_HEADER from <winnt.h>.
#[derive(Debug)]
struct MZHeader {
    signature: u16,
    bytes_in_last_block: u16,
    blocks_in_file: u16,
    num_relocs: u16,
    header_paragraphs: u16,
    min_extra_paragraphs: u16,
    max_extra_paragraphs: u16,
    ss: u16,
    sp: u16,
    csum: u16,
    ip: u16,
    cs: u16,
    reloc_table_offset: u16,
    overlay_number: u16,
}

fn read_mz_header<R: Read>(r: &mut R) -> io::Result<MZHeader> {
    let mut buf = [0; 28];
    r.read_exact(&mut buf[..])?;
    Ok(MZHeader{
        signature: parse_u16le(&buf, 0),
        bytes_in_last_block: parse_u16le(&buf, 2),
        blocks_in_file: parse_u16le(&buf, 4),
        num_relocs: parse_u16le(&buf, 6),
        header_paragraphs: parse_u16le(&buf, 8),
        min_extra_paragraphs: parse_u16le(&buf, 10),
        max_extra_paragraphs: parse_u16le(&buf, 12),
        ss: parse_u16le(&buf, 14),
        sp: parse_u16le(&buf, 16),
        csum: parse_u16le(&buf, 18),
        ip: parse_u16le(&buf, 20),
        cs: parse_u16le(&buf, 22),
        reloc_table_offset: parse_u16le(&buf, 24),
        overlay_number: parse_u16le(&buf, 26),
    })
}

enum DecompressError {
    Io(io::Error),
    Format(String),
}

impl From<io::Error> for DecompressError {
    fn from(err: io::Error) -> Self {
        DecompressError::Io(err)
    }
}

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecompressError::Io(ref err) => err.fmt(f),
            &DecompressError::Format(ref err) => write!(f, "Packed file is corrupt ({})", err),
        }
    }
}

fn lookup_reference_stub<R: io::Read>(mut input: R) -> io::Result<Option<&'static [u8]>> {
    let mut stub = Vec::new();
    for reference_stub in stubs::STUBS.iter() {
        // We need the reference stubs to be sorted by length.
        assert!(stub.len() <= reference_stub.len());
        let old_len = stub.len();
        stub.resize(reference_stub.len(), 0);
        input.read_exact(&mut stub[old_len..])?;
        if &stub == reference_stub {
            return Ok(Some(reference_stub));
        }
    }
    Ok(None)
}

struct TopLevelError {
    path: Option<PathBuf>,
    kind: DecompressError,
}

impl fmt::Display for TopLevelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &TopLevelError { path: None, ref kind } => kind.fmt(f),
            &TopLevelError { path: Some(ref path), ref kind } => write!(f, "{}: {}", path.display(), kind),
        }
    }
}

fn decompress(buf: &mut [u8], mut src: usize, mut dst: usize) -> Result<(), String> {
    // Skip 0xff padding (only up to 16 bytes of it).
    for _ in 0..16 {
        if src == 0 {
            break
        }
        if buf[src-1] != 0xff {
            break
        }
        src -= 1;
    }
    loop {
        if dst < src {
            return Err("criss-cross".to_owned());
        }
        if src == 0 {
            return Err("read underflow".to_owned());
        }
        let command = buf[src-1];
        src -= 1;
        let mut length: usize = 0;
        if src < 2 {
            return Err("read underflow".to_owned());
        }
        length |= (buf[src-1] as usize) << 8;
        src -= 1;
        length |= buf[src-1] as usize;
        src -= 1;
        match command & 0xfe {
            0xb0 => {
                if src == 0 {
                    return Err("read underflow".to_owned());
                }
                let fill = buf[src-1];
                src -= 1;
                debug!("fill {:02x} {} {:02x}", command, length, fill);
                if dst < length {
                    return Err("write underflow".to_owned());
                }
                for i in dst-length..dst {
                    buf[i] = fill;
                }
                dst -= length;
            }
            0xb2 => {
                debug!("copy {:02x} {}", command, length);
                if src < length {
                    return Err("read underflow".to_owned());
                }
                if dst < length {
                    return Err("write underflow".to_owned());
                }
                for i in 0..length {
                    buf[dst-i-1] = buf[src-i-1];
                }
                src -= length;
                dst -= length;
            }
            _ => {
                return Err(format!("bogus! {:02x}", command));
            }
        }
        if command & 0x01 != 0 {
            break
        }
    }
    debug!("finish src {} dst {}", src, dst);
    Ok(())
}

const EXEPACK_SIGNATURE: u16 = 0x4252; // "RB"

fn decompress_format_skip_len(mut data: &mut Vec<u8>, exepack_vars_buffer: &[u8]) -> Result<(), DecompressError> {
    #[derive(Debug)]
    struct EXEPACKHeader {
        real_ip: u16,
        real_cs: u16,
        mem_start: u16,
        exepack_size: u16,
        real_sp: u16,
        real_ss: u16,
        dest_len: u16,
        skip_len: u16,
        signature: u16,
    };
    assert_eq!(exepack_vars_buffer.len(), 18);
    let mut r = io::Cursor::new(exepack_vars_buffer);
    let exepack_header = EXEPACKHeader {
        real_ip: read_u16le(&mut r)?,
        real_cs: read_u16le(&mut r)?,
        mem_start: read_u16le(&mut r)?,
        exepack_size: read_u16le(&mut r)?,
        real_sp: read_u16le(&mut r)?,
        real_ss: read_u16le(&mut r)?,
        dest_len: read_u16le(&mut r)?,
        skip_len: read_u16le(&mut r)?,
        signature: read_u16le(&mut r)?,
    };
    debug!("{:?}", exepack_header);
    if exepack_header.signature != EXEPACK_SIGNATURE {
        return Err(DecompressError::Format(format!("bad EXEPACK signature 0x{:04x}; expected 0x{:04x}", exepack_header.signature, EXEPACK_SIGNATURE)));
    }

    let skip_len = 16 * (exepack_header.skip_len as usize).checked_sub(1)
        .ok_or(DecompressError::Format("skip_len too small".to_owned()))?;
    let compressed_size = data.len().checked_sub(skip_len)
        .ok_or(DecompressError::Format("skip_len too large".to_owned()))?;
    let uncompressed_size = (exepack_header.dest_len as usize * 16).checked_sub(skip_len)
        .ok_or(DecompressError::Format("skip_len too large".to_owned()))?;
    if uncompressed_size < compressed_size {
        return Err(DecompressError::Format("dest_len too small".to_owned()));
    }
    data.resize(uncompressed_size, 0);
    let res = decompress(&mut data, compressed_size, uncompressed_size);
    debug!("res {:?}", res);

    Ok(())
}

struct MZEXE {
    header: MZHeader,
    data: Vec<u8>,
    // relocations
}

// Unpack an input executable and return the elements of an unpacked executable.
fn unpack<F: Read + Seek>(input: &mut F) -> Result<MZEXE, DecompressError> {
    let header = read_mz_header(input)
        .map_err(|err| io::Error::new(err.kind(), format!("reading EXE header: {}", err)))?;
    debug!("{:?}", header);
    if header.signature != MZ_SIGNATURE {
        return Err(DecompressError::Format(format!("bad EXE magic 0x{:04x}; expected 0x{:04x}", header.signature, MZ_SIGNATURE)));
    }

    let compdata_start = header.header_paragraphs as u64 * 16;
    if compdata_start < input.seek(SeekFrom::Current(0))? {
        // Compressed data overlaps MZ header?
        return Err(DecompressError::Format(format!("bad MZ header size 0x{:04x}", header.header_paragraphs)));
    }
    input.seek(SeekFrom::Start(compdata_start))?;

    // Compressed data starts immediately after the MZ header, and continues up
    // to cs:0000.
    let mut compdata = Vec::new();
    compdata.resize(header.cs as usize * 16, 0);
    input.read_exact(&mut compdata)?;

    // The EXEPACK variables start at cs:0000 and continue up to cs:ip.
    let mut exepack_vars_buffer = Vec::new();
    exepack_vars_buffer.resize(header.ip as usize, 0);
    input.read_exact(&mut exepack_vars_buffer)?;
    debug!("{:?}", exepack_vars_buffer);

    // The EXEPACK decompression stub starts at cs:ip.
    let reference_stub = lookup_reference_stub(input)?;
    debug!("{:?}", reference_stub);

    decompress_format_skip_len(&mut compdata, &exepack_vars_buffer)?;

    // relocations

    // check for unused trailing data

    Ok(MZEXE{header: header, data: Vec::new()})
}

fn unpack_file<P: AsRef<Path>>(path: P) -> Result<MZEXE, DecompressError> {
    let input = File::open(&path)?;
    let mut input = io::BufReader::new(input);
    unpack(&mut input)
}

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#File_Format
fn decompress_mode<P: AsRef<Path>>(input_path: P, _output_path: P) -> Result<(), TopLevelError> {
    let exe = match unpack_file(&input_path) {
        Err(err) => return Err(TopLevelError {
            path: Some(input_path.as_ref().to_path_buf()),
            kind: err,
        }),
        Ok(f) => f,
    };

    Ok(())
}

fn print_usage<W: Write>(w: &mut W, opts: getopts::Options) -> io::Result<()> {
    let brief = format!("\
Usage: {} [OPTION]... INPUT.EXE OUTPUT.EXE\n\
Compress or decompress a DOS MZ executable with EXEPACK.",
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
        process::exit(match err.kind {
            DecompressError::Io(_) => 1,
            // EXEPACK returns 255 on a "Packed file is corrupt" error.
            DecompressError::Format(_) => 255,
        });
    }
}
