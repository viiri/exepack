extern crate getopts;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::process;

const MZ_SIGNATURE: u16 = 0x5a4d;

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

fn read_mz_header<R: Read>(r: &mut R) -> io::Result<MZHeader> {
    Ok(MZHeader{
        // Assuming that these initializers are evaluated in order...
        signature: read_u16le(r)?,
        bytes_in_last_block: read_u16le(r)?,
        blocks_in_file: read_u16le(r)?,
        num_relocs: read_u16le(r)?,
        header_paragraphs: read_u16le(r)?,
        min_extra_paragraphs: read_u16le(r)?,
        max_extra_paragraphs: read_u16le(r)?,
        ss: read_u16le(r)?,
        sp: read_u16le(r)?,
        csum: read_u16le(r)?,
        ip: read_u16le(r)?,
        cs: read_u16le(r)?,
        reloc_table_offset: read_u16le(r)?,
        overlay_number: read_u16le(r)?,
    })
}

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK
fn decompress<F, P>(mut input: F, _output_filename: P) -> Result<(), Box<Error>>
    where F: Read + Seek,
          P: AsRef<Path>,
{
    input.seek(SeekFrom::Start(0))?;
    let header = read_mz_header(&mut input)?;
    if header.signature != MZ_SIGNATURE {
        return Err(From::from(format!("bad MZ signature 0x{:04x} (expected {:04x}", header.signature, MZ_SIGNATURE)));
    }
    println!("{:?}", header);

    let compdata_start = header.header_paragraphs as u64 * 16;
    let compdata_length = (header.cs as usize * 16) + header.ip as usize;

    let mut compdata = Vec::new();
    compdata.resize(compdata_length, 0);
    input.seek(SeekFrom::Start(compdata_start))?;
    input.read_exact(&mut compdata)?;

    Ok(())
}

fn print_usage<W: Write>(w: &mut W, opts: getopts::Options) -> io::Result<()> {
    let brief = format!("\
Usage: {} [OPTION]... INPUT.EXE OUTPUT.EXE\n\
Compress or decompress a DOS MZ executable with EXEPACK.",
        env::args().next().unwrap());
    write!(w, "{}", opts.usage(&brief))
}

fn main_sub() -> Result<(), Box<Error>> {
    let mut opts = getopts::Options::new();
    opts.optflag("d", "decompress", "decompress");
    opts.optflag("h", "help", "show this help");
    let matches = opts.parse(env::args().skip(1))?;

    if matches.opt_present("h") {
        print_usage(&mut io::stdout(), opts)?;
        return Ok(())
    }

    if matches.free.len() != 2 {
        print_usage(&mut io::stderr(), opts)?;
        return Err(From::from("\nerror: Need INPUT.EXE and OUTPUT.EXE arguments"));
    }
    let input_filename = &matches.free[0];
    let output_filename = &matches.free[1];

    let input_file = match File::open(input_filename) {
        Ok(f) => f,
        Err(err) => return Err(From::from(format!("{}: {}", input_filename, err))),
    };

    if matches.opt_present("d") {
        decompress(input_file, output_filename)?;
    } else {
        unimplemented!("compress");
    }

    Ok(())
}

fn main() {
    if let Err(err) = main_sub() {
        eprintln!("{}", err);
        process::exit(1);
    }
}
