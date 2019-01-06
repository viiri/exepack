extern crate getopts;

use std::cmp;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str;

mod stubs;

const DEBUG: bool = true;

macro_rules! debug {
    ($($x:tt)*) => {
        if DEBUG {
            eprintln!($($x)*);
        }
    };
}

fn read_u16le<R: Read>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok((buf[0] as u16) | ((buf[1] as u16) << 8))
}

fn write_u16le<W: Write>(w: &mut W, v: u16) -> io::Result<usize> {
    let buf: [u8; 2] = [
        (v & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
    ];
    w.write_all(&buf[..]).and(Ok(2))
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

const EXE_MAGIC: u16 = 0x5a4d; // "MZ"
// The length of an EXE header excluding the variable-sized padding.
const EXE_HEADER_LEN: u64 = 28;

#[derive(Debug)]
struct EXE {
    header: EXEHeader,
    data: Vec<u8>,
    relocations: Vec<Relocation>,
}

// http://www.delorie.com/djgpp/doc/exe/
// This is a form of IMAGE_DOS_HEADER from <winnt.h>.
#[derive(Debug)]
struct EXEHeader {
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

#[derive(Debug)]
struct Relocation {
    segment: u16,
    offset: u16,
}

fn read_exe_header<R: Read>(r: &mut R) -> io::Result<EXEHeader> {
    Ok(EXEHeader{
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

// Return a tuple (e_cblp, e_cp) that encodes len as appropriate for the
// so-named EXE header fields. Panics if the size is too large to be
// represented (> 0x1fffe00).
fn encode_exe_len(len: usize) -> (u16, u16) {
    let blocks_in_file = (len + 511) / 512;
    if blocks_in_file > 0xffff {
        panic!("cannot represent the length {}", len);
    }
    let bytes_in_last_block = len % 512;
    (bytes_in_last_block as u16, blocks_in_file as u16)
}

#[test]
fn test_encode_exe_len() {
    assert_eq!(encode_exe_len(0), (0, 0));
    assert_eq!(encode_exe_len(1), (1, 1));
    assert_eq!(encode_exe_len(511), (511, 1));
    assert_eq!(encode_exe_len(512), (0, 1));
    assert_eq!(encode_exe_len(513), (1, 2));
    assert_eq!(encode_exe_len(512*0xffff-1), (511, 0xffff));
    assert_eq!(encode_exe_len(512*0xffff), (0, 0xffff));
}

#[test]
#[should_panic]
fn test_encode_exe_len_too_large() {
    encode_exe_len(512*0xffff + 1);
}

enum EXEFormatError {
    BadMagic(u16),
    BadNumPages(u16, u16),
    HeaderTooShort(u16),
}

impl fmt::Display for EXEFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &EXEFormatError::BadMagic(e_magic) => write!(f, "Bad EXE magic 0x{:04x}; expected 0x{:04x}", e_magic, EXE_MAGIC),
            &EXEFormatError::BadNumPages(e_cb, e_cblp) => write!(f, "Bad EXE size {}×512+{}", e_cb, e_cblp),
            &EXEFormatError::HeaderTooShort(e_cparhdr) => write!(f, "EXE header of {} bytes is too small", e_cparhdr as u64 * 16),
        }
    }
}

enum EXEPACKFormatError {
    UnknownStub(Vec<u8>, Vec<u8>),
    BadMagic(Vec<u8>, u16),
    HeaderSizeMismatch(Vec<u8>, usize),
    PaddingTooShort(u16),
    PaddingTooLong(u16),
    EXEPACKTooShort(u16, usize),
    Crossover(usize, usize),
    SrcOverflow(),
    FillOverflow(usize, usize, u8, usize, u8),
    CopyOverflow(usize, usize, u8, usize),
    BogusCommand(usize, u8, usize),
    Gap(usize, usize),
    TooManyRelocations(usize),
}

impl fmt::Display for EXEPACKFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &EXEPACKFormatError::UnknownStub(ref _header_buffer, ref _stub) =>
                write!(f, "Unknown decompression stub"),
            &EXEPACKFormatError::BadMagic(ref header, magic) =>
                write!(f, "EXEPACK header \"{}\" has bad magic 0x{:04x}; expected 0x{:04x}", escape(&header), magic, EXEPACK_MAGIC),
            &EXEPACKFormatError::HeaderSizeMismatch(ref header, expected_len) =>
                write!(f, "EXEPACK header \"{}\" is {} bytes, expected {}", escape(&header), header.len(), expected_len),
            &EXEPACKFormatError::PaddingTooShort(skip_len) =>
                write!(f, "EXEPACK padding length of {} paragraphs is invalid", skip_len),
            &EXEPACKFormatError::PaddingTooLong(skip_len) =>
                write!(f, "EXEPACK padding length of {} paragraphs is too long", skip_len),
            &EXEPACKFormatError::EXEPACKTooShort(exepack_size, header_and_stub_len) =>
                write!(f, "EXEPACK size of {} bytes is too short for header and stub of {} bytes", exepack_size, header_and_stub_len),
            &EXEPACKFormatError::Crossover(dst, src) =>
                write!(f, "write index {} outpaced read index {}", dst, src),
            &EXEPACKFormatError::SrcOverflow() =>
                write!(f, "reached end of compressed stream without seeing a termination command"),
            &EXEPACKFormatError::FillOverflow(dst, _src, _command, length, fill) =>
                write!(f, "write overflow: fill {}×'{}' at index {}", length, escape_u8(fill), dst),
            &EXEPACKFormatError::CopyOverflow(dst, src, _command, length) =>
                write!(f, "{}: copy {} bytes from index {} to index {}",
                    if src < length { "read overflow" } else { "write overflow" },
                    length, src, dst),
            &EXEPACKFormatError::BogusCommand(src, command, length) =>
                write!(f, "unknown command 0x{:02x} with ostensible length {} at index {}", command, length, src),
            &EXEPACKFormatError::Gap(dst, original_src) =>
                write!(f, "decompression left a gap of {} unwritten bytes between write index {} and original read index {}", dst - original_src, dst, original_src),
            &EXEPACKFormatError::TooManyRelocations(num_relocations) =>
                write!(f, "too many relocation entries ({}) to represent in an EXE header", num_relocations),
        }
    }
}

enum DecompressError {
    Io(io::Error),
    EXE(EXEFormatError),
    EXEPACK(EXEPACKFormatError),
}

impl From<io::Error> for DecompressError {
    fn from(err: io::Error) -> Self {
        DecompressError::Io(err)
    }
}

impl From<EXEFormatError> for DecompressError {
    fn from(err: EXEFormatError) -> Self {
        DecompressError::EXE(err)
    }
}

impl From<EXEPACKFormatError> for DecompressError {
    fn from(err: EXEPACKFormatError) -> Self {
        DecompressError::EXEPACK(err)
    }
}

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecompressError::Io(ref err) => err.fmt(f),
            &DecompressError::EXE(ref err) => err.fmt(f),
            &DecompressError::EXEPACK(ref err) => {
                match err {
                    &EXEPACKFormatError::UnknownStub(_, _) => err.fmt(f),
                    _ => write!(f, "Packed file is corrupt: {}", err),
                }
            }
        }
    }
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

// The basic decompression loop. The compressed data are read (going backwards)
// starting at src, and written (also going backwards) back to the same buffer
// starting at dst.
fn decompress(buf: &mut [u8], mut dst: usize, mut src: usize) -> Result<(), EXEPACKFormatError> {
    let original_src = src;
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
            // The command we're about to read was overwritten.
            return Err(EXEPACKFormatError::Crossover(dst, src))
        }
        // Read the command byte.
        src = src.checked_sub(1).ok_or(EXEPACKFormatError::SrcOverflow())?;
        let command = buf[src];
        // Read the 16-bit length.
        let mut length: usize = 0;
        src = src.checked_sub(1).ok_or(EXEPACKFormatError::SrcOverflow())?;
        length |= (buf[src] as usize) << 8;
        src = src.checked_sub(1).ok_or(EXEPACKFormatError::SrcOverflow())?;
        length |= buf[src] as usize;
        match command & 0xfe {
            0xb0 => {
                src = src.checked_sub(1).ok_or(EXEPACKFormatError::SrcOverflow())?;
                let fill = buf[src];
                // debug!("0x{:02x} fill {} 0x{:02x}", command, length, fill);
                dst = dst.checked_sub(length).ok_or(EXEPACKFormatError::FillOverflow(dst, src, command, length, fill))?;
                for i in 0..length {
                    buf[dst+i] = fill;
                }
            }
            0xb2 => {
                // debug!("0x{:02x} copy {}", command, length);
                src = src.checked_sub(length).ok_or(EXEPACKFormatError::CopyOverflow(dst, src, command, length))?;
                dst = dst.checked_sub(length).ok_or(EXEPACKFormatError::CopyOverflow(dst, src, command, length))?;
                for i in 0..length {
                    buf[dst+length-i-1] = buf[src+length-i-1];
                }
            }
            _ => {
                return Err(EXEPACKFormatError::BogusCommand(src, command, length));
            }
        }
        if command & 0x01 != 0 {
            break
        }
    }
    if original_src < dst {
        // Decompression finished okay but left a gap of uninitialized bytes.
        return Err(EXEPACKFormatError::Gap(dst, original_src));
    }
    Ok(())
}

const EXEPACK_MAGIC: u16 = 0x4252; // "RB"

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#EXEPACK_variables
#[derive(Debug)]
struct EXEPACKHeader {
    real_ip: u16,
    real_cs: u16,
    // "mem_start" is actually just scratch space for the decompression stub.
    exepack_size: u16,
    real_sp: u16,
    real_ss: u16,
    dest_len: u16,
    skip_len: u16,
    signature: u16,
}

fn parse_exepack_header(buf: &[u8], uses_skip_len: bool) -> Result<EXEPACKHeader, EXEPACKFormatError> {
    let mut r = io::Cursor::new(buf);
    if !uses_skip_len && buf.len() != 16 {
        return Err(EXEPACKFormatError::HeaderSizeMismatch(buf.to_vec(), 16));
    }
    if uses_skip_len && buf.len() != 18 {
        return Err(EXEPACKFormatError::HeaderSizeMismatch(buf.to_vec(), 18));
    }
    let real_ip = read_u16le(&mut r).unwrap();
    let real_cs = read_u16le(&mut r).unwrap();
    let _ = read_u16le(&mut r).unwrap(); // Ignore "mem_start".
    let exepack_size = read_u16le(&mut r).unwrap();
    let real_sp = read_u16le(&mut r).unwrap();
    let real_ss = read_u16le(&mut r).unwrap();
    let dest_len = read_u16le(&mut r).unwrap();
    let skip_len = if uses_skip_len {
        read_u16le(&mut r).unwrap()
    } else {
        1
    };
    let signature = read_u16le(&mut r).unwrap();
    Ok(EXEPACKHeader {
        real_ip,
        real_cs,
        exepack_size,
        real_sp,
        real_ss,
        dest_len,
        skip_len,
        signature,
    })
}

// Discard a certain number of bytes from an io::BufRead.
fn discard<R: io::BufRead>(br: &mut R, mut n: u64) -> io::Result<()> {
    while n > 0 {
        let len = {
            let buf = br.fill_buf()?;
            cmp::min(n, buf.len() as u64)
        };
        br.consume(len as usize);
        n = n.checked_sub(len).unwrap();
    }
    Ok(())
}

// Like io::Read::read_exact, except that it returns the number of bytes read
// instead of io::ErrorKind::UnexpectedEof when it reaches EOF.
fn read_up_to<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = r.read(&mut buf[total..])?;
        if n == 0 {
            break
        }
        total += n;
    }
    Ok(total)
}

// Read a decompression stub and return both the stub and a boolean indicating
// whether the EXEPACK format that the stub implements uses an explicit skip_len
// variable or not. It works by incrementally reading and comparing against a
// table of known stubs. In the event that there is no match, returns whatever
// we have read so far along with None for the skip_len indicator.
fn read_stub<R: Read>(r: &mut R) -> io::Result<(Vec<u8>, Option<bool>)> {
    // Mapping of known stubs to whether they use skip_len. Needs to be sorted
    // by length.
    const KNOWN_STUBS: [(&[u8], bool); 2] = [
        (stubs::STUB_258, false),
        (stubs::STUB_283, true),
    ];
    let mut stub = Vec::new();
    for &(known_stub, uses_skip_len) in KNOWN_STUBS.iter() {
        assert!(stub.len() <= known_stub.len());
        let old_len = stub.len();
        stub.resize(known_stub.len(), 0);
        let n = read_up_to(r, &mut stub[old_len..])?;
        // A short read means no match and we are done.
        if old_len + n < stub.len() {
            stub.resize(old_len + n, 0);
            break;
        }
        if &stub == &known_stub {
            return Ok((stub, Some(uses_skip_len)))
        }
    }
    return Ok((stub, None))
}

fn read_relocations<R: Read>(r: &mut R) -> io::Result<Vec<Relocation>> {
    let mut relocations = Vec::new();
    for i in 0..16 {
        let num_relocations = read_u16le(r)?;
        for _ in 0..num_relocations {
            let offset = read_u16le(r)?;
            relocations.push(Relocation {
                segment: i * 0x1000,
                offset,
            });
        }
    }
    Ok(relocations)
}

// Unpack an input executable and return the elements of an unpacked executable.
// file_size_hint is an optional externally provided hint of the file's total
// length, which we use to emit a warning when it exceeds the length stated in
// the EXE header.
fn unpack<R: Read>(input: &mut R, file_len_hint: Option<u64>) -> Result<EXE, DecompressError> {
    let mut input = io::BufReader::new(input);

    let exe_header = read_exe_header(&mut input)
        .map_err(|err| io::Error::new(err.kind(), format!("reading EXE header: {}", err)))?;
    debug!("{:?}", exe_header);

    // Begin consistency tests on the fields of the EXE header.
    if exe_header.signature != EXE_MAGIC {
        return Err(DecompressError::EXE(EXEFormatError::BadMagic(exe_header.signature)));
    }

    // Consistency of e_cparhdr. We need the stated header length to be at least
    // as large as the header we just read.
    let exe_header_len = exe_header.header_paragraphs as u64 * 16;
    if exe_header_len < EXE_HEADER_LEN {
        return Err(DecompressError::EXE(EXEFormatError::HeaderTooShort(exe_header.header_paragraphs)));
    }

    // Consistency of e_cp and e_cblp.
    if exe_header.blocks_in_file == 0 || exe_header.bytes_in_last_block >= 512 {
        return Err(DecompressError::EXE(EXEFormatError::BadNumPages(exe_header.blocks_in_file, exe_header.bytes_in_last_block)));
    }
    let exe_len = (exe_header.blocks_in_file - 1) as u64 * 512
        + if exe_header.bytes_in_last_block == 0 { 512 } else { exe_header.bytes_in_last_block } as u64;
    if exe_len < exe_header_len {
        return Err(DecompressError::EXE(EXEFormatError::BadNumPages(exe_header.blocks_in_file, exe_header.bytes_in_last_block)));
    }
    if let Some(file_len) = file_len_hint {
        // The EXE file length is allowed to be smaller than the length of the
        // file containing it. Emit a warning that we are ignoring trailing
        // garbage. The opposite situation, exe_len > file_len, is an error that
        // we will notice later when we get an unexpected EOF.
        if exe_len < file_len {
            eprintln!("warning: EXE file size is {}; ignoring {} trailing bytes", file_len, file_len - exe_len);
        }
    }

    // Read and discard any header padding.
    discard(&mut input, exe_header_len - EXE_HEADER_LEN)?;
    // Now we are positioned just after the EXE header. Trim any data that lies
    // beyond the length of the EXE file stated in the header.
    let mut input = input.take(exe_len - exe_header_len);

    // Compressed data starts immediately after the EXE header and ends at
    // cs:0000. We will decompress into the very same buffer (after expanding
    // it).
    let mut work_buffer = Vec::new();
    work_buffer.resize(exe_header.cs as usize * 16, 0);
    input.read_exact(&mut work_buffer)?;

    // The EXEPACK header starts at cs:0000 and ends at cs:ip. We won't know the
    // layout of the EXEPACK header (i.e., whether there is a skip_len member)
    // until after we have read and identified the decompression stub.
    let mut exepack_header_buffer = Vec::new();
    exepack_header_buffer.resize(exe_header.ip as usize, 0);
    input.read_exact(&mut exepack_header_buffer)?;

    // The decompression stub starts at cs:ip. We incrementally read with
    // increasing, known stub lengths until we find a match or exhaust the list
    // of known stubs. What we care about is whether the stub uses an explicit
    // skip_len in the EXEPACK header, or an implicit skip_len of 1.
    let (mut stub, uses_skip_len) = read_stub(&mut input)?;
    let uses_skip_len = match uses_skip_len {
        Some(uses_skip_len) => uses_skip_len,
        None => {
            // Our decompression stub wasn't in the table. Read some more data
            // (to have a chance of including "Packed file is corrupt" when the
            // stub is longer than any we know of) and return an error.
            let old_len = stub.len();
            if stub.len() < 512 {
                stub.resize(512, 0);
            }
            let n = read_up_to(&mut input, &mut stub[old_len..]).unwrap_or(0); // Ignore an io::Error here.
            stub.resize(old_len + n, 0);
            return Err(DecompressError::EXEPACK(EXEPACKFormatError::UnknownStub(exepack_header_buffer, stub)));
        }
    };

    // Now that we know what stub we're dealing with, we can interpret the
    // EXEPACK header.
    let exepack_header = parse_exepack_header(&exepack_header_buffer, uses_skip_len)?;
    if exepack_header.signature != EXEPACK_MAGIC {
        return Err(DecompressError::EXEPACK(EXEPACKFormatError::BadMagic(exepack_header_buffer, exepack_header.signature)));
    }
    debug!("{:?}", exepack_header);

    // The EXEPACK header's exepack_size field contains the length of the
    // EXEPACK header, the decompression stub, and the relocation table all
    // together. The decompression stub uses this value to control how much of
    // itself to copy out of the way before starting the main compression loop.
    // Therefore we are justified in raising an error if any reads go past
    // exepack_size.
    let mut input = {
        let read_so_far = exepack_header_buffer.len() + stub.len();
        if (exepack_header.exepack_size as usize) < read_so_far {
            return Err(DecompressError::EXEPACK(EXEPACKFormatError::EXEPACKTooShort(exepack_header.exepack_size, read_so_far)));
        }
        input.take((exepack_header.exepack_size as usize - read_so_far) as u64)
    };

    // The skip_len variable is 1 greater than the number of paragraphs of
    // padding between the compressed data and the EXEPACK header. It cannot be
    // 0 because that would mean −1 paragraphs of padding.
    let padding_len = 16 * (exepack_header.skip_len as usize).checked_sub(1)
        .ok_or(DecompressError::EXEPACK(EXEPACKFormatError::PaddingTooShort(exepack_header.skip_len)))?;
    let compressed_len = work_buffer.len().checked_sub(padding_len)
        .ok_or(DecompressError::EXEPACK(EXEPACKFormatError::PaddingTooLong(exepack_header.skip_len)))?;
    // It's weird that skip_len applies to the *un*compressed length as well,
    // but it does (see the disassembly in stubs.rs). Why didn't they just make
    // data_len that much smaller?
    let uncompressed_len = (exepack_header.dest_len as usize * 16).checked_sub(padding_len)
        .ok_or(DecompressError::EXEPACK(EXEPACKFormatError::PaddingTooLong(exepack_header.skip_len)))?;
    // Expand the buffer to hold the uncompressed data.
    if uncompressed_len > compressed_len {
        work_buffer.resize(uncompressed_len, 0);
    }
    // Now let's actually decompress the buffer.
    decompress(&mut work_buffer, uncompressed_len, compressed_len)?;

    // The last step is to parse the relocation table that follows the
    // decompression stub.
    let relocations = read_relocations(&mut input)?;
    debug!("{:?}", relocations);

    // It's not an error if there is trailing data here (i.e., if
    // exepack_header.exepack_size is larger than it needs to be). Any trailing data
    // would be ignored by the EXEPACK decompression stub.

    // Finally, construct a new EXE.
    // Pad the header to the smallest multiple of 512 bytes that holds both the
    // EXEHeader struct and all the relocations (each relocation is 4 bytes).
    let num_header_pages = ((EXE_HEADER_LEN as usize + 4 * relocations.len()) + 511) / 512;
    let (bytes_in_last_block, blocks_in_file) = encode_exe_len(num_header_pages * 512 + uncompressed_len);
    let new_exe_header = EXEHeader{
        signature: EXE_MAGIC,
        bytes_in_last_block: bytes_in_last_block,
        blocks_in_file: blocks_in_file,
        num_relocs: if relocations.len() > 0xffff {
            return Err(DecompressError::EXEPACK(EXEPACKFormatError::TooManyRelocations(relocations.len())))
        } else {
            relocations.len() as u16
        },
        header_paragraphs: (num_header_pages * 512 / 16) as u16,
        min_extra_paragraphs: exe_header.min_extra_paragraphs,
        max_extra_paragraphs: exe_header.max_extra_paragraphs,
        ss: exepack_header.real_ss,
        sp: exepack_header.real_sp,
        csum: 0,
        ip: exepack_header.real_ip,
        cs: exepack_header.real_cs,
        reloc_table_offset: EXE_HEADER_LEN as u16,
        overlay_number: 0,
    };
    debug!("{:?}", new_exe_header);
    Ok(EXE{header: new_exe_header, data: work_buffer, relocations})
}

fn unpack_file<P: AsRef<Path>>(path: P) -> Result<EXE, DecompressError> {
    let mut f = File::open(&path)?;
    let file_len = f.metadata()?.len();
    unpack(&mut f, Some(file_len))
}

fn write_exe_header<W: Write>(w: &mut W, header: &EXEHeader) -> io::Result<usize> {
    let mut n = 0;
    n += write_u16le(w, header.signature)?;
    n += write_u16le(w, header.bytes_in_last_block)?;
    n += write_u16le(w, header.blocks_in_file)?;
    n += write_u16le(w, header.num_relocs)?;
    n += write_u16le(w, header.header_paragraphs)?;
    n += write_u16le(w, header.min_extra_paragraphs)?;
    n += write_u16le(w, header.max_extra_paragraphs)?;
    n += write_u16le(w, header.ss)?;
    n += write_u16le(w, header.sp)?;
    n += write_u16le(w, header.csum)?;
    n += write_u16le(w, header.ip)?;
    n += write_u16le(w, header.cs)?;
    n += write_u16le(w, header.reloc_table_offset)?;
    n += write_u16le(w, header.overlay_number)?;
    Ok(n)
}

fn write_exe<W: Write>(w: &mut W, exe: &EXE) -> io::Result<usize> {
    let mut n = 0;
    n += write_exe_header(w, &exe.header)?;
    for relocation in exe.relocations.iter() {
        n += write_u16le(w, relocation.offset)?;
        n += write_u16le(w, relocation.segment)?;
    }
    // http://www.delorie.com/djgpp/doc/exe/: "Note that some OSs and/or
    // programs may fail if the header is not a multiple of 512 bytes." The
    // unpack function has already added the necessary amounts to
    // bytes_in_last_block and blocks_in_file, expecting us to do this padding
    // here.
    while n % 512 != 0 {
        let zeroes = [0; 16];
        n += w.write(&zeroes[0..cmp::min(512 - n%512, zeroes.len())])?;
    }
    w.write_all(&exe.data)?;
    n += exe.data.len();
    Ok(n)
}

fn write_exe_file<P: AsRef<Path>>(path: P, exe: &EXE) -> io::Result<usize> {
    let f = File::create(&path)?;
    let mut f = io::BufWriter::new(f);
    let n = write_exe(&mut f, exe)?;
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
    // debug!("{:?}", exe);

    if let Err(err) = write_exe_file(&output_path, &exe) {
        return Err(TopLevelError {
            path: Some(output_path.as_ref().to_path_buf()),
            kind: DecompressError::Io(err),
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
        if let DecompressError::EXEPACK(EXEPACKFormatError::UnknownStub(ref exepack_header_buffer, ref stub)) = err.kind {
            // UnknownStub gets special treatment. We search for "Packed
            // file is corrupt" and display the stub if it is found, or warn
            // that the input may not be EXEPACK if it is not.
            display_unknown_stub(&mut io::stderr(), &exepack_header_buffer, &stub).unwrap();
        }
        process::exit(match err.kind {
            DecompressError::Io(_) | DecompressError::EXE(_) => 1,
            // EXEPACK returns 255 on a "Packed file is corrupt" error.
            DecompressError::EXEPACK(_) => 255,
        });
    }
}
