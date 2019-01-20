//! Compressor and decompressor for self-extracting DOS executables with
//! Microsoft EXEPACK.
//!
//! There are different versions of the EXEPACK format, with slightly different
//! internal data structures. This program identifies what format is in used by
//! looking up the executable portion of the file (the "decompression stub") in
//! a table of known stubs. See the `stubs` module. If the program doesn't
//! recognize a stub, it can't decompress it.
//!
//! One common format is documented at
//! <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#File_Format>. See
//! doc/README.stubs for other formats that this program can deal with.
//!
//! # Compression
//!
//! The `pack` function takes an `io::Read` and outputs a compressed `EXE`
//! struct. The `write_exe` function takes an `EXE` struct and writes it to an
//! `io::Write`.
//!
//! # Decompression
//!
//! The `unpack` function takes an `io::Read` and outputs a decompressed `EXE`
//! struct. The `write_exe` function takes an `EXE` struct and writes it to an
//! `io::Write`.
//!
//! # Inconsistencies
//!
//! Doesn't try to be bug-compatible will all versions of EXEPACK. Known
//! differences:
//!
//! - Some versions of EXEPACK have a bug when the offset of a segment:offset
//!   relocation entry is 0xffff: they write the second byte at address 0 in the
//!   same segment rather than the following segment.
//! - Some versions of EXEPACK don't restore the ax register before jumping to
//!   the decompressed program.
//! - If an executable contains relocations at the outer EXEPACK layer, they
//!   would be applied by DOS (presumably patching the compressed data) before
//!   decompression starts. This library doesn't permit such relocations.

use std::cmp;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic;

/// Our pre-assembled decompression stub.
pub const STUB: &'static [u8; 283] = include!("stub.in");

/// If `DEBUG` is true, the library will print debugging information to stderr.
pub static DEBUG: atomic::AtomicBool = atomic::AtomicBool::new(false);

macro_rules! debug {
    ($($x:tt)*) => {
        if DEBUG.load(atomic::Ordering::Relaxed) {
            eprintln!($($x)*);
        }
    }
}

/// Round `n` up to the next multiple of `m`.
fn round_up(n: usize, m: usize) -> Option<usize> {
    n.checked_add((m - n % m) % m)
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

fn push_u16le(buf: &mut Vec<u8>, v: u16) {
    buf.push(v as u8);
    buf.push((v >> 8) as u8);
}

fn checked_u16(n: usize) -> Option<u16> {
    if n > 0xffff {
        None
    } else {
        Some(n as u16)
    }
}

/// Discard a certain number of bytes from an `io::Read`.
fn discard<R: io::Read>(r: &mut R, mut n: u64) -> io::Result<()> {
    let mut buf = [0; 256];
    while n > 0 {
        let len = cmp::min(n, buf.len() as u64);
        r.read_exact(&mut buf[0..len as usize])?;
        n = n.checked_sub(len as u64).unwrap();
    }
    Ok(())
}

/// Add a prefix to the message of an `io::Error`.
fn annotate_io_error(err: io::Error, msg: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", msg, err))
}

pub const EXE_MAGIC: u16 = 0x5a4d; // "MZ"
// The length of an EXE header excluding the variable-sized padding.
pub const EXE_HEADER_LEN: u64 = 28;

#[derive(Debug)]
pub struct EXE {
    pub header: EXEHeader,
    pub data: Vec<u8>,
    pub relocations: Vec<Pointer>,
}

// http://www.delorie.com/djgpp/doc/exe/
// This is a form of IMAGE_DOS_HEADER from <winnt.h>.
#[derive(Debug)]
pub struct EXEHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
}

impl EXEHeader {
    fn exe_len(&self) -> u64 {
        if self.e_cp == 0 || self.e_cblp >= 512 {
            panic!("nonsense exe len e_cp={} e_cblp={}", self.e_cp, self.e_cblp);
        }
        (self.e_cp - 1) as u64 * 512
            + if self.e_cblp == 0 { 512 } else { self.e_cblp } as u64
    }

    fn header_len(&self) -> u64 {
        self.e_cparhdr as u64 * 16
    }
}

#[derive(Debug, Copy, Clone)]
/// A segment:offset far pointer.
pub struct Pointer {
    pub segment: u16,
    pub offset: u16,
}

impl Pointer {
    fn abs(&self) -> u32 {
        self.segment as u32 * 16 + self.offset as u32
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04x}:{:04x}", self.segment, self.offset)
    }
}

impl cmp::Ord for Pointer {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.abs().cmp(&other.abs())
    }
}

impl cmp::PartialOrd for Pointer {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::PartialEq for Pointer {
    fn eq(&self, other: &Self) -> bool {
        self.abs() == other.abs()
    }
}

impl cmp::Eq for Pointer {
}

#[derive(Debug)]
pub enum EXEFormatError {
    BadMagic(u16),
    BadNumPages(u16, u16),
    HeaderTooShort(u16),
    RelocationsOutsideHeader(u16, u16),
    RelocationsNotSupported(u16, u16),
    TooLong(usize),
    CompressedTooLong(usize),
    SSTooLarge(usize),
}

impl fmt::Display for EXEFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &EXEFormatError::BadMagic(e_magic) => write!(f, "Bad EXE magic 0x{:04x}; expected 0x{:04x}", e_magic, EXE_MAGIC),
            &EXEFormatError::BadNumPages(e_cb, e_cblp) => write!(f, "Bad EXE size ({}, {})", e_cb, e_cblp),
            &EXEFormatError::HeaderTooShort(e_cparhdr) => write!(f, "EXE header of {} bytes is too small", e_cparhdr as u64 * 16),
            &EXEFormatError::RelocationsOutsideHeader(e_crlc, e_lfarlc) => write!(f, "{} relocations starting at 0x{:04x} lie outside the EXE header", e_crlc, e_lfarlc),
            &EXEFormatError::RelocationsNotSupported(_e_crlc, _e_lfarlc) => write!(f, "relocations before decompression are not supported"),
            &EXEFormatError::TooLong(len) => write!(f, "EXE size of {} is too large to represent", len),
            &EXEFormatError::CompressedTooLong(len) => write!(f, "compressed data of {} bytes is too large to represent", len),
            &EXEFormatError::SSTooLarge(ss) => write!(f, "stack segment 0x{:04x} is too large to represent", ss),
        }
    }
}

fn read_exe_header<R: Read>(r: &mut R) -> io::Result<EXEHeader> {
    Ok(EXEHeader{
        e_magic: read_u16le(r)?,
        e_cblp: read_u16le(r)?,
        e_cp: read_u16le(r)?,
        e_crlc: read_u16le(r)?,
        e_cparhdr: read_u16le(r)?,
        e_minalloc: read_u16le(r)?,
        e_maxalloc: read_u16le(r)?,
        e_ss: read_u16le(r)?,
        e_sp: read_u16le(r)?,
        e_csum: read_u16le(r)?,
        e_ip: read_u16le(r)?,
        e_cs: read_u16le(r)?,
        e_lfarlc: read_u16le(r)?,
        e_ovno: read_u16le(r)?,
    })
}

fn read_exe_relocations<R: Read>(r: &mut R, relocations: &mut Vec<Pointer>, n: usize) -> io::Result<()> {
    for _ in 0..n {
        relocations.push(Pointer {
            offset: read_u16le(r)?,
            segment: read_u16le(r)?,
        });
    }
    Ok(())
}

/// Read an EXE header (including relocations and padding) and do consistency
/// checks on it. Reads exactly `header.header_len()` bytes from `r`. Doesn't
/// support relocation entries stored outside the header.
fn read_and_check_exe_header<R: Read>(r: &mut R) -> Result<(EXEHeader, Vec<Pointer>), Error> {
    let exe_header = read_exe_header(r)
        .map_err(|err| annotate_io_error(err, "reading EXE header"))?;
    debug!("{:?}", exe_header);

    // Begin consistency tests on the fields of the EXE header.
    if exe_header.e_magic != EXE_MAGIC {
        return Err(Error::EXE(EXEFormatError::BadMagic(exe_header.e_magic)));
    }

    // Consistency of e_cparhdr. We need the stated header length to be at least
    // as large as the header we just read.
    if exe_header.header_len() < EXE_HEADER_LEN {
        return Err(Error::EXE(EXEFormatError::HeaderTooShort(exe_header.e_cparhdr)));
    }

    // Consistency of e_cp and e_cblp.
    if exe_header.e_cp == 0 || exe_header.e_cblp >= 512 {
        return Err(Error::EXE(EXEFormatError::BadNumPages(exe_header.e_cp, exe_header.e_cblp)));
    }
    if exe_header.exe_len() < exe_header.header_len() {
        return Err(Error::EXE(EXEFormatError::BadNumPages(exe_header.e_cp, exe_header.e_cblp)));
    }

    // Consistency of e_lfarlc and e_crlc.
    let relocations_start = exe_header.e_lfarlc as u64;
    let relocations_end = relocations_start + exe_header.e_crlc as u64 * 4;

    let mut relocations = Vec::new();
    if exe_header.e_crlc > 0 {
        // Discard up to the beginning of relocations.
        discard(r, relocations_start.checked_sub(EXE_HEADER_LEN)
            .ok_or(Error::EXE(EXEFormatError::RelocationsOutsideHeader(exe_header.e_crlc, exe_header.e_lfarlc)))?
        ).map_err(|err| annotate_io_error(err, "reading to beginning of relocation table"))?;
        // Read relocations.
        read_exe_relocations(r, &mut relocations, exe_header.e_crlc as usize)
            .map_err(|err| annotate_io_error(err, "reading EXE relocation table"))?;
        // Discard any remaining header padding.
        discard(r, exe_header.header_len().checked_sub(relocations_end)
            .ok_or(Error::EXE(EXEFormatError::RelocationsOutsideHeader(exe_header.e_crlc, exe_header.e_lfarlc)))?
        ).map_err(|err| annotate_io_error(err, "reading to end of header"))?;
    } else {
        discard(r, exe_header.header_len().checked_sub(EXE_HEADER_LEN).unwrap())
            .map_err(|err| annotate_io_error(err, "reading to end of header"))?;
    }

    Ok((exe_header, relocations))
}

// The EXE header contains a limit to the overall length of the EXE file in the
// e_cblp and e_cp fields. This function trims an io::Read to limit it to the
// length specified in the header, assuming that the header (including
// relocations and padding) has already been read. file_len_hint is an optional
// externally provided hint of the input file's total length, which we use to
// emit a warning when it exceeds the length stated in the EXE header. Panics if
// the EXE length is less than the header length (which cannot happen if the
// header was returned from read_and_check_exe_header).
fn trim_input_from_header<R: Read>(
    input: R,
    header: &EXEHeader,
    file_len_hint: Option<u64>
) -> io::Take<R> {
    if let Some(file_len) = file_len_hint {
        // The EXE file length is allowed to be smaller than the length of the
        // file containing it. Emit a warning that we are ignoring trailing
        // garbage. The opposite situation, exe_len > file_len, is an error that
        // we will notice later when we get an unexpected EOF.
        if header.exe_len() < file_len {
            eprintln!("warning: EXE file size is {}; ignoring {} trailing bytes", file_len, file_len - header.exe_len());
        }
    }
    input.take(header.exe_len().checked_sub(header.header_len()).unwrap())
}

/// Read an EXE file.
/// `file_len_hint` is an optional externally provided hint of
/// the input file's total length, which we use to emit a warning when it
/// exceeds the length stated in the EXE header.
pub fn read_exe<R: Read>(input: &mut R, file_len_hint: Option<u64>) -> Result<EXE, Error> {
    let (header, relocations) = read_and_check_exe_header(input)?;
    debug!("{:?}", relocations);

    // Now we are positioned just after the EXE header. Trim any data that lies
    // beyond the length of the EXE file stated in the header.
    let mut input = trim_input_from_header(input, &header, file_len_hint);

    let mut data: Vec<u8> = Vec::new();
    // The input.take above ensures that we will read no more than 0xffff*512
    // bytes < 32 MB here.
    input.read_to_end(&mut data)
        .map_err(|err| annotate_io_error(err, "reading EXE body"))?;

    Ok(EXE {
        header: header,
        data: data,
        relocations: relocations,
    })
}

/// Return a tuple `(e_cblp, e_cp)` that encodes len as appropriate for the
/// so-named EXE header fields. Returns None if the size is too large to be
/// represented (> 0x1fffe00).
pub fn encode_exe_len(len: usize) -> Option<(u16, u16)> {
    let e_cp = (len + 511) / 512;
    if e_cp > 0xffff {
        None
    } else {
        let e_cblp = len % 512;
        Some((e_cblp as u16, e_cp as u16))
    }
}

#[test]
fn test_encode_exe_len() {
    assert_eq!(encode_exe_len(0), Some((0, 0)));
    assert_eq!(encode_exe_len(1), Some((1, 1)));
    assert_eq!(encode_exe_len(511), Some((511, 1)));
    assert_eq!(encode_exe_len(512), Some((0, 1)));
    assert_eq!(encode_exe_len(513), Some((1, 2)));
    assert_eq!(encode_exe_len(512*0xffff-1), Some((511, 0xffff)));
    assert_eq!(encode_exe_len(512*0xffff), Some((0, 0xffff)));
    assert_eq!(encode_exe_len(512*0xffff+1), None);
}

#[derive(Debug, PartialEq)]
pub enum EXEPACKFormatError {
    UnknownStub(Vec<u8>, Vec<u8>),
    BadMagic(u16),
    UnknownHeaderLength(usize),
    SkipTooShort(u16),
    SkipTooLong(u16),
    EXEPACKTooShort(u16, usize),
    Crossover(usize, usize),
    SrcOverflow(),
    FillOverflow(usize, usize, u8, usize, u8),
    CopyOverflow(usize, usize, u8, usize),
    BogusCommand(usize, u8, usize),
    Gap(usize, usize),
    TooManyEXERelocations(usize),
    UncompressedTooLong(usize),
    RelocationAddrTooLarge(Pointer),
    EXEPACKTooLong(usize),
}

impl fmt::Display for EXEPACKFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &EXEPACKFormatError::UnknownStub(ref _header_buffer, ref _stub) =>
                write!(f, "Unknown decompression stub"),
            &EXEPACKFormatError::BadMagic(magic) =>
                write!(f, "EXEPACK header has bad magic 0x{:04x}; expected 0x{:04x}", magic, EXEPACK_MAGIC),
            &EXEPACKFormatError::UnknownHeaderLength(header_len) =>
                write!(f, "don't know how to interpret EXEPACK header of {} bytes", header_len),
            &EXEPACKFormatError::SkipTooShort(skip_len) =>
                write!(f, "EXEPACK skip_len of {} paragraphs is invalid", skip_len),
            &EXEPACKFormatError::SkipTooLong(skip_len) =>
                write!(f, "EXEPACK skip_len of {} paragraphs is too long", skip_len),
            &EXEPACKFormatError::EXEPACKTooShort(exepack_size, header_and_stub_len) =>
                write!(f, "EXEPACK size of {} bytes is too short for header and stub of {} bytes", exepack_size, header_and_stub_len),
            &EXEPACKFormatError::Crossover(dst, src) =>
                write!(f, "write index {} outpaced read index {}", dst, src),
            &EXEPACKFormatError::SrcOverflow() =>
                write!(f, "reached end of compressed stream without seeing a termination command"),
            &EXEPACKFormatError::FillOverflow(dst, _src, _command, length, fill) =>
                write!(f, "write overflow: fill {}×'\\{:02x}' at index {}", length, fill, dst),
            &EXEPACKFormatError::CopyOverflow(dst, src, _command, length) =>
                write!(f, "{}: copy {} bytes from index {} to index {}",
                    if src < length { "read overflow" } else { "write overflow" },
                    length, src, dst),
            &EXEPACKFormatError::BogusCommand(src, command, length) =>
                write!(f, "unknown command 0x{:02x} with ostensible length {} at index {}", command, length, src),
            &EXEPACKFormatError::Gap(dst, original_src) =>
                write!(f, "decompression left a gap of {} unwritten bytes between write index {} and original read index {}", dst - original_src, dst, original_src),
            &EXEPACKFormatError::TooManyEXERelocations(num_relocations) =>
                write!(f, "too many relocation entries ({}) to represent in an EXE header", num_relocations),
            &EXEPACKFormatError::UncompressedTooLong(len) =>
                write!(f, "uncompressed size {} is too large to represent in an EXEPACK header", len),
            &EXEPACKFormatError::RelocationAddrTooLarge(ref pointer) =>
                write!(f, "relocation address {} is too large to represent in the EXEPACK table", pointer),
            &EXEPACKFormatError::EXEPACKTooLong(len) =>
                write!(f, "EXEPACK area is too long at {} bytes", len),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    EXE(EXEFormatError),
    EXEPACK(EXEPACKFormatError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<EXEFormatError> for Error {
    fn from(err: EXEFormatError) -> Self {
        Error::EXE(err)
    }
}

impl From<EXEPACKFormatError> for Error {
    fn from(err: EXEPACKFormatError) -> Self {
        Error::EXEPACK(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Io(ref err) => err.fmt(f),
            &Error::EXE(ref err) => err.fmt(f),
            &Error::EXEPACK(ref err) => err.fmt(f),
        }
    }
}

/// The basic compression loop. The compressed data are read (going forwards)
/// from `input` and written into the end of `output`.
///
/// <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Decompression_algorithm>
pub fn compress(output: &mut Vec<u8>, input: &[u8]) {
    // Since we produce our own self-extracting executable, technically we
    // could compress however we like. But we want to remain compatible with
    // https://github.com/w4kfu/unEXEPACK and other external EXEPACK unpackers,
    // so we use the standard EXEPACK encoding: 0xb2 for a copy, 0xb0 for a
    // fill, MSb == 1 to mark the end.
    //
    // The algorithm here uses dynamic programming. We define 3 states that the
    // compressed stream may be in:
    // * C ("copy") for a 0xb2/0xb3 block (copy the next len bytes)
    // * F ("fill") for a 0xb0/0xb1 block (fill len copies of the next byte)
    // * R ("runout") for the end of the stream after the last C or F block,
    //   which is copied verbatim from the compressed input to the decompressed
    //   output simply by virtue of remaining untouched in the buffer.
    // For each input position i, we compute the minimum length of the
    // compression of the first i bytes of the reversed input sequence. Assuming
    // we know the values for index i-1, we compute the values for index i using
    // the recurrences:
    //      C[i] = min(
    //          4 + F[i-1], // if we were in F, start a C block
    //          1 + C[i-1], // if we were in C, continue the same C block
    //      )
    //      F[i] = min(
    //          4 + C[i-1], // if we were in C, start an F block
    //          0 + F[i-1], // if we were in F, stay in the same F block
    //      )
    //      R[i] = min(     // runout bytes always cost 1
    //          1 + C[i-1],
    //          1 + F[i-1],
    //          1 + R[i-1],
    //      )
    // The transitions R→R R→C, R→F, C→C, C→F, F→F, F→C are valid, while C→R and
    // F→R are not (once you leave the runout you can't go back to it;
    // everything following has to be a C or F block). The actual formulas used
    // in the code are a little more complicated because we also have to account
    // for the fact that the length of each block is limited. For example, if a
    // current C block is full, we can't append to it and instead have to start
    // a new one.
    //
    // The we walk backwards through the minimum-cost tables. At each index i we
    // choose whichever of C, F, and R has the lowest cost--with the restriction
    // that once we have select C or F once, we can never again select R. Then
    // we jump i ahead by the length of the command, and repeat until we reach
    // the beginning of the tables. In the case where we stayed in R throughout
    // (i.e., an incompressible sequence), we tack on a dummy "copy 0" command
    // at the end--in this case (the worst case) the compressed data are 3 bytes
    // larger than the uncompressed.
    //
    // I'm not sure the algorithm used here is optimal with respect to the
    // length of commands. In the 1-dimensional C and F tables I'm storing the
    // single command length that led to the minimum cost at each position. A
    // more complete consideration of cases would make each table 2-dimensional,
    // indexed by input position and by command length. If there is a
    // difference, it's likely to be minor.
    //
    // A greedy algorithm (that uses F for runs of 5 or longer, C otherwise) is
    // not optimal. Consider the sequence
    //      ... 01 02 03 04 05 cc cc cc cc cc 01 02 03 04 05
    // (Assume the left side doesn't enter runout.) A greedy compressor would
    // compress it to
    //      ... 01 02 03 04 05 05 00 b2 cc 05 00 b0 01 02 03 04 05 05 00 b2
    // i.e., a C of length 5, then an F of length 5, then a C of length 5. But
    // switching from C to F back to C again costs more than compressing the run
    // of 5 cc's saves. A better compression is just one long C:
    //      ... 01 02 03 04 05 cc cc cc cc cc 01 02 03 04 05 0f 00 b2
    //
    // We don't take advantage of every possible optimization. For example,
    // suppose for a moment that the maximum length we can use is 6 rather than
    // 0xffff. Consider the 7-byte sequence
    //      cc cc cc cc cc cc cc
    // We will compress this into 5 bytes as
    //      cc cc 06 00 b1
    // (i.e., fill 6×cc, then one runout cc). But we could save 1 additional
    // byte by re-using one of the cc's both as a command parameter and a
    // runout byte:
    //      cc 06 00 b1
    // For that matter, if we happened to get the 8-byte input
    //      cc 06 cc cc cc cc cc cc
    // we could re-use the 2 bytes cc 06 and compress as
    //      cc 06 00 b1

    // The longest length of any command.
    const MAX_LEN: u16 = 0xffff;

    // Stage 1: build the tables of costs and command lengths for each input
    // position.

    // Allocate tables of costs (minimum compressed length) for each of C, F,
    // and R; and additionally command lengths for C and F (R doesn't have
    // command lengths). C[i+1].cost is the minimum length to compress up
    // input[0..i] if we are in a C command at position i; likewise for F and R.
    #[derive(Ord, PartialOrd, PartialEq, Eq)]
    struct Entry {
        cost: u32,
        len: u16,
    }
    #[allow(non_snake_case)]
    let (mut C, mut F, mut R): (Vec<Entry>, Vec<Entry>, Vec<u32>) = (
        Vec::with_capacity(input.len() + 1),
        Vec::with_capacity(input.len() + 1),
        Vec::with_capacity(input.len() + 1),
    );
    // The tables are 1 element longer than the input. The zeroth entry in each
    // represents the "-1" index; i.e., the cost/length of compressing a
    // zero-length input using each of the strategies.
    C.push(Entry{cost: 3, len: 0}); // 00 00 b1
    F.push(Entry{cost: 4, len: 0}); // XX 00 00 b3
    // if we've done the whole input in the R state, we'll need to append a
    // 00 00 b1 (just as in C), solely for the sake of giving the decompression
    // routine a termination indicator.
    R.push(3);

    for j in (0..input.len()).rev() {
        // j indexes input backwards from input.len()-1 to 0; i indexes the
        // cost/length tables forward from 1 to input.len().
        let i = input.len() - j;
        // If we require byte j to be in a C command, then we either start a new
        // C command here, or continue an existing C command.
        let entry = cmp::min(
            // If we previous byte was in an F, then it costs 4 bytes to start a
            // C at this point.
            Entry{cost: 4 + F[i-1].cost, len: 1},
            // If we were already in a C command, we have the option of
            // appending the current byte into the same command for an
            // additional cost of 1--but only if its len does not exceed
            // MAX_LEN. If it does, then we have to start a new C command at a
            // cost of 4.
            if C[i-1].len < MAX_LEN {
                Entry{cost: 1 + C[i-1].cost, len: 1 + C[i-1].len}
            } else {
                Entry{cost: 4 + C[i-1].cost, len: 1}
            }
        );
        // Push the minimum value to C[i].
        C.push(entry);

        // If we require byte j to be in an F command, then we either start a
        // new F command here, or continue an existing F command.
        let entry = cmp::min(
            // If we previous byte was in a C, then it costs 4 bytes to start an
            // F at this point.
            Entry{cost: 4 + C[i-1].cost, len: 1},
            // If we were already in a F command, we have the option of
            // including the current byte in the same command for an additional
            // cost of 0--but only if its len does not exceed MAX_LEN *and* the
            // byte value is identical to the previous one (or we are at the
            // first byte and there is no previous one yet). Otherwise, we need
            // to start a new F command at a cost of 4.
            if F[i-1].len < MAX_LEN && (j == input.len()-1 || input[j] == input[j+1]) {
                Entry{cost: 0 + F[i-1].cost, len: 1 + F[i-1].len}
            } else {
                Entry{cost: 4 + F[i-1].cost, len: 1}
            }
        );
        // Push the minimum value to F[i].
        F.push(entry);

        // Finally, if we require byte j to be in the R runout, the cost is 1
        // greater than the minimum cost so far using any of C, F, or R (the
        // cost of the verbatim byte itself). Note that we can switch from from
        // C or F to R, but once in R there is no going back to C or F.
        let cost = C[i-1].cost.min(F[i-1].cost).min(R[i-1]) + 1;
        // Push the minimum cost to R[i].
        R.push(cost);
    }

    // Stage 2: trace back through the C, F, and R tables to recover the
    // sequence of commands that lead to the minimum costs we computed.
    enum Cmd {
        C,
        F,
        R,
    }
    // The command currently in effect. We encode forward, but the decompressor
    // will run backwards. Start in the runout.
    let mut cmd = Cmd::R;
    // The first time we encode a C or F (i.e., when we get out of the runout),
    // we need to set the LSb to indicate that it is the final command.
    let mut is_final: u8 = 0x01;
    let mut j = 0;
    while j < input.len() {
        // j indexes input from beginning to end; i indexes the cost/length
        // tables from end to beginning.
        let i = input.len() - j;
        // We consult the C and F tables and see if either of them have a lower
        // cost than the current command (which may be C, F, or R) at this
        // index.
        let mut cost = match cmd {
            Cmd::C => C[i].cost,
            Cmd::F => F[i].cost,
            Cmd::R => R[i],
        };
        if C[i].cost < cost {
            cost = C[i].cost;
            cmd = Cmd::C;
        }
        if F[i].cost < cost {
            cmd = Cmd::F;
        }

        // Now encode the command we've found to be the cheapest at this
        // position.
        match cmd {
            Cmd::C => {
                let len = C[i].len as usize;
                output.extend(input[j..j+len].iter());
                output.push(len as u8);
                output.push((len >> 8) as u8);
                output.push(0xb2 | is_final);
                is_final = 0;
                j += len;
            }
            Cmd::F => {
                let len = F[i].len as usize;
                output.push(input[j]);
                output.push(len as u8);
                output.push((len >> 8) as u8);
                output.push(0xb0 | is_final);
                is_final = 0;
                j += len;
            }
            Cmd::R => {
                output.push(input[j]);
                j += 1;
            }
        }
    }
    assert_eq!(j, input.len());
    // If we got all the way to the end and are still in the runout, then we
    // need to append a dummy, zero-length C command for the sake of giving the
    // decompression routine something to interpret. This is the worst case for
    // an incompressible input, an expansion of 3 bytes.
    if let Cmd::R = cmd {
        output.push(0);
        output.push(0);
        assert_eq!(is_final, 1);
        output.push(0xb2 | is_final);
    }
}

/// Encode a compressed relocation table.
fn encode_relocations(buf: &mut Vec<u8>, relocations: &[Pointer]) -> Result<(), Error> {
    // http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Relocation_Table
    let mut relocations: Vec<&Pointer> = relocations.iter().collect();
    relocations.sort();
    let mut i = 0;
    for segment_index in 0..16 {
        let mut j = i;
        while j < relocations.len() && relocations[j].abs() >> 16 == segment_index {
            j += 1;
        }
        // The checked_u16 cannot fail; for that to happen, the input EXE must
        // have contained at least 0x10000 relocations, which is impossible to
        // represent in the e_crlc field.
        push_u16le(buf, checked_u16(j - i).unwrap());
        for pointer in relocations[i..j].iter() {
            push_u16le(buf, (pointer.abs() & 0xffff) as u16);
        }
        i = j;
    }
    if i < relocations.len() {
        return Err(Error::EXEPACK(EXEPACKFormatError::RelocationAddrTooLarge(*relocations[i])));
    }
    Ok(())
}

/// Pack an input executable and return the elements of the packed executable.
/// `file_len_hint` is an optional externally provided hint of the input file's
/// total length, which we use to emit a warning when it exceeds the length
/// stated in the EXE header.
pub fn pack<R: Read>(input: &mut R, file_len_hint: Option<u64>) -> Result<EXE, Error> {
    let exe = read_exe(input, file_len_hint)?;

    let mut uncompressed = exe.data;
    // Pad uncompressed to a multiple of 16 bytes.
    {
        let len = round_up(uncompressed.len(), 16).unwrap();
        uncompressed.resize(len, 0x00);
    }
    assert_eq!(uncompressed.len() % 16, 0);

    let mut compressed = Vec::new();
    compress(&mut compressed, &uncompressed);
    // Pad compressed to a multiple of 16 bytes.
    {
        let len = round_up(compressed.len(), 16).unwrap();
        compressed.resize(len, 0xff);
    }
    assert_eq!(compressed.len() % 16, 0);

    let mut relocations_buffer = Vec::new();
    encode_relocations(&mut relocations_buffer, &exe.relocations)?;


    // Now we have the pieces we need. Start putting together the output EXE.
    // The `data` vec will hold the EXE body (everything after the header).
    let mut data = Vec::new();

    // Start with the padded, compressed data.
    data.extend(compressed.iter());

    // Next, the 18-byte EXEPACK header.
    let exepack_size = (18 as usize)
        .checked_add(STUB.len()).unwrap()
        .checked_add(relocations_buffer.len()).unwrap();
    for exe_var in [
        exe.header.e_ip,    // real_ip
        exe.header.e_cs,    // real_ip
        0,                  // mem_start (unused)
        checked_u16(exepack_size)   // exepack_size
            .ok_or(Error::EXEPACK(EXEPACKFormatError::EXEPACKTooLong(exepack_size)))?,
        exe.header.e_sp,    // real_sp
        exe.header.e_ss,    // real_ss
        checked_u16(uncompressed.len() / 16)    // dest_len
            .ok_or(Error::EXEPACK(EXEPACKFormatError::UncompressedTooLong(uncompressed.len())))?,
        1,                  // skip_len
        EXEPACK_MAGIC,      // signature
    ].iter() {
        push_u16le(&mut data, *exe_var);
    }

    // Then the stub itself.
    data.extend(STUB.iter());

    // Finally, the packed relocation table.
    data.extend(relocations_buffer.iter());


    // Now that we know how big the output will be, we can build the EXE header.
    let (e_cblp, e_cp) = encode_exe_len(512 + data.len())
        .ok_or(Error::EXE(EXEFormatError::TooLong(data.len())))?;
    // The code segment points at the EXEPACK header, immediately after the
    // compressed data.
    let e_cs = checked_u16(compressed.len() / 16)
        .ok_or(Error::EXE(EXEFormatError::CompressedTooLong(compressed.len())))?;
    // When the decompression stub runs, it will copy itself to a location
    // higher in memory (past the end of the uncompressed data size) so that the
    // decompression process doesn't overwrite it while it is running. But we
    // also have to account for the possibility that the uncompressed data size
    // lies in the middle of the decompression stub--in that case the stub would
    // be overwritten while it is running not by the decompression, but by its
    // own copy operation. The decompression stub knows about this possibility
    // and will copy itself to the end of uncompressed data or to the end of
    // itself, whichever is greater. We need to do the same here with regard to
    // the stack segment, placing it at least exepack_size past whichever
    // address the stub will copy itself to.
    // The Microsoft EXEPACK stubs don't handle the latter situation and the
    // compressor instead refuses to work when it arises: "L1114 file not
    // suitable for /EXEPACK; relink without".
    // https://archive.org/details/bitsavers_ibmpcdos15lReferenceJul88_10507385/page/n128?q=EXEPACK
    let (e_ss, e_sp) = {
        let len = cmp::max(uncompressed.len(), data.len()) + exepack_size;
        // Reserve 16 bytes for the stack. The stub doesn't need much.
        let stack_pointer = round_up(len, 16).unwrap() + 16;
        // Now, shift as many bits as possible from the segment to the offset,
        // because we have to encode e_sp in the EXE header and we can compress
        // slightly larger files if it's smaller.
        if stack_pointer <= 0xffff {
            (0u16, stack_pointer as u16)
        } else {
            let e_sp = 0xfff0 | (stack_pointer & 0xf);
            let e_ss = (stack_pointer - e_sp) >> 4;
            (
                checked_u16(e_ss).ok_or(Error::EXE(EXEFormatError::SSTooLarge(e_ss)))?,
                e_sp as u16
            )
        }
    };
    let new_exe_header = EXEHeader{
        e_magic: EXE_MAGIC,
        e_cblp: e_cblp,
        e_cp: e_cp,
        e_crlc: 0,
        e_cparhdr: (512 / 16) as u16,   // No relocations means a fixed-size EXE header.
        e_minalloc: exe.header.e_minalloc,
        e_maxalloc: exe.header.e_maxalloc,
        e_ss: e_ss,
        e_sp: e_sp,
        e_csum: 0,
        e_ip: 18, // Stub begins just after the EXEPACK header.
        e_cs: e_cs,
        e_lfarlc: EXE_HEADER_LEN as u16,
        e_ovno: 0,
    };
    debug!("{:?}", new_exe_header);
    Ok(EXE{header: new_exe_header, data: data, relocations: Vec::new()})
}

/// Return a new index after reading up to 15 bytes of 0xff padding from the end
/// of `buf[..i]`.
pub fn unpad(buf: &[u8], mut i: usize) -> usize {
    for _ in 0..15 {
        if i == 0 {
            break
        }
        if buf[i-1] != 0xff {
            break
        }
        i -= 1;
    }
    i
}

/// The basic decompression loop. The compressed data are read (going backwards)
/// starting at `src`, and written (also going backwards) back to the same buffer
/// starting at `dst`.
///
/// <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Decompression_algorithm>
pub fn decompress(buf: &mut [u8], mut dst: usize, mut src: usize) -> Result<(), EXEPACKFormatError> {
    let original_src = src;
    loop {
        if src < original_src && dst < src {
            // The byte we're about to read--or one of the bytes farther down
            // the line--was overwritten. This is allowed to happen on the first
            // iteration, before we've written anything.
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
                src = src.checked_sub(length).ok_or(EXEPACKFormatError::SrcOverflow())?;
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

fn parse_exepack_header(buf: &[u8]) -> Result<EXEPACKHeader, EXEPACKFormatError> {
    let mut r = io::Cursor::new(buf);
    let uses_skip_len = match buf.len() {
        16 => false,
        18 => true,
        _ => return Err(EXEPACKFormatError::UnknownHeaderLength(buf.len())),
    };
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

/// Read a decompression stub (the executable code following the EXEPACK header
/// and preceding the packed relocation table). Returns (stub, true) if it finds
/// a match, or (partial, false) if it reads 512 bytes without a match.
///
/// There are many different decompression stubs--see some examples in the doc
/// directory. What they all have in common is a suffix of
/// `"\xcd\x21\xb8\xff\x4c\xcd\x21"`--standing for the instructions
/// `int 0x21; mov ax, 0x4cff; int 0x21`--followed by a 22-byte error string,
/// most often `"Packed file is corrupt"`.
fn read_stub<R: Read>(r: &mut R) -> io::Result<(Vec<u8>, bool)> {
    const SUFFIX: &'static [u8] = b"\xcd\x21\xb8\xff\x4c\xcd\x21";
    let mut buf = Vec::new();
    while buf.len() < 512 {
        {
            let len = buf.len();
            buf.push(0);
            let n = r.read(&mut buf[len..])?;
            if n == 0 {
                break;
            }
            buf.resize(len + n, 0);
        }
        if buf.ends_with(SUFFIX) {
            {
                let len = buf.len();
                buf.resize(len+22, 0);
                r.read_exact(&mut buf[len..])?;
                return Ok((buf, true));
            }
        }
    }
    Ok((buf, false))
}

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Relocation_Table
fn read_relocations<R: Read>(r: &mut R) -> io::Result<Vec<Pointer>> {
    let mut relocations = Vec::new();
    for i in 0..16 {
        let num_relocations = read_u16le(r)?;
        for _ in 0..num_relocations {
            let offset = read_u16le(r)?;
            relocations.push(Pointer {
                segment: i * 0x1000,
                offset: offset,
            });
        }
    }
    Ok(relocations)
}

/// Unpack an input executable and return the elements of an unpacked executable.
/// `file_len_hint` is an optional externally provided hint of the file's total
/// length, which we use to emit a warning when it exceeds the length stated in
/// the EXE header.
pub fn unpack<R: Read>(input: &mut R, file_len_hint: Option<u64>) -> Result<EXE, Error> {
    let (exe_header, relocations) = read_and_check_exe_header(input)?;
    debug!("{:?}", relocations);
    if relocations.len() > 0 {
        return Err(Error::EXE(EXEFormatError::RelocationsNotSupported(exe_header.e_crlc, exe_header.e_lfarlc)));
    }

    // Now we are positioned just after the EXE header. Trim any data that lies
    // beyond the length of the EXE file stated in the header.
    let mut input = trim_input_from_header(input, &exe_header, file_len_hint);

    // Compressed data starts immediately after the EXE header and ends at
    // cs:0000. We will decompress into the very same buffer (after expanding
    // it).
    let mut work_buffer = vec![0; exe_header.e_cs as usize * 16];
    input.read_exact(&mut work_buffer)
        .map_err(|err| annotate_io_error(err, "reading compressed data"))?;

    // The EXEPACK header starts at cs:0000 and ends at cs:ip.
    let mut exepack_header_buffer = vec![0; exe_header.e_ip as usize];
    input.read_exact(&mut exepack_header_buffer)
        .map_err(|err| annotate_io_error(err, "reading EXEPACK header"))?;
    let exepack_header = parse_exepack_header(&exepack_header_buffer)?;
    if exepack_header.signature != EXEPACK_MAGIC {
        return Err(Error::EXEPACK(EXEPACKFormatError::BadMagic(exepack_header.signature)));
    }
    debug!("{:?}", exepack_header);

    // The decompression stub starts at cs:ip.
    let (stub, found) = read_stub(&mut input)
        .map_err(|err| annotate_io_error(err, "reading EXEPACK decompression stub"))?;
    if !found {
        return Err(Error::EXEPACK(EXEPACKFormatError::UnknownStub(exepack_header_buffer, stub)));
    }
    debug!("found stub of length {}", stub.len());

    // The EXEPACK header's exepack_size field contains the length of the
    // EXEPACK header, the decompression stub, and the relocation table all
    // together. The decompression stub uses this value to control how much of
    // itself to copy out of the way before starting the main compression loop.
    // Therefore we are justified in raising an error if any reads go past
    // exepack_size.
    let mut input = {
        let read_so_far = exepack_header_buffer.len() + stub.len();
        if (exepack_header.exepack_size as usize) < read_so_far {
            return Err(Error::EXEPACK(EXEPACKFormatError::EXEPACKTooShort(exepack_header.exepack_size, read_so_far)));
        }
        input.take((exepack_header.exepack_size as usize - read_so_far) as u64)
    };

    // The skip_len variable is 1 greater than the number of paragraphs of
    // padding between the compressed data and the EXEPACK header. It cannot be
    // 0 because that would mean −1 paragraphs of padding.
    let skip_len = 16 * (exepack_header.skip_len as usize).checked_sub(1)
        .ok_or(Error::EXEPACK(EXEPACKFormatError::SkipTooShort(exepack_header.skip_len)))?;
    let compressed_len = work_buffer.len().checked_sub(skip_len)
        .ok_or(Error::EXEPACK(EXEPACKFormatError::SkipTooLong(exepack_header.skip_len)))?;
    // It's weird that skip_len applies to the *un*compressed length as well,
    // but it does (see the disassembly in stubs.rs). Why didn't they just make
    // data_len that much smaller?
    let uncompressed_len = (exepack_header.dest_len as usize * 16).checked_sub(skip_len)
        .ok_or(Error::EXEPACK(EXEPACKFormatError::SkipTooLong(exepack_header.skip_len)))?;
    // Expand the buffer to hold the uncompressed data.
    if uncompressed_len > compressed_len {
        work_buffer.resize(uncompressed_len, 0);
    }
    // Remove 0xff padding.
    let compressed_len = unpad(&work_buffer, compressed_len);
    // Now let's actually decompress the buffer.
    decompress(&mut work_buffer, uncompressed_len, compressed_len)?;
    // Decompression might have shrunk the input; trim the buffer if so.
    work_buffer.resize(uncompressed_len, 0);

    // The last step is to parse the relocation table that follows the
    // decompression stub.
    let relocations = read_relocations(&mut input)
        .map_err(|err| annotate_io_error(err, "reading EXEPACK relocation table"))?;
    debug!("{:?}", relocations);

    // It's not an error if there is trailing data here (i.e., if
    // exepack_header.exepack_size is larger than it needs to be). Any trailing data
    // would be ignored by the EXEPACK decompression stub.

    // Finally, construct a new EXE.
    // Pad the header to the smallest multiple of 512 bytes that holds both the
    // EXEHeader struct and all the relocations (each relocation is 4 bytes).
    let num_header_pages = ((EXE_HEADER_LEN as usize + 4 * relocations.len()) + 511) / 512;
    let (e_cblp, e_cp) = encode_exe_len(num_header_pages * 512 + uncompressed_len)
        .ok_or(Error::EXE(EXEFormatError::TooLong(num_header_pages * 512 + uncompressed_len)))?;
    let e_crlc = checked_u16(relocations.len())
        .ok_or(Error::EXEPACK(EXEPACKFormatError::TooManyEXERelocations(relocations.len())))?;
    let new_exe_header = EXEHeader{
        e_magic: EXE_MAGIC,
        e_cblp: e_cblp,
        e_cp: e_cp,
        e_crlc: e_crlc,
        e_cparhdr: (num_header_pages * 512 / 16) as u16,
        e_minalloc: exe_header.e_minalloc,
        e_maxalloc: exe_header.e_maxalloc,
        e_ss: exepack_header.real_ss,
        e_sp: exepack_header.real_sp,
        e_csum: 0,
        e_ip: exepack_header.real_ip,
        e_cs: exepack_header.real_cs,
        e_lfarlc: EXE_HEADER_LEN as u16,
        e_ovno: 0,
    };
    debug!("{:?}", new_exe_header);
    Ok(EXE{header: new_exe_header, data: work_buffer, relocations})
}

fn write_exe_header<W: Write>(w: &mut W, header: &EXEHeader) -> io::Result<usize> {
    let mut n = 0;
    n += write_u16le(w, header.e_magic)?;
    n += write_u16le(w, header.e_cblp)?;
    n += write_u16le(w, header.e_cp)?;
    n += write_u16le(w, header.e_crlc)?;
    n += write_u16le(w, header.e_cparhdr)?;
    n += write_u16le(w, header.e_minalloc)?;
    n += write_u16le(w, header.e_maxalloc)?;
    n += write_u16le(w, header.e_ss)?;
    n += write_u16le(w, header.e_sp)?;
    n += write_u16le(w, header.e_csum)?;
    n += write_u16le(w, header.e_ip)?;
    n += write_u16le(w, header.e_cs)?;
    n += write_u16le(w, header.e_lfarlc)?;
    n += write_u16le(w, header.e_ovno)?;
    Ok(n)
}

fn write_exe_relocations<W: Write>(w: &mut W, relocations: &[Pointer]) -> io::Result<usize> {
    let mut n = 0;
    for pointer in relocations.iter() {
        n += write_u16le(w, pointer.offset)?;
        n += write_u16le(w, pointer.segment)?;
    }
    Ok(n)
}

/// Serialize an `EXE` structure to `w`. Returns the number of bytes written.
pub fn write_exe<W: Write>(w: &mut W, exe: &EXE) -> io::Result<usize> {
    let mut n = 0;
    n += write_exe_header(w, &exe.header)
        .map_err(|err| {debug!("annotate"); annotate_io_error(err, "writing EXE header")})?;
    n += write_exe_relocations(w, &exe.relocations)
        .map_err(|err| annotate_io_error(err, "writing EXE relocations"))?;
    // http://www.delorie.com/djgpp/doc/exe/: "Note that some OSs and/or
    // programs may fail if the header is not a multiple of 512 bytes." The
    // unpack function has already added the necessary amounts to e_cblp and
    // e_cp, expecting us to do this padding here.
    while n % 512 != 0 {
        let zeroes = [0; 16];
        n += w.write(&zeroes[0..cmp::min(512 - n%512, zeroes.len())])
            .map_err(|err| annotate_io_error(err, "writing EXE header padding"))?;
    }
    w.write_all(&exe.data)
        .map_err(|err| annotate_io_error(err, "writing EXE body"))?;
    n += exe.data.len();
    Ok(n)
}
