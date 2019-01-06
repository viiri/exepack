use std::cmp;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::atomic;

mod stubs;

pub static DEBUG: atomic::AtomicBool = atomic::AtomicBool::new(false);

macro_rules! debug {
    ($($x:tt)*) => {
        if DEBUG.load(atomic::Ordering::Relaxed) {
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

const EXE_MAGIC: u16 = 0x5a4d; // "MZ"
// The length of an EXE header excluding the variable-sized padding.
const EXE_HEADER_LEN: u64 = 28;

#[derive(Debug)]
pub struct EXE {
    header: EXEHeader,
    data: Vec<u8>,
    relocations: Vec<Relocation>,
}

// http://www.delorie.com/djgpp/doc/exe/
// This is a form of IMAGE_DOS_HEADER from <winnt.h>.
#[derive(Debug)]
pub struct EXEHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
}

#[derive(Debug)]
pub struct Relocation {
    segment: u16,
    offset: u16,
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

// Return a tuple (e_cblp, e_cp) that encodes len as appropriate for the
// so-named EXE header fields. Panics if the size is too large to be
// represented (> 0x1fffe00).
fn encode_exe_len(len: usize) -> (u16, u16) {
    let e_cp = (len + 511) / 512;
    if e_cp > 0xffff {
        panic!("cannot represent the length {}", len);
    }
    let e_cblp = len % 512;
    (e_cblp as u16, e_cp as u16)
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

pub enum EXEFormatError {
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

pub enum EXEPACKFormatError {
    UnknownStub(Vec<u8>, Vec<u8>),
    BadMagic(u16),
    HeaderSizeMismatch(usize, usize),
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
            &EXEPACKFormatError::BadMagic(magic) =>
                write!(f, "EXEPACK header has bad magic 0x{:04x}; expected 0x{:04x}", magic, EXEPACK_MAGIC),
            &EXEPACKFormatError::HeaderSizeMismatch(header_len, expected_len) =>
                write!(f, "EXEPACK header is {} bytes, expected {}", header_len, expected_len),
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
                write!(f, "write overflow: fill {}×'\\{:02x}' at index {}", length, fill, dst),
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
            &Error::EXEPACK(ref err) => {
                match err {
                    &EXEPACKFormatError::UnknownStub(_, _) => err.fmt(f),
                    _ => write!(f, "Packed file is corrupt: {}", err),
                }
            }
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
        return Err(EXEPACKFormatError::HeaderSizeMismatch(buf.len(), 16));
    }
    if uses_skip_len && buf.len() != 18 {
        return Err(EXEPACKFormatError::HeaderSizeMismatch(buf.len(), 18));
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
pub fn unpack<R: Read>(input: &mut R, file_len_hint: Option<u64>) -> Result<EXE, Error> {
    let mut input = io::BufReader::new(input);

    let exe_header = read_exe_header(&mut input)
        .map_err(|err| io::Error::new(err.kind(), format!("reading EXE header: {}", err)))?;
    debug!("{:?}", exe_header);

    // Begin consistency tests on the fields of the EXE header.
    if exe_header.e_magic != EXE_MAGIC {
        return Err(Error::EXE(EXEFormatError::BadMagic(exe_header.e_magic)));
    }

    // Consistency of e_cparhdr. We need the stated header length to be at least
    // as large as the header we just read.
    let exe_header_len = exe_header.e_cparhdr as u64 * 16;
    if exe_header_len < EXE_HEADER_LEN {
        return Err(Error::EXE(EXEFormatError::HeaderTooShort(exe_header.e_cparhdr)));
    }

    // Consistency of e_cp and e_cblp.
    if exe_header.e_cp == 0 || exe_header.e_cblp >= 512 {
        return Err(Error::EXE(EXEFormatError::BadNumPages(exe_header.e_cp, exe_header.e_cblp)));
    }
    let exe_len = (exe_header.e_cp - 1) as u64 * 512
        + if exe_header.e_cblp == 0 { 512 } else { exe_header.e_cblp } as u64;
    if exe_len < exe_header_len {
        return Err(Error::EXE(EXEFormatError::BadNumPages(exe_header.e_cp, exe_header.e_cblp)));
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
    work_buffer.resize(exe_header.e_cs as usize * 16, 0);
    input.read_exact(&mut work_buffer)?;

    // The EXEPACK header starts at cs:0000 and ends at cs:ip. We won't know the
    // layout of the EXEPACK header (i.e., whether there is a skip_len member)
    // until after we have read and identified the decompression stub.
    let mut exepack_header_buffer = Vec::new();
    exepack_header_buffer.resize(exe_header.e_ip as usize, 0);
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
            return Err(Error::EXEPACK(EXEPACKFormatError::UnknownStub(exepack_header_buffer, stub)));
        }
    };

    // Now that we know what stub we're dealing with, we can interpret the
    // EXEPACK header.
    let exepack_header = parse_exepack_header(&exepack_header_buffer, uses_skip_len)?;
    if exepack_header.signature != EXEPACK_MAGIC {
        return Err(Error::EXEPACK(EXEPACKFormatError::BadMagic(exepack_header.signature)));
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
            return Err(Error::EXEPACK(EXEPACKFormatError::EXEPACKTooShort(exepack_header.exepack_size, read_so_far)));
        }
        input.take((exepack_header.exepack_size as usize - read_so_far) as u64)
    };

    // The skip_len variable is 1 greater than the number of paragraphs of
    // padding between the compressed data and the EXEPACK header. It cannot be
    // 0 because that would mean −1 paragraphs of padding.
    let padding_len = 16 * (exepack_header.skip_len as usize).checked_sub(1)
        .ok_or(Error::EXEPACK(EXEPACKFormatError::PaddingTooShort(exepack_header.skip_len)))?;
    let compressed_len = work_buffer.len().checked_sub(padding_len)
        .ok_or(Error::EXEPACK(EXEPACKFormatError::PaddingTooLong(exepack_header.skip_len)))?;
    // It's weird that skip_len applies to the *un*compressed length as well,
    // but it does (see the disassembly in stubs.rs). Why didn't they just make
    // data_len that much smaller?
    let uncompressed_len = (exepack_header.dest_len as usize * 16).checked_sub(padding_len)
        .ok_or(Error::EXEPACK(EXEPACKFormatError::PaddingTooLong(exepack_header.skip_len)))?;
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
    let (e_cblp, e_cp) = encode_exe_len(num_header_pages * 512 + uncompressed_len);
    let new_exe_header = EXEHeader{
        e_magic: EXE_MAGIC,
        e_cblp: e_cblp,
        e_cp: e_cp,
        e_crlc: if relocations.len() > 0xffff {
            return Err(Error::EXEPACK(EXEPACKFormatError::TooManyRelocations(relocations.len())))
        } else {
            relocations.len() as u16
        },
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

pub fn write_exe<W: Write>(w: &mut W, exe: &EXE) -> io::Result<usize> {
    let mut n = 0;
    n += write_exe_header(w, &exe.header)?;
    for relocation in exe.relocations.iter() {
        n += write_u16le(w, relocation.offset)?;
        n += write_u16le(w, relocation.segment)?;
    }
    // http://www.delorie.com/djgpp/doc/exe/: "Note that some OSs and/or
    // programs may fail if the header is not a multiple of 512 bytes." The
    // unpack function has already added the necessary amounts to e_cblp and
    // e_cp, expecting us to do this padding here.
    while n % 512 != 0 {
        let zeroes = [0; 16];
        n += w.write(&zeroes[0..cmp::min(512 - n%512, zeroes.len())])?;
    }
    w.write_all(&exe.data)?;
    n += exe.data.len();
    Ok(n)
}
