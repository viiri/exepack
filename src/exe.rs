//! Reading and writing 16-bit DOS MZ executables.

use std::cmp;
use std::convert::TryInto;
use std::fmt;
use std::io::{self, prelude::*};

use crate::{annotate_io_error, read_u16le};
use pointer::Pointer;

const MAGIC: u16 = 0x5a4d; // "MZ"
// The length of an EXE header excluding the variable-sized padding.
const HEADER_LEN: u64 = 28;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(FormatError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::Io(err) => err.fmt(f),
            Error::Format(err) => err.fmt(f),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<FormatError> for Error {
    fn from(err: FormatError) -> Self {
        Error::Format(err)
    }
}

#[derive(Debug)]
pub enum FormatError {
    BadMagic(u16),
    BadNumPages(u16, u16),
    HeaderTooShort(u16),
    RelocationsOutsideHeader(u16, u16),
    TooManyRelocations(usize),
    TooLong(usize),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &FormatError::BadMagic(e_magic) => write!(f, "Bad EXE magic 0x{:04x}; expected 0x{:04x}", e_magic, MAGIC),
            &FormatError::BadNumPages(e_cb, e_cblp) => write!(f, "Bad EXE size ({}, {})", e_cb, e_cblp),
            &FormatError::HeaderTooShort(e_cparhdr) => write!(f, "EXE header of {} bytes is too small", e_cparhdr as u64 * 16),
            &FormatError::RelocationsOutsideHeader(e_crlc, e_lfarlc) => write!(f, "{} relocations starting at 0x{:04x} lie outside the EXE header", e_crlc, e_lfarlc),
            &FormatError::TooManyRelocations(n) => write!(f, "{} relocations are too many to fit in 16 bits", n),
            &FormatError::TooLong(len) => write!(f, "EXE size of {} is too large to represent", len),
        }
    }
}

#[derive(Debug)]
pub struct Exe {
    // Some fields taken verbatim from the EXE header, the ones that aren't
    // related to the "container" aspects of EXE. Other fields like e_cblp,
    // e_cp, and e_cparhdr, which depend on the size of the body and the number
    // of relocations, are re-computed as needed.
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_ovno: u16,

    // Everything following the header.
    pub body: Vec<u8>,

    // Relocations from the header.
    pub relocs: Vec<Pointer>,
}

impl Exe {
    /// Return a new `Header` appropriate for this `Exe`.
    fn make_header(&self) -> Result<Header, FormatError> {
        // http://www.delorie.com/djgpp/doc/exe/: "Note that some OSs and/or
        // programs may fail if the header is not a multiple of 512 bytes."
        let num_header_pages = ((HEADER_LEN as usize + 4 * self.relocs.len()) + 511) / 512;
        let (e_cblp, e_cp) = encode_exe_len(num_header_pages * 512 + self.body.len())
            .ok_or(FormatError::TooLong(num_header_pages * 512 + self.body.len()))?;
        let e_crlc = self.relocs.len().try_into()
            .or(Err(FormatError::TooManyRelocations(self.relocs.len())))?;
        Ok(Header {
            e_magic: MAGIC,
            e_cblp: e_cblp,
            e_cp: e_cp,
            e_crlc: e_crlc,
            e_cparhdr: (num_header_pages * 512 / 16) as u16,
            e_minalloc: self.e_minalloc,
            e_maxalloc: self.e_maxalloc,
            e_ss: self.e_ss,
            e_sp: self.e_sp,
            e_csum: 0,
            e_ip: self.e_ip,
            e_cs: self.e_cs,
            e_lfarlc: HEADER_LEN as u16,
            e_ovno: self.e_ovno,
        })
    }

    /// Reads an EXE file into an `Exe` structure.
    ///
    /// `file_len_hint` is an optional externally provided hint of
    /// the input file's total length, which we use to emit a warning when it
    /// exceeds the length stated in the EXE header.
    pub fn read<R: Read + ?Sized>(input: &mut R, file_len_hint: Option<u64>) -> Result<Self, Error> {
        let (header, relocs) = read_and_check_exe_header(input)?;
        debug!("{:?}", relocs);

        // Now we are positioned just after the EXE header. Trim any data that lies
        // beyond the length of the EXE file stated in the header.
        let input = &mut trim_input_from_header(input, &header, file_len_hint);

        // The trim_input_from_header above ensures that we will read no more than
        // 0xffff*512 bytes < 32 MB here.
        let mut body = vec![0; header.exe_len().checked_sub(header.header_len()).unwrap() as usize];
        input.read_exact(&mut body)
            .map_err(|err| annotate_io_error(err, "reading EXE body"))?;

        Ok(Self {
            e_minalloc: header.e_minalloc,
            e_maxalloc: header.e_maxalloc,
            e_ss: header.e_ss,
            e_sp: header.e_sp,
            e_ip: header.e_ip,
            e_cs: header.e_cs,
            e_ovno: header.e_ovno,
            body,
            relocs,
        })
    }

    /// Serializes the `Exe` structure to `w`. Returns the number of bytes
    /// written.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<u64, Error> {
        let header = self.make_header()?;
        debug!("{:?}", header);
        let mut n: u64 = 0;
        n += header.write(w)
            .map_err(|err| annotate_io_error(err, "writing EXE header"))? as u64;
        n += write_exe_relocations(w, &self.relocs)
            .map_err(|err| annotate_io_error(err, "writing EXE relocations"))? as u64;
        assert!(n <= header.header_len());
        while n < header.header_len() {
            let zeroes = [0; 16];
            n += w.write(&zeroes[0..cmp::min((header.header_len() - n) as usize, zeroes.len())])
                .map_err(|err| annotate_io_error(err, "writing EXE header padding"))? as u64;
        }
        w.write_all(&self.body)
            .map_err(|err| annotate_io_error(err, "writing EXE body"))?;
        n += self.body.len() as u64;
        Ok(n)
    }
}

fn write_u16le<W: Write + ?Sized>(w: &mut W, v: u16) -> io::Result<usize> {
    let buf = &u16::to_le_bytes(v);
    w.write_all(&u16::to_le_bytes(v)).and(Ok(buf.len()))
}

fn write_exe_relocations<W: Write + ?Sized>(w: &mut W, relocs: &[Pointer]) -> io::Result<usize> {
    let mut n = 0;
    for pointer in relocs.iter() {
        n += write_u16le(w, pointer.offset)?;
        n += write_u16le(w, pointer.segment)?;
    }
    Ok(n)
}

/// A DOS EXE header. See <http://www.delorie.com/djgpp/doc/exe/>.
/// The field names are taken from `IMAGE_DOS_HEADER` from \<winnt.h\>.
#[derive(Debug)]
pub struct Header {
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

impl Header {
    pub fn exe_len(&self) -> u64 {
        if self.e_cp == 0 && self.e_cblp == 0 {
            return 0;
        }
        if self.e_cp == 0 || self.e_cblp >= 512 {
            panic!("nonsense exe len e_cp={} e_cblp={}", self.e_cp, self.e_cblp);
        }
        (self.e_cp - 1) as u64 * 512
            + if self.e_cblp == 0 { 512 } else { self.e_cblp } as u64
    }

    pub fn header_len(&self) -> u64 {
        self.e_cparhdr as u64 * 16
    }

    /// Reads an EXE header (only the fixed-length fields, not the relocations
    /// or padding) into an `Header` structure.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> io::Result<Self> {
        Ok(Self {
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

    /// Serializes the `Header` structure to `w`. Returns the number of bytes
    /// written.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> io::Result<usize> {
        let mut n = 0;
        n += write_u16le(w, self.e_magic)?;
        n += write_u16le(w, self.e_cblp)?;
        n += write_u16le(w, self.e_cp)?;
        n += write_u16le(w, self.e_crlc)?;
        n += write_u16le(w, self.e_cparhdr)?;
        n += write_u16le(w, self.e_minalloc)?;
        n += write_u16le(w, self.e_maxalloc)?;
        n += write_u16le(w, self.e_ss)?;
        n += write_u16le(w, self.e_sp)?;
        n += write_u16le(w, self.e_csum)?;
        n += write_u16le(w, self.e_ip)?;
        n += write_u16le(w, self.e_cs)?;
        n += write_u16le(w, self.e_lfarlc)?;
        n += write_u16le(w, self.e_ovno)?;
        Ok(n)
    }
}

fn read_exe_relocs<R: Read + ?Sized>(r: &mut R, num_relocs: usize) -> io::Result<Vec<Pointer>> {
    let mut relocs = Vec::with_capacity(num_relocs);
    for _ in 0..num_relocs {
        relocs.push(Pointer {
            offset: read_u16le(r)?,
            segment: read_u16le(r)?,
        });
    }
    Ok(relocs)
}

/// Reads and discards `n` bytes.
fn discard<R: Read + ?Sized>(r: &mut R, n: u64) -> io::Result<()> {
    io::copy(&mut r.take(n), &mut io::sink()).and(Ok(()))
}

/// Read an EXE header (including relocations and padding) and do consistency
/// checks on it. Reads exactly `header.header_len()` bytes from `r`. Doesn't
/// support relocation entries stored outside the header.
pub fn read_and_check_exe_header<R: Read + ?Sized>(r: &mut R) -> Result<(Header, Vec<Pointer>), Error> {
    let header = Header::read(r)
        .map_err(|err| annotate_io_error(err, "reading EXE header"))?;
    debug!("{:?}", header);

    // Begin consistency tests on the fields of the EXE header.
    if header.e_magic != MAGIC {
        return Err(From::from(FormatError::BadMagic(header.e_magic)));
    }

    // Consistency of e_cparhdr. We need the stated header length to be at least
    // as large as the header we just read.
    if header.header_len() < HEADER_LEN {
        return Err(From::from(FormatError::HeaderTooShort(header.e_cparhdr)));
    }

    // Consistency of e_cp and e_cblp.
    if (header.e_cp == 0 && header.e_cblp != 0) || header.e_cblp >= 512 {
        return Err(From::from(FormatError::BadNumPages(header.e_cp, header.e_cblp)));
    }
    if header.exe_len() < header.header_len() {
        return Err(From::from(FormatError::BadNumPages(header.e_cp, header.e_cblp)));
    }

    // Consistency of e_lfarlc and e_crlc.
    let relocations_start = header.e_lfarlc as u64;
    let relocations_end = relocations_start + header.e_crlc as u64 * 4;

    let relocs = if header.e_crlc > 0 {
        // Discard up to the beginning of relocations.
        discard(r, relocations_start.checked_sub(HEADER_LEN)
            .ok_or(FormatError::RelocationsOutsideHeader(header.e_crlc, header.e_lfarlc))?
        ).map_err(|err| annotate_io_error(err, "reading to beginning of relocation table"))?;
        // Read relocations.
        let mut relocs = read_exe_relocs(r, header.e_crlc as usize)
            .map_err(|err| annotate_io_error(err, "reading EXE relocation table"))?;
        // Discard any remaining header padding.
        discard(r, header.header_len().checked_sub(relocations_end)
            .ok_or(FormatError::RelocationsOutsideHeader(header.e_crlc, header.e_lfarlc))?
        ).map_err(|err| annotate_io_error(err, "reading to end of header"))?;
        relocs
    } else {
        discard(r, header.header_len().checked_sub(HEADER_LEN).unwrap())
            .map_err(|err| annotate_io_error(err, "reading to end of header"))?;
        Vec::new()
    };

    Ok((header, relocs))
}

/// The EXE header contains a limit to the overall length of the EXE file in the
/// `e_cblp` and `e_cp` fields. This function trims an `io::Read` to limit it to
/// the length specified in the header, assuming that the header (including
/// relocations and padding) has already been read. `file_len_hint` is an
/// optional externally provided hint of the input file's total length, which we
/// use to emit a warning when it exceeds the length stated in the EXE header.
/// Panics if the EXE length is less than the header length (which cannot happen
/// if the header was returned from `read_and_check_exe_header`).
pub fn trim_input_from_header<R: Read>(input: R, header: &Header, file_len_hint: Option<u64>) -> io::Take<R> {
    if let Some(file_len) = file_len_hint {
        // The EXE file length is allowed to be smaller than the length of the
        // file containing it. Emit a warning that we are ignoring trailing
        // garbage.
        if header.exe_len() < file_len {
            eprintln!("warning: EXE file size is {}; ignoring {} trailing bytes", header.exe_len(), file_len - header.exe_len());
        }
    }
    input.take(header.exe_len().checked_sub(header.header_len()).unwrap())
}

/// Returns a tuple `(e_cblp, e_cp)` that encodes `len` as appropriate for the
/// so-named EXE header fields. Returns `None` if the `len` is too large to be
/// represented (> 0x1fffe00).
pub fn encode_exe_len(len: usize) -> Option<(u16, u16)> {
    // Number of 512-byte blocks needed to store len, rounded up.
    let e_cp: u16 = ((len + 511) / 512).try_into().ok()?;
    // Number of bytes remaining after all the full blocks.
    let e_cblp: u16 = (len % 512).try_into().ok()?;
    Some((e_cblp, e_cp))
}

#[test]
fn test_encode_exe_len() {
    assert_eq!(encode_exe_len(0), Some((0, 0)));
    assert_eq!(encode_exe_len(1), Some((1, 1)));
    assert_eq!(encode_exe_len(511), Some((511, 1)));
    assert_eq!(encode_exe_len(512), Some((0, 1)));
    assert_eq!(encode_exe_len(513), Some((1, 2)));
    assert_eq!(encode_exe_len(512 * 0xffff - 1), Some((511, 0xffff)));
    assert_eq!(encode_exe_len(512 * 0xffff), Some((0, 0xffff)));
    assert_eq!(encode_exe_len(512 * 0xffff + 1), None);
}
