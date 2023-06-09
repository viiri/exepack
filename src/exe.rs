//! Reading and writing 16-bit DOS MZ executables.
//!
//! # References
//!
//! * [EXE Format](http://www.delorie.com/djgpp/doc/exe/)
//! * [Notes on the format of DOS .EXE files](http://www.tavi.co.uk/phobos/exeformat.html)

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::io::{self, Read, Write};

use pointer::Pointer;

/// The magic number of an EXE file, interpreted as a little-endian integer.
const MAGIC: u16 = 0x5a4d; // "MZ"

/// The length of an EXE header, excluding relocations and variable-sized
/// padding.
const HEADER_LEN: u16 = 28;

/// The error type for `Exe::read` and `Exe::write` operations.
#[derive(Debug)]
pub enum Error {
    /// An `io::Error` that occurred while reading or writing an `Exe`.
    Io(io::Error),
    /// An EXE file format error.
    Format(FormatError),
}

impl std::error::Error for Error {}

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

/// An EXE file format error.
#[derive(Debug)]
pub enum FormatError {
    /// While reading, the file's magic number is not `b"MZ"`.
    Magic { e_magic: u16 },
    /// While reading, the header fields `e_cp` and `e_cblp` are an invalid
    /// length encoding. They encode a negative length, or have `e_cblp` > 511.
    InvalidSize { e_cp: u16, e_cblp: u16 },
    /// While reading, the relocation table starts before the end of the fixed
    /// part of the EXE header.
    RelocationsOverlapHeader { e_lfarlc: u16 },
    /// While reading, the header length declared by `e_cparhdr` is too short to
    /// contain the EXE header and relocation table.
    HeaderTooShort { e_cparhdr: u16 },
    /// While reading, the EXE size is too short to contain the EXE header.
    TooShort { e_cp: u16, e_cblp: u16, e_cparhdr: u16 },
    /// While writing, the EXE size is too large to represent.
    TooLong { len: usize },
    /// While writing, the number of relocations exceeds 0xffff.
    TooManyRelocations { num: usize },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FormatError::Magic { e_magic } =>
                write!(f, "Bad EXE magic (e_magic={:#04x})", e_magic),
            FormatError::InvalidSize { e_cp, e_cblp } =>
                write!(f, "Invalid EXE size encoding (e_cp={}, e_cblp={})", e_cp, e_cblp),
            FormatError::RelocationsOverlapHeader { e_lfarlc } =>
                write!(f, "Relocation table overlaps the EXE header (e_lfarlc={})", e_lfarlc),
            FormatError::HeaderTooShort { e_cparhdr } =>
                write!(f, "EXE header is too short (e_cparhdr={})", e_cparhdr),
            FormatError::TooShort { e_cp, e_cblp, e_cparhdr } =>
                write!(f, "EXE is too short to contain header (e_cp={}, e_cblp={}, e_cparhdr={})", e_cp, e_cblp, e_cparhdr),
            FormatError::TooLong { len } =>
                write!(f, "EXE size is too large to represent ({})", len),
            FormatError::TooManyRelocations { num } =>
                write!(f, "Too many relocations to represent in 16 bits ({})", num),
        }
    }
}

/// Adds a prefix to the message of an `io::Error`.
fn annotate_io_error(err: io::Error, msg: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", msg, err))
}

/// Reads a little-endian `u16` from `r`.
fn read_u16le<R: Read + ?Sized>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Writes a little-endian `u16` to `w`. Returns the number of bytes written,
/// always 2.
fn write_u16le<W: Write + ?Sized>(w: &mut W, v: u16) -> io::Result<u64> {
    let buf = &u16::to_le_bytes(v);
    w.write_all(&u16::to_le_bytes(v)).and(Ok(buf.len().try_into().unwrap()))
}

/// Reads and discards `n` bytes from `r`. Returns an error of the kind
/// `io::ErrorKind::UnexpectedEof` if EOF occurs before `n` bytes can be read.
fn discard<R: Read + ?Sized>(r: &mut R, n: u64) -> io::Result<u64> {
    io::copy(&mut r.take(n), &mut io::sink()).and_then(|count| {
        if count == n {
            Ok(count)
        } else {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("{}", count)))
        }
    })
}

/// Returns the number of 512-byte pages needed to represent `n`, rounded up.
fn pages(n: usize) -> usize {
    if n % 512 == 0 {
        n / 512
    } else {
        n / 512 + 1
    }
}

/// Converts a `(e_cblp, e_cp)` tuple into a single length value. Returns `None`
/// if the inputs are an invalid encoding (encode a negative length, or have
/// `e_cblp` > 511).
fn decode_exe_len(e_cblp: u16, e_cp: u16) -> Option<u64> {
    let e_cblp = u64::from(e_cblp);
    let e_cp = u64::from(e_cp);
    match (e_cblp, e_cp) {
        (0, _) => Some(e_cp * 512),
        (_, 0) => None, // Encodes a negative length.
        (1..=511, _) => Some((e_cp - 1) * 512 + e_cblp),
        _ => None, // e_cblp > 511.
    }
}

/// Returns a tuple `(e_cblp, e_cp)` that encodes `len` for the so-named EXE
/// header fields. Returns `None` if the `len` is too large to be represented
/// (> 0x1fffe00).
fn encode_exe_len(len: usize) -> Option<(u16, u16)> {
    // Number of 512-byte pages needed to store len, rounded up.
    let e_cp = u16::try_from(pages(len)).ok()?;
    // Number of bytes remaining after all the full blocks.
    let e_cblp = u16::try_from(len % 512).unwrap();
    Some((e_cblp, e_cp))
}

/// Reads a relocation table from `r`.
fn read_relocs<R: Read + ?Sized>(r: &mut R, num_relocs: usize) -> io::Result<Vec<Pointer>> {
    let mut relocs = Vec::with_capacity(num_relocs);
    for _ in 0..num_relocs {
        relocs.push(Pointer {
            offset: read_u16le(r)?,
            segment: read_u16le(r)?,
        });
    }
    Ok(relocs)
}

/// Writes a relocation table to `w`. Returns the number of bytes written.
fn write_relocs<W: Write + ?Sized>(w: &mut W, relocs: &[Pointer]) -> io::Result<u64> {
    let mut n = 0;
    for pointer in relocs {
        n += write_u16le(w, pointer.offset)?;
        n += write_u16le(w, pointer.segment)?;
    }
    Ok(n)
}

/// Incremental calculator of the MZ executable checksum algorithm.
///
/// # References
///
/// * [Q71971: Calculating the Checksum for a Segmented-Executable File](https://jeffpar.github.io/kbarchive/kb/071/Q71971/)
#[derive(Debug)]
struct Checksum {
    sum: u16,  // Accumulated checksum so far.
    odd: bool, // Whether we have seen only the low-order byte of the latest word.
}

impl Checksum {
    /// Creates a new `Checksum`.
    pub fn new() -> Self {
        Self { sum: 0u16, odd: false }
    }

    /// Accumulates the contents of `input` into the running checksum state.
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        let mut input = input.as_ref();
        if input.len() == 0 {
            return;
        }

        // If we have only processed the low-order byte of the latest word,
        // treat the first byte of the input as its high-order byte.
        if self.odd {
            self.sum = self.sum.wrapping_add(u16::from(input[0])<<8);
            input = &input[1..];
        }
        self.odd = false;

        // Process the rest of the input, except for perhaps a final odd byte.
        let iter = input.chunks_exact(2);
        let remainder = iter.remainder();
        self.sum = iter.fold(self.sum, |sum, s| sum.wrapping_add(u16::from_le_bytes(s.try_into().unwrap())));

        // If there's a final odd byte, add it as the low-order byte of a word
        // to the sum, and set the odd flag.
        if remainder.len() == 1 {
            self.sum = self.sum.wrapping_add(u16::from(remainder[0]));
            self.odd = true;
        };
    }

    /// Returns the checksum of the input processed so far.
    pub fn finalize(&self) -> u16 {
        !self.sum
    }
}

/// A 16-bit MZ format DOS executable. It omits any data that may have appeared
/// after the end of the size stated in the EXE header.
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

    /// Relocation addresses.
    pub relocs: Vec<Pointer>,

    /// The program body that follows the header.
    pub body: Vec<u8>,
}

impl Exe {
    /// Reads an EXE file into an `Exe` structure. Leaves the input positioned
    /// immediately after the end of the EXE file.
    pub fn read<R: Read + ?Sized>(input: &mut R) -> Result<Self, Error> {
        // Read the fixed fields of the header.
        {
            let e_magic = read_u16le(input)?;
            if e_magic != MAGIC {
                return Err(From::from(FormatError::Magic { e_magic }));
            }
        }
        let e_cblp = read_u16le(input)?;
        let e_cp = read_u16le(input)?;
        let exe_len = decode_exe_len(e_cblp, e_cp)
                .ok_or(FormatError::InvalidSize { e_cp, e_cblp })?;
        let num_relocs = {
            let e_crlc = read_u16le(input)?;
            usize::from(e_crlc)
        };
        let e_cparhdr = read_u16le(input)?;
        let header_len = u64::from(e_cparhdr) * 16;
        let e_minalloc = read_u16le(input)?;
        let e_maxalloc = read_u16le(input)?;
        let e_ss = read_u16le(input)?;
        let e_sp = read_u16le(input)?;
        // Ignore the checksum on input. In practice, nothing verifies EXE
        // checksums (not even MS-DOS), hence many checksums are incorrect.
        //
        // https://jeffpar.github.io/kbarchive/kb/071/Q71971/
        // "Note that Microsoft LINK does not correctly calculate the checksum
        // if the linker command line includes the /CODEVIEW or /EXEPACK option
        // switches. However, because the MS-DOS, Microsoft Windows, and OS/2
        // versions 1.x do not verify the checksum, this behavior does not
        // present a problem under normal circumstances. Microsoft LINK version
        // 5.3 and later do not compute a 16-bit or 32-bit checksum. The
        // reserved bytes in the .EXE header are set to zero."
        //
        // Here are examples of DOS implementations ignoring the checksum:
        // https://github.com/microsoft/MS-DOS/blob/80ab2fddfdf30f09f0a0a637654cbb3cd5c7baa6/v2.0/source/EXE2BIN.ASM#L79
        // https://sourceforge.net/p/dosbox/code-0/HEAD/tree/dosbox/tags/RELEASE_0_74_3/src/dos/dos_execute.cpp#l46
        // https://github.com/FDOS/kernel/blob/ke2043/kernel/task.c#L601
        read_u16le(input)?; // e_csum
        let e_ip = read_u16le(input)?;
        let e_cs = read_u16le(input)?;
        let e_lfarlc = read_u16le(input)?;
        let relocs_offset = u64::from(e_lfarlc);
        let e_ovno = read_u16le(input)?;

        // We have now read HEADER_LEN bytes.
        let mut pos = u64::from(HEADER_LEN);

        // Read the relocation table.
        let relocs = if num_relocs == 0 {
            Vec::new()
        } else {
            // Discard bytes up to the beginning of the relocation table.
            pos += discard(input, relocs_offset.checked_sub(pos)
                .ok_or(FormatError::RelocationsOverlapHeader { e_lfarlc })?
            ).map_err(|err| annotate_io_error(err, "reading to beginning of relocation table"))?;
            assert_eq!(pos, relocs_offset);
            // Read the relocation table itself.
            read_relocs(input, num_relocs)
                .map_err(|err| annotate_io_error(err, "reading EXE relocation table"))?
        };
        pos += u64::try_from(relocs.len()).unwrap() * 4;

        // Discard bytes up to the end of the header.
        pos += discard(input, header_len.checked_sub(pos)
            .ok_or(FormatError::HeaderTooShort { e_cparhdr })?
        ).map_err(|err| annotate_io_error(err, "reading to end of header"))?;

        // Read the EXE body.
        let body = {
            let body_len = exe_len.checked_sub(pos)
                .ok_or(FormatError::TooShort { e_cp, e_cblp, e_cparhdr })?;
            let mut body = vec![0; body_len.try_into().unwrap()];
            input.read_exact(&mut body)
                .map_err(|err| annotate_io_error(err, "reading EXE body"))?;
            body
        };

        Ok(Self {
            e_minalloc,
            e_maxalloc,
            e_ss, e_sp,
            e_ip, e_cs,
            e_ovno,
            relocs,
            body,
        })
    }

    /// Serializes the `Exe` header to `w`, including padding to a multiple of
    /// 512 bytes. `e_csum` is the value to write for the `e_csum` field.
    fn write_header<W: Write + ?Sized>(&self, w: &mut W, e_csum: u16) -> Result<u64, Error> {
        // http://www.delorie.com/djgpp/doc/exe/: "Note that some OSs and/or
        // programs may fail if the header is not a multiple of 512 bytes."
        let num_header_pages = pages(usize::from(HEADER_LEN) + 4 * self.relocs.len());
        let exe_len = num_header_pages * 512 + self.body.len();
        let (e_cblp, e_cp) = encode_exe_len(exe_len)
            .ok_or(FormatError::TooLong { len: exe_len })?;
        let e_crlc = self.relocs.len().try_into()
            .or(Err(FormatError::TooManyRelocations { num: self.relocs.len() }))?;
        // This next calculation always fits into a u16, so panic rather than
        // return an error.
        let e_cparhdr = u16::try_from(num_header_pages * 512 / 16).unwrap();
        let mut n = 0;
        n += write_u16le(w, MAGIC)?;
        n += write_u16le(w, e_cblp)?;
        n += write_u16le(w, e_cp)?;
        n += write_u16le(w, e_crlc)?;
        n += write_u16le(w, e_cparhdr)?;
        n += write_u16le(w, self.e_minalloc)?;
        n += write_u16le(w, self.e_maxalloc)?;
        n += write_u16le(w, self.e_ss)?;
        n += write_u16le(w, self.e_sp)?;
        n += write_u16le(w, e_csum)?;
        n += write_u16le(w, self.e_ip)?;
        n += write_u16le(w, self.e_cs)?;
        n += write_u16le(w, HEADER_LEN)?;
        n += write_u16le(w, self.e_ovno)?;
        assert_eq!(n, u64::from(HEADER_LEN));

        n += write_relocs(w, &self.relocs)
            .map_err(|err| annotate_io_error(err, "writing EXE relocations"))?;

        assert!(n <= u64::from(e_cparhdr) * 16);
        n += io::copy(&mut io::repeat(0).take(u64::from(e_cparhdr) * 16 - n), w)
            .map_err(|err| annotate_io_error(err, "writing EXE header padding"))?;

        Ok(n)
    }

    /// Serializes the `Exe` structure to `w`. Returns the number of bytes
    /// written.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<u64, Error> {
        // First, find what the checksum of the file would be if we were to
        // write it with a zero e_csum.
        let e_csum = {
            let mut v = Vec::new();
            self.write_header(&mut v, 0)?;
            let mut c = Checksum::new();
            c.update(&v);
            c.update(&self.body);
            c.finalize()
        };
        let mut n: u64 = 0;
        // Now, write the header with the checksum computed earlier.
        n += self.write_header(w, e_csum)?;
        w.write_all(&self.body)
            .map_err(|err| annotate_io_error(err, "writing EXE body"))?;
        n += u64::try_from(self.body.len()).unwrap();
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::io;
    use std::path;

    fn store_u16le(buf: &mut [u8], i: usize, v: u16) {
        buf[i..i + 2].clone_from_slice(&u16::to_le_bytes(v));
    }

    #[test]
    fn test_discard() {
        let mut r = &b"aaaabcde"[..];
        assert_eq!(discard(&mut r, 0).unwrap(), 0);
        assert_eq!(r, b"aaaabcde");
        assert_eq!(discard(&mut r, 4).unwrap(), 4);
        assert_eq!(r, b"bcde");
        assert_eq!(discard(&mut r, 5).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_pages() {
        assert_eq!(pages(0), 0);
        assert_eq!(pages(1), 1);
        assert_eq!(pages(511), 1);
        assert_eq!(pages(512), 1);
        assert_eq!(pages(513), 2);
        assert_eq!(pages(std::usize::MAX), std::usize::MAX / 512 + 1);
    }

    // checksum of a single flat byte slice
    fn checksum(p: &[u8]) -> u16 {
        let mut c = Checksum::new();
        c.update(p);
        c.finalize()
    }

    #[test]
    fn test_checksum() {
        {
            let c = Checksum::new();
            assert_eq!(c.finalize(), !0u16);
        }

        for (data, expected) in &[
            (vec![], !0u16),
            (vec![vec![1]], !1u16),
            (vec![vec![], vec![1]], !1u16),
            (vec![vec![1], vec![]], !1u16),
            (vec![vec![1, 1]], !0x0101u16),
            (vec![vec![], vec![1, 1]], !0x0101u16),
            (vec![vec![1], vec![1]], !0x0101u16),
            (vec![vec![1, 1], vec![]], !0x0101u16),
            (vec![vec![1, 0], vec![1]], !2u16),
            (vec![vec![1], vec![0, 1]], !2u16),
            (vec![vec![1, 1], vec![1, 1]], !0x0202u16),
            (vec![vec![255]], !255u16),
            (vec![vec![255], vec![0]], !255u16),
            (vec![vec![0x42, 0xff]], !0xff42u16),
            (vec![(0..=255).collect()], 49279),
        ] {
            let mut c = Checksum::new();
            for p in data.iter() {
                c.update(&p);
            }
            assert_eq!(c.finalize(), *expected, "{:?}", data);
            // Incremental checksum of chunks should match the one-shot checksum
            // of the entire flat array.
            assert_eq!(c.finalize(), checksum(&data.into_iter().cloned().flatten().collect::<Vec<u8>>()), "{:?}", data);
        }
    }

    fn save_exe<P: AsRef<path::Path>>(path: P, contents: &[u8]) -> io::Result<()> {
        let f = fs::File::create(path)?;
        let mut w = io::BufWriter::new(f);
        w.write(contents)?;
        w.flush()?;
        Ok(())
    }

    // call save_exe if the environment variable EXEPACK_TEST_SAVE_EXE is set.
    fn maybe_save_exe<P: AsRef<path::Path>>(path: P, contents: &[u8]) -> io::Result<()> {
        if let Some(_) = env::var_os("EXEPACK_TEST_SAVE_EXE") {
            save_exe(path, contents)?;
        }
        Ok(())
    }

    // load a sample EXE's contents
    fn read_sample() -> Vec<u8> {
        let mut contents = Vec::new();
        let mut f = fs::File::open("tests/hello.exe").unwrap();
        f.read_to_end(&mut contents).unwrap();
        contents
    }

    // a version of Exe::read that works from a byte buffer rather than an
    // io::Read
    fn read_exe(buf: &[u8]) -> Result<Exe, Error> {
        Exe::read(&mut buf.clone())
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

    #[test]
    fn test_decode_exe_len() {
        assert_eq!(decode_exe_len(0, 0), Some(0));
        assert_eq!(decode_exe_len(1, 1), Some(1));
        assert_eq!(decode_exe_len(511, 1), Some(511));
        assert_eq!(decode_exe_len(0, 1), Some(512));
        assert_eq!(decode_exe_len(1, 2), Some(513));
        assert_eq!(decode_exe_len(511, 0xffff), Some(0xffff * 512 - 1));
        assert_eq!(decode_exe_len(0, 0xffff), Some(0xffff * 512));

        // When e_cp == 0, e_cblp must be 0, otherwise it would encode a negative
        // length.
        assert_eq!(decode_exe_len(1, 0), None);
        assert_eq!(decode_exe_len(511, 0), None);
        // e_cblp must be <= 511.
        assert_eq!(decode_exe_len(512, 1), None);
    }

    #[test]
    fn test_read_exe_bad_magic() {
        let mut sample = read_sample();
        sample[0] = b'X';
        sample[1] = b'Y';
        maybe_save_exe("tests/bad_exe_magic.exe", &sample).unwrap();
        match read_exe(&sample) {
            Err(Error::Format(FormatError::Magic { e_magic: 0x5958 })) => (),
            x => panic!("{:?}", x),
        }
    }

    #[test]
    fn test_read_exe_eof() {
        let sample = read_sample();
        for &len in &[
            0,  // empty file
            27, // EOF during header
            30, // EOF during relocations
            48, // EOF during header padding
            96, // EOF during body
        ] {
            read_exe(&sample).unwrap(); // make sure it actually loads when there's no truncation

            let sample = &sample[..len];
            maybe_save_exe(format!("tests/truncate_{}.exe", len), sample).unwrap();
            match read_exe(sample) {
                Err(Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => (),
                x => panic!("{} {:?}", len, x),
            }
        }
    }

    // test variations of e_cblp and e_cp.
    #[test]
    fn test_read_exe_len() {
        let sample = read_sample();
        let sample_exe = read_exe(&sample).unwrap();

        // bogus encodings
        for &(e_cblp, e_cp) in &[
            (512u16, 1u16),
            (0xffffu16, 1u16),
            (100u16, 0u16),
        ] {
            let mut sample = sample.clone();
            tests::store_u16le(&mut sample, 2, e_cblp);
            tests::store_u16le(&mut sample, 4, e_cp);
            maybe_save_exe(format!("tests/e_cblp={}_e_cp={}.exe", e_cblp, e_cp), &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::InvalidSize { .. })) => (),
                x => panic!("{:?}", x),
            }
        }

        // not long enough to contain the header
        for &len in &[
            0,  // empty file
            27, // EOF during header
            30, // EOF during relocations
            48, // EOF during header padding
        ] {
            let mut sample = sample.clone();
            let (e_cblp, e_cp) = encode_exe_len(len).unwrap();
            tests::store_u16le(&mut sample, 2, e_cblp);
            tests::store_u16le(&mut sample, 4, e_cp);
            maybe_save_exe(format!("tests/exe_len_{}.exe", len), &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::TooShort { .. })) => (),
                x => panic!("{:?}", x),
            }
        }

        // short EXE file size is okay as long as it's after the header, but it
        // shortens the EXE body
        {
            let mut sample = sample.clone();
            let hdr_size = sample.len().checked_sub(sample_exe.body.len()).unwrap();
            let len = hdr_size + 32;
            let (e_cblp, e_cp) = encode_exe_len(len).unwrap();
            tests::store_u16le(&mut sample, 2, e_cblp);
            tests::store_u16le(&mut sample, 4, e_cp);
            maybe_save_exe(format!("tests/exe_len_{}.exe", len), &sample).unwrap();
            let exe = read_exe(&sample).unwrap();
            assert_eq!(exe.body.len(), 32);
        }
    }

    // read should permit a bad checksum
    #[test]
    fn test_read_exe_checksum() {
        let mut sample = read_sample();

        // Try reading the sample as is.
        read_exe(&sample).unwrap();

        // Invert e_csum and try reading again.
        let e_csum = u16::from_le_bytes(sample[0x12..0x12+2].try_into().unwrap());
        tests::store_u16le(&mut sample, 0x12, !e_csum);
        read_exe(&sample).unwrap();
    }

    #[test]
    fn test_read_exe_overlaps() {
        let sample = read_sample();
        let sample_exe = read_exe(&sample).unwrap();

        {
            let mut sample = sample.clone();
            // e_cparhdr = 1, in the middle of the header
            tests::store_u16le(&mut sample, 8, 1);
            maybe_save_exe("tests/cparhdr_short_header.exe", &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::HeaderTooShort { e_cparhdr: 1 })) => (),
                x => panic!("{:?}", x),
            }
        }
        {
            let mut sample = sample.clone();
            // e_cparhdr = 2, in the middle of the relocations
            tests::store_u16le(&mut sample, 8, 2);
            maybe_save_exe("tests/cparhdr_short_relocs.exe", &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::HeaderTooShort { e_cparhdr: 2 })) => (),
                x => panic!("{:?}", x),
            }
        }
        {
            let mut sample = sample.clone();
            let hdr_size = sample.len().checked_sub(sample_exe.body.len()).unwrap();
            // e_lfarlc points to after the header end
            tests::store_u16le(&mut sample, 24, (hdr_size + 32).try_into().unwrap());
            maybe_save_exe("tests/cparhdr_relocs_outside_header.exe", &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::HeaderTooShort { .. })) => (),
                x => panic!("{:?}", x),
            }
        }
    }

    // write should write a correct checksum
    #[test]
    fn test_write_exe_checksum() {
        let exe = Exe {
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_ip: 0,
            e_cs: 0,
            e_ovno: 0,
            relocs: vec![Pointer { segment: 12, offset: 34 }],
            body: b"Hello world".to_vec(),
        };
        let mut buf = Vec::new();
        exe.write(&mut buf).unwrap();
        assert_eq!(checksum(&buf), 0u16);
        tests::store_u16le(&mut buf, 0x12, 0u16);
        assert_eq!(!u16::from_le_bytes(buf[0x12..0x12+2].try_into().unwrap()), !0u16);
    }

    #[test]
    fn test_write_exe_too_long() {
        let exe = Exe {
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_ip: 0,
            e_cs: 0,
            e_ovno: 0,
            relocs: Vec::new(),
            body: std::iter::repeat(0).take(0xffff * 512 + 1).collect(),
        };
        match exe.write(&mut io::sink()) {
            Err(Error::Format(FormatError::TooLong { len: 0x2000001 })) => (),
            x => panic!("{:?}", x),
        }
    }

    #[test]
    fn test_write_exe_too_many_relocations() {
        let exe = Exe {
            e_minalloc: 0,
            e_maxalloc: 0,
            e_ss: 0,
            e_sp: 0,
            e_ip: 0,
            e_cs: 0,
            e_ovno: 0,
            relocs: (0..0x10000).map(|i| Pointer { segment: (i >> 16) as u16, offset: i as u16 }).collect(),
            body: Vec::new(),
        };
        match exe.write(&mut io::sink()) {
            Err(Error::Format(FormatError::TooManyRelocations { num: 0x10000 })) => (),
            x => panic!("{:?}", x),
        }
    }
}
