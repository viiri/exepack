//! Reading and writing 16-bit DOS MZ executables.

use std::convert::TryInto;
use std::fmt;
use std::io::{self, prelude::*};

pub use pointer::Pointer;

fn read_u16le<R: Read + ?Sized>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Adds a prefix to the message of an `io::Error`.
fn annotate_io_error(err: io::Error, msg: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {}", msg, err))
}

const MAGIC: u16 = 0x5a4d; // "MZ"

/// The length of an EXE header, excluding relocations and variable-sized
/// padding.
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
    HeaderTooShort(u64),
    RelocationsOverlapHeader(u64),
    TooManyRelocations(usize),
    TooShort(u64, u64),
    TooLong(usize),
    HeaderTooLong(usize),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FormatError::BadMagic(e_magic) => write!(f, "Bad EXE magic 0x{:04x}; expected 0x{:04x}", e_magic, MAGIC),
            FormatError::BadNumPages(e_cp, e_cblp) => write!(f, "Bad EXE size ({}, {})", e_cp, e_cblp),
            FormatError::HeaderTooShort(header_len) => write!(f, "EXE header of {} bytes is too small", header_len),
            FormatError::RelocationsOverlapHeader(relocs_offset) => write!(f, "Relocations starting at 0x{:04x} overlap the EXE header", relocs_offset),
            FormatError::TooManyRelocations(n) => write!(f, "{} relocations are too many to fit in 16 bits", n),
            FormatError::TooShort(exe_len, header_len) => write!(f, "EXE size of {} bytes is too small to contain header of {} bytes", exe_len, header_len),
            FormatError::TooLong(len) => write!(f, "EXE size of {} bytes is too large to represent", len),
            FormatError::HeaderTooLong(len) => write!(f, "EXE header size of {} bytes is too large to represent", len),
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

    // Relocations from the header.
    pub relocs: Vec<Pointer>,

    // The program body following the header.
    pub body: Vec<u8>,
}

impl Exe {
    /// Reads an EXE file into an `Exe` structure.
    ///
    /// `file_len_hint` is an optional externally provided hint of
    /// the input file's total length, which we use to emit a warning when it
    /// exceeds the length stated in the EXE header.
    pub fn read<R: Read + ?Sized>(input: &mut R, file_len_hint: Option<u64>) -> Result<Self, Error> {
        // Read the fixed fields of the header.
        {
            let e_magic = read_u16le(input)?;
            if e_magic != MAGIC {
                return Err(Error::Format(FormatError::BadMagic(e_magic)));
            }
        }
        let exe_len = {
            let e_cblp = read_u16le(input)?;
            let e_cp = read_u16le(input)?;
            decode_exe_len(e_cblp, e_cp)
                .ok_or(Error::Format(FormatError::BadNumPages(e_cp, e_cblp)))?
        };
        let num_relocs = {
            let e_crlc = read_u16le(input)?;
            e_crlc as usize
        };
        let header_len = {
            let e_cparhdr = read_u16le(input)?;
            e_cparhdr as u64 * 16
        };
        let e_minalloc = read_u16le(input)?;
        let e_maxalloc = read_u16le(input)?;
        let e_ss = read_u16le(input)?;
        let e_sp = read_u16le(input)?;
        // Ignore the checksum. I cannot find a clear specification of how it
        // could be computed, and I have found no implementation of DOS that
        // checks it.
        // https://github.com/microsoft/MS-DOS/blob/80ab2fddfdf30f09f0a0a637654cbb3cd5c7baa6/v2.0/source/EXE2BIN.ASM#L79
        // https://sourceforge.net/p/dosbox/code-0/HEAD/tree/dosbox/tags/RELEASE_0_74_3/src/dos/dos_execute.cpp#l46
        // https://sourceforge.net/p/freedos/svn/HEAD/tree/kernel/tags/ke2042/kernel/task.c#l555
        read_u16le(input)?;
        let e_ip = read_u16le(input)?;
        let e_cs = read_u16le(input)?;
        let relocs_offset = {
            let e_lfarlc = read_u16le(input)?;
            e_lfarlc as u64
        };
        let e_ovno = read_u16le(input)?;

        // We have now read HEADER_LEN bytes.
        let mut pos: u64 = HEADER_LEN;

        // Read the relocation table.
        let relocs = if num_relocs > 0 {
            // Discard bytes up to the beginning of the relocation table.
            pos += discard(input, relocs_offset.checked_sub(pos)
                .ok_or(Error::Format(FormatError::RelocationsOverlapHeader(relocs_offset)))?
            ).map_err(|err| annotate_io_error(err, "reading to beginning of relocation table"))?;
            assert_eq!(pos, relocs_offset);
            // Read the relocation table itself.
            read_relocs(input, num_relocs)
                .map_err(|err| annotate_io_error(err, "reading EXE relocation table"))?
        } else {
            Vec::new()
        };
        debug!("{:?}", relocs);
        pos += relocs.len() as u64 * 4;

        // Discard bytes up to the end of the header.
        pos += discard(input, header_len.checked_sub(pos)
            .ok_or(Error::Format(FormatError::HeaderTooShort(header_len)))?
        ).map_err(|err| annotate_io_error(err, "reading to end of header"))?;

        // Read the EXE body.
        let body = {
            let body_len = exe_len.checked_sub(pos)
                .ok_or(Error::Format(FormatError::TooShort(exe_len, header_len)))?;
            let mut body = vec![0; body_len.try_into().unwrap()];
            input.read_exact(&mut body)
                .map_err(|err| annotate_io_error(err, "reading EXE body"))?;
            pos += body_len;
            body
        };

        if let Some(file_len_hint) = file_len_hint {
            // The EXE file length is allowed to be smaller than the length of the
            // file containing it. Emit a warning that we are ignoring trailing
            // garbage.
            if pos < file_len_hint {
                eprintln!("warning: EXE file size is {}; ignoring {} trailing bytes", exe_len, file_len_hint - pos);
            }
        }

        Ok(Self {
            e_minalloc: e_minalloc,
            e_maxalloc: e_maxalloc,
            e_ss: e_ss,
            e_sp: e_sp,
            e_ip: e_ip,
            e_cs: e_cs,
            e_ovno: e_ovno,
            relocs,
            body,
        })
    }

    fn write_header<W: Write + ?Sized>(&self, w: &mut W) -> Result<u64, Error> {
        // http://www.delorie.com/djgpp/doc/exe/: "Note that some OSs and/or
        // programs may fail if the header is not a multiple of 512 bytes."
        let num_header_pages = ((HEADER_LEN as usize + 4 * self.relocs.len()) + 511) / 512;
        let (e_cblp, e_cp) = encode_exe_len(num_header_pages * 512 + self.body.len())
            .ok_or(FormatError::TooLong(num_header_pages * 512 + self.body.len()))?;
        let e_crlc = self.relocs.len().try_into()
            .or(Err(FormatError::TooManyRelocations(self.relocs.len())))?;
        let e_cparhdr: u16 = (num_header_pages * 512 / 16).try_into()
            .or(Err(FormatError::HeaderTooLong(num_header_pages * 512)))?;
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
        n += write_u16le(w, 0)?; // e_csum
        n += write_u16le(w, self.e_ip)?;
        n += write_u16le(w, self.e_cs)?;
        n += write_u16le(w, HEADER_LEN as u16)?;
        n += write_u16le(w, self.e_ovno)?;
        assert_eq!(n as u64, HEADER_LEN);

        n += write_relocs(w, &self.relocs)
            .map_err(|err| annotate_io_error(err, "writing EXE relocations"))? as u64;

        assert!(n <= e_cparhdr as u64 * 16);
        n += io::copy(&mut io::repeat(0).take(e_cparhdr as u64 * 16 - n), w)
            .map_err(|err| annotate_io_error(err, "writing EXE header padding"))? as u64;

        Ok(n as u64)
    }

    /// Serializes the `Exe` structure to `w`. Returns the number of bytes
    /// written.
    pub fn write<W: Write + ?Sized>(&self, w: &mut W) -> Result<u64, Error> {
        let mut n: u64 = 0;
        n += self.write_header(w)? as u64;
        w.write_all(&self.body)
            .map_err(|err| annotate_io_error(err, "writing EXE body"))?;
        n += self.body.len() as u64;
        Ok(n)
    }
}

fn write_u16le<W: Write + ?Sized>(w: &mut W, v: u16) -> io::Result<u64> {
    let buf = &u16::to_le_bytes(v);
    w.write_all(&u16::to_le_bytes(v)).and(Ok(buf.len() as u64))
}

fn write_relocs<W: Write + ?Sized>(w: &mut W, relocs: &[Pointer]) -> io::Result<u64> {
    let mut n = 0;
    for pointer in relocs.iter() {
        n += write_u16le(w, pointer.offset)?;
        n += write_u16le(w, pointer.segment)?;
    }
    Ok(n)
}

/// Reads and discards `n` bytes.
fn discard<R: Read + ?Sized>(r: &mut R, n: u64) -> io::Result<u64> {
    io::copy(&mut r.take(n), &mut io::sink())
}

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

/// Returns a tuple `(e_cblp, e_cp)` that encodes `len` as appropriate for the
/// so-named EXE header fields. Returns `None` if the `len` is too large to be
/// represented (> 0x1fffe00).
fn encode_exe_len(len: usize) -> Option<(u16, u16)> {
    // Number of 512-byte blocks needed to store len, rounded up.
    let e_cp: u16 = ((len + 511) / 512).try_into().ok()?;
    // Number of bytes remaining after all the full blocks.
    let e_cblp: u16 = (len % 512).try_into().ok()?;
    Some((e_cblp, e_cp))
}

/// Converts a `(e_cblp, e_cp)` tuple into a single length value. Returns `None`
/// if the inputs are an invalid encoding (encode a negative length, or have
/// `e_cblp` > 511).
fn decode_exe_len(e_cblp: u16, e_cp: u16) -> Option<u64> {
    match (e_cblp, e_cp) {
        (0, _) => Some(e_cp as u64 * 512),
        (_, 0) => None, // Encodes a negative length.
        (1..=511, _) => Some((e_cp - 1) as u64 * 512 + e_cblp as u64),
        _ => None, // e_cblp > 511.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path;

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

    fn read_exe_with_hint(buf: &[u8], file_len_hint: Option<u64>) -> Result<Exe, Error> {
        Exe::read(&mut io::Cursor::new(buf), file_len_hint)
    }

    // a version of exepack::read_exe that works from a byte buffer rather than an
    // io::Read, with no size hint
    fn read_exe(buf: &[u8]) -> Result<Exe, Error> {
        read_exe_with_hint(buf, None)
    }

    fn store_u16le(buf: &mut [u8], i: usize, v: u16) {
        buf[i] = v as u8;
        buf[i + 1] = (v >> 8) as u8;
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
        assert_eq!(decode_exe_len(511, 0xffff), Some(0xffff*512-1));
        assert_eq!(decode_exe_len(0, 0xffff), Some(0xffff*512));

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
            Err(Error::Format(FormatError::BadMagic(0x5958))) => (),
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
            for &file_len_hint in &[ // file_len_hint shouldn't matter
                Some(sample.len() as u64),
                Some(len as u64),
                None,
            ] {
                read_exe_with_hint(&sample, file_len_hint).unwrap(); // no truncation ⇒ ok

                let sample = &sample[..len];
                maybe_save_exe(format!("tests/truncate_{}.exe", len), sample).unwrap();
                match read_exe_with_hint(sample, file_len_hint) {
                    Err(Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => (),
                    x => panic!("{} {:?}", len, x),
                }
            }
        }
    }

    // test variations of e_cblp and e_cp.
    #[test]
    fn test_read_exe_len() {
        let sample = read_sample();

        // bogus encodings
        for &(e_cblp, e_cp) in &[
            (512, 1),
            (0xffff, 1),
            (sample.len(), 0),
        ] {
            let mut sample = sample.clone();
            store_u16le(&mut sample, 2, e_cblp as u16);
            store_u16le(&mut sample, 4, e_cp as u16);
            maybe_save_exe(format!("tests/e_cblp={}_e_cp={}.exe", e_cblp, e_cp), &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::BadNumPages(_, _))) => (),
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
            store_u16le(&mut sample, 2, e_cblp as u16);
            store_u16le(&mut sample, 4, e_cp as u16);
            maybe_save_exe(format!("tests/exe_len_{}.exe", len), &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::TooShort(_, _))) => (),
                x => panic!("{:?}", x),
            }
        }

        // short EXE file size is okay as long as it's after the header, but it
        // shortens the EXE body
        {
            let mut sample = sample.clone();
            let len = 96;
            let (e_cblp, e_cp) = encode_exe_len(len).unwrap();
            store_u16le(&mut sample, 2, e_cblp as u16);
            store_u16le(&mut sample, 4, e_cp as u16);
            maybe_save_exe(format!("tests/exe_len_{}.exe", len), &sample).unwrap();
            let exe = read_exe(&sample).unwrap();
            assert_eq!(exe.body.len(), len - 64);
        }
    }

    #[test]
    fn test_read_exe_overlaps() {
        let sample = read_sample();

        {
            let mut sample = sample.clone();
            // e_cparhdr = 1, in the middle of the header
            store_u16le(&mut sample, 8, 1);
            maybe_save_exe("tests/cparhdr_short_header.exe", &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::HeaderTooShort(16))) => (),
                x => panic!("{:?}", x),
            }
        }
        {
            let mut sample = sample.clone();
            // e_cparhdr = 2, in the middle of the relocations
            store_u16le(&mut sample, 8, 2);
            maybe_save_exe("tests/cparhdr_short_relocs.exe", &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::HeaderTooShort(32))) => (),
                x => panic!("{:?}", x),
            }
        }
        {
            let mut sample = sample.clone();
            // e_lfarlc = 128, after the header end
            store_u16le(&mut sample, 24, 128);
            maybe_save_exe("tests/cparhdr_relocs_outside_header.exe", &sample).unwrap();
            match read_exe(&sample) {
                Err(Error::Format(FormatError::HeaderTooShort(64))) => (),
                x => panic!("{:?}", x),
            }
        }
    }
}
