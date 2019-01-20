extern crate exepack;

use std::fs;
use std::io::{self, Seek, Write};
use std::iter;
use std::path;

// If true, save EXE generated during the course of testing to the filesystem,
// so you can examine/test them externally.
const SAVE_EXES: bool = true;

fn round_up(n: usize, m: usize) -> usize {
    n.checked_add((m - n % m) % m).unwrap()
}

// generate a body of the given length, with repeating bytes so it is easily
// compressible.
fn compressible_body(len: usize) -> Vec<u8> {
    // 90 is a 1-byte NOP.
    iter::repeat(0x90).take(len).collect()
}

// generate a body of the given length, with no repeating bytes so its size
// cannot be smaller after compression
fn incompressible_body(len: usize) -> Vec<u8> {
    // 66 90 is a 2-byte NOP.
    [0x66, 0x90].iter().cloned().cycle().take(len).collect()
}

fn make_exe(body: Vec<u8>, relocations: Vec<exepack::Pointer>) -> exepack::EXE {
    let header_len = round_up(exepack::EXE_HEADER_LEN as usize + 4 * relocations.len(), 512);
    let (e_cblp, e_cp) = exepack::encode_exe_len(header_len + body.len()).unwrap();
    exepack::EXE{
        header: exepack::EXEHeader{
            e_magic: exepack::EXE_MAGIC,
            e_cblp: e_cblp,
            e_cp: e_cp,
            e_crlc: relocations.len() as u16,
            e_cparhdr: (header_len / 16) as u16,
            e_minalloc: 0xffff,
            e_maxalloc: 0xffff,
            e_ss: 0x0000,
            e_sp: 0x0080,
            e_csum: 0,
            e_ip: 0x0000,
            e_cs: 0x0000,
            e_lfarlc: exepack::EXE_HEADER_LEN as u16,
            e_ovno: 0,
        },
        data: body,
        relocations: relocations,
    }
}

fn make_relocations(n: usize) -> Vec<exepack::Pointer> {
    (0..n).map(|address| exepack::Pointer {
        segment: (address >> 4) as u16,
        offset: (address & 0xf) as u16,
    }).collect()
}

fn make_compressible_exe(body_len: usize, num_relocations: usize) -> exepack::EXE {
    make_exe(compressible_body(body_len), make_relocations(num_relocations))
}

fn make_incompressible_exe(body_len: usize, num_relocations: usize) -> exepack::EXE {
    make_exe(incompressible_body(body_len), make_relocations(num_relocations))
}

fn save_exe<P: AsRef<path::Path>>(path: P, exe: &exepack::EXE) -> io::Result<()> {
    let f = fs::File::create(path)?;
    let mut w = io::BufWriter::new(f);
    exepack::write_exe(&mut w, exe)?;
    w.flush()
}

// call save_exe if SAVE_EXES is true
fn maybe_save_exe<P: AsRef<path::Path>>(path: P, exe: &exepack::EXE) -> io::Result<()> {
    if SAVE_EXES {
        save_exe(path, exe)?;
    }
    Ok(())
}

// a version of exepack::pack that works from a source EXE rather than an
// io::Read, with no size hint.
fn pack(source: &exepack::EXE) -> Result<exepack::EXE, exepack::Error> {
    let mut f = io::Cursor::new(Vec::new());
    exepack::write_exe(&mut f, source).unwrap();
    f.seek(io::SeekFrom::Start(0)).unwrap();
    exepack::pack(&mut f, None)
}

#[test]
fn test_pack_lengths() {
    // Input files may be too big to compress for various reasons.
    // Compression doesn't always decrease the size: it may stay the
    // same or increase by 16 bytes (00 00 b3 plus padding)--this is not even
    // counting the ≈350 bytes for the EXEPACK block.
    //
    // An EXE file may be up to 512*0xffff bytes long (this constraint
    // is imposed by the e_cblp and e_cp header fields). Compressing
    // such a large EXE would result in a file whose length could not be
    // represented in the header. But the maximum addressable segment is only
    // 0xffff anyway, and other constraints mean that you will run into problems
    // even before that, regardless of whether the code is compressible or not:
    // - the 16-bit EXEPACK dest_len field needs to represent the complete
    //   uncompressed size.
    // - the EXE header cs field needs to be greater than the compressed size.
    // - the EXE header ss field needs to be greater than the compressed size
    //   and the uncompressed size.

    // Check for an EXE or EXEPACK error in a macro, for meaningful line numbers
    // in test output.
    macro_rules! want_error {
        ($r:expr) => {
            match $r {
                Err(exepack::Error::EXE(_)) => (),
                Err(exepack::Error::EXEPACK(_)) => (),
                x => panic!("{:?}", x),
            }
        }
    }

    // Size of an EXEPACK block with no relocations.
    let exepack_size = 18 + exepack::STUB.len() + 32;

    // Maximum size compressible inputs.
    // The main constraint here is the ss field in the EXE header, which must
    // point after the eventual destination of the EXEPACK block. In the case of
    // a compressible input, the EXEPACK block will copy itself from inside to
    // the end of the decompression buffer, and ss can go right after that.
    let len = 16*0xffff - round_up(exepack_size, 16);
    let exe = make_compressible_exe(len, 0);
    maybe_save_exe("tests/maxlen_compressible.exe", &exe).unwrap();
    let out = pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_compressible.packed.exe", &out).unwrap();
    // 1 byte longer is an error.
    let exe = make_compressible_exe(len+1, 0);
    maybe_save_exe("tests/maxlen+1_compressible.exe", &exe).unwrap();
    want_error!(pack(&exe));

    // Relocations take up additional space, 2 bytes per. The packed relocation
    // format allows for up to 16*0xffff relocations, but of course an input EXE
    // can only have up to 0xffff, and furthermore we are limited to the entire
    // EXEPACK block being 0xffff bytes or less.
    let num_relocations = (0xffff - exepack_size) / 2;
    let len = 16*0xffff - round_up(exepack_size + num_relocations*2, 16);
    let exe = make_compressible_exe(len, num_relocations);
    maybe_save_exe("tests/maxlen_maxrelocs_compressible.exe", &exe).unwrap();
    let out = pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_maxrelocs_compressible.packed.exe", &out).unwrap();
    // 1 byte longer is an error.
    let exe = make_compressible_exe(len+1, num_relocations);
    maybe_save_exe("tests/maxlen+1_maxrelocs_compressible.exe", &exe).unwrap();
    want_error!(pack(&exe));
    // 1 more relocation is an error.
    let exe = make_compressible_exe(len, num_relocations+1);
    maybe_save_exe("tests/maxlen_maxrelocs+1_compressible.exe", &exe).unwrap();
    want_error!(pack(&exe));

    // Maximum size incompressible inputs.
    // In the case of an incompressible input, the EXEPACK block will copy
    // itself even further, to the end of itself, so we need at least *two*
    // EXEPACK blocks after the decompression buffer. Then we also need to
    // subtract 4 bytes to prevent the compressed buffer from spilling into the
    // next paragraph (4 bytes of 0x00 padding can be encoded into 4 bytes as
    // 00 04 00 b1).
    let len = 16*0xffff - 2*round_up(exepack_size, 16) - 4;
    let exe = make_incompressible_exe(len, 0);
    maybe_save_exe("tests/maxlen_incompressible.exe", &exe).unwrap();
    let out = pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_incompressible.packed.exe", &out).unwrap();
    // 1 byte longer input is an error.
    let exe = make_incompressible_exe(len+1, 0);
    maybe_save_exe("tests/maxlen+1_incompressible.exe", &exe).unwrap();
    want_error!(pack(&exe));

    // Relocations take up additional space.
    let num_relocations = (0xffff - exepack_size) / 2;
    let len = 16*0xffff - 2*round_up(exepack_size + num_relocations*2, 16)-4;
    let exe = make_incompressible_exe(len, num_relocations);
    maybe_save_exe("tests/maxlen_maxrelocs_incompressible.exe", &exe).unwrap();
    let out = pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_maxrelocs_incompressible.packed.exe", &out).unwrap();
    // 1 byte longer is an error.
    let exe = make_incompressible_exe(len+1, num_relocations);
    maybe_save_exe("tests/maxlen+1_maxrelocs_incompressible.exe", &exe).unwrap();
    want_error!(pack(&exe));
    // 1 more relocation is an error.
    let exe = make_incompressible_exe(len, num_relocations+1);
    maybe_save_exe("tests/maxlen_maxrelocs+1_incompressible.exe", &exe).unwrap();
    want_error!(pack(&exe));
}
