// One thing we don't test: whether the self-extracting EXE actually works as an
// executable. For that, you have to load it up in DOSBox or something.

extern crate exepack;

use std::env;
use std::fs;
use std::io::{self, Write};
use std::iter;
use std::path;

use exepack::exe;

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

fn make_exe(body: Vec<u8>, relocs: Vec<exepack::Pointer>) -> exe::Exe {
    exe::Exe {
        e_minalloc: 0xffff,
        e_maxalloc: 0xffff,
        e_ss: 0x0000,
        e_sp: 0x0080,
        e_ip: 0x0000,
        e_cs: 0x0000,
        e_ovno: 0,
        body: body,
        relocs: relocs,
    }
}

fn make_relocs(n: usize) -> Vec<exepack::Pointer> {
    (0..n).map(|address| exepack::Pointer {
        segment: (address >> 4) as u16,
        offset: (address & 0xf) as u16,
    }).collect()
}

fn make_compressible_exe(body_len: usize, num_relocs: usize) -> exe::Exe {
    make_exe(compressible_body(body_len), make_relocs(num_relocs))
}

fn make_incompressible_exe(body_len: usize, num_relocs: usize) -> exe::Exe {
    make_exe(incompressible_body(body_len), make_relocs(num_relocs))
}

fn save_exe<P: AsRef<path::Path>>(path: P, exe: &exe::Exe) -> Result<(), exepack::Error> {
    let f = fs::File::create(path)?;
    let mut w = io::BufWriter::new(f);
    exe.write(&mut w)?;
    w.flush()?;
    Ok(())
}

// call save_exe if the environment variable EXEPACK_TEST_SAVE_EXE is set.
fn maybe_save_exe<P: AsRef<path::Path>>(path: P, exe: &exe::Exe) -> Result<(), exepack::Error> {
    if let Some(_) = env::var_os("EXEPACK_TEST_SAVE_EXE") {
        save_exe(path, exe)?;
    }
    Ok(())
}

#[test]
fn test_pack_relocs() {
    // two encodings of the largest relocation address EXEPACK can represent.
    // f000:ffff
    // ffff:000f
    for &pointer in [
        exepack::Pointer{ segment: 0xf000, offset: 0xffff },
        exepack::Pointer{ segment: 0xffff, offset: 0x000f },
    ].iter() {
        let mut exe = make_compressible_exe(128, 0);
        exe.relocs.push(pointer);
        maybe_save_exe(format!("tests/reloc_{:04x}:{:04x}.exe", pointer.segment, pointer.offset), &exe).unwrap();
        let out = exepack::pack(&exe).unwrap();
        maybe_save_exe(format!("tests/reloc_{:04x}:{:04x}.packed.exe", pointer.segment, pointer.offset), &out).unwrap();
    }

    // two encodings of a relocation address too large to represent
    // f001:fff0
    // ffff:0010
    for &pointer in [
        exepack::Pointer{ segment: 0xf001, offset: 0xfff0 },
        exepack::Pointer{ segment: 0xffff, offset: 0x0010 },
    ].iter() {
        let mut exe = make_compressible_exe(128, 0);
        exe.relocs.push(pointer);
        maybe_save_exe(format!("tests/reloc_{:04x}:{:04x}.exe", pointer.segment, pointer.offset), &exe).unwrap();
        match exepack::pack(&exe) {
            Err(exepack::Error::Exepack(exepack::ExepackFormatError::RelocationAddrTooLarge(_))) => (),
            x => panic!("{:?} {}", x, pointer),
        }
    }
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

    // Check for an EXE or EXEPACK error in a macro, for meaningful line numbers
    // in test output.
    macro_rules! want_error {
        ($r:expr) => {
            match $r {
                Err(exepack::Error::Exe(_)) => (),
                Err(exepack::Error::Exepack(_)) => (),
                x => panic!("{:?}", x),
            }
        }
    }

    // Size of an EXEPACK block with no relocations.
    let exepack_size = 18 + exepack::STUB.len() + 32;

    // Maximum size compressible inputs.
    // The main constraint here is the dest_len field, representing the size of
    // the uncompressed output.
    let len = 16 * 0xffff;
    let exe = make_compressible_exe(len, 0);
    maybe_save_exe("tests/maxlen_compressible.exe", &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_compressible.packed.exe", &out).unwrap();
    // 1 byte longer is an error.
    let exe = make_compressible_exe(len + 1, 0);
    maybe_save_exe("tests/maxlen+1_compressible.exe", &exe).unwrap();
    want_error!(exepack::pack(&exe));

    // Relocations take up space, 2 bytes per; however part of the additional
    // space can be shared within the decompression buffer (below dest_len).
    // executable we can compress because the extra space still lies beneath
    // dest_len. The packed relocation format allows for up to 16*0xffff
    // relocations, but of course an input EXE can only have up to 0xffff, and
    // furthermore we are limited to the entire EXEPACK block being 0xffff bytes
    // or less.
    let num_relocs = (0xffff - exepack_size) / 2;
    // (exepack_size + 2*num_relocs) is now either 0xfffe or 0xffff, which
    // puts the stack pointer at dest_len + 0x10000 + 16. (The stub uses a
    // 16-byte stack.) The maximum representable stack pointer is ffff:fff0, so
    // the maximum dest_len = 16*0xffff+0xfff0 - (0x10000+16) = 16*0xffff - 32.
    let len = 16 * 0xfffd;
    let exe = make_compressible_exe(len, num_relocs);
    maybe_save_exe("tests/maxlen_maxrelocs_compressible.exe", &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_maxrelocs_compressible.packed.exe", &out).unwrap();
    // 1 byte longer is an error.
    let exe = make_compressible_exe(len + 1, num_relocs);
    maybe_save_exe("tests/maxlen+1_maxrelocs_compressible.exe", &exe).unwrap();
    want_error!(exepack::pack(&exe));
    // 1 more relocation is an error.
    let exe = make_compressible_exe(len, num_relocs + 1);
    maybe_save_exe("tests/maxlen_maxrelocs+1_compressible.exe", &exe).unwrap();
    want_error!(exepack::pack(&exe));

    // Maximum size incompressible inputs.
    // The main constraint here is no longer dest_len, but e_cs in the EXE
    // header, which points to the start of the EXEPACK block, which comes right
    // after the end of compressed data. So the compressed data (including the
    // padding to 16 bits) cannot be larger than 16*0xffff. It turns out that
    // the largest incompressible stream we can represent in that space has
    // length 16*0xffff-4, with the 4 trailing bytes 00 04 00 b1 encoding the
    // trailing 4 bytes of 0x00 padding.
    let len = 16 * 0xffff - 4;
    let exe = make_incompressible_exe(len, 0);
    maybe_save_exe("tests/maxlen_incompressible.exe", &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_incompressible.packed.exe", &out).unwrap();
    // 1 byte longer input is an error.
    let exe = make_incompressible_exe(len + 1, 0);
    maybe_save_exe("tests/maxlen+1_incompressible.exe", &exe).unwrap();
    want_error!(exepack::pack(&exe));

    // Relocations take up additional space. The size of the EXEPACK block
    // rounds up to 0x10000, so our ceiling is now 16*0xeffd, and the same logic
    // applies as earlier with respect to subtracting 32 for the stack pointer
    // and subtracting 4 for compression overhead.
    let num_relocs = (0xffff - exepack_size) / 2;
    let len = 16 * 0xeffd - 4;
    let exe = make_incompressible_exe(len, num_relocs);
    maybe_save_exe("tests/maxlen_maxrelocs_incompressible.exe", &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    maybe_save_exe("tests/maxlen_maxrelocs_incompressible.packed.exe", &out).unwrap();
    // 1 byte longer is an error.
    let exe = make_incompressible_exe(len + 1, num_relocs);
    maybe_save_exe("tests/maxlen+1_maxrelocs_incompressible.exe", &exe).unwrap();
    want_error!(exepack::pack(&exe));
    // 1 more relocation is an error.
    let exe = make_incompressible_exe(len, num_relocs + 1);
    maybe_save_exe("tests/maxlen_maxrelocs+1_incompressible.exe", &exe).unwrap();
    want_error!(exepack::pack(&exe));
}

// We don't ask for perfect identity in comparing EXEs. The packing/unpacking
// roundtrip may change the size of the header, and may add padding to the end
// of the body. The location of the relocation table may change. We don't check
// the checksums.
fn check_exes_equivalent(count: usize, a: &exe::Exe, b: &exe::Exe) {
    // Let a be the one with the shorter body.
    let (a, b) = if a.body.len() <= b.body.len() {
        (a, b)
    } else {
        (b, a)
    };

    assert_eq!(a.e_minalloc, b.e_minalloc, "{}", count);
    assert_eq!(a.e_maxalloc, b.e_maxalloc, "{}", count);
    assert_eq!(a.e_ss, b.e_ss, "{}", count);
    assert_eq!(a.e_sp, b.e_sp, "{}", count);
    assert_eq!(a.e_ip, b.e_ip, "{}", count);
    assert_eq!(a.e_cs, b.e_cs, "{}", count);
    assert_eq!(a.e_ovno, b.e_ovno, "{}", count);

    let diff = (b.body.len() as isize).checked_sub(a.body.len() as isize).unwrap();
    // should not add more than 15 bytes of padding
    assert!(0 <= diff && diff < 16, "{} {} {}", a.body.len(), b.body.len(), count);
    let (b_body, b_padding) = b.body.split_at(a.body.len());
    // body up to padding must be identical
    assert_eq!(a.body, b_body, "{}", count);
    // padding must be zeroed
    for c in b_padding {
        assert_eq!(*c, 0x00, "{:?} {}", b_padding, count);
    }

    // relocations must be identical
    let mut a_relocs = a.relocs.clone();
    a_relocs.sort();
    let mut b_relocs = a.relocs.clone();
    b_relocs.sort();
    assert_eq!(a_relocs, b_relocs, "{}", count);
}

fn pack_roundtrip_count(count: usize, max: usize, exe: exe::Exe) -> exe::Exe {
    if count + 1 > max {
        return exe;
    }
    let packed = pack_roundtrip_count(count + 1, max, exepack::pack(&exe).unwrap());
    maybe_save_exe(format!("tests/hello_roundtrip_{}.packed.exe", count + 1), &packed).unwrap();
    let unpacked = exepack::unpack(&packed).unwrap();
    maybe_save_exe(format!("tests/hello_roundtrip_{}.unpacked.exe", count), &unpacked).unwrap();
    check_exes_equivalent(count, &exe, &unpacked);
    unpacked
}

// test that compressing and re-compressing, then decompressing and
// re-decompressing, gives equivalent results all the way down and up the chain.
#[test]
fn test_pack_roundtrip() {
    let exe = {
        let mut f = fs::File::open("tests/hello.exe").unwrap();
        exe::Exe::read(&mut f, None).unwrap()
    };
    pack_roundtrip_count(0, 9, exe);
}
