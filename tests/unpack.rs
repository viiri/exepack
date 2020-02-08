extern crate exepack;

use std::env;
use std::fs;
use std::io::{self, Seek, Write};
use std::iter;
use std::path;
use std::str;

use exepack::exe;

fn store_u16le(buf: &mut [u8], i: usize, v: u16) {
    buf[i] = v as u8;
    buf[i + 1] = (v >> 8) as u8;
}

fn fetch_u16le(buf: &[u8], i: usize) -> u16 {
    buf[i] as u16 | ((buf[i + 1] as u16) << 8)
}

fn unpacked_sample() -> exe::Exe {
    let mut f = fs::File::open("tests/hello.exe").unwrap();
    exe::Exe::read(&mut f, None).unwrap()
}

fn packed_sample() -> exe::Exe {
    let mut f = fs::File::open("tests/hello.exe").unwrap();
    exepack::pack(&mut f, None).unwrap()
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

// a version of exepack::unpack that works from a source EXE rather than an
// io::Read, with no size hint.
fn unpack(source: &exe::Exe) -> Result<exe::Exe, exepack::Error> {
    let mut f = io::Cursor::new(Vec::new());
    source.write(&mut f).unwrap();
    f.seek(io::SeekFrom::Start(0)).unwrap();
    exepack::unpack(&mut f, None)
}

#[test]
fn test_unpack_bad_exepack_magic() {
    let mut sample = packed_sample();
    store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 16, 0x1234);
    maybe_save_exe("tests/bad_exepack_magic.exe", &sample).unwrap();
    match unpack(&sample) {
        Err(exepack::Error::Exepack(exepack::ExepackFormatError::BadMagic(0x1234))) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unpack_short_exepack_header() {
    let mut sample = packed_sample();
    sample.e_ip = 14;
    store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 16, 0x1234);
    maybe_save_exe("tests/short_exepack_header.exe", &sample).unwrap();
    match unpack(&sample) {
        Err(exepack::Error::Exepack(exepack::ExepackFormatError::UnknownHeaderLength(14))) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unpack_long_exepack_header() {
    let mut sample = packed_sample();
    sample.e_ip = 20;
    store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 16, 0x1234);
    maybe_save_exe("tests/long_exepack_header.exe", &sample).unwrap();
    match unpack(&sample) {
        Err(exepack::Error::Exepack(exepack::ExepackFormatError::UnknownHeaderLength(20))) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unpack_unknown_stub() {
    let mut sample = packed_sample();
    // tweak a byte at the end of the stub
    let message = sample.e_cs as usize * 16 + sample.e_ip as usize + exepack::STUB.len() - 22;
    sample.body[message - 5] ^= 0xff;
    maybe_save_exe("tests/exepack_unknown_stub.exe", &sample).unwrap();
    match unpack(&sample) {
        Err(exepack::Error::Exepack(exepack::ExepackFormatError::UnknownStub(_, _))) => (),
        x => panic!("{:?}", x),
    }
}

// we can't handle an EXEPACK packed file that also has relocations (at the EXE
// layer, not the EXEPACK layer)
#[test]
fn test_unpack_relocations() {
    let mut sample = packed_sample();
    sample.relocs.push(exepack::Pointer { segment: 0x0012, offset: 0x3400 });
    maybe_save_exe("tests/exepack_with_relocs.exe", &sample).unwrap();
    match unpack(&sample) {
        Err(exepack::Error::Exepack(exepack::ExepackFormatError::RelocationsNotSupported(1, 28))) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unpack_short_exepack_size() {
    for &exepack_size in &[
        10,     // shorter than EXEPACK header
        100,    // shorter than stub
        18 + exepack::STUB.len() + 2,   // shorter than packed relocations
    ] {
        let mut sample = packed_sample();
        store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 6, exepack_size as u16);
        maybe_save_exe(format!("tests/exepack_size_{}.exe", exepack_size), &sample).unwrap();
        match unpack(&sample) {
            Err(exepack::Error::Exepack(exepack::ExepackFormatError::ExepackTooShort(_, _))) => (),
            Err(exepack::Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => (),
            x => panic!("{:?}", x),
        }
    }
}

// We don't ask for perfect identity in comparing EXEs. The packing/unpacking
// roundtrip may change the size of the header, and may add padding to the end
// of the body. The location of the relocation table may change. We don't check
// the checksums.
fn check_exes_equivalent(a: &exe::Exe, b: &exe::Exe) {
    // Let a be the one with the shorter body.
    let (a, b) = if a.body.len() <= b.body.len() {
        (a, b)
    } else {
        (b, a)
    };

    assert_eq!(a.e_minalloc, b.e_minalloc);
    assert_eq!(a.e_maxalloc, b.e_maxalloc);
    assert_eq!(a.e_ss, b.e_ss);
    assert_eq!(a.e_sp, b.e_sp);
    assert_eq!(a.e_ip, b.e_ip);
    assert_eq!(a.e_cs, b.e_cs);
    assert_eq!(a.e_ovno, b.e_ovno);

    let diff = (b.body.len() as isize).checked_sub(a.body.len() as isize).unwrap();
    // should not add more than 15 bytes of padding
    assert!(0 <= diff && diff < 16, "{} {}", a.body.len(), b.body.len());
    let (b_body, b_padding) = b.body.split_at(a.body.len());
    // body up to padding must be identical
    assert_eq!(a.body, b_body);
    // padding must be zeroed
    for c in b_padding {
        assert_eq!(*c, 0x00, "{:?}", b_padding);
    }

    // relocations must be identical
    let mut a_relocs = a.relocs.clone();
    a_relocs.sort();
    let mut b_relocs = a.relocs.clone();
    b_relocs.sort();
    assert_eq!(a_relocs, b_relocs);
}

// The message can be other than "Packed file is corrupt"
#[test]
fn test_unpack_altered_message() {
    let original = unpacked_sample();
    for message in &[
        b"Fichero corrompido    ", // as in stub_283_es
        b"XXXXXXXXXXXXXXXXXXXXXX",
    ] {
        let mut sample = packed_sample();
        let start = sample.e_cs as usize * 16 + sample.e_ip as usize + exepack::STUB.len() - 22;
        {
            let message_buf = &mut sample.body[start..start + message.len()];
            message_buf.copy_from_slice(&message[..]);
        }
        maybe_save_exe(format!("tests/exepack_message_{}.exe", str::replace(str::from_utf8(&message[..]).unwrap(), " ", "_")), &sample).unwrap();
        check_exes_equivalent(&original, &unpack(&sample).unwrap());
    }
}

#[test]
fn test_unpack_trailing_garbage() {
    // it's okay for there to be garbage if it's past exepack_size.
    let original = unpacked_sample();
    let mut sample = packed_sample();
    sample.body.extend(iter::repeat(b'X').take(64));
    maybe_save_exe("tests/exe_trailing_garbage.exe", &sample).unwrap();
    check_exes_equivalent(&original, &unpack(&sample).unwrap());

    // but if it's inside exepack_size, it means the relocation table was not as
    // long as we thought it should be, so we may have guessed the end of the
    // decompression stub wrong.
    let exepack_size = fetch_u16le(&sample.body, sample.e_cs as usize * 16 + 6);
    store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 6, exepack_size as u16 + 64);
    maybe_save_exe("tests/exepack_trailing_garbage.exe", &sample).unwrap();
    match unpack(&sample) {
        Err(exepack::Error::Exepack(exepack::ExepackFormatError::UnknownStub(_, _))) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unpack_skip_len() {
    // 0 skip_len is always an error
    {
        let mut sample = packed_sample();
        store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 14, 0);
        maybe_save_exe(format!("tests/exepack_skip_len_{}.exe", 0), &sample).unwrap();
        match unpack(&sample) {
            Err(exepack::Error::Exepack(exepack::ExepackFormatError::SkipTooShort(0))) => (),
            x => panic!("{:?}", x),
        }
    }

    // skip_len can be greater than 1
    {
        let original = unpacked_sample();
        let mut sample = packed_sample();
        let skip_len = 10;
        store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 14, skip_len);
        let start = sample.e_cs as usize * 16;
        // bump dest_len and cs to compensate for the added skip padding
        let dest_len = fetch_u16le(&mut sample.body, start + 12);
        store_u16le(&mut sample.body, start + 12, dest_len + skip_len - 1);
        sample.e_cs += skip_len - 1;
        // insert skip padding
        sample.body.splice(start..start, iter::repeat(0xaa).take(16 * (skip_len - 1) as usize));
        maybe_save_exe(format!("tests/exepack_skip_len_{}_good.exe", skip_len), &sample).unwrap();
        check_exes_equivalent(&original, &unpack(&sample).unwrap());
    }

    // skip_len that doesn't agree with cs and dest_len is an error
    {
        let mut sample = packed_sample();
        let skip_len = 10;
        store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 14, skip_len);
        // increased skip_len but didn't actually add padding, nor adjust
        // dest_len and cs
        maybe_save_exe(format!("tests/exepack_skip_len_{}_bad.exe", skip_len), &sample).unwrap();
        match unpack(&sample) {
            Err(exepack::Error::Exepack(exepack::ExepackFormatError::SkipTooLong(_))) => (),
            x => panic!("{:?}", x),
        }
    }
}
