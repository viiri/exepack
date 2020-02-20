use std::iter;
use std::str;

use exe;
use exepack;
use pointer::Pointer;
use tests;

#[test]
fn test_bad_exepack_magic() {
    let mut sample = tests::packed_sample();
    tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 16, 0x1234);
    tests::maybe_save_exe("tests/bad_exepack_magic.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::BadMagic(0x1234)) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_short_exepack_header() {
    let mut sample = tests::packed_sample();
    sample.e_ip = 14;
    tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 16, 0x1234);
    tests::maybe_save_exe("tests/short_exepack_header.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownHeaderLength(14)) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_long_exepack_header() {
    let mut sample = tests::packed_sample();
    sample.e_ip = 20;
    tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 16, 0x1234);
    tests::maybe_save_exe("tests/long_exepack_header.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownHeaderLength(20)) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unknown_stub() {
    let mut sample = tests::packed_sample();
    // tweak a byte at the end of the stub
    let message = sample.e_cs as usize * 16 + sample.e_ip as usize + exepack::STUB.len() - 22;
    sample.body[message - 5] ^= 0xff;
    tests::maybe_save_exe("tests/exepack_unknown_stub.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownStub(_, _)) => (),
        x => panic!("{:?}", x),
    }
}

// we can't handle an EXEPACK packed file that also has relocations (at the EXE
// layer, not the EXEPACK layer)
#[test]
fn test_relocations() {
    let mut sample = tests::packed_sample();
    sample.relocs.push(Pointer { segment: 0x0012, offset: 0x3400 });
    tests::maybe_save_exe("tests/exepack_with_relocs.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::RelocationsNotSupported) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_short_exepack_size() {
    fn test_unpack(exepack_size: u16) -> Result<exe::Exe, exepack::FormatError> {
        let mut sample = tests::packed_sample();
        tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 6, exepack_size as u16);
        tests::maybe_save_exe(format!("tests/exepack_size_{}.exe", exepack_size), &sample).unwrap();
        exepack::unpack(&sample)
    }
    // exepack_size shorter than EXEPACK header
    match test_unpack(10) {
        Err(exepack::FormatError::ExepackTooShort(_)) => (),
        x => panic!("{:?}", x),
    }
    // exepack_size shorter than EXEPACK header + stub
    match test_unpack(100) {
        Err(exepack::FormatError::UnknownStub(_, _)) => (),
        x => panic!("{:?}", x),
    }
    // exepack_size shorter than EXEPACK header + stub + packed relocations
    match test_unpack((18 + exepack::STUB.len() + 2) as u16) {
        Err(exepack::FormatError::ExepackTooShort(_)) => (),
        x => panic!("{:?}", x),
    }
}

// We don't ask for perfect identity in comparing EXEs. The packing/unpacking
// roundtrip may change the size of the header, and may add padding to the end
// of the body. The location of the relocation table may change.
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
fn test_altered_message() {
    let original = tests::unpacked_sample();
    for message in &[
        b"Fichero corrompido    ", // as in stub_283_es
        b"XXXXXXXXXXXXXXXXXXXXXX",
    ] {
        let mut sample = tests::packed_sample();
        let start = sample.e_cs as usize * 16 + sample.e_ip as usize + exepack::STUB.len() - 22;
        {
            let message_buf = &mut sample.body[start..start + message.len()];
            message_buf.copy_from_slice(&message[..]);
        }
        tests::maybe_save_exe(format!("tests/exepack_message_{}.exe", str::replace(str::from_utf8(&message[..]).unwrap(), " ", "_")), &sample).unwrap();
        check_exes_equivalent(&original, &exepack::unpack(&sample).unwrap());
    }
}

#[test]
fn test_trailing_garbage() {
    // it's okay for there to be garbage if it's past exepack_size.
    let original = tests::unpacked_sample();
    let mut sample = tests::packed_sample();
    sample.body.extend(iter::repeat(b'X').take(64));
    tests::maybe_save_exe("tests/exe_trailing_garbage.exe", &sample).unwrap();
    check_exes_equivalent(&original, &exepack::unpack(&sample).unwrap());

    // but if it's inside exepack_size, it means the relocation table was not as
    // long as we thought it should be, so we may have guessed the end of the
    // decompression stub wrong.
    let exepack_size = tests::fetch_u16le(&sample.body, sample.e_cs as usize * 16 + 6);
    tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 6, exepack_size as u16 + 64);
    tests::maybe_save_exe("tests/exepack_trailing_garbage.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownStub(_, _)) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_skip_len() {
    // 0 skip_len is always an error
    {
        let mut sample = tests::packed_sample();
        tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 14, 0);
        tests::maybe_save_exe(format!("tests/exepack_skip_len_{}.exe", 0), &sample).unwrap();
        match exepack::unpack(&sample) {
            Err(exepack::FormatError::SkipTooShort(0)) => (),
            x => panic!("{:?}", x),
        }
    }

    // skip_len can be greater than 1
    {
        let original = tests::unpacked_sample();
        let mut sample = tests::packed_sample();
        let skip_len = 10;
        tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 14, skip_len);
        let start = sample.e_cs as usize * 16;
        // bump dest_len and cs to compensate for the added skip padding
        let dest_len = tests::fetch_u16le(&mut sample.body, start + 12);
        tests::store_u16le(&mut sample.body, start + 12, dest_len + skip_len - 1);
        sample.e_cs += skip_len - 1;
        // insert skip padding
        sample.body.splice(start..start, iter::repeat(0xaa).take(16 * (skip_len - 1) as usize));
        tests::maybe_save_exe(format!("tests/exepack_skip_len_{}_good.exe", skip_len), &sample).unwrap();
        check_exes_equivalent(&original, &exepack::unpack(&sample).unwrap());
    }

    // skip_len that doesn't agree with cs and dest_len is an error
    {
        let mut sample = tests::packed_sample();
        let skip_len = 10;
        tests::store_u16le(&mut sample.body, sample.e_cs as usize * 16 + 14, skip_len);
        // increased skip_len but didn't actually add padding, nor adjust
        // dest_len and cs
        tests::maybe_save_exe(format!("tests/exepack_skip_len_{}_bad.exe", skip_len), &sample).unwrap();
        match exepack::unpack(&sample) {
            Err(exepack::FormatError::SkipTooLong(_)) => (),
            x => panic!("{:?}", x),
        }
    }
}
