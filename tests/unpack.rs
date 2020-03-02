use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs;
use std::iter;
use std::str;

extern crate exepack as exepack_crate;
use exepack_crate::exe;
use exepack_crate::exepack;
use exepack_crate::pointer::Pointer;

mod common;

pub fn store_u16le(buf: &mut [u8], i: usize, v: u16) {
    buf[i..i + 2].clone_from_slice(&u16::to_le_bytes(v));
}

pub fn fetch_u16le(buf: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(buf[i..i + 2].try_into().unwrap())
}

pub fn unpacked_sample() -> exe::Exe {
    let mut f = fs::File::open("tests/hello.exe").unwrap();
    exe::Exe::read(&mut f, None).unwrap()
}

pub fn packed_sample() -> exe::Exe {
    let mut f = fs::File::open("tests/hello.exe").unwrap();
    let exe = exe::Exe::read(&mut f, None).unwrap();
    exepack::pack(&exe).unwrap()
}

#[test]
fn test_bad_exepack_signature() {
    let mut sample = packed_sample();
    store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 16, 0x1234);
    common::maybe_save_exe("tests/bad_exepack_magic.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::Signature { signature: 0x1234 }) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_short_exepack_header() {
    let mut sample = packed_sample();
    sample.e_ip = 14;
    store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 16, 0x1234);
    common::maybe_save_exe("tests/short_exepack_header.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownHeaderLength { len: 14 }) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_long_exepack_header() {
    let mut sample = packed_sample();
    sample.e_ip = 20;
    store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 16, 0x1234);
    common::maybe_save_exe("tests/long_exepack_header.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownHeaderLength { len: 20 }) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_unknown_stub() {
    let mut sample = packed_sample();
    // tweak a byte at the end of the stub
    let message = usize::from(sample.e_cs) * 16 + usize::from(sample.e_ip) + exepack::STUB.len() - 22;
    sample.body[message - 5] ^= 0xff;
    common::maybe_save_exe("tests/exepack_unknown_stub.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownStub { .. }) => (),
        x => panic!("{:?}", x),
    }
}

// we can't handle an EXEPACK packed file that also has relocations (at the EXE
// layer, not the EXEPACK layer)
#[test]
fn test_relocations() {
    let mut sample = packed_sample();
    sample.relocs.push(Pointer { segment: 0x0012, offset: 0x3400 });
    common::maybe_save_exe("tests/exepack_with_relocs.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::RelocationsNotSupported) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_short_exepack_size() {
    fn test_unpack(exepack_size: u16) -> Result<exe::Exe, exepack::FormatError> {
        let mut sample = packed_sample();
        store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 6, exepack_size);
        common::maybe_save_exe(format!("tests/exepack_size_{}.exe", exepack_size), &sample).unwrap();
        exepack::unpack(&sample)
    }
    // exepack_size shorter than EXEPACK header
    match test_unpack(10) {
        Err(exepack::FormatError::ExepackTooShort { .. }) => (),
        x => panic!("{:?}", x),
    }
    // exepack_size shorter than EXEPACK header + stub
    match test_unpack(100) {
        Err(exepack::FormatError::UnknownStub { .. }) => (),
        x => panic!("{:?}", x),
    }
    // exepack_size shorter than EXEPACK header + stub + packed relocations
    match test_unpack(u16::try_from(18 + exepack::STUB.len() + 2).unwrap()) {
        Err(exepack::FormatError::ExepackTooShort { .. }) => (),
        x => panic!("{:?}", x),
    }
}

// The message can be other than "Packed file is corrupt"
#[test]
fn test_altered_message() {
    let original = unpacked_sample();
    for message in &[
        b"Fichero corrompido    ", // as in stub_283_es
        b"XXXXXXXXXXXXXXXXXXXXXX",
    ] {
        let mut sample = packed_sample();
        let start = usize::from(sample.e_cs) * 16 + usize::from(sample.e_ip) + exepack::STUB.len() - 22;
        {
            let message_buf = &mut sample.body[start..start + message.len()];
            message_buf.copy_from_slice(&message[..]);
        }
        common::maybe_save_exe(format!("tests/exepack_message_{}.exe", str::replace(str::from_utf8(&message[..]).unwrap(), " ", "_")), &sample).unwrap();
        common::assert_exes_equivalent(&original, &exepack::unpack(&sample).unwrap());
    }
}

#[test]
fn test_trailing_garbage() {
    // it's okay for there to be garbage if it's past exepack_size.
    let original = unpacked_sample();
    let mut sample = packed_sample();
    sample.body.extend(iter::repeat(b'X').take(64));
    common::maybe_save_exe("tests/exe_trailing_garbage.exe", &sample).unwrap();
    common::assert_exes_equivalent(&original, &exepack::unpack(&sample).unwrap());

    // but if it's inside exepack_size, it means the relocation table was not as
    // long as we thought it should be, so we may have guessed the end of the
    // decompression stub wrong.
    let exepack_size = fetch_u16le(&sample.body, usize::from(sample.e_cs) * 16 + 6);
    store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 6, u16::try_from(exepack_size).unwrap() + 64);
    common::maybe_save_exe("tests/exepack_trailing_garbage.exe", &sample).unwrap();
    match exepack::unpack(&sample) {
        Err(exepack::FormatError::UnknownStub { .. }) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_skip_len() {
    // 0 skip_len is always an error
    {
        let mut sample = packed_sample();
        store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 14, 0);
        common::maybe_save_exe(format!("tests/exepack_skip_len_{}.exe", 0), &sample).unwrap();
        match exepack::unpack(&sample) {
            Err(exepack::FormatError::SkipLenInvalid { skip_len: 0 }) => (),
            x => panic!("{:?}", x),
        }
    }

    // skip_len can be greater than 1
    {
        let original = unpacked_sample();
        let mut sample = packed_sample();
        let skip_len = 10;
        store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 14, skip_len);
        let start = usize::from(sample.e_cs) * 16;
        // bump dest_len and cs to compensate for the added skip padding
        let dest_len = fetch_u16le(&mut sample.body, start + 12);
        store_u16le(&mut sample.body, start + 12, dest_len + skip_len - 1);
        sample.e_cs += skip_len - 1;
        // insert skip padding
        sample.body.splice(start..start, iter::repeat(0xaa).take(16 * usize::from(skip_len - 1)));
        common::maybe_save_exe(format!("tests/exepack_skip_len_{}_good.exe", skip_len), &sample).unwrap();
        common::assert_exes_equivalent(&original, &exepack::unpack(&sample).unwrap());
    }

    // skip_len that doesn't agree with cs and dest_len is an error
    {
        let mut sample = packed_sample();
        let skip_len = 10;
        store_u16le(&mut sample.body, usize::from(sample.e_cs) * 16 + 14, skip_len);
        // increased skip_len but didn't actually add padding, nor adjust
        // dest_len and cs
        common::maybe_save_exe(format!("tests/exepack_skip_len_{}_bad.exe", skip_len), &sample).unwrap();
        match exepack::unpack(&sample) {
            Err(exepack::FormatError::SkipLenInvalid { .. }) => (),
            x => panic!("{:?}", x),
        }
    }
}
