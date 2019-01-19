extern crate exepack;

use std::fs;
use std::io::{self, Read, Write};
use std::path;

// If true, save EXE generated during the course of testing to the filesystem,
// so you can examine/test them externally.
const SAVE_EXES: bool = true;

fn save_exe<P: AsRef<path::Path>>(path: P, contents: &[u8]) -> Result<(), exepack::Error> {
    let f = fs::File::create(path)?;
    let mut w = io::BufWriter::new(f);
    w.write(contents)?;
    w.flush()?;
    Ok(())
}

// call save_exe if SAVE_EXES is true
fn maybe_save_exe<P: AsRef<path::Path>>(path: P, contents: &[u8]) -> Result<(), exepack::Error> {
    if SAVE_EXES {
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

fn read_exe_with_hint(buf: &[u8], file_len_hint: Option<u64>) -> Result<exepack::EXE, exepack::Error> {
    exepack::read_exe(&mut io::Cursor::new(buf), file_len_hint)
}

// a version of exepack::read_exe that works from a byte buffer rather than an
// io::Read, with no size hint
fn read_exe(buf: &[u8]) -> Result<exepack::EXE, exepack::Error> {
    read_exe_with_hint(buf, None)
}

fn store_u16le(buf: &mut [u8], i: usize, v: u16) {
    buf[i] = v as u8;
    buf[i+1] = (v >> 8) as u8;
}

#[test]
fn test_read_exe_bad_magic() {
    let mut sample = read_sample();
    sample[0] = b'X';
    sample[1] = b'Y';
    maybe_save_exe("tests/bad_exe_magic.exe", &sample).unwrap();
    match read_exe(&sample) {
        Err(exepack::Error::EXE(exepack::EXEFormatError::BadMagic(0x5958))) => (),
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
                Err(exepack::Error::Io(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => (),
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
            Err(exepack::Error::EXE(exepack::EXEFormatError::BadNumPages(_, _))) => (),
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
        let (e_cblp, e_cp) = exepack::encode_exe_len(len).unwrap();
        store_u16le(&mut sample, 2, e_cblp as u16);
        store_u16le(&mut sample, 4, e_cp as u16);
        maybe_save_exe(format!("tests/exe_len_{}.exe", len), &sample).unwrap();
        match read_exe(&sample) {
            Err(exepack::Error::EXE(exepack::EXEFormatError::BadNumPages(_, _))) => (),
            x => panic!("{:?}", x),
        }
    }

    // short EXE file size is okay as long as it's after the header, but it
    // shortens the EXE body
    {
        let mut sample = sample.clone();
        let len = 96;
        let (e_cblp, e_cp) = exepack::encode_exe_len(len).unwrap();
        store_u16le(&mut sample, 2, e_cblp as u16);
        store_u16le(&mut sample, 4, e_cp as u16);
        maybe_save_exe(format!("tests/exe_len_{}.exe", len), &sample).unwrap();
        let exe = read_exe(&sample).unwrap();
        assert_eq!(exe.body.len(), len-64);
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
            Err(exepack::Error::EXE(exepack::EXEFormatError::HeaderTooShort(1))) => (),
            x => panic!("{:?}", x),
        }
    }
    {
        let mut sample = sample.clone();
        // e_cparhdr = 2, in the middle of the relocations
        // gets interpreted as "relocations outside header"
        store_u16le(&mut sample, 8, 2);
        maybe_save_exe("tests/cparhdr_short_relocs.exe", &sample).unwrap();
        match read_exe(&sample) {
            Err(exepack::Error::EXE(exepack::EXEFormatError::RelocationsOutsideHeader(2, 28))) => (),
            x => panic!("{:?}", x),
        }
    }
    {
        let mut sample = sample.clone();
        // e_lfarlc = 128, after the header end
        store_u16le(&mut sample, 24, 128);
        maybe_save_exe("tests/cparhdr_relocs_outside_header.exe", &sample).unwrap();
        match read_exe(&sample) {
            Err(exepack::Error::EXE(exepack::EXEFormatError::RelocationsOutsideHeader(2, 128))) => (),
            x => panic!("{:?}", x),
        }
    }
}
