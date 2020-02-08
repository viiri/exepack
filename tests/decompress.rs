extern crate exepack;

use std::iter;

const COPY: u8 = 0xb2;
const FILL: u8 = 0xb0;
const FINAL: u8 = 0x01;

fn mkvec<T: Copy>(s: &[T]) -> Vec<T> {
    let mut v: Vec<T> = Vec::new();
    v.extend(s.iter().map(|&x| x));
    v
}

#[test]
fn test_unpad() {
    // unpadding can leave an empty buffer
    assert_eq!(exepack::unpad(&[0xff, 0xff], 2), 0, "{:?}", &[0xff, 0xff]);
    // 0 to 15 bytes of padding is okay
    for pad_len in 0..16 {
        let input: Vec<_> = [0xaa, 0xaa, 0xaa].iter().cloned()
            .chain(iter::repeat(0xff).take(pad_len))
            .collect();
        assert_eq!(exepack::unpad(&input, input.len()), 3, "{:?}", input);
    }
    // shouldn't read 16 or more bytes of padding
    for pad_len in 16..24 {
        let input: Vec<_> = [0xaa, 0xaa, 0xaa].iter().cloned()
            .chain(iter::repeat(0xff).take(pad_len))
            .collect();
        assert_eq!(exepack::unpad(&input, input.len()), pad_len - 12, "{:?}", input);
    }
}

// non-mutating version of exepack::decompress, return the trimmed, decompressed
// output instead of modifying the input in place.
fn decompress(buf: &[u8], dst: usize, src: usize) -> Result<Vec<u8>, exepack::ExepackFormatError> {
    let mut work = Vec::new();
    work.extend(buf.iter());
    match exepack::decompress(&mut work, dst, src) {
        Ok(_) => { work.resize(dst, 0); Ok(work) },
        Err(e) => Err(e),
    }
}

#[test]
fn test_decompress_boguscommand() {
    assert_eq!(decompress(&[0x00, 0x00, 0xaa], 3, 3), Err(exepack::ExepackFormatError::BogusCommand(2, 0xaa, 0)));
    assert_eq!(decompress(&[0x34, 0x12, 0xaa, 0xbb, 0x01, 0x00, COPY], 7, 7), Err(exepack::ExepackFormatError::BogusCommand(2, 0xaa, 0x1234)));
    assert_eq!(decompress(&[0x00, 0x34, 0x12, 0xaa, 0xbb, 0x01, 0x00, FILL], 8, 8), Err(exepack::ExepackFormatError::BogusCommand(3, 0xaa, 0x1234)));
}

#[test]
fn test_decompress_srcoverflow() {
    let inputs: &[&[u8]] = &[
        // empty buffer
        &[],
        // EOF before reading length
        &[FILL|FINAL],
        &[COPY|FINAL],
        // EOF while reading length
        &[0x12, FILL|FINAL],
        &[0x12, COPY|FINAL],
        // EOF before reading fill byte
        &[0x00, 0x00, FILL|FINAL],
        // EOF while reading copy body
        &[0x01, 0x00, COPY|FINAL],
        &[0xaa, 0xaa, 0x08, 0x00, COPY],
    ];
    for input in inputs {
        assert_eq!(decompress(input, input.len(), input.len()), Err(exepack::ExepackFormatError::SrcOverflow()), "{:?}", input);
    }
}

#[test]
fn test_decompress_crossover() {
    let inputs: &[(&[u8], usize)] = &[
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL], 9),
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL], 8),
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL], 7),
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x01, 0x00, COPY], 3),
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x01, 0x00, COPY], 2),
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x01, 0x00, COPY], 1),
    ];
    for &(input, dst) in inputs {
        let src = input.len();
        let mut work = mkvec(input);
        if dst > src {
            work.resize(dst, 0);
        }
        match decompress(&work, dst, src) {
            Err(exepack::ExepackFormatError::Crossover(_, _)) => (),
            x => panic!("{:?} {:?}", x, (input, dst)),
        }
    }
}

#[test]
fn test_decompress_filloverflow() {
    let inputs: &[(&[u8], usize)] = &[
        (&[0xaa, 0x01, 0x00, FILL|FINAL], 0),
        (&[0xaa, 0x10, 0x00, FILL|FINAL], 15),
    ];
    for &(input, dst) in inputs {
        let src = input.len();
        let mut work = mkvec(input);
        if dst > src {
            work.resize(dst, 0);
        }
        match decompress(&work, dst, src) {
            Err(exepack::ExepackFormatError::FillOverflow(_, _, _, _, 0xaa)) => (),
            x => panic!("{:?} {:?}", x, (input, dst)),
        }
    }
}

#[test]
fn test_decompress_copyoverflow() {
    let inputs: &[(&[u8], usize)] = &[
        (&[0xaa, 0x01, 0x00, COPY|FINAL], 0),
        (&[0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x05, 0x00, COPY|FINAL], 2),
    ];
    for &(input, dst) in inputs {
        let src = input.len();
        let mut work = mkvec(input);
        if dst > src {
            work.resize(dst, 0);
        }
        match decompress(&work, dst, src) {
            Err(exepack::ExepackFormatError::CopyOverflow(_, _, _, _)) => (),
            x => panic!("{:?} {:?}", x, (input, dst)),
        }
    }
}

#[test]
fn test_decompress_gap() {
    let inputs: &[(&[u8], usize)] = &[
        (&[0x00, 0x00, COPY|FINAL], 4),
        (&[0xaa, 0x01, 0x00, COPY|FINAL], 6),
        (&[0xaa, 0x10, 0x00, FILL|FINAL], 21),
    ];
    for &(input, dst) in inputs {
        let src = input.len();
        let mut work = mkvec(input);
        if dst > src {
            work.resize(dst, 0);
        }
        match decompress(&work, dst, src) {
            Err(exepack::ExepackFormatError::Gap(_, _)) => (),
            x => panic!("{:?} {:?}", x, (input, dst)),
        }
    }
}

#[test]
fn test_decompress_ok() {
    let inputs: &[(&[u8], usize, &[u8])] = &[
        (&[0x01, 0x02, 0x03, 0x04, 0x05, 0x05, 0x00, COPY|FINAL], 5,
         &[0x01, 0x02, 0x03, 0x04, 0x05]),
        (&[0x01, 0x02, 0x03, 0x04, 0x05, 0x02, 0x00, COPY|FINAL], 5,
         &[0x01, 0x02, 0x03, 0x04, 0x05]),
        (&[0x01, 0x02, 0x03, 0x04, 0x05, 0x02, 0x00, COPY|FINAL], 2,
         &[0x04, 0x05]),
        (&[0xaa, 0x04, 0x00, FILL|FINAL], 4,
         &[0xaa, 0xaa, 0xaa, 0xaa]),
        // allow reuse of src bytes, even if they are command bytes
        (&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL], 10,
         &[0x00, 0x00, COPY|FINAL, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]),
        (&[0xaa, 0x04, 0x00, FILL|FINAL], 8,
         &[0xaa, 0x04, 0x00, FILL|FINAL, 0xaa, 0xaa, 0xaa, 0xaa]),
        // allow dst < src for the first command only.
        (&[0x01, 0x02, 0x03, 0x00, 0x00, COPY|FINAL], 3,
         &[0x01, 0x02, 0x03]),
        (&[0x01, 0x02, 0x02, 0x00, COPY|FINAL, 0x00, 0x00, COPY], 5,
         &[0x01, 0x02, 0x02, 0x01, 0x02]),
    ];
    for &(input, dst, output) in inputs {
        let src = input.len();
        let mut work = mkvec(input);
        if dst > src {
            work.resize(dst, 0);
        }
        assert_eq!(&decompress(&work, dst, src).unwrap(), &output);
    }
}

#[test]
fn test_compress_roundtrip() {
    let inputs: &[&[u8]] = &[
        &[],
        &[1],
        &[1, 2, 3, 4, 5],
        &[1, 2, 3, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1, 2, 3, 4],
        b"Hellllllllllllllllo, world\n",
        // try compressing command codes themselves
        &[FILL, FILL, FILL, FILL, FILL, FILL, FILL, FILL],
        &[COPY, COPY, COPY, COPY, COPY, COPY, COPY, COPY],
        &[FILL|FINAL, FILL|FINAL, FILL|FINAL, FILL|FINAL, FILL|FINAL, FILL|FINAL, FILL|FINAL, FILL|FINAL],
        &[COPY|FINAL, COPY|FINAL, COPY|FINAL, COPY|FINAL, COPY|FINAL, COPY|FINAL, COPY|FINAL, COPY|FINAL],
        // long inputs
        &[0xff; 0xffff+2],
        &[0xff; 0xff10+2],
        &[0xff; 0xffff*2],
    ];
    for input in inputs {
        let mut work = Vec::new();
        exepack::compress(&mut work, input);
        let compressed_len = work.len();
        if work.len() < input.len() {
            work.resize(input.len(), 0);
        }
        exepack::decompress(&mut work, input.len(), compressed_len).unwrap();
        assert_eq!(&&work[0..input.len()], input);
    }
}
