extern crate exepack;

#[test]
fn test_roundtrip() {
    let inputs: &[&[u8]] = &[
        &[],
        &[1],
        &[1, 2, 3, 4, 5],
        &[1, 2, 3, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1, 2, 3, 4],
        &[0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0, 0xb0],
        &[0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1, 0xb1],
        &[0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2, 0xb2],
        &[0xb3, 0xb3, 0xb3, 0xb3, 0xb3, 0xb3, 0xb3, 0xb3],
        &[0xff; 0xffff+2],
        &[0xff; 0xff10+2],
        &[0xff; 0xffff*2],
    ];

    for input in inputs.iter() {
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
