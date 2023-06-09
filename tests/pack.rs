use std::iter;

extern crate exepack as exepack_crate;
use exepack_crate::exe;
use exepack_crate::exepack;
use exepack_crate::pointer::Pointer;

pub mod common;

fn make_exe(body: Vec<u8>, relocs: Vec<Pointer>) -> exe::Exe {
    exe::Exe {
        e_minalloc: 0x0000,
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

fn make_relocs(n: usize) -> Vec<Pointer> {
    (0..n).map(|x| x + 256).map(|address| Pointer {
        segment: (address >> 4) as u16,
        offset: (address & 0xf) as u16,
    }).collect()
}

fn make_compressible_exe(body_len: usize, num_relocs: usize) -> exe::Exe {
    make_exe(common::compressible_text(body_len), make_relocs(num_relocs))
}

fn make_incompressible_exe(body_len: usize, num_relocs: usize) -> exe::Exe {
    make_exe(common::incompressible_text(body_len), make_relocs(num_relocs))
}

fn make_semicompressible_exe(body_len: usize, num_relocs: usize) -> exe::Exe {
    make_exe(common::semicompressible_text(body_len), make_relocs(num_relocs))
}

#[test]
fn test_relocs() {
    // two encodings of the largest relocation address EXEPACK can represent.
    // f000:ffff
    // ffff:000f
    for &pointer in &[
        Pointer{ segment: 0xf000, offset: 0xffff },
        Pointer{ segment: 0xffff, offset: 0x000f },
    ] {
        let mut exe = make_compressible_exe(128, 0);
        exe.relocs.push(pointer);
        common::maybe_save_exe(format!("tests/reloc_{:04x}:{:04x}.exe", pointer.segment, pointer.offset), &exe).unwrap();
        let out = exepack::pack(&exe).unwrap();
        common::maybe_save_exe(format!("tests/reloc_{:04x}:{:04x}.packed.exe", pointer.segment, pointer.offset), &out).unwrap();
    }

    // too many relocations within a single segment
    {
        let mut exe = make_compressible_exe(128, 0);
        exe.relocs = iter::repeat(Pointer { segment: 0x1100, offset: 0xf234 }).take(65536).collect();
        match exepack::pack(&exe) {
            Err(exepack::FormatError::TooManyRelocations { segment: 0x2000, num: 65536 }) => (),
            x => panic!("{:?}", x),
        }
    }

    // two encodings of a relocation address too large to represent
    // f001:fff0
    // ffff:0010
    for &pointer in &[
        Pointer{ segment: 0xf001, offset: 0xfff0 },
        Pointer{ segment: 0xffff, offset: 0x0010 },
    ] {
        let mut exe = make_compressible_exe(128, 0);
        exe.relocs.push(pointer);
        common::maybe_save_exe(format!("tests/reloc_{:04x}:{:04x}.exe", pointer.segment, pointer.offset), &exe).unwrap();
        match exepack::pack(&exe) {
            Err(exepack::FormatError::RelocationTooLarge { .. }) => (),
            x => panic!("{:?} {}", x, pointer),
        }
    }
}

#[test]
fn test_minalloc() {
    // The size of an EXEPACK block with no relocations.
    let exepack_base_size = usize::from(exepack::HEADER_LEN) + exepack::STUB.len() + 32;

    let round_up = |x: usize| x.checked_add((16 - x % 16) % 16).unwrap();

    // The computation for output e_minalloc is
    //   max( in.body.len/16 + in.e_minalloc,
    //        in.body.len/16 + exepack_size/16 + exepack_stack/16,
    //       out.body.len/16 + exepack_size/16 + exepack_stack/16)
    // So we have three cases to test.

    // This is the case where the max is
    //   in.body.len/16 + in.e_minalloc
    // We make the input compressible (so out.body.len is small) and set a large
    // in.e_minalloc (so it is larger than the EXEPACK block and stack).
    let exe = exe::Exe {
        e_minalloc: 10000,
        ..make_compressible_exe(10240, 0)
    };
    common::maybe_save_exe(format!("tests/minalloc_{}_compressible.exe", exe.e_minalloc), &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    common::maybe_save_exe(format!("tests/minalloc_{}_compressible.packed.exe", exe.e_minalloc), &out).unwrap();
    assert_eq!(
        round_up(out.body.len()) + usize::from(out.e_minalloc)*16,
        round_up(exe.body.len()) + usize::from(exe.e_minalloc)*16,
    );
    // Also try an incompressible input file for this case. out.body.len is
    // slightly larger than in.body.len, the large in.e_minalloc more than makes
    // up for it.
    let exe = exe::Exe {
        e_minalloc: 10000,
        ..make_incompressible_exe(10240, 0)
    };
    common::maybe_save_exe(format!("tests/minalloc_{}_incompressible.exe", exe.e_minalloc), &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    common::maybe_save_exe(format!("tests/minalloc_{}_incompressible.packed.exe", exe.e_minalloc), &out).unwrap();
    assert_eq!(
        round_up(out.body.len()) + usize::from(out.e_minalloc)*16,
        round_up(exe.body.len()) + usize::from(exe.e_minalloc)*16,
    );

    // This is the case where the max is
    //   in.body.len/16 + exepack_size/16 + exepack_stack/16,
    // We make the input compressible (so out.body.len is small) and set a small
    // in.e_minalloc (so the EXEPACK block and stack are bigger).
    let exe = exe::Exe {
        e_minalloc: 0,
        ..make_compressible_exe(10240, 0)
    };
    common::maybe_save_exe(format!("tests/minalloc_{}_compressible.exe", exe.e_minalloc), &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    common::maybe_save_exe(format!("tests/minalloc_{}_compressible.packed.exe", exe.e_minalloc), &out).unwrap();
    assert_eq!(
        round_up(out.body.len()) + usize::from(out.e_minalloc)*16,
        round_up(exe.body.len()) + round_up(exepack_base_size) + round_up(usize::from(exepack::STACK_SIZE)),
    );

    // This is the case where the max is
    //   out.body.len/16 + exepack_size/16 + exepack_stack/16)
    // We make the input incompressible (so out.body.len is larger than
    // in.body.len) and set a small in.e_minalloc (so the EXEPACK block and
    // stack are bigger).
    let exe = exe::Exe {
        e_minalloc: 0,
        ..make_incompressible_exe(10240, 0)
    };
    common::maybe_save_exe(format!("tests/minalloc_{}_incompressible.exe", exe.e_minalloc), &exe).unwrap();
    let out = exepack::pack(&exe).unwrap();
    common::maybe_save_exe(format!("tests/minalloc_{}_incompressible.packed.exe", exe.e_minalloc), &out).unwrap();
    assert_eq!(
        round_up(out.body.len()) + usize::from(out.e_minalloc)*16,
        round_up(out.body.len()) + round_up(exepack_base_size) + round_up(usize::from(exepack::STACK_SIZE)),
    );
}

#[test]
fn test_minalloc_overflow() {
    // The large initial e_minalloc, combined with the large size difference due
    // to a compressible input, should result in an overflow in the output
    // e_minalloc field.
    let exe = exe::Exe {
        e_minalloc: 0x9000,
        ..make_compressible_exe(0x8000 * 16, 0)
    };
    common::maybe_save_exe("tests/minalloc_overflow.exe", &exe).unwrap();
    match exepack::pack(&exe) {
        Err(exepack::FormatError::MinAllocTooLarge { minalloc: 69608 }) => (),
        x => panic!("{:?}", x),
    }
}

#[test]
fn test_lengths() {
    // Input files may be too big to compress for various reasons. Compression
    // doesn't always decrease the size: it may stay the same or increase by 16
    // bytes (00 00 b3 plus padding), even before counting the ≈350 bytes for
    // the EXEPACK block.
    //
    // An EXE file may be up to 512*0xffff bytes long (this constraint is
    // imposed by the e_cblp and e_cp header fields). Compressing such a large
    // EXE would result in a file whose length could not be represented in the
    // header. But the maximum addressable segment is only 0xffff anyway, and
    // other constraints mean that you will run into problems even before that,
    // regardless of whether the code is compressible or not:
    // - the 16-bit EXE e_minalloc field needs to represent the difference
    //   between uncompressed and compressed sizes, plus some overhead.
    // - the 16-bit EXEPACK dest_len field needs to represent the complete
    //   uncompressed size.
    // - the EXE header cs field needs to be greater than the compressed size.

    // Check for an error in a macro, for meaningful line numbers in test
    // output.
    macro_rules! want_error {
        ($r:expr) => {
            assert!($r.is_err(), "{:?}", $r);
        };
    }

    // The size of an EXEPACK block with no relocations.
    let exepack_base_size = usize::from(exepack::HEADER_LEN) + exepack::STUB.len() + 32;

    // Maximum size compressible inputs.

    // The bottleneck here is the dest_len field in the EXEPACK header,
    // representing the size of the uncompressed output.
    {
        let len = 16 * 0xffff;
        // We use a semicompressible text here, because if we used a highly
        // compressible one, the compressed data would be so much smaller than
        // the uncompressed data that e_minalloc would become a tighter
        // constraint than dest_len, because it represents the difference is
        // sizes, plus the overhead of the copied EXEPACK block.
        let exe = make_semicompressible_exe(len, 0);
        common::maybe_save_exe("tests/maxlen_semicompressible.exe", &exe).unwrap();
        let out = exepack::pack(&exe).unwrap();
        common::maybe_save_exe("tests/maxlen_semicompressible.packed.exe", &out).unwrap();
        // 1 byte longer is an error.
        let exe = make_compressible_exe(len + 1, 0);
        common::maybe_save_exe("tests/maxlen+1_semicompressible.exe", &exe).unwrap();
        want_error!(exepack::pack(&exe));
    }

    // Each relocation adds 2 bytes to exepack_size, which has a maximum value
    // of 0xffff. As we add relocations, eventually the bottleneck becomes not
    // dest_len but exepack_size in the EXEPACK header, along with e_ss and e_sp
    // in the EXE header, which point at dest_len*16 + ceil(exepack_size/16)*16.
    {
        let num_relocs = (0xffff - exepack_base_size) / 2;
        // exepack_size = exepack_base_size + 2*num_relocs is now either 0xfffe
        // or 0xffff, which is as large as it can be. Now we must additionaly
        // satisfy the constraint of the EXE header stack pointer, by making
        // dest_len just small enough to permit the stack pointer to fit. In
        // this situation, with an compressible body, the compressed data and
        // the EXEPACK block both fit beneath dest_len, so the EXEPACK block
        // will be copied to dest_len exactly, with the stack allocated just
        // beyond the copy. The maximum stack pointer is ffff:ffff, so we have
        //   round_up(len) + round_up(exepack_size) + STACK_SIZE <= ffff:ffff
        //   round_up(len) <= ffff:ffff - round_up(exepack_size) - STACK_SIZE
        //   len <= round_down(ffff:ffff - round_up(exepack_size) - STACK_SIZE)
        let len = (0xffff * 16 + 0xffff - 0x10000 - usize::from(exepack::STACK_SIZE)) / 16 * 16;
        let exe = make_compressible_exe(len, num_relocs);
        common::maybe_save_exe("tests/maxlen_maxrelocs_compressible.exe", &exe).unwrap();
        let out = exepack::pack(&exe).unwrap();
        common::maybe_save_exe("tests/maxlen_maxrelocs_compressible.packed.exe", &out).unwrap();
        // 1 byte longer is an error.
        let exe = make_compressible_exe(len + 1, num_relocs);
        common::maybe_save_exe("tests/maxlen+1_maxrelocs_compressible.exe", &exe).unwrap();
        want_error!(exepack::pack(&exe));
        // 1 more relocation is an error.
        let exe = make_compressible_exe(len, num_relocs + 1);
        common::maybe_save_exe("tests/maxlen_maxrelocs+1_compressible.exe", &exe).unwrap();
        want_error!(exepack::pack(&exe));
    }

    // Maximum size incompressible inputs.

    // The bottleneck here is no longer dest_len, but e_cs in the EXE header,
    // which points to the start of the EXEPACK block, immediately after the end
    // of compressed data. The compressed data (including the padding to a
    // multiple of 16 bytes) cannot be larger than 16*0xffff. As it turns out,
    // the largest incompressible stream we can represent in that space has
    // length 16*0xffff-4, with the 4 trailing bytes 00 04 00 b1 encoding the
    // trailing 4 bytes of 0x00 padding.
    {
        let len = 16 * 0xffff - 4;
        let exe = make_incompressible_exe(len, 0);
        common::maybe_save_exe("tests/maxlen_incompressible.exe", &exe).unwrap();
        let out = exepack::pack(&exe).unwrap();
        common::maybe_save_exe("tests/maxlen_incompressible.packed.exe", &out).unwrap();
        // 1 byte longer input is an error.
        let exe = make_incompressible_exe(len + 1, 0);
        common::maybe_save_exe("tests/maxlen+1_incompressible.exe", &exe).unwrap();
        want_error!(exepack::pack(&exe));
    }

    // Now also test an incompressible input with the maximum number of
    // relocations. Here again, the bottleneck is exepack_size in the EXEPACK
    // header, and e_ss and e_sp in the EXE header.
    {
        let num_relocs = (0xffff - exepack_base_size) / 2;
        // With an incompressible body, the compressed data and the EXEPACK
        // block overlap dest_len before decompression. This means the
        // decompression stub will copy the EXEPACK block not to dest_len, but
        // to after itself. We must account, therefore, for *two* quantities of
        // exepack_size after dest_len, before the space allocated for the
        // stack. The same logic applies as above with subtracting 4 for
        // compression overhead.
        //   round_up(len + 4) + round_up(exepack_size) + round_up(exepack_size) + STACK_SIZE <= ffff:ffff
        //   round_up(len + 4) <= ffff:ffff - 2*round_up(exepack_size) - STACK_SIZE
        //   len + 4 <= round_down(ffff:ffff - 2*round_up(exepack_size) - STACK_SIZE)
        //   len <= round_down(ffff:ffff - 2*round_up(exepack_size) - STACK_SIZE) - 4
        let len = (0xffff * 16 + 0xffff - 0x20000 - usize::from(exepack::STACK_SIZE)) / 16 * 16 - 4;
        let exe = make_incompressible_exe(len, num_relocs);
        common::maybe_save_exe("tests/maxlen_maxrelocs_incompressible.exe", &exe).unwrap();
        let out = exepack::pack(&exe).unwrap();
        common::maybe_save_exe("tests/maxlen_maxrelocs_incompressible.packed.exe", &out).unwrap();
        // 1 byte longer is an error.
        let exe = make_incompressible_exe(len + 1, num_relocs);
        common::maybe_save_exe("tests/maxlen+1_maxrelocs_incompressible.exe", &exe).unwrap();
        want_error!(exepack::pack(&exe));
        // 1 more relocation is an error.
        let exe = make_incompressible_exe(len, num_relocs + 1);
        common::maybe_save_exe("tests/maxlen_maxrelocs+1_incompressible.exe", &exe).unwrap();
        want_error!(exepack::pack(&exe));
    }
}
