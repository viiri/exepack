//! Compressor and decompressor for self-extracting DOS executables with
//! Microsoft EXEPACK.
//!
//! There are different versions of the EXEPACK format, with slightly different
//! internal data structures. This program identifies what format is in used by
//! looking up the executable portion of the file (the "decompression stub") in
//! a table of known stubs. See the `stubs` module. If the program doesn't
//! recognize a stub, it can't decompress it.
//!
//! One common format is documented at
//! <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#File_Format>. See
//! doc/README.stubs for other formats that this program can deal with.
//!
//! # Compression
//!
//! The `pack` function takes an uncompressed `exe::Exe` and outputs a
//! compressed `exe::Exe`.
//!
//! # Decompression
//!
//! The `unpack` function takes a compressed `exe::Exe` and outputs an
//! uncompressed `exe::Exe`.
//!
//! # Inconsistencies
//!
//! Doesn't try to be bug-compatible will all versions of EXEPACK. Known
//! differences:
//!
//! - Some versions of EXEPACK have a bug when the offset of a segment:offset
//!   relocation entry is 0xffff: they write the second byte at address 0 in the
//!   same segment rather than the following segment.
//! - Some versions of EXEPACK don't restore the ax register before jumping to
//!   the decompressed program.
//! - If an executable contains relocations at the outer EXEPACK layer, they
//!   would be applied by DOS (presumably patching the compressed data) before
//!   decompression starts. This library doesn't permit such relocations.

use std::cmp;
use std::convert::TryInto;
use std::fmt;
use std::io::{self, prelude::*};

use exe;

/// Our pre-assembled decompression stub.
pub const STUB: &'static [u8; 283] = include_bytes!("stub.bin");

/// Round `n` up to the next multiple of `m`.
fn round_up(n: usize, m: usize) -> Option<usize> {
    n.checked_add((m - n % m) % m)
}

fn read_u16le<R: Read + ?Sized>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn push_u16le(buf: &mut Vec<u8>, v: u16) {
    buf.extend(&u16::to_le_bytes(v));
}

#[derive(Debug, PartialEq)]
pub enum FormatError {
    RelocationsNotSupported,
    HeaderPastEndOfFile(u64),
    UnknownStub(Vec<u8>, Vec<u8>),
    BadMagic(u16),
    UnknownHeaderLength(usize),
    SkipTooShort(u16),
    SkipTooLong(u16),
    ExepackTooShort(u16),
    SrcOverflow(),
    FillOverflow(usize, usize, u8, usize, u8),
    CopyOverflow(usize, usize, u8, usize),
    BogusCommand(usize, u8, usize),
    Gap(usize, usize),
    UncompressedTooLong(usize),
    RelocationAddrTooLarge(exe::Pointer),
    ExepackTooLong(usize),
    CompressedTooLong(usize),
    SSTooLarge(usize),
}

impl std::error::Error for FormatError {}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FormatError::RelocationsNotSupported =>
                write!(f, "relocations before decompression are not supported"),
            FormatError::HeaderPastEndOfFile(offset) =>
                write!(f, "EXEPACK header at 0x{:x} is past the end of the file", offset),
            FormatError::UnknownStub(_header_buffer, _stub) =>
                write!(f, "Unknown decompression stub"),
            FormatError::BadMagic(magic) =>
                write!(f, "EXEPACK header has bad magic 0x{:04x}; expected 0x{:04x}", magic, EXEPACK_MAGIC),
            FormatError::UnknownHeaderLength(header_len) =>
                write!(f, "don't know how to interpret EXEPACK header of {} bytes", header_len),
            FormatError::SkipTooShort(skip_len) =>
                write!(f, "EXEPACK skip_len of {} paragraphs is invalid", skip_len),
            FormatError::SkipTooLong(skip_len) =>
                write!(f, "EXEPACK skip_len of {} paragraphs is too long", skip_len),
            FormatError::ExepackTooShort(exepack_size) =>
                write!(f, "EXEPACK size of {} bytes is too short for header, stub, and relocations", exepack_size),
            FormatError::SrcOverflow() =>
                write!(f, "reached end of compressed stream without seeing a termination command"),
            FormatError::FillOverflow(dst, _src, _command, length, fill) =>
                write!(f, "write overflow: fill {}×'\\{:02x}' at index {}", length, fill, dst),
            FormatError::CopyOverflow(dst, src, _command, length) =>
                write!(f, "{}: copy {} bytes from index {} to index {}",
                    if src < length { "read overflow" } else { "write overflow" },
                    length, src, dst),
            FormatError::BogusCommand(src, command, length) =>
                write!(f, "unknown command 0x{:02x} with ostensible length {} at index {}", command, length, src),
            FormatError::Gap(dst, original_src) =>
                write!(f, "decompression left a gap of {} unwritten bytes between write index {} and original read index {}", dst - original_src, dst, original_src),
            FormatError::UncompressedTooLong(len) =>
                write!(f, "uncompressed size {} is too large to represent in an EXEPACK header", len),
            FormatError::RelocationAddrTooLarge(pointer) =>
                write!(f, "relocation address {} is too large to represent in the EXEPACK table", pointer),
            FormatError::ExepackTooLong(len) =>
                write!(f, "EXEPACK area is too long at {} bytes", len),
            FormatError::CompressedTooLong(len) =>
                write!(f, "compressed data of {} bytes is too large to represent", len),
            FormatError::SSTooLarge(ss) =>
                write!(f, "stack segment 0x{:04x} is too large to represent", ss),
        }
    }
}

/// The basic compression loop. The compressed data are read (going forwards)
/// from `input` and written into the end of `output`.
///
/// <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Decompression_algorithm>
fn compress(output: &mut Vec<u8>, input: &[u8]) {
    // Since we produce our own self-extracting executable, technically we
    // could compress however we like. But we want to remain compatible with
    // https://github.com/w4kfu/unEXEPACK and other external EXEPACK unpackers,
    // so we use the standard EXEPACK encoding: 0xb2 for a copy, 0xb0 for a
    // fill, LSb == 1 to mark the end.
    //
    // The algorithm here uses dynamic programming. We define 3 states that the
    // compressed stream may be in:
    // * C ("copy") for a 0xb2/0xb3 block (copy the next len bytes)
    // * F ("fill") for a 0xb0/0xb1 block (fill len copies of the next byte)
    // * R ("runout") for the end of the stream after the last C or F block,
    //   which is copied verbatim from the compressed input to the decompressed
    //   output simply by virtue of remaining untouched in the buffer.
    // For each input position i, we compute the minimum length of the
    // compression of the first i bytes of the reversed input sequence. Assuming
    // we know the values for index i-1, we compute the values for index i using
    // the recurrences:
    //      C[i] = min(
    //          4 + F[i-1], // if we were in F, start a C block
    //          1 + C[i-1], // if we were in C, continue the same C block
    //      )
    //      F[i] = min(
    //          4 + C[i-1], // if we were in C, start an F block
    //          0 + F[i-1], // if we were in F, stay in the same F block
    //      )
    //      R[i] = min(     // runout bytes always cost 1
    //          1 + C[i-1],
    //          1 + F[i-1],
    //          1 + R[i-1],
    //      )
    // The transitions R→R R→C, R→F, C→C, C→F, F→F, F→C are valid, while C→R and
    // F→R are not (once you leave the runout you can't go back to it;
    // everything following has to be a C or F block). The actual formulas used
    // in the code are a little more complicated because we also have to account
    // for the fact that the length of each block is limited. For example, if a
    // current C block is full, we can't append to it and instead have to start
    // a new one.
    //
    // Then we walk backwards through the minimum-cost tables. At each index i
    // we choose whichever of C, F, and R has the lowest cost--with the
    // restriction that once we have selected C or F once, we can never again
    // select R. Then we jump i ahead by the length of the command, and repeat
    // until we reach the beginning of the tables. In the case where we stayed
    // in R throughout (i.e., an incompressible sequence), we tack on a dummy
    // "copy 0" command at the end--in this case (the worst case) the compressed
    // data are 3 bytes larger than the uncompressed.
    //
    // I'm not sure the algorithm used here is optimal with respect to the
    // length of commands. In the 1-dimensional C and F tables I'm storing the
    // single command length that led to the minimum cost at each position. A
    // more complete consideration of cases would make each table 2-dimensional,
    // indexed by input position and by command length. If there is a
    // difference, it's likely to be minor.
    //
    // A greedy algorithm (that uses F for runs of 5 or longer, C otherwise) is
    // not optimal. Consider the sequence
    //      ... 01 02 03 04 05 cc cc cc cc cc 01 02 03 04 05
    // (Assume the left side doesn't enter runout.) A greedy compressor would
    // compress it to
    //      ... 01 02 03 04 05 05 00 b2 cc 05 00 b0 01 02 03 04 05 05 00 b2
    // i.e., a C of length 5, then an F of length 5, then a C of length 5. But
    // switching from C to F back to C again costs more than compressing the run
    // of 5 cc's saves. A better compression is just one long C:
    //      ... 01 02 03 04 05 cc cc cc cc cc 01 02 03 04 05 0f 00 b2
    //
    // We don't take advantage of every possible optimization. For example,
    // suppose for a moment that the maximum length we can use is 6 rather than
    // 0xffff. Consider the 7-byte sequence
    //      cc cc cc cc cc cc cc
    // We will compress this into 5 bytes as
    //      cc cc 06 00 b1
    // (i.e., fill 6×cc, then one runout cc). But we could save 1 additional
    // byte by re-using one of the cc's both as a command parameter and a
    // runout byte:
    //      cc 06 00 b1
    // For that matter, if we happened to get the 8-byte input
    //      cc 06 cc cc cc cc cc cc
    // we could re-use the 2 bytes cc 06 and compress as
    //      cc 06 00 b1

    // The longest length of any command.
    const MAX_LEN: u16 = 0xffff;

    // Stage 1: build the tables of costs and command lengths for each input
    // position.

    // Allocate tables of costs (minimum compressed length) for each of C, F,
    // and R; and additionally command lengths for C and F (R doesn't have
    // command lengths). C[i+1].cost is the minimum length to compress up
    // input[0..i] if we are in a C command at position i; likewise for F and R.
    #[derive(Ord, PartialOrd, PartialEq, Eq)]
    struct Entry {
        cost: u32,
        len: u16,
    }
    #[allow(non_snake_case)]
    let (mut C, mut F, mut R): (Vec<Entry>, Vec<Entry>, Vec<u32>) = (
        Vec::with_capacity(input.len() + 1),
        Vec::with_capacity(input.len() + 1),
        Vec::with_capacity(input.len() + 1),
    );
    // The tables are 1 element longer than the input. The zeroth entry in each
    // represents the "-1" index; i.e., the cost/length of compressing a
    // zero-length input using each of the strategies.
    C.push(Entry { cost: 3, len: 0 }); // 00 00 b1
    F.push(Entry { cost: 4, len: 0 }); // XX 00 00 b3
    // If we've done the whole input in the R state, we'll need to append a
    // 00 00 b1 (just as in the C case), solely for the sake of giving the
    // decompression routine a termination indicator.
    R.push(3);                         // 00 00 b1

    for j in (0..input.len()).rev() {
        // j indexes input backwards from input.len()-1 to 0; i indexes the
        // cost/length tables forward from 1 to input.len().
        let i = input.len() - j;
        // If we require byte j to be in a C command, then we either start a new
        // C command here, or continue an existing C command.
        let entry = cmp::min(
            // If we previous byte was in an F, then it costs 4 bytes to start a
            // C at this point.
            Entry { cost: 4 + F[i - 1].cost, len: 1 },
            // If we were already in a C command, we have the option of
            // appending the current byte into the same command for an
            // additional cost of 1--but only if its len does not exceed
            // MAX_LEN. If it does, then we have to start a new C command at a
            // cost of 4.
            if C[i - 1].len < MAX_LEN {
                Entry { cost: 1 + C[i - 1].cost, len: 1 + C[i - 1].len }
            } else {
                Entry { cost: 4 + C[i - 1].cost, len: 1 }
            }
        );
        // Push the minimum value to C[i].
        C.push(entry);

        // If we require byte j to be in an F command, then we either start a
        // new F command here, or continue an existing F command.
        let entry = cmp::min(
            // If we previous byte was in a C, then it costs 4 bytes to start an
            // F at this point.
            Entry { cost: 4 + C[i - 1].cost, len: 1 },
            // If we were already in a F command, we have the option of
            // including the current byte in the same command for an additional
            // cost of 0--but only if its len does not exceed MAX_LEN *and* the
            // byte value is identical to the previous one (or we are at the
            // first byte and there is no previous one yet). Otherwise, we need
            // to start a new F command at a cost of 4.
            if F[i - 1].len < MAX_LEN && (j == input.len() - 1 || input[j] == input[j + 1]) {
                Entry { cost: 0 + F[i - 1].cost, len: 1 + F[i - 1].len }
            } else {
                Entry { cost: 4 + F[i - 1].cost, len: 1 }
            }
        );
        // Push the minimum value to F[i].
        F.push(entry);

        // Finally, if we require byte j to be in the R runout, the cost is 1
        // greater than the minimum cost so far using any of C, F, or R (the
        // cost of the verbatim byte itself). Note that we can switch from from
        // C or F to R, but once in R there is no going back to C or F.
        let cost = C[i - 1].cost.min(F[i - 1].cost).min(R[i - 1]) + 1;
        // Push the minimum cost to R[i].
        R.push(cost);
    }

    // Stage 2: trace back through the C, F, and R tables to recover the
    // sequence of commands that lead to the minimum costs we computed.

    enum Cmd {
        C,
        F,
        R,
    }
    // The command currently in effect. We encode forwards, but the decompressor
    // will run backwards. Start in the runout.
    let mut cmd = Cmd::R;
    // The first time we encode a C or F (i.e., when we get out of the runout),
    // we need to set the LSb to indicate that it is the final command.
    let mut is_final: u8 = 0x01;
    let mut j = 0;
    while j < input.len() {
        // j indexes input from beginning to end; i indexes the cost/length
        // tables from end to beginning.
        let i = input.len() - j;
        // We consult the C and F tables and see if either of them have a lower
        // cost than the current command (which may be C, F, or R) at this
        // index.
        let mut cost = match cmd {
            Cmd::C => C[i].cost,
            Cmd::F => F[i].cost,
            Cmd::R => R[i],
        };
        if C[i].cost < cost {
            cost = C[i].cost;
            cmd = Cmd::C;
        }
        if F[i].cost < cost {
            cmd = Cmd::F;
        }

        // Now encode the command we've found to be the cheapest at this
        // position.
        match cmd {
            Cmd::C => {
                let len = C[i].len as usize;
                output.extend(input[j..(j + len)].iter());
                output.extend_from_slice(&u16::to_le_bytes(len as u16));
                output.push(0xb2 | is_final);
                is_final = 0;
                j += len;
            }
            Cmd::F => {
                let len = F[i].len as usize;
                output.push(input[j]);
                output.extend_from_slice(&u16::to_le_bytes(len as u16));
                output.push(0xb0 | is_final);
                is_final = 0;
                j += len;
            }
            Cmd::R => {
                output.push(input[j]);
                j += 1;
            }
        }
    }
    assert_eq!(j, input.len());
    // If we got all the way to the end and are still in the runout, then we
    // need to append a dummy, zero-length C command for the sake of giving the
    // decompression routine something to interpret. This is the worst case for
    // an incompressible input, an expansion of 3 bytes.
    if let Cmd::R = cmd {
        output.push(0);
        output.push(0);
        assert_eq!(is_final, 1);
        output.push(0xb2 | is_final);
    }
}

/// Encode a compressed relocation table.
fn encode_relocs(buf: &mut Vec<u8>, relocs: &[exe::Pointer]) -> Result<(), FormatError> {
    // http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Relocation_Table
    let mut relocs: Vec<_> = relocs.iter().cloned().collect();
    relocs.sort();
    let mut i = 0;
    for segment_index in 0..16 {
        let mut j = i;
        while j < relocs.len() && relocs[j].abs() >> 16 == segment_index {
            j += 1;
        }
        // The try_into cannot fail; for that to happen, the input EXE must
        // have contained at least 0x10000 relocations, which is impossible to
        // represent in the e_crlc field.
        push_u16le(buf, (j - i).try_into().unwrap());
        for pointer in relocs[i..j].iter() {
            push_u16le(buf, (pointer.abs() & 0xffff) as u16);
        }
        i = j;
    }
    if i < relocs.len() {
        return Err(FormatError::RelocationAddrTooLarge(relocs[i]));
    }
    Ok(())
}

/// Pack an input executable and return the elements of the packed executable.
pub fn pack(exe: &exe::Exe) -> Result<exe::Exe, FormatError> {
    let mut uncompressed = exe.body.clone();
    // Pad uncompressed to a multiple of 16 bytes.
    {
        let len = round_up(uncompressed.len(), 16).unwrap();
        uncompressed.resize(len, 0x00);
    }
    assert_eq!(uncompressed.len() % 16, 0);

    let mut compressed = Vec::new();
    compress(&mut compressed, &uncompressed);
    // Pad compressed to a multiple of 16 bytes.
    {
        let len = round_up(compressed.len(), 16).unwrap();
        compressed.resize(len, 0xff);
    }
    assert_eq!(compressed.len() % 16, 0);

    let mut relocs_buf = Vec::new();
    encode_relocs(&mut relocs_buf, &exe.relocs)?;


    // Now we have the pieces we need. Start putting together the output EXE.
    // The `body` vec will hold the EXE body (everything after the header).
    let mut body = Vec::new();

    // Start with the padded, compressed data.
    body.extend(compressed.iter());

    // Next, the 18-byte EXEPACK header.
    let exepack_size = (18 as usize)
        .checked_add(STUB.len()).unwrap()
        .checked_add(relocs_buf.len()).unwrap();
    encode_exepack_header(&mut body, &Header {
        real_ip: exe.e_ip,
        real_cs: exe.e_cs,
        exepack_size: exepack_size.try_into()
            .or(Err(FormatError::ExepackTooLong(exepack_size)))?,
        real_sp: exe.e_sp,
        real_ss: exe.e_ss,
        dest_len: (uncompressed.len() / 16).try_into()
            .or(Err(FormatError::UncompressedTooLong(uncompressed.len())))?,
        skip_len: 1,
        signature: EXEPACK_MAGIC,
    });

    // Then the stub itself.
    body.extend(STUB.iter());

    // Finally, the packed relocation table.
    body.extend(relocs_buf.iter());


    // Now that we know how big the output will be, we can build the output EXE.
    // The code segment points at the EXEPACK header, immediately after the
    // compressed data.
    let e_cs = (compressed.len() / 16).try_into()
        .or(Err(FormatError::CompressedTooLong(compressed.len())))?;
    // When the decompression stub runs, it will copy itself to a location
    // higher in memory (past the end of the uncompressed data size) so that the
    // decompression process doesn't overwrite it while it is running. But we
    // also have to account for the possibility that the uncompressed data size
    // lies in the middle of the decompression stub--in that case the stub would
    // be overwritten while it is running not by the decompression, but by its
    // own copy operation. The decompression stub knows about this possibility
    // and will copy itself to the end of uncompressed data or to the end of
    // itself, whichever is greater. We need to do the same here with regard to
    // the stack segment, placing it at least exepack_size past whichever
    // address the stub will copy itself to.
    // The Microsoft EXEPACK stubs don't handle the latter situation and the
    // compressor instead refuses to work when it arises: "L1114 file not
    // suitable for /EXEPACK; relink without".
    // https://archive.org/details/bitsavers_ibmpcdos15lReferenceJul88_10507385/page/n128?q=EXEPACK
    let (e_ss, e_sp) = {
        let len = cmp::max(uncompressed.len(), body.len()) + exepack_size;
        // Reserve 16 bytes for the stack. The stub doesn't need much.
        let stack_pointer = round_up(len, 16).unwrap() + 16;
        // Now, shift as many bits as possible from the segment to the offset,
        // because we have to encode e_sp in the EXE header and we can compress
        // slightly larger files if it's smaller.
        if stack_pointer <= 0xffff {
            (0u16, stack_pointer as u16)
        } else {
            let e_sp = 0xfff0 | (stack_pointer & 0xf);
            let e_ss = (stack_pointer - e_sp) >> 4;
            (
                e_ss.try_into().or(Err(FormatError::SSTooLarge(e_ss)))?,
                e_sp.try_into().unwrap(),
            )
        }
    };
    Ok(exe::Exe {
        e_minalloc: exe.e_minalloc,
        e_maxalloc: exe.e_maxalloc,
        e_ss: e_ss,
        e_sp: e_sp,
        e_ip: 18, // Stub begins just after the EXEPACK header.
        e_cs: e_cs,
        e_ovno: exe.e_ovno,
        body,
        relocs: Vec::new(), // No relocations at the EXEPACK layer.
    })
}

/// Return a new index after reading up to 15 bytes of 0xff padding from the end
/// of `buf[..i]`.
fn unpad(buf: &[u8], mut i: usize) -> usize {
    for _ in 0..15 {
        if i == 0 {
            break;
        }
        if buf[i - 1] != 0xff {
            break;
        }
        i -= 1;
    }
    i
}

/// The basic decompression loop. The compressed data are read (going backwards)
/// starting at `src`, and written (also going backwards) back to the same buffer
/// starting at `dst`.
///
/// <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Decompression_algorithm>
fn decompress(buf: &mut [u8], mut dst: usize, mut src: usize) -> Result<(), FormatError> {
    let original_src = src;
    loop {
        // Read the command byte.
        src = src.checked_sub(1).ok_or(FormatError::SrcOverflow())?;
        let command = buf[src];
        // Read the 16-bit length.
        src = src.checked_sub(2).ok_or(FormatError::SrcOverflow())?;
        let length = u16::from_le_bytes(buf[src..src+2].try_into().unwrap()) as usize;
        match command & 0xfe {
            0xb0 => {
                src = src.checked_sub(1).ok_or(FormatError::SrcOverflow())?;
                let fill = buf[src];
                // debug!("0x{:02x} fill {} 0x{:02x}", command, length, fill);
                dst = dst.checked_sub(length).ok_or(FormatError::FillOverflow(dst, src, command, length, fill))?;
                for i in 0..length {
                    buf[dst + i] = fill;
                }
            }
            0xb2 => {
                // debug!("0x{:02x} copy {}", command, length);
                src = src.checked_sub(length).ok_or(FormatError::SrcOverflow())?;
                dst = dst.checked_sub(length).ok_or(FormatError::CopyOverflow(dst, src, command, length))?;
                for i in 0..length {
                    buf[dst + length - i - 1] = buf[src + length - i - 1];
                }
            }
            _ => {
                return Err(FormatError::BogusCommand(src+2, command, length));
            }
        }
        if command & 0x01 != 0 {
            break;
        }
    }
    if original_src < dst {
        // Decompression finished okay but left a gap of uninitialized bytes.
        return Err(FormatError::Gap(dst, original_src));
    }
    Ok(())
}

const EXEPACK_MAGIC: u16 = 0x4252; // "RB"

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#EXEPACK_variables
#[derive(Debug)]
struct Header {
    real_ip: u16,
    real_cs: u16,
    // "mem_start" is actually just scratch space for the decompression stub.
    exepack_size: u16,
    real_sp: u16,
    real_ss: u16,
    dest_len: u16,
    skip_len: u16,
    signature: u16,
}

fn parse_exepack_header(mut buf: &[u8]) -> Result<Header, FormatError> {
    let uses_skip_len = match buf.len() {
        16 => false,
        18 => true,
        _ => return Err(FormatError::UnknownHeaderLength(buf.len())),
    };

    let real_ip = read_u16le(&mut buf).unwrap();
    let real_cs = read_u16le(&mut buf).unwrap();
    read_u16le(&mut buf).unwrap(); // Ignore "mem_start".
    let exepack_size = read_u16le(&mut buf).unwrap();
    let real_sp = read_u16le(&mut buf).unwrap();
    let real_ss = read_u16le(&mut buf).unwrap();
    let dest_len = read_u16le(&mut buf).unwrap();
    let skip_len = if uses_skip_len {
        read_u16le(&mut buf).unwrap()
    } else {
        1
    };
    let signature = read_u16le(&mut buf).unwrap();
    if signature != EXEPACK_MAGIC {
        return Err(FormatError::BadMagic(signature));
    }

    Ok(Header {
        real_ip,
        real_cs,
        exepack_size,
        real_sp,
        real_ss,
        dest_len,
        skip_len,
        signature,
    })
}

fn encode_exepack_header(buf: &mut Vec<u8>, header: &Header) {
    push_u16le(buf, header.real_ip);
    push_u16le(buf, header.real_cs);
    push_u16le(buf, 0); // mem_start
    push_u16le(buf, header.exepack_size);
    push_u16le(buf, header.real_sp);
    push_u16le(buf, header.real_ss);
    push_u16le(buf, header.dest_len);
    push_u16le(buf, header.skip_len);
    push_u16le(buf, header.signature);
}

/// Finds the end of a decompression stub (the executable code following the
/// EXEPACK header and preceding the packed relocation table). Returns
/// `Some(offset)` if the end of the stub was found; `None` otherwise.
///
/// There are many different decompression stubs. See some examples in the doc
/// directory. What they all have in common is a suffix of
/// `b"\xcd\x21\xb8\xff\x4c\xcd\x21"` (standing for the instructions
/// `int 0x21; mov ax, 0x4cff; int 0x21`), followed by a 22-byte error string,
/// most often `b"Packed file is corrupt"`.
fn locate_end_of_stub(stub: &[u8]) -> Option<usize> {
    const SUFFIX: &'static [u8] = b"\xcd\x21\xb8\xff\x4c\xcd\x21";
    for (i, window) in stub.windows(SUFFIX.len()).enumerate() {
        if window == SUFFIX {
            return Some(i + SUFFIX.len() + 22);
        }
    }
    None
}

// http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Relocation_Table
fn parse_exepack_relocs(buf: &[u8]) -> Option<(usize, Vec<exe::Pointer>)> {
    let mut relocs = Vec::new();
    let mut i = 0;
    for segment in 0..16 {
        if i + 2 > buf.len() {
            return None;
        }
        let num_relocs = u16::from_le_bytes(buf[i..i+2].try_into().unwrap());
        i += 2;
        for _ in 0..num_relocs {
            if i + 2 > buf.len() {
                return None;
            }
            let offset = u16::from_le_bytes(buf[i..i+2].try_into().unwrap());
            i += 2;
            relocs.push(exe::Pointer {
                segment: segment * 0x1000,
                offset: offset,
            });
        }
    }
    Some((i, relocs))
}

/// Unpack an input executable and return the elements of an unpacked executable.
pub fn unpack(exe: &exe::Exe) -> Result<exe::Exe, FormatError> {
    if !exe.relocs.is_empty() {
        return Err(FormatError::RelocationsNotSupported);
    }

    // Compressed data starts immediately after the EXE header and ends at
    // cs:0000.
    let mut work_buffer = exe.body.clone();

    // The EXEPACK header starts at cs:0000 and ends at cs:ip.
    let exepack_header_offset = exe.e_cs as usize * 16;
    if exepack_header_offset > work_buffer.len() {
        return Err(FormatError::HeaderPastEndOfFile(exepack_header_offset as u64));
    }
    let mut exepack_header_buf = work_buffer.split_off(exepack_header_offset);

    // The decompression stub starts at cs:ip.
    let exepack_header_len = exe.e_ip as usize;
    if exepack_header_len > exepack_header_buf.len() {
        return Err(FormatError::HeaderPastEndOfFile(exepack_header_offset as u64));
    }
    let mut stub = exepack_header_buf.split_off(exepack_header_len);

    let exepack_header = parse_exepack_header(&exepack_header_buf)?;
    debug!("{:?}", exepack_header);

    // The EXEPACK header's exepack_size field contains the length of the
    // EXEPACK header, the decompression stub, and the relocation table all
    // together. The decompression stub uses this value to control how much of
    // itself to copy out of the way before starting the main compression loop.
    // Truncate what remains of the buffer to exepack_size, taking into account
    // that we have already read exepack_header_buf.
    stub.truncate((exepack_header.exepack_size as usize).checked_sub(exepack_header_buf.len())
        .ok_or(FormatError::ExepackTooShort(exepack_header.exepack_size))?
    );

    // The decompression stub ends at a point determined by pattern matching.
    // The packed relocation table follows immediately after.
    let stub_len = locate_end_of_stub(&stub)
        .ok_or(FormatError::UnknownStub(exepack_header_buf.clone(), stub.clone()))?;
    debug!("found stub of length {}", stub_len);
    let relocs_buf = stub.split_off(stub_len);

    // Parse the packed relocation table.
    let relocs = {
        let (i, relocs) = parse_exepack_relocs(&relocs_buf)
            .ok_or(FormatError::ExepackTooShort(exepack_header.exepack_size))?;
        debug!("{:?}", relocs);
        // If there is any trailing data here, it means that exepack_size was
        // too big compared to our reckoning of where the packed relocation
        // table started; in other words it's possible that read_stub didn't
        // find the end of the stub correctly. Report this as an UnknownStub
        // error.
        if i != relocs_buf.len() {
            return Err(FormatError::UnknownStub(exepack_header_buf.clone(), stub.clone()));
        }
        relocs
    };

    // The skip_len variable is 1 greater than the number of paragraphs of
    // padding between the compressed data and the EXEPACK header. It cannot be
    // 0 because that would mean −1 paragraphs of padding.
    let skip_len = 16 * (exepack_header.skip_len as usize).checked_sub(1)
        .ok_or(FormatError::SkipTooShort(exepack_header.skip_len))?;
    // It's weird that skip_len applies to both the compressed and uncompressed
    // lengths, but it does. Which seems to make skip_len pointless. If skip_len
    // applied only to the uncompressed length, it could be useful for
    // decoupling the end of decompression buffer and the location to which the
    // EXEPACK copies itself, in the case where the end of the decompression
    // buffer lies within the EXEPACK block, which would cause the EXEPACK block
    // to clobber itself while it is still running. But it doesn't. (Our custom
    // STUB has extra logic to handle that case, but the Microsoft stubs do
    // not.)
    let compressed_len = work_buffer.len().checked_sub(skip_len)
        .ok_or(FormatError::SkipTooLong(exepack_header.skip_len))?;
    let uncompressed_len = (exepack_header.dest_len as usize * 16).checked_sub(skip_len)
        .ok_or(FormatError::SkipTooLong(exepack_header.skip_len))?;
    // Expand the buffer, if needed, to hold the uncompressed data.
    work_buffer.resize(cmp::max(compressed_len, uncompressed_len), 0);
    // Remove 0xff padding.
    let compressed_len = unpad(&work_buffer, compressed_len);
    // Now let's actually decompress the buffer.
    decompress(&mut work_buffer, uncompressed_len, compressed_len)?;
    // Decompression might have shrunk the input; trim the buffer if so.
    work_buffer.resize(uncompressed_len, 0);

    // Finally, construct a new EXE.
    Ok(exe::Exe {
        e_minalloc: exe.e_minalloc,
        e_maxalloc: exe.e_maxalloc,
        e_ss: exepack_header.real_ss,
        e_sp: exepack_header.real_sp,
        e_ip: exepack_header.real_ip,
        e_cs: exepack_header.real_cs,
        e_ovno: exe.e_ovno,
        body: work_buffer,
        relocs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    #[test]
    fn test_unpad() {
        // unpadding can leave an empty buffer
        assert_eq!(unpad(&[0xff, 0xff], 2), 0, "{:?}", &[0xff, 0xff]);
        // 0 to 15 bytes of padding is okay
        for pad_len in 0..16 {
            let input: Vec<_> = [0xaa, 0xaa, 0xaa].iter().cloned()
                .chain(iter::repeat(0xff).take(pad_len))
                .collect();
            assert_eq!(unpad(&input, input.len()), 3, "{:?}", input);
        }
        // shouldn't read 16 or more bytes of padding
        for pad_len in 16..24 {
            let input: Vec<_> = [0xaa, 0xaa, 0xaa].iter().cloned()
                .chain(iter::repeat(0xff).take(pad_len))
                .collect();
            assert_eq!(unpad(&input, input.len()), pad_len - 12, "{:?}", input);
        }
    }

    const COPY: u8 = 0xb2;
    const FILL: u8 = 0xb0;
    const FINAL: u8 = 0x01;

    // non-mutating version of decompress, return the trimmed, decompressed
    // output instead of modifying the input in place.
    fn decompress_new(buf: &[u8], dst: usize, src: usize) -> Result<Vec<u8>, FormatError> {
        let mut work: Vec<_> = buf.to_vec();
        match decompress(&mut work, dst, src) {
            Ok(_) => { work.resize(dst, 0); Ok(work) },
            Err(e) => Err(e),
        }
    }

    #[test]
    fn test_decompress_boguscommand() {
        assert_eq!(decompress_new(&[0x00, 0x00, 0xaa], 3, 3), Err(FormatError::BogusCommand(2, 0xaa, 0)));
        assert_eq!(decompress_new(&[0x34, 0x12, 0xaa, 0xbb, 0x01, 0x00, COPY], 7, 7), Err(FormatError::BogusCommand(2, 0xaa, 0x1234)));
        assert_eq!(decompress_new(&[0x00, 0x34, 0x12, 0xaa, 0xbb, 0x01, 0x00, FILL], 8, 8), Err(FormatError::BogusCommand(3, 0xaa, 0x1234)));
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
            assert_eq!(decompress_new(input, input.len(), input.len()), Err(FormatError::SrcOverflow()), "{:?}", input);
        }
    }

    #[test]
    fn test_decompress_crossover() {
        // dst overwrites src with something bogus
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL, 0xff, 0xff], 9, 7), Err(FormatError::BogusCommand(2, 0xaa, 0x0000)));
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL, 0xff], 8, 7), Err(FormatError::BogusCommand(2, 0xaa, 0xaa00)));
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL], 7, 7), Err(FormatError::BogusCommand(2, 0xaa, 0xaaaa)));
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x01, 0x00, COPY], 3, 7), Err(FormatError::BogusCommand(2, 0xaa, 0x0000)));

        // dst overwrites src with a valid command
        assert_eq!(decompress_new(&[0xaa, 0x01, 0x00, 0xff, COPY|FINAL, 0x01, 0x00, FILL], 4, 8), Ok(vec![0xaa, 0x01, 0xaa, COPY|FINAL]));
        assert_eq!(decompress_new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0x01, 0x00, COPY|FINAL, 0x04, 0x00, COPY], 5, 12), Ok(vec![0xaa, 0xaa, 0x01, 0x00, COPY|FINAL]));
    }

    #[test]
    fn test_decompress_filloverflow() {
        let inputs: &[(&[u8], usize)] = &[
            (&[0xaa, 0x01, 0x00, FILL|FINAL], 0),
            (&[0xaa, 0x10, 0x00, FILL|FINAL], 15),
        ];
        for &(input, dst) in inputs {
            let src = input.len();
            let mut work = input.to_vec();
            if dst > src {
                work.resize(dst, 0);
            }
            match decompress_new(&work, dst, src) {
                Err(FormatError::FillOverflow(_, _, _, _, 0xaa)) => (),
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
            let mut work = input.to_vec();
            if dst > src {
                work.resize(dst, 0);
            }
            match decompress_new(&work, dst, src) {
                Err(FormatError::CopyOverflow(_, _, _, _)) => (),
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
            let mut work = input.to_vec();
            if dst > src {
                work.resize(dst, 0);
            }
            match decompress_new(&work, dst, src) {
                Err(FormatError::Gap(_, _)) => (),
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
            let mut work = input.to_vec();
            if dst > src {
                work.resize(dst, 0);
            }
            assert_eq!(&decompress_new(&work, dst, src).unwrap(), &output);
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
            compress(&mut work, input);
            let compressed_len = work.len();
            if work.len() < input.len() {
                work.resize(input.len(), 0);
            }
            decompress(&mut work, input.len(), compressed_len).unwrap();
            assert_eq!(&&work[0..input.len()], input);
        }
    }
}