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
use std::io::{self, Read};

use exe;
use pointer::Pointer;

/// Our pre-assembled decompression stub.
pub const STUB: [u8; 283] = *include_bytes!("stub.bin");

/// Round `n` up to the next multiple of `m`.
fn round_up(n: usize, m: usize) -> Option<usize> {
    n.checked_add((m - n % m) % m)
}

/// Reads a little-endian `u16` from `r`.
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
    RelocationAddrTooLarge(Pointer),
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
/// # References
///
/// * <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Decompression_algorithm>
fn compress(output: &mut Vec<u8>, input: &[u8]) {
    // Since we produce our own self-extracting executable, technically we
    // could compress however we like. But we want to remain compatible with
    // https://github.com/w4kfu/unEXEPACK and other external EXEPACK unpackers,
    // so we use the standard EXEPACK encoding: 0xb2 for a Copy command, 0xb0
    // for a Fill command, LSb == 1 to mark the final command.
    //
    // The algorithm uses dynamic programming. We build three notional tables of
    // costs. "Cost" is the minimum number of bytes needed to compress a prefix
    // of the input:
    //
    //  * C[i] = the cost to compress input[..i], if we are in a Copy command at
    //           index i.
    //  * F[i] = the cost to compress input[..i], if we are in a Fill command at
    //           index i.
    //  * R[i] = the cost to compress input[..i], if we do not use any Copy or
    //           Fill commands up to index i. The R stands for "runout".
    //
    // We start with fictitious table entries C[-1] = 0, F[-1] = 0, R[-1] = 0.
    // We then fill out the rest of the table, working backwards, according to
    // the recurrences:
    //   C[i] = min(
    //     // start a new Copy command: [input[i], 01, 00, b2]
    //     min(C[i-1], F[i-1], R[i-1]) + 4,
    //     // continue an existing Copy command (only if i > 0, and the command
    //     // has length remaining)
    //     C[i-1] + 1,
    //   )
    //   F[i] = min(
    //     // start a new Fill command: [input[i], 01, 00, b0]
    //     min(C[i-1], F[i-1], R[i-1]) + 4,
    //     // continue an existing Fill command (only if i > 0, the command has
    //     // length remaining, and input[i] == input[i-1])
    //     F[i-1] + 0,
    //   )
    //   R[i] = i + 1     // if i < input.len() - 1
    //       or i + 1 + 3 // if i == input.len() - 1
    // The extra 3 in the final entry of the R table represents the fact that
    // there must be at least one command in the compressed stream. If we find
    // that the best way to compress the input is not to use any Copy or Fill
    // commands at all, we must at least append a dummy 3-byte length-zero Copy
    // command to give the decompressor something to work with.
    //
    // Along with every cost that we store in the C or F tables, we store the
    // command length that got us that cost.
    //
    // We then make a pass over the cost tables and decide on a command for each
    // index, according to which table has the minimum cost at that index. Each
    // Copy and Fill command has an associated length; Runout commands do not
    // have a length. Call this array of commands CMD. Now CMD[input.len() - 1]
    // tells us how we should start the compressed stream.
    //
    // We make a pass backward over the CMD table and remove the commands that
    // don't actually get used in the final compressed stream. That means, we
    // start at the end of CMD, and if we find a Copy(len) or Fill(len) command,
    // skip over that many commands, then repeat. We quit when we hit the first
    // Runout command, filling the remainder of the CMD array with Runouts.
    //
    // Finally, we pass forward over the reduced CMD array and emit code for
    // each command. For a Runout, we just copy the corresponding byte from the
    // input. For a Copy(len), we copy that many bytes from the input to the
    // output, and append the length and command code. For a Fill(len), we copy
    // the fill byte to the output, then append the length and the command code.
    // In the event that we get to the end of the CMD array having only seen
    // Runout commands, we emit an extra dummy Copy command.
    //
    // A greedy algorithm (one that uses Fill for runs of 5 or longer, Copy
    // otherwise) is not optimal. Consider the sequence
    //      ... 01 02 03 04 05 cc cc cc cc cc 01 02 03 04 05
    // (Assume the left side doesn't enter runout.) A greedy compressor would
    // compress it to 20 bytes:
    //      ... 01 02 03 04 05 05 00 b2 cc 05 00 b0 01 02 03 04 05 05 00 b2
    // i.e., a Copy of length 5, then a Fill of length 5, then a Copy of length
    // 5. But switching from Copy to Fill back to Copy costs more than
    // compressing the run of 5 cc's saves. A better compression is just one
    // long Copy, 18 bytes total:
    //      ... 01 02 03 04 05 cc cc cc cc cc 01 02 03 04 05 0f 00 b2
    //
    // But this algorithm is not completely optimal either. We don't take
    // advantage of certain optimizations involving self-referential or
    // self-modifying code. For example, suppose for a moment that the maximum
    // command length were 6 rather than 0xffff. Consider the 7-byte sequence
    //      cc cc cc cc cc cc cc
    // We will compress it into 5 bytes as
    //      cc cc 06 00 b1
    // (i.e., Fill(6) cc, then one Runout cc). But we could save 1 byte by
    // re-using one of the cc's both as a command parameter and as a runout
    // byte:
    //      cc 06 00 b1
    // For that matter, if we happened to get the 8-byte input
    //      cc 06 cc cc cc cc cc cc
    // we could re-use the 2 bytes cc 06 and compress as
    //      cc 06 00 b1

    // The maximum length of a Copy or Fill command.
    const MAX_LEN: u16 = 0xffff;

    #[derive(Clone, Copy)]
    enum Command {
        Copy(u16),
        Fill(u16),
        Runout,
    }
    let mut commands: Vec<Command> = Vec::with_capacity(input.len());

    // Stage 1: build the tables of costs and command lengths for each input
    // position.

    #[derive(Clone, Copy)]
    struct Entry {
        cost: usize,
        len: u16,
    }
    // Here is an optimization compared to the algorithm as described above.
    // Because a recurrence for index i refers at most to index i-1, we don't
    // have to remember the full C, F, and R tables. Instead we just remember
    // the most recent value. At the top of each iteration of the following
    // loop, copy.cost == C[i-1], fill.cost == F[i-1], and
    // runout_cost == R[i-1]; and at the bottom of the loop, copy.cost == C[i],
    // fill.cost == F[i], and runout_cost == R[i].
    let mut copy = Entry { cost: 0, len: 0 };
    let mut fill = Entry { cost: 0, len: 0 };
    let mut runout_cost: usize = 0;
    for i in 0..input.len() {
        // prev_min_cost = min(C[i-1], F[i-1], R[i-1])
        let prev_min_cost = copy.cost.min(fill.cost).min(runout_cost);

        copy = [
            // We always have the option of starting a new Copy command.
            Some(Entry { cost: prev_min_cost + 4, len: 1 }),
            // Or we may extend an existing Copy command, if its length is less
            // than the maximum.
            if i > 0 && copy.len < MAX_LEN {
                Some(Entry { cost: copy.cost + 1, len: copy.len + 1 })
            } else {
                None
            },
        ].into_iter().filter_map(|&x| x).min_by_key(|entry| entry.cost).unwrap();

        fill = [
            // We always have the option of starting a new Fill command.
            Some(Entry { cost: prev_min_cost + 4, len: 1 }),
            // Or we may extend an existing Copy command, if its length is less
            // than the maximum and the current input byte is equal to the
            // previous.
            if i > 0 && input[i] == input[i - 1] && fill.len < MAX_LEN {
                Some(Entry { cost: fill.cost + 0, len: fill.len + 1 })
            } else {
                None
            },
        ].into_iter().filter_map(|&x| x).min_by_key(|entry| entry.cost).unwrap();

        runout_cost = if i < input.len() - 1 {
            i + 1
        } else {
            i + 1 + 3
        };

        // Choose the command with the minimum cost and assign to CMD[i].
        let (_, cmd) = [
            (runout_cost, Command::Runout),
            (copy.cost, Command::Copy(copy.len)),
            (fill.cost, Command::Fill(fill.len)),
        ].into_iter().cloned().min_by_key(|&(cost, _)| cost).unwrap();
        commands.push(cmd);
    }

    // Stage 2: Retain only the commands that are reachable, starting from the
    // end of CMD.

    let mut commands_subset = Vec::new();
    let mut i = commands.len();
    while i > 0 {
        let cmd_ref = &commands[i - 1];
        match *cmd_ref {
            Command::Copy(len) => i -= len as usize,
            Command::Fill(len) => i -= len as usize,
            Command::Runout => break,
        }
        commands_subset.push(cmd_ref);
    }

    // Stage 3: Output the remaining commands.

    // i now points to the end of the runout. Another optimization here: we
    // don't store a bunch of Runout commands at the beginning of
    // commands_subset; we just memcpy the whole runout at once.
    output.extend_from_slice(&input[..i]);

    let mut is_final = 1;
    // commands_subset is in decompression order (back to front), but we need to
    // output it front to back.
    for cmd in commands_subset.into_iter().rev() {
        match *cmd {
            Command::Copy(len) => {
                output.extend_from_slice(&input[i..(i + len as usize)]);
                output.extend_from_slice(&len.to_le_bytes());
                output.push(0xb2 | is_final);
                is_final = 0;
                i += len as usize;
            }
            Command::Fill(len) => {
                output.push(input[i]);
                output.extend_from_slice(&len.to_le_bytes());
                output.push(0xb0 | is_final);
                is_final = 0;
                i += len as usize;
            }
            Command::Runout => panic!(),
        }
    }
    // If we got all the way to the end without emitting a Copy or Fill command,
    // we must append a dummy command. This is the worst case for an
    // incompressible input, an expansion of 3 bytes.
    if is_final != 0 {
        output.extend_from_slice(&0u16.to_le_bytes());
        output.push(0xb2 | is_final);
    }
}

/// Encode a compressed relocation table.
fn encode_relocs(buf: &mut Vec<u8>, relocs: &[Pointer]) -> Result<(), FormatError> {
    // http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Relocation_Table
    let mut relocs = relocs.to_vec();
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
    body.extend_from_slice(&compressed);

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
    body.extend_from_slice(&STUB);

    // Finally, the packed relocation table.
    body.extend_from_slice(&relocs_buf);


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
                dst = dst.checked_sub(length).ok_or(FormatError::FillOverflow(dst, src, command, length, fill))?;
                for i in 0..length {
                    buf[dst + i] = fill;
                }
            }
            0xb2 => {
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
fn parse_exepack_relocs(buf: &[u8]) -> Option<(usize, Vec<Pointer>)> {
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
            relocs.push(Pointer {
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
    let relocs_buf = stub.split_off(stub_len);

    // Parse the packed relocation table.
    let relocs = {
        let (i, relocs) = parse_exepack_relocs(&relocs_buf)
            .ok_or(FormatError::ExepackTooShort(exepack_header.exepack_size))?;
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
        for input in &[
            // empty buffer
            &[] as &[u8],
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
        ] {
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
        for &(input, dst) in &[
            (&[0xaa, 0x01, 0x00, FILL|FINAL] as &[u8], 0),
            (&[0xaa, 0x10, 0x00, FILL|FINAL], 15),
        ] {
            let src = input.len();
            let mut work = input.to_vec();
            work.resize(cmp::max(src, dst), 0);
            match decompress_new(&work, dst, src) {
                Err(FormatError::FillOverflow(_, _, _, _, 0xaa)) => (),
                x => panic!("{:?} {:?}", x, (input, dst)),
            }
        }
    }

    #[test]
    fn test_decompress_copyoverflow() {
        for &(input, dst) in &[
            (&[0xaa, 0x01, 0x00, COPY|FINAL] as &[u8], 0),
            (&[0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x05, 0x00, COPY|FINAL], 2),
        ] {
            let src = input.len();
            let mut work = input.to_vec();
            work.resize(cmp::max(src, dst), 0);
            match decompress_new(&work, dst, src) {
                Err(FormatError::CopyOverflow(_, _, _, _)) => (),
                x => panic!("{:?} {:?}", x, (input, dst)),
            }
        }
    }

    #[test]
    fn test_decompress_gap() {
        for &(input, dst) in &[
            (&[0x00, 0x00, COPY|FINAL] as &[u8], 4),
            (&[0xaa, 0x01, 0x00, COPY|FINAL], 6),
            (&[0xaa, 0x10, 0x00, FILL|FINAL], 21),
        ] {
            let src = input.len();
            let mut work = input.to_vec();
            work.resize(cmp::max(src, dst), 0);
            match decompress_new(&work, dst, src) {
                Err(FormatError::Gap(_, _)) => (),
                x => panic!("{:?} {:?}", x, (input, dst)),
            }
        }
    }

    #[test]
    fn test_decompress_ok() {
        for &(input, dst, output) in &[
            (&[0x01u8, 0x02, 0x03, 0x04, 0x05, 0x05, 0x00, COPY|FINAL] as &[u8], 5,
             &[0x01u8, 0x02, 0x03, 0x04, 0x05] as &[u8]),
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
        ] {
            let src = input.len();
            let mut work = input.to_vec();
            work.resize(cmp::max(src, dst), 0);
            assert_eq!(&decompress_new(&work, dst, src).unwrap(), &output);
        }
    }

    #[test]
    fn test_compress_roundtrip() {
        for input in &[
            &[] as &[u8],
            &[1],
            &[1, 2, 3, 4, 5],
            &[1, 2, 3, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1, 2, 3, 4],
            &[3, 3, 3, 3, 3, 3, 3, 3, 1, 2, 1, 2, 1, 2, 1, 2, 9, 9, 9, 9, 9, 9, 9, 9],
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
        ] {
            let mut work = Vec::new();
            compress(&mut work, input);
            let compressed_len = work.len();
            work.resize(cmp::max(compressed_len, input.len()), 0);
            decompress(&mut work, input.len(), compressed_len).unwrap();
        }
    }

    // Test that compress gets below certain thresholds for certain inputs.
    #[test]
    fn test_compress_density() {
        for (ordering, limit, input) in &[
            // empty input should compress to a length-zero Copy
            (cmp::Ordering::Equal, 3, &[] as &[u8]),
            // Fill command and Copy command are equal
            (cmp::Ordering::Equal, 4, &[1]),
            // should use a Fill command instead of a Copy command
            // an implementation may erroneously use a Copy here if not counting
            // the 3 bytes of the dummy copy after a runout
            (cmp::Ordering::Equal, 4, &[1, 1]),
            // cheaper to do the latter part as a long Copy instead of switching
            // Copy, Fill, Copy, Fill
            (cmp::Ordering::Less, 23, &[9, 9, 9, 9, 9, 9, 9, 9, 1, 2, 3, 4, 5, 9, 9, 9, 9, 9, 1, 2, 3, 4, 5]),
        ] {
            let mut work = Vec::new();
            compress(&mut work, &input);
            assert_eq!(work.len().cmp(limit), *ordering, "{} {:?}", work.len(), work);
        }
    }
}
