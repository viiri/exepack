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
//! * Some versions of EXEPACK have a bug when the offset of a segment:offset
//!   relocation entry is 0xffff: they write the second byte at address 0 in the
//!   same segment rather than the following segment.
//! * Some versions of EXEPACK don't restore the `ax` register before jumping to
//!   the decompressed program.
//! * If an executable contains relocations at the outer EXEPACK layer, they
//!   would be applied by DOS (presumably patching the compressed data) before
//!   decompression starts. This library doesn't permit such relocations.

use std::cmp;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::io::{self, Read};

use exe;
use pointer::Pointer;

/// The signature of an EXEPACK header, interpreted as a little-endian integer.
const SIGNATURE: u16 = 0x4252; // "RB"

/// The size of the EXEPACK header that we write.
const HEADER_LEN: usize = 18;

/// Our pre-assembled decompression stub.
pub const STUB: [u8; 283] = *include_bytes!("stub.bin");

/// An EXEPACK format error.
#[derive(Debug, PartialEq)]
pub enum FormatError {
    /// The compressed EXE has relocations.
    RelocationsNotSupported,
    /// The EXEPACK header, whose location and length are given by `cs` and `ip`
    /// in the EXE header, extends past the end of the file.
    HeaderPastEndOfFile { offset: usize, len: usize },
    /// The EXEPACK header length was not 16 or 18 bytes.
    UnknownHeaderLength { len: usize },
    /// The signature in the EXEPACK header did not have the expected value of
    /// `b"RB"`.
    Signature { signature: u16 },
    /// The EXEPACK block is too short to contain header, stub, and relocations.
    ExepackTooShort { exepack_size: u16 },
    /// The decompression stub is not one we recognize.
    UnknownStub { exepack_header: Vec<u8>, stub: Vec<u8> },
    /// `skip_len` is 0, or represents a size larger than either the compressed
    /// or uncompressed length.
    SkipLenInvalid { skip_len: u16 },
    /// Decompression reached the beginning of the compressed data before
    /// finding a termination command.
    SrcOverflow,
    /// A Fill command would extend past the beginning of the uncompressed data.
    FillOverflow { dst: usize, src: usize, command: u8, length: usize, fill: u8 },
    /// A Copy command would extend past the beginning of the uncompressed data.
    CopyOverflow { dst: usize, src: usize, command: u8, length: usize },
    /// The command byte was not any recognized command (Copy or Fill).
    UnknownCommand { src: usize, command: u8 },
    /// Decompression left a gap of uninitialized bytes between the decompressed
    /// data and the end of the original compressed data.
    Gap { dst: usize, compressed_len: usize },
    /// There are more than 0xffff relocations in a single segment, which cannot
    /// be represented in the packed relocation table.
    TooManyRelocations { segment: u16, num: usize },
    /// A relocation entry exceeded 20 bits.
    RelocationTooLarge { pointer: Pointer },
    /// The `exepack_size` field is too large to represent in the EXEPACK
    /// header.
    ExepackSizeTooLarge { exepack_size: usize },
    /// The `dest_len` field is too large to represent in the EXEPACK header.
    UncompressedSizeTooLarge { uncompressed_len: usize },
    /// The compressed size is too large to store in the `cs` field of the EXE
    /// header.
    CompressedSizeTooLarge { compressed_len: usize },
    /// The stack pointer is too large to represent in the `e_ss` and `e_sp`
    /// fields of the EXE header.
    StackPointerTooLarge { stack_pointer: usize },
}

impl std::error::Error for FormatError {}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FormatError::RelocationsNotSupported =>
                write!(f, "relocations before decompression are not supported"),
            FormatError::HeaderPastEndOfFile { offset, len } =>
                write!(f, "EXEPACK header extends past the end of the file (offset={}, len={})", offset, len),
            FormatError::UnknownHeaderLength { len } =>
                write!(f, "don't know how to interpret EXEPACK header of {} bytes", len),
            FormatError::Signature { signature } =>
                write!(f, "Bad EXEPACK header signature {:#04x}", signature),
            FormatError::ExepackTooShort { exepack_size } =>
                write!(f, "EXEPACK size {} is too short for header, stub, and relocations", exepack_size),
            FormatError::UnknownStub { .. } =>
                write!(f, "unknown decompression stub"),
            FormatError::SkipLenInvalid { skip_len } =>
                write!(f, "skip_len of {} paragraphs is invalid", skip_len),
            FormatError::SrcOverflow =>
                write!(f, "read overflow: reached the end of compressed data before seeing a termination command"),
            FormatError::FillOverflow { dst, length, fill, .. } =>
                write!(f, "write overflow: fill {}×'\\{:02x}' at index {}", length, fill, dst),
            FormatError::CopyOverflow { dst, length, .. } =>
                write!(f, "write overflow: copy {} bytes at index {}", length, dst),
            FormatError::UnknownCommand { src, command } =>
                write!(f, "unknown command {:#02x} at index {}", command, src),
            FormatError::Gap { dst, compressed_len } =>
                write!(f, "decompression left a gap of unwritten bytes between write index {} and original read index {}", dst, compressed_len),
            FormatError::TooManyRelocations { segment, num } =>
                write!(f, "too many relocations ({}) in segment {:#04x}", num, segment),
            FormatError::RelocationTooLarge { pointer } =>
                write!(f, "relocation address {} is too large to represent", pointer),
            FormatError::ExepackSizeTooLarge { exepack_size } =>
                write!(f, "EXEPACK size {} is too large to represent", exepack_size),
            FormatError::UncompressedSizeTooLarge { uncompressed_len } =>
                write!(f, "uncompressed size {} is too large to represent", uncompressed_len),
            FormatError::CompressedSizeTooLarge { compressed_len } =>
                write!(f, "compressed size {} is too large to represent", compressed_len),
            FormatError::StackPointerTooLarge { stack_pointer } =>
                write!(f, "stack pointer {:#x} is too large to represent", stack_pointer),
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
            Command::Copy(len) => i -= usize::from(len),
            Command::Fill(len) => i -= usize::from(len),
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
                output.extend_from_slice(&input[i..(i + usize::from(len))]);
                output.extend_from_slice(&len.to_le_bytes());
                output.push(0xb2 | is_final);
                is_final = 0;
                i += usize::from(len);
            }
            Command::Fill(len) => {
                output.push(input[i]);
                output.extend_from_slice(&len.to_le_bytes());
                output.push(0xb0 | is_final);
                is_final = 0;
                i += usize::from(len);
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

/// Returns a new index after skipping up to 15 bytes of 0xff padding from the
/// end of `buf[..i]`.
fn unpad(buf: &[u8], i: usize) -> usize {
    i - buf[..i].iter().rev().take(15).take_while(|&&x| x == 0xff).count()
}

/// The basic decompression loop. The compressed data are read (going backwards)
/// starting at `src`, and written (also going backwards) back to the same buffer
/// starting at `dst`.
///
/// # References
///
/// * <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Decompression_algorithm>
fn decompress(buf: &mut Vec<u8>, compressed_len: usize, uncompressed_len: usize)
-> Result<(), FormatError> {
    let mut src = compressed_len;
    let mut dst = uncompressed_len;

    // Expand the work buffer to the uncompressed size, if necessary.
    if dst > buf.len() {
        buf.resize(dst, 0);
    }

    // Skip over 0xff padding.
    src = unpad(&buf, src);

    loop {
        // Read the command byte.
        src = src.checked_sub(1).ok_or(FormatError::SrcOverflow)?;
        let command = buf[src];

        // Read the 16-bit length.
        src = src.checked_sub(2).ok_or(FormatError::SrcOverflow)?;
        let length = usize::from(u16::from_le_bytes(buf[src..src+2].try_into().unwrap()));

        match command & 0xfe {
            0xb0 => {
                src = src.checked_sub(1).ok_or(FormatError::SrcOverflow)?;
                let fill = buf[src];
                dst = dst.checked_sub(length).ok_or(FormatError::FillOverflow { dst, src, command, length, fill })?;
                for i in 0..length {
                    buf[dst + i] = fill;
                }
            }
            0xb2 => {
                src = src.checked_sub(length).ok_or(FormatError::SrcOverflow)?;
                dst = dst.checked_sub(length).ok_or(FormatError::CopyOverflow { dst, src, command, length })?;
                for i in 0..length {
                    buf[dst + length - i - 1] = buf[src + length - i - 1];
                }
            }
            _ => {
                return Err(FormatError::UnknownCommand { src: src + 2, command });
            }
        }

        if command & 0x01 != 0 {
            break;
        }
    }

    if compressed_len < dst {
        // The dst pointer did not catch up to the end of the original
        // uncompressed data, leaving a gap of uninitialized bytes.
        return Err(FormatError::Gap { dst, compressed_len });
    }

    // Trim to uncompressed_len, in case compressed_len was greater.
    buf.truncate(uncompressed_len);

    Ok(())
}

/// Reads a little-endian `u16` from `r`.
fn read_u16le<R: Read + ?Sized>(r: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

/// Appends a little-endian `u16` to `buf`.
fn push_u16le(buf: &mut Vec<u8>, v: u16) {
    buf.extend(&u16::to_le_bytes(v));
}

/// An EXEPACK header.
///
/// # References
///
/// * <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#EXEPACK_variables>
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
}

impl Header {
    /// Parses an EXEPACK header into a `Header` structure.
    pub fn parse(mut buf: &[u8]) -> Result<Self, FormatError> {
        let uses_skip_len = match buf.len() {
            16 => false,
            18 => true,
            _ => return Err(FormatError::UnknownHeaderLength { len: buf.len() }),
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
        if signature != SIGNATURE {
            return Err(FormatError::Signature { signature });
        }

        Ok(Self {
            real_ip,
            real_cs,
            exepack_size,
            real_sp,
            real_ss,
            dest_len,
            skip_len,
        })
    }

    /// Appends an encoded `Header` to `buf`.
    pub fn write(&self, buf: &mut Vec<u8>) {
        push_u16le(buf, self.real_ip);
        push_u16le(buf, self.real_cs);
        push_u16le(buf, 0); // mem_start
        push_u16le(buf, self.exepack_size);
        push_u16le(buf, self.real_sp);
        push_u16le(buf, self.real_ss);
        push_u16le(buf, self.dest_len);
        push_u16le(buf, self.skip_len);
        push_u16le(buf, SIGNATURE);
    }
}

/// Rounds `n` up to the next multiple of `m`.
fn round_up(n: usize, m: usize) -> Option<usize> {
    n.checked_add((m - n % m) % m)
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
        let num = j - i;
        push_u16le(buf, num.try_into()
            .or(Err(FormatError::TooManyRelocations { segment: (segment_index << 12) as u16, num }))?);
        for pointer in relocs[i..j].iter() {
            push_u16le(buf, pointer.abs() as u16);
        }
        i = j;
    }
    if i < relocs.len() {
        return Err(FormatError::RelocationTooLarge { pointer: relocs[i] });
    }
    Ok(())
}

/// Compresses an input `exe::Exe` and returns the result as a new `exe::Exe`.
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

    // Encode the packed relocation table now, because we will need to know its
    // length to compute exepack_size.
    let mut relocs_buf = Vec::new();
    encode_relocs(&mut relocs_buf, &exe.relocs)?;

    // Now we have the pieces we need. Start putting together the output EXE.
    // The `body` vec will hold the EXE body (everything after the header).
    let mut body = Vec::new();

    // Start with the padded, compressed data.
    body.extend_from_slice(&compressed);

    // Next, the 18-byte EXEPACK header.
    let exepack_size = HEADER_LEN
        .checked_add(STUB.len()).unwrap()
        .checked_add(relocs_buf.len()).unwrap();
    Header {
        real_ip: exe.e_ip,
        real_cs: exe.e_cs,
        exepack_size: exepack_size.try_into()
            .or(Err(FormatError::ExepackSizeTooLarge { exepack_size }))?,
        real_sp: exe.e_sp,
        real_ss: exe.e_ss,
        dest_len: (uncompressed.len() / 16).try_into()
            .or(Err(FormatError::UncompressedSizeTooLarge { uncompressed_len: uncompressed.len() }))?,
        skip_len: 1,
    }.write(&mut body);

    // Then the stub itself.
    body.extend_from_slice(&STUB);

    // Finally, the packed relocation table.
    body.extend_from_slice(&relocs_buf);

    // Now that we know how big the output will be, we can build the output EXE.
    // The code segment points at the EXEPACK header, immediately after the
    // compressed data.
    let e_cs = (compressed.len() / 16).try_into()
        .or(Err(FormatError::CompressedSizeTooLarge { compressed_len: compressed.len() }))?;
    // When the decompression stub runs, it will copy itself to a location
    // higher in memory (past the end of the uncompressed data size) so that the
    // decompression process doesn't overwrite it while it is running. But we
    // also have to account for the possibility that the uncompressed data size
    // lies in the middle of the decompression stub--in that case the stub would
    // be overwritten while it is running not by the decompression, but by its
    // own copy operation. Our decompression stub knows about this possibility
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
        if let Ok(e_sp) = u16::try_from(stack_pointer) {
            (0u16, e_sp)
        } else {
            let e_sp = 0xfff0 | (stack_pointer & 0xf);
            let e_ss = (stack_pointer - e_sp) >> 4;
            (
                e_ss.try_into().or(Err(FormatError::StackPointerTooLarge { stack_pointer }))?,
                e_sp.try_into().unwrap(),
            )
        }
    };
    Ok(exe::Exe {
        e_minalloc: exe.e_minalloc,
        e_maxalloc: exe.e_maxalloc,
        e_ss, e_sp,
        e_ip: HEADER_LEN.try_into().unwrap(), // Stub begins just after the EXEPACK header.
        e_cs,
        e_ovno: exe.e_ovno,
        body,
        relocs: Vec::new(), // No relocations at the EXEPACK layer.
    })
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

/// Parses a packed EXEPACK relocation table.
///
/// # References
///
/// * http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#Relocation_Table
fn parse_relocs(buf: &[u8]) -> Option<(usize, Vec<Pointer>)> {
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

/// Uncompresses an `exe::Exe` and returns the result as a new `exe::Exe`.
pub fn unpack(exe: &exe::Exe) -> Result<exe::Exe, FormatError> {
    if !exe.relocs.is_empty() {
        return Err(FormatError::RelocationsNotSupported);
    }

    // Compressed data starts immediately after the EXE header and ends at
    // cs:0000.
    let mut work_buffer = exe.body.clone();

    // The EXEPACK header starts at cs:0000 and ends at cs:ip.
    let exepack_header_offset = usize::from(exe.e_cs) * 16;
    let exepack_header_len = usize::from(exe.e_ip);
    if exepack_header_offset > work_buffer.len() {
        return Err(FormatError::HeaderPastEndOfFile { offset: exepack_header_offset, len: exepack_header_len });
    }
    let mut exepack_header = work_buffer.split_off(exepack_header_offset);

    // The decompression stub starts at cs:ip.
    if exepack_header_len > exepack_header.len() {
        return Err(FormatError::HeaderPastEndOfFile { offset: exepack_header_offset, len: exepack_header_len });
    }
    let mut stub = exepack_header.split_off(exepack_header_len);

    let header = Header::parse(&exepack_header)?;

    // The EXEPACK header's exepack_size field contains the length of the
    // EXEPACK header, the decompression stub, and the relocation table all
    // together. The decompression stub uses this value to control how much of
    // itself to copy out of the way before starting the main compression loop.
    // Truncate what remains of the buffer to exepack_size, taking into account
    // that we have already read exepack_header.
    stub.truncate(usize::from(header.exepack_size).checked_sub(exepack_header.len())
        .ok_or(FormatError::ExepackTooShort { exepack_size: header.exepack_size })?
    );

    // The decompression stub ends at a point determined by pattern matching.
    // The packed relocation table follows immediately after.
    let stub_len = locate_end_of_stub(&stub)
        .ok_or(FormatError::UnknownStub { exepack_header: exepack_header.clone(), stub: stub.clone() })?;
    let relocs_buf = stub.split_off(stub_len);

    // Parse the packed relocation table.
    let relocs = {
        let (i, relocs) = parse_relocs(&relocs_buf)
            .ok_or(FormatError::ExepackTooShort { exepack_size: header.exepack_size })?;
        // If there is any trailing data here, it means that exepack_size was
        // too big compared to our reckoning of where the packed relocation
        // table started; in other words it's possible that read_stub didn't
        // find the end of the stub correctly. Report this as an UnknownStub
        // error.
        if i != relocs_buf.len() {
            return Err(FormatError::UnknownStub { exepack_header: exepack_header.clone(), stub: stub.clone() });
        }
        relocs
    };

    // The skip_len variable is 1 greater than the number of paragraphs of
    // padding between the compressed data and the EXEPACK header. It cannot be
    // 0 because that would mean −1 paragraphs of padding.
    let skip_len = 16 * usize::from(header.skip_len).checked_sub(1)
        .ok_or(FormatError::SkipLenInvalid { skip_len: header.skip_len })?;
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
        .ok_or(FormatError::SkipLenInvalid { skip_len: header.skip_len })?;
    let uncompressed_len = (usize::from(header.dest_len) * 16).checked_sub(skip_len)
        .ok_or(FormatError::SkipLenInvalid { skip_len: header.skip_len })?;

    // Now let's actually decompress the buffer.
    decompress(&mut work_buffer, compressed_len, uncompressed_len)?;

    // Finally, construct a new EXE.
    Ok(exe::Exe {
        e_minalloc: exe.e_minalloc,
        e_maxalloc: exe.e_maxalloc,
        e_ss: header.real_ss,
        e_sp: header.real_sp,
        e_ip: header.real_ip,
        e_cs: header.real_cs,
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
    fn decompress_new(buf: &[u8], src: usize, dst: usize) -> Result<Vec<u8>, FormatError> {
        let mut work: Vec<_> = buf.to_vec();
        match decompress(&mut work, src, dst) {
            Ok(_) => Ok(work),
            Err(e) => Err(e),
        }
    }

    #[test]
    fn test_decompress_boguscommand() {
        assert_eq!(decompress_new(&[0x00, 0x00, 0xaa], 3, 3), Err(FormatError::UnknownCommand { src: 2, command: 0xaa }));
        assert_eq!(decompress_new(&[0x34, 0x12, 0xaa, 0xbb, 0x01, 0x00, COPY], 7, 7), Err(FormatError::UnknownCommand { src: 2, command: 0xaa }));
        assert_eq!(decompress_new(&[0x00, 0x34, 0x12, 0xaa, 0xbb, 0x01, 0x00, FILL], 8, 8), Err(FormatError::UnknownCommand { src: 3, command: 0xaa }));
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
            assert_eq!(decompress_new(input, input.len(), input.len()), Err(FormatError::SrcOverflow), "{:?}", input);
        }
    }

    #[test]
    fn test_decompress_crossover() {
        // dst overwrites src with something bogus
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL, 0xff, 0xff], 7, 9),
                   Err(FormatError::UnknownCommand { src: 2, command: 0xaa }));
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL, 0xff], 7, 8),
                   Err(FormatError::UnknownCommand { src: 2, command: 0xaa }));
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x07, 0x00, FILL], 7, 7),
                   Err(FormatError::UnknownCommand { src: 2, command: 0xaa }));
        assert_eq!(decompress_new(&[0x00, 0x00, COPY|FINAL, 0xaa, 0x01, 0x00, COPY], 7, 3),
                   Err(FormatError::UnknownCommand { src: 2, command: 0xaa }));

        // dst overwrites src with a valid command
        assert_eq!(decompress_new(&[0xaa, 0x01, 0x00, 0xff, COPY|FINAL, 0x01, 0x00, FILL], 8, 4),
                   Ok(vec![0xaa, 0x01, 0xaa, COPY|FINAL]));
        assert_eq!(decompress_new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0x01, 0x00, COPY|FINAL, 0x04, 0x00, COPY], 12, 5),
                   Ok(vec![0xaa, 0xaa, 0x01, 0x00, COPY|FINAL]));
    }

    #[test]
    fn test_decompress_filloverflow() {
        for &(input, dst) in &[
            (&[0xaa, 0x01, 0x00, FILL|FINAL] as &[u8], 0),
            (&[0xaa, 0x10, 0x00, FILL|FINAL], 15),
        ] {
            match decompress_new(input, input.len(), dst) {
                Err(FormatError::FillOverflow { fill: 0xaa, .. }) => (),
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
            match decompress_new(input, input.len(), dst) {
                Err(FormatError::CopyOverflow { .. }) => (),
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
            match decompress_new(input, input.len(), dst) {
                Err(FormatError::Gap { .. }) => (),
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
            assert_eq!(&decompress_new(input, input.len(), dst).unwrap(), &output);
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
            decompress(&mut work, compressed_len, input.len()).unwrap();
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
