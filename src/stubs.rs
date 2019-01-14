// Our pre-assembled decompression stub.
pub const STUB_OURS: &'static [u8; 283] = include!("stub.in");

/// Seems to be the most common decompression stub. Matches the format described
/// at <http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#File_Format> and
/// understood by <https://github.com/w4kfu/unEXEPACK> and
/// <https://sourceforge.net/p/openkb/code/ci/master/tree/src/tools/unexepack.c>.
///
/// Has a pointer underflow bug where segments may become negative and the
/// wrapping behavior depends on the state of the A20 gate—this is the cause of
/// the notorious "Packed file is corrupt" error on some PCs when an
/// EXEPACK-packed executable is loaded in the first 64 KB of RAM.
///
/// Samples:
///
/// - <https://archive.org/download/msdos_Mega_Man/msdos_Mega_Man.zip/mm.exe>
/// - <https://archive.org/download/TheAdventuresOfCaptainComic/AdventuresOfCaptainComicEpisode1The-PlanetOfDeathR2sw1988michaelA.Denioaction.zip/COMIC.EXE>
///
/// NASM source code to make an equivalent of this stub:
///
/// ```nasm,ignore
/// BITS 16
///
/// exepack_start:
///
/// real_IP:        dw      0x0000
/// real_CS:        dw      0x0000
/// mem_start:      dw      0x0000  ; uninitialized and filled in by the EXEPACK code
/// exepack_size:   dw      (exepack_end - exepack_start)
/// real_SP:        dw      0x0000
/// real_SS:        dw      0x0000
/// dest_len:       dw      0x0000  ; has a skip_len built in
/// skip_len:       dw      0x0000
/// signature:      db      'RB'
///
/// ; |mem_start                 |exepack_start                     |mem_start+dest_len
/// ; [compressed data] skip_len [EXEPACK]                 skip_len [EXEPACK copy]
/// ; \------------------------- dest_len -------------------------/
///
/// ; On load, es is set to the segment of the 256-byte Program Segment Prefix (PSP).
/// ; cs is set to exepack_start (beginning of EXEPACK header).
/// ; ip is set to copy_decompressor_stub.
/// copy_decompressor_stub:
///         mov ax, es
///         add ax, word 0x10       ; ax = es + 0x10 (segment immediately after the PSP)
///         push cs
///         pop ds                  ; ds = cs (exepack_start)
///         mov [mem_start], ax
///         add ax, [dest_len]
///         mov es, ax              ; es = mem_start + dest_len
///         mov cx, [exepack_size]
///         mov di, cx              ; cx = exepack_size
///         dec di
///         mov si, di              ; si = exepack_size - 1
///         std                     ; copy operations go backwards
///         rep movsb               ; copy exepack_size bytes from ds (exepack_start; i.e., this code) to es (mem_start + dest_len)
///         mov dx, [skip_len]
///         push ax                 ; segment to jump to (mem_start + dest_len)
///         mov ax, (decompress - exepack_start)
///         push ax                 ; offset to jump to (i.e., label "decompress" in the copied block of code)
///         retf
///
/// decompress:
///         mov bx, es              ; bx = mem_start + dest_len
///         mov ax, ds
///         sub ax, dx              ; subtract skip_len
///         mov ds, ax              ; ds = exepack_start - skip_len
///         mov es, ax              ; es = exepack_start - skip_len (scratch; used for the upcoming scasb)
///         mov di, 15              ; di = final byte in final paragraph
///         mov cx, 16
///         mov al, 0xff
///         repe scasb              ; scan es:di backwards for first non-0xff byte
///         inc di
///         mov si, di              ; ds:si points to the final byte of the compressed data in the original buffer
///         mov ax, bx
///         sub ax, dx
///         mov es, ax              ; es = mem_start + dest_len - skip_len
///         mov di, 15              ; es:di points to the final byte of the decompression buffer
/// ; src =  ds:si
/// ; dest = es:di
/// .loop:
///         mov cl, 4
///         ; adjust ds:si so that si is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep movsb" may wrap around the segment
///         mov ax, si
///         not ax
///         shr ax, cl
///         je .si_full             ; if (si < 0xfff0)
///         mov dx, ds
///         sub dx, ax              ; underflow possible here
///         mov ds, dx              ; ds -= (0xffff - si) >> 4
///         or si, 0xfff0           ; si |= 0xfff0
/// .si_full:
///         ; adjust es:di so that di is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
///         mov ax, di
///         not ax
///         shr ax, cl
///         je .di_full             ; if (di < 0xfff0)
///         mov dx, es
///         sub dx, ax              ; underflow possible here
///         mov es, dx              ; es -= (0xffff - di) >> 4
///         or di, 0xfff0           ; di |= 0xfff0
/// .di_full:
///         ; dl = command byte
///         ; cx = length
///         lodsb
///         mov dl, al              ; command = *(uint8_t *) si--
///         dec si                  ; (uint8_t *) si--
///         lodsw
///         mov cx, ax              ; length = *(uint16_t *) si--
///         inc si                  ; (uint8_t *) si++
///         mov al, dl
///         and al, 0xfe
/// .try_b0:
///         cmp al, 0xb0
///         jne .try_b2             ; if (command & 0xfe) == 0xb0
///         lodsb                   ; al = *(uint8_t *) si--
///         rep stosb               ; copy length copies of al backwards into es:di
///         jmp .loop_end
///         nop
/// .try_b2:
///         cmp al, 0xb2
///         jne error               ; if (command & 0xfe) == 0xb2
///         rep movsb               ; copy length bytes backward into es:di from ds:si
/// .loop_end:
///         mov al, dl
///         test al, 1
///         je .loop                ; repeat until (command & 0x01) == 1
///
///         mov si, (relocation_entries - exepack_start)
///         push cs
///         pop ds                  ; ds = exepack_start
///         mov bx, word [mem_start]        ; bx = mem_start
///         cld                     ; copy operations go forwards
///         xor dx, dx              ; section_start = 0
/// apply_relocations:
///         ; dx = current section start (increments by 0x1000)
///         ; cx = number of entries in current section
/// .loop:
///         lodsw
///         mov cx, ax              ; num_entries = *(uint16_t *) si++
///         jcxz .next_section      ; if (num_entries > 0)
///         mov ax, dx
///         add ax, bx
///         mov es, ax              ; es = mem_start + section_start
/// .next_address:                  ; while (num_entries > 0)
///         lodsw
///         mov di, ax              ; addr = *(uint16_t *) si++
///         cmp di, 0xffff
///         je .write_relocation_ffff       ; address with offset of 0xffff needs special handling
///         ; else write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
/// .relocation_written:
///         loop .next_address
/// .next_section:
///         cmp dx, 0xf000
///         je .loop_end            ; if (section_start == 0xf000) break
///         add dx, 0x1000          ; else section_start += 0x1000 and repeat
///         jmp .loop
/// .write_relocation_ffff:
///         ; handle addr == 0xffff
///         ; otherwise the two-byte write would write the second byte at address 0 in the same segment
///         mov ax, es
///         inc ax
///         mov es, ax              ; adjust segment and offset
///         sub di, 0x10            ; so that di == 0xffef
///         ; write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
///         dec ax
///         mov es, ax              ; restore segment to what it was
///         jmp .relocation_written ; back to address loop
/// .loop_end:
///         mov ax, bx              ; ax = mem_start
///         mov di, word [real_SP]  ; di = real_SP
///         mov si, word [real_SS]
///         add si, ax              ; si = mem_start + real_SS
///         add word [real_CS], ax  ; real_CS += mem_start
///         sub ax, 0x10
///         mov ds, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov es, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov bx, real_IP         ; bx points to the 4-byte long pointer real_CS:real_IP.
///         cli
///         mov ss, si              ; ss = mem_start + real_SS
///         mov sp, di              ; sp = real_SP
///         sti
///         jmp far [cs:bx]         ; jump to real_CS:real_IP
///
/// error:
///         mov ah, 0x40            ; ah=0x40 => write to file handle
///         mov bx, 2               ; file handle 2 (stderr)
///         mov cx, 0x16            ; 22 bytes of data (strlen("Packed file is corrupt"))
///         mov dx, cs
///         mov ds, dx              ; ds = cs
///         mov dx, .errmsg         ; ds:dx is address of string to write
///         int 0x21                ; syscall
///         mov ax, 0x4cff          ; ah=0x4c => exit program; al=0xff => exit code -1
///         int 0x21                ; syscall
/// .errmsg:        db      'Packed file is corrupt'
///
/// relocation_entries:
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///
/// exepack_end:
/// ```
pub const STUB_283: &'static [u8] = b"\
\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\x8e\xc0\
\x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x8b\x16\x0e\x00\
\x50\xb8\x38\x00\x50\xcb\x8c\xc3\x8c\xd8\x2b\xc2\x8e\xd8\x8e\xc0\
\xbf\x0f\x00\xb9\x10\x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x2b\
\xc2\x8e\xc0\xbf\x0f\x00\xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x74\x09\
\x8c\xda\x2b\xd0\x8e\xda\x83\xce\xf0\x8b\xc7\xf7\xd0\xd3\xe8\x74\
\x09\x8c\xc2\x2b\xd0\x8e\xc2\x83\xcf\xf0\xac\x8a\xd0\x4e\xad\x8b\
\xc8\x46\x8a\xc2\x24\xfe\x3c\xb0\x75\x06\xac\xf3\xaa\xeb\x07\x90\
\x3c\xb2\x75\x6b\xf3\xa4\x8a\xc2\xa8\x01\x74\xba\xbe\x2d\x01\x0e\
\x1f\x8b\x1e\x04\x00\xfc\x33\xd2\xad\x8b\xc8\xe3\x13\x8b\xc2\x03\
\xc3\x8e\xc0\xad\x8b\xf8\x83\xff\xff\x74\x11\x26\x01\x1d\xe2\xf3\
\x81\xfa\x00\xf0\x74\x16\x81\xc2\x00\x10\xeb\xdc\x8c\xc0\x40\x8e\
\xc0\x83\xef\x10\x26\x01\x1d\x48\x8e\xc0\xeb\xe2\x8b\xc3\x8b\x3e\
\x08\x00\x8b\x36\x0a\x00\x03\xf0\x01\x06\x02\x00\x2d\x10\x00\x8e\
\xd8\x8e\xc0\xbb\x00\x00\xfa\x8e\xd6\x8b\xe7\xfb\x2e\xff\x2f\xb4\
\x40\xbb\x02\x00\xb9\x16\x00\x8c\xca\x8e\xda\xba\x17\x01\xcd\x21\
\xb8\xff\x4c\xcd\x21Packed file is corrupt";

/// Similar to `STUB_283`, except that the EXEPACK header lacks the `skip_len`
/// field (and hence is 16 rather than 18 bytes). Instead, it always acts as if
/// `skip_len` were 1; i.e., no space between the end of compressed data and the
/// beginning of the EXEPACK header. It also has a bug when a relocation entry
/// is 0xffff: the first byte of the altered value will be written at offset
/// 0xffff in the es segment, but the second byte will wrap around and be
/// written at offset 0 in the same segment, instead of offset 0 in the
/// following segment.
///
/// Sample:
///
/// - <https://archive.org/download/TheAdventuresOfCaptainComic/AdventuresOfCaptainComicEpisode1The-PlanetOfDeathsw1988michaelA.Denioaction.zip/COMIC.EXE>
///
/// NASM source code to make an equivalent of this stub:
///
/// ```nasm,ignore
/// BITS 16
///
/// exepack_start:
///
/// real_IP:        dw      0x0000
/// real_CS:        dw      0x0000
/// mem_start:      dw      0x0000  ; uninitialized and filled in by the EXEPACK code
/// exepack_size:   dw      (exepack_end - exepack_start)
/// real_SP:        dw      0x0000
/// real_SS:        dw      0x0000
/// dest_len:       dw      0x0000
/// signature:      db      'RB'
///
/// ; On load, es is set to the segment of the 256-byte Program Segment Prefix (PSP).
/// ; cs is set to exepack_start (beginning of EXEPACK header).
/// ; ip is set to copy_decompressor_stub.
/// copy_decompressor_stub:
///         mov ax, es
///         add ax, word 0x10       ; ax = es + 0x10 (segment immediately after the PSP)
///         push cs
///         pop ds                  ; ds = cs (exepack_start)
///         mov [mem_start], ax
///         add ax, [dest_len]
///         mov es, ax              ; es = mem_start + dest_len
///         mov cx, [exepack_size]
///         mov di, cx              ; cx = exepack_size
///         dec di
///         mov si, di              ; si = exepack_size - 1
///         std                     ; copy operations go backwards
///         rep movsb               ; copy exepack_size bytes from ds (exepack_start; i.e., this code) to es (mem_start + dest_len)
///         push ax                 ; segment to jump to (mem_start + dest_len)
///         mov ax, (decompress - exepack_start)
///         push ax                 ; offset to jump to (i.e., label "decompress" in the copied block of code)
///         retf
///
/// decompress:
///         mov bx, es              ; bx = mem_start + dest_len
///         mov ax, ds
///         dec ax                  ; move back 1 paragraph (equivalent of skip_len == 1)
///         mov ds, ax              ; ds = exepack_start - 1
///         mov es, ax              ; es = exepack_start - 1 (scratch; used for the upcoming scasb)
///         mov di, 15              ; di = final byte in final paragraph
///         mov cx, 16
///         mov al, 0xff
///         repe scasb              ; scan es:di backwards for first non-0xff byte
///         inc di
///         mov si, di              ; ds:si points to the final byte of the compressed data in the original buffer
///         mov ax, bx
///         dec ax
///         mov es, ax              ; es = mem_start + dest_len - 1
///         mov di, 15              ; es:di points to the final byte of the decompression buffer
/// ; src =  ds:si
/// ; dest = es:di
/// .loop:
///         mov cl, 4
///         ; adjust ds:si so that si is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep movsb" may wrap around the segment
///         mov ax, si
///         not ax
///         shr ax, cl
///         je .si_full             ; if (si < 0xfff0)
///         mov dx, ds
///         sub dx, ax              ; underflow possible here
///         mov ds, dx              ; ds -= (0xffff - si) >> 4
///         or si, 0xfff0           ; si |= 0xfff0
/// .si_full:
///         ; adjust es:di so that di is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
///         mov ax, di
///         not ax
///         shr ax, cl
///         je .di_full             ; if (di < 0xfff0)
///         mov dx, es
///         sub dx, ax              ; underflow possible here
///         mov es, dx              ; es -= (0xffff - di) >> 4
///         or di, 0xfff0           ; di |= 0xfff0
/// .di_full:
///         ; dl = command byte
///         ; cx = length
///         lodsb
///         mov dl, al              ; command = *(uint8_t *) si--
///         dec si                  ; (uint8_t *) si--
///         lodsw
///         mov cx, ax              ; length = *(uint16_t *) si--
///         inc si                  ; (uint8_t *) si++
///         mov al, dl
///         and al, 0xfe
/// .try_b0:
///         cmp al, 0xb0
///         jne .try_b2             ; if (command & 0xfe) == 0xb0
///         lodsb                   ; al = *(uint8_t *) si--
///         rep stosb               ; copy length copies of al backwards into es:di
///         jmp .loop_end
///         nop
/// .try_b2:
///         cmp al, 0xb2
///         jne error               ; if (command & 0xfe) == 0xb2
///         rep movsb               ; copy length bytes backward into es:di from ds:si
/// .loop_end:
///         mov al, dl
///         test al, 1
///         je .loop                ; repeat until (command & 0x01) == 1
///
///         mov si, (relocation_entries - exepack_start)
///         push cs
///         pop ds                  ; ds = exepack_start
///         mov bx, word [mem_start]        ; bx = mem_start
///         cld                     ; copy operations go forwards
///         xor dx, dx              ; section_start = 0
/// apply_relocations:
///         ; dx = current section start (increments by 0x1000)
///         ; cx = number of entries in current section
/// .loop:
///         lodsw
///         mov cx, ax              ; num_entries = *(uint16_t *) si++
///         jcxz .next_section      ; if (num_entries > 0)
///         mov ax, dx
///         add ax, bx
///         mov es, ax              ; es = mem_start + section_start
/// .next_address:                  ; while (num_entries > 0)
///         lodsw
///         mov di, ax              ; addr = *(uint16_t *) si++
///         ; write the relocation entry (bug if di == 0xffff)
///         add word [es:di], bx    ; *addr += mem_start
///         loop .next_address
/// .next_section:
///         cmp dx, 0xf000
///         je .loop_end            ; if (section_start == 0xf000) break
///         add dx, 0x1000          ; else section_start += 0x1000 and repeat
///         jmp .loop
/// .loop_end:
///         mov ax, bx              ; ax = mem_start
///         mov di, word [real_SP]  ; di = real_SP
///         mov si, word [real_SS]
///         add si, ax              ; si = mem_start + real_SS
///         add word [real_CS], ax  ; real_CS += mem_start
///         sub ax, 0x10
///         mov ds, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov es, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov bx, real_IP         ; bx points to the 4-byte long pointer real_CS:real_IP.
///         cli
///         mov ss, si              ; ss = mem_start + real_SS
///         mov sp, di              ; sp = real_SP
///         sti
///         jmp far [cs:bx]         ; jump to real_CS:real_IP
///
/// error:
///         mov ah, 0x40            ; ah=0x40 => write to file handle
///         mov bx, 2               ; file handle 2 (stderr)
///         mov cx, 0x16            ; 22 bytes of data (strlen("Packed file is corrupt"))
///         mov dx, cs
///         mov ds, dx              ; ds = cs
///         mov dx, .errmsg         ; ds:dx is address of string to write
///         int 0x21                ; syscall
///         mov ax, 0x4cff          ; ah=0x4c => exit program; al=0xff => exit code -1
///         int 0x21                ; syscall
/// .errmsg:        db      'Packed file is corrupt'
///
/// relocation_entries:
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///
/// exepack_end:
/// ```
///
/// This stub's `decompress` subroutine matches the one in the left-hand
/// (pre-hotpatch) listing at
/// <https://blogs.technet.microsoft.com/uktechnet/2013/08/12/the-original-appcompat-solving-a-20-year-old-mystery-for-me/>.
/// (Archived listing graphic at
/// <https://web.archive.org/web/20170115043824/http://www.microsoft.com/security/portal/blog-images/a/exepack.png>.)
/// The right-hand side shows how the code is hotpatched to remove pointer
/// underflow and reliance on specific address wrapping behavior. It still has
/// the built-in assumption that `skip_len` = 1.
///
/// ```nasm,ignore
/// BITS 16
///
/// decompress:
///         push es                 ; mem_start + dest_len
///         mov ax, ds
///         dec ax                  ; move back 1 paragraph (equivalent of skip_len == 1)
///         mov ds, ax              ; ds = exepack_start - 1
///         mov es, ax              ; es = exepack_start - 1 (scratch; used for the upcoming scasb)
///         mov di, 15              ; di = final byte in final paragraph
///         push di
///         mov cx, 16
///         mov al, 0xff
///         repe scasb              ; scan es:di backwards for first non-0xff byte
///         inc di
///         mov si, di              ; ds:si points to the final byte of the compressed data in the original buffer
///         pop di                  ; es:di points to the final byte of the decompression buffer
///         pop ax                  ; ax = mem_start + dest_len
///         dec ax
///         mov es, ax              ; es = mem_start + dest_len - 1
/// ; src =  ds:si
/// ; dest = es:di
/// .loop:
///         mov cx, 0x0204
///         ; adjust ds:si and es:di so that si/di are as high as possible in their respective segments (without changing the addresses pointed to)
///         ; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
///         ; we run this operation twice (ch=0x02): the first time for ds:si, the second for es:di
///         mov ax, si
///         not ax
///         shr ax, cl              ; shift right by 4
///         je .offset_ok           ; if (si < 0xfff0)
///         mov dx, ds
///         or si, 0xfff0           ; si |= 0xfff0
///         sub dx, ax              ; new_seg = old_seg - ((0xffff - si) >> 4)
///         jnb .segment_ok         ; if (new_seg < 0) shrink si instead (fix for A20 bug)
///         neg dx
///         shl dx, cl
///         sub si, dx              ; si -= (0xffff - new_seg)
///         xor dx, dx              ; new_seg = 0
/// .segment_ok:
///         mov ds, dx
/// .offset_ok:
///         ; swap ds:si and es:di
///         xchg si, di
///         push ds
///         push es
///         pop ds
///         pop es
///         dec ch
///         jne .loop               ; do it again for the other pair of registers
///
///         ; dl = command byte
///         ; cx = length
///         lodsb
///         xchg dx, ax             ; command = *(uint8_t *) si--
///         dec si                  ; (uint8_t *) si--
///         lodsw
///         mov cx, ax              ; length = *(uint16_t *) si--
///         inc si                  ; (uint8_t *) si++
///         mov al, dl
///         and al, 0xfe
/// .try_b0:
///         cmp al, 0xb0
///         jne .try_b2             ; if (command & 0xfe) == 0xb0
///         lodsb                   ; al = *(uint8_t *) si--
///         rep stosb               ; copy length copies of al backwards into es:di
///         jmp .loop_end
/// .try_b2:
///         cmp al, 0xb2
///         jne error               ; if (command & 0xfe) == 0xb2
///         rep movsb               ; copy length bytes backward into es:di from ds:si
/// .loop_end:
///         xchg dx, ax
///         test al, 1
///         je .loop                ; repeat until (command & 0x01) == 1
///         nop
///         nop
/// ```
pub const STUB_258: &[u8] = b"\
\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\x8e\xc0\
\x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x50\xb8\x32\x00\
\x50\xcb\x8c\xc3\x8c\xd8\x48\x8e\xd8\x8e\xc0\xbf\x0f\x00\xb9\x10\
\x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x48\x8e\xc0\xbf\x0f\x00\
\xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x74\x0a\x8c\xda\x2b\xd0\x8e\xda\
\x81\xce\xf0\xff\x8b\xc7\xf7\xd0\xd3\xe8\x74\x0a\x8c\xc2\x2b\xd0\
\x8e\xc2\x81\xcf\xf0\xff\xac\x8a\xd0\x4e\xad\x8b\xc8\x46\x8a\xc2\
\x24\xfe\x3c\xb0\x75\x06\xac\xf3\xaa\xeb\x07\x90\x3c\xb2\x75\x56\
\xf3\xa4\x8a\xc2\xa8\x01\x74\xb8\xbe\x12\x01\x0e\x1f\x8b\x1e\x04\
\x00\xfc\x33\xd2\xad\x8b\xc8\xe3\x0e\x8b\xc2\x03\xc3\x8e\xc0\xad\
\x8b\xf8\x26\x01\x1d\xe2\xf8\x81\xfa\x00\xf0\x74\x06\x81\xc2\x00\
\x10\xeb\xe1\x8b\xc3\x8b\x3e\x08\x00\x8b\x36\x0a\x00\x03\xf0\x01\
\x06\x02\x00\x2d\x10\x00\x8e\xd8\x8e\xc0\xbb\x00\x00\xfa\x8e\xd6\
\x8b\xe7\xfb\x2e\xff\x2f\xb4\x40\xbb\x02\x00\xb9\x16\x00\x8c\xca\
\x8e\xda\xba\xfc\x00\xcd\x21\xb8\xff\x4c\xcd\x21Packed file is corrupt";

/// Like `STUB_258`, does not have an explicit `skip_len` field. Fixes the bug
/// with writing a relocation to offset 0xffff. (See the
/// `.write_relocation_ffff` label.)
///
/// Sample:
///
/// - <https://archive.org/download/MicroCom_109_Gambling_Games/MicroCom_109_Gambling_Games.zip/casino.exe>
///
/// NASM source code to make an equivalent of this stub:
///
/// ```nasm,ignore
/// BITS 16
///
/// exepack_start:
///
/// real_IP:        dw      0x0000
/// real_CS:        dw      0x0000
/// mem_start:      dw      0x0000  ; uninitialized and filled in by the EXEPACK code
/// exepack_size:   dw      (exepack_end - exepack_start)
/// real_SP:        dw      0x0000
/// real_SS:        dw      0x0000
/// dest_len:       dw      0x0000
/// signature:      db      'RB'
///
/// ; On load, es is set to the segment of the 256-byte Program Segment Prefix (PSP).
/// ; cs is set to exepack_start (beginning of EXEPACK header).
/// ; ip is set to copy_decompressor_stub.
/// copy_decompressor_stub:
///         mov ax, es
///         add ax, word 0x10       ; ax = es + 0x10 (segment immediately after the PSP)
///         push cs
///         pop ds                  ; ds = cs (exepack_start)
///         mov [mem_start], ax
///         add ax, [dest_len]
///         mov es, ax              ; es = mem_start + dest_len
///         mov cx, [exepack_size]
///         mov di, cx              ; cx = exepack_size
///         dec di
///         mov si, di              ; si = exepack_size - 1
///         std                     ; copy operations go backwards
///         rep movsb               ; copy exepack_size bytes from ds (exepack_start; i.e., this code) to es (mem_start + dest_len)
///         push ax                 ; segment to jump to (mem_start + dest_len)
///         mov ax, (decompress - exepack_start)
///         push ax                 ; offset to jump to (i.e., label "decompress" in the copied block of code)
///         retf
///
/// decompress:
///         mov bx, es              ; bx = mem_start + dest_len
///         mov ax, ds
///         dec ax                  ; move back 1 paragraph (equivalent of skip_len == 1)
///         mov ds, ax              ; ds = exepack_start - 1
///         mov es, ax              ; es = exepack_start - 1 (scratch; used for the upcoming scasb)
///         mov di, 15              ; di = final byte in final paragraph
///         mov cx, 16
///         mov al, 0xff
///         repe scasb              ; scan es:di backwards for first non-0xff byte
///         inc di
///         mov si, di              ; ds:si points to the final byte of the compressed data in the original buffer
///         mov ax, bx
///         dec ax
///         mov es, ax              ; es = mem_start + dest_len - 1
///         mov di, 15              ; es:di points to the final byte of the decompression buffer
/// ; src =  ds:si
/// ; dest = es:di
/// .loop:
///         mov cl, 4
///         ; adjust ds:si so that si is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep movsb" may wrap around the segment
///         mov ax, si
///         not ax
///         shr ax, cl
///         je .si_full             ; if (si < 0xfff0)
///         mov dx, ds
///         sub dx, ax              ; underflow possible here
///         mov ds, dx              ; ds -= (0xffff - si) >> 4
///         or si, 0xfff0           ; si |= 0xfff0
/// .si_full:
///         ; adjust es:di so that di is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
///         mov ax, di
///         not ax
///         shr ax, cl
///         je .di_full             ; if (di < 0xfff0)
///         mov dx, es
///         sub dx, ax              ; underflow possible here
///         mov es, dx              ; es -= (0xffff - di) >> 4
///         or di, 0xfff0           ; di |= 0xfff0
/// .di_full:
///         ; dl = command byte
///         ; cx = length
///         lodsb
///         mov dl, al              ; command = *(uint8_t *) si--
///         dec si                  ; (uint8_t *) si--
///         lodsw
///         mov cx, ax              ; length = *(uint16_t *) si--
///         inc si                  ; (uint8_t *) si++
///         mov al, dl
///         and al, 0xfe
/// .try_b0:
///         cmp al, 0xb0
///         jne .try_b2             ; if (command & 0xfe) == 0xb0
///         lodsb                   ; al = *(uint8_t *) si--
///         rep stosb               ; copy length copies of al backwards into es:di
///         jmp .loop_end
///         nop
/// .try_b2:
///         cmp al, 0xb2
///         jne error               ; if (command & 0xfe) == 0xb2
///         rep movsb               ; copy length bytes backward into es:di from ds:si
/// .loop_end:
///         mov al, dl
///         test al, 1
///         je .loop                ; repeat until (command & 0x01) == 1
///
///         mov si, (relocation_entries - exepack_start)
///         push cs
///         pop ds                  ; ds = exepack_start
///         mov bx, word [mem_start]        ; bx = mem_start
///         cld                     ; copy operations go forwards
///         xor dx, dx              ; section_start = 0
/// apply_relocations:
///         ; dx = current section start (increments by 0x1000)
///         ; cx = number of entries in current section
/// .loop:
///         lodsw
///         mov cx, ax              ; num_entries = *(uint16_t *) si++
///         jcxz .next_section      ; if (num_entries > 0)
///         mov ax, dx
///         add ax, bx
///         mov es, ax              ; es = mem_start + section_start
/// .next_address:                  ; while (num_entries > 0)
///         lodsw
///         mov di, ax              ; addr = *(uint16_t *) si++
///         cmp di, 0xffff
///         je .write_relocation_ffff       ; address with offset of 0xffff needs special handling
///         ; else write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
/// .relocation_written:
///         loop .next_address
/// .next_section:
///         cmp dx, 0xf000
///         je .loop_end            ; if (section_start == 0xf000) break
///         add dx, 0x1000          ; else section_start += 0x1000 and repeat
///         jmp .loop
/// .write_relocation_ffff:
///         ; handle addr == 0xffff
///         ; otherwise the two-byte write would write the second byte at address 0 in the same segment
///         mov ax, es
///         inc ax
///         mov es, ax              ; adjust segment and offset
///         sub di, 0x10            ; so that di == 0xffef
///         ; write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
///         dec ax
///         mov es, ax              ; restore segment to what it was
///         jmp .relocation_written ; back to address loop
/// .loop_end:
///         mov ax, bx              ; ax = mem_start
///         mov di, word [real_SP]  ; di = real_SP
///         mov si, word [real_SS]
///         add si, ax              ; si = mem_start + real_SS
///         add word [real_CS], ax  ; real_CS += mem_start
///         sub ax, 0x10
///         mov ds, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov es, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov bx, real_IP         ; bx points to the 4-byte long pointer real_CS:real_IP.
///         cli
///         mov ss, si              ; ss = mem_start + real_SS
///         mov sp, di              ; sp = real_SP
///         sti
///         jmp far [cs:bx]         ; jump to real_CS:real_IP
///
/// error:
///         mov ah, 0x40            ; ah=0x40 => write to file handle
///         mov bx, 2               ; file handle 2 (stderr)
///         mov cx, 0x16            ; 22 bytes of data (strlen("Packed file is corrupt"))
///         mov dx, cs
///         mov ds, dx              ; ds = cs
///         mov dx, .errmsg         ; ds:dx is address of string to write
///         int 0x21                ; syscall
///         mov ax, 0x4cff          ; ah=0x4c => exit program; al=0xff => exit code -1
///         int 0x21                ; syscall
/// .errmsg:        db      'Packed file is corrupt'
///
/// relocation_entries:
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///
/// exepack_end:
/// ```
pub const STUB_279: &[u8] = b"\
\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\x8e\xc0\
\x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x50\xb8\x32\x00\
\x50\xcb\x8c\xc3\x8c\xd8\x48\x8e\xd8\x8e\xc0\xbf\x0f\x00\xb9\x10\
\x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x48\x8e\xc0\xbf\x0f\x00\
\xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x74\x0a\x8c\xda\x2b\xd0\x8e\xda\
\x81\xce\xf0\xff\x8b\xc7\xf7\xd0\xd3\xe8\x74\x0a\x8c\xc2\x2b\xd0\
\x8e\xc2\x81\xcf\xf0\xff\xac\x8a\xd0\x4e\xad\x8b\xc8\x46\x8a\xc2\
\x24\xfe\x3c\xb0\x75\x06\xac\xf3\xaa\xeb\x07\x90\x3c\xb2\x75\x6b\
\xf3\xa4\x8a\xc2\xa8\x01\x74\xb8\xbe\x27\x01\x0e\x1f\x8b\x1e\x04\
\x00\xfc\x33\xd2\xad\x8b\xc8\xe3\x13\x8b\xc2\x03\xc3\x8e\xc0\xad\
\x8b\xf8\x83\xff\xff\x74\x11\x26\x01\x1d\xe2\xf3\x81\xfa\x00\xf0\
\x74\x16\x81\xc2\x00\x10\xeb\xdc\x8c\xc0\x40\x8e\xc0\x83\xef\x10\
\x26\x01\x1d\x48\x8e\xc0\xeb\xe2\x8b\xc3\x8b\x3e\x08\x00\x8b\x36\
\x0a\x00\x03\xf0\x01\x06\x02\x00\x2d\x10\x00\x8e\xd8\x8e\xc0\xbb\
\x00\x00\xfa\x8e\xd6\x8b\xe7\xfb\x2e\xff\x2f\xb4\x40\xbb\x02\x00\
\xb9\x16\x00\x8c\xca\x8e\xda\xba\x11\x01\xcd\x21\xb8\xff\x4c\xcd\
\x21Packed file is corrupt";

/// Identical to `STUB_279` except that it has a shorter encoding for the two
/// instances of the `or di, 0xfff0` instruction: `83cff0` instead of
/// `81cff0ff`.
///
/// Sample:
///
/// - <https://archive.org/download/MicroCom_374_Cash-Track/MicroCom_374_Cash-Track.zip/cashtrac.exe>
///
/// NASM source code to make an equivalent of this stub:
///
/// ```nasm,ignore
/// BITS 16
///
/// exepack_start:
///
/// real_IP:        dw      0x0000
/// real_CS:        dw      0x0000
/// mem_start:      dw      0x0000  ; uninitialized and filled in by the EXEPACK code
/// exepack_size:   dw      (exepack_end - exepack_start)
/// real_SP:        dw      0x0000
/// real_SS:        dw      0x0000
/// dest_len:       dw      0x0000
/// signature:      db      'RB'
///
/// ; On load, es is set to the segment of the 256-byte Program Segment Prefix (PSP).
/// ; cs is set to exepack_start (beginning of EXEPACK header).
/// ; ip is set to copy_decompressor_stub.
/// copy_decompressor_stub:
///         mov ax, es
///         add ax, word 0x10       ; ax = es + 0x10 (segment immediately after the PSP)
///         push cs
///         pop ds                  ; ds = cs (exepack_start)
///         mov [mem_start], ax
///         add ax, [dest_len]
///         mov es, ax              ; es = mem_start + dest_len
///         mov cx, [exepack_size]
///         mov di, cx              ; cx = exepack_size
///         dec di
///         mov si, di              ; si = exepack_size - 1
///         std                     ; copy operations go backwards
///         rep movsb               ; copy exepack_size bytes from ds (exepack_start; i.e., this code) to es (mem_start + dest_len)
///         push ax                 ; segment to jump to (mem_start + dest_len)
///         mov ax, (decompress - exepack_start)
///         push ax                 ; offset to jump to (i.e., label "decompress" in the copied block of code)
///         retf
///
/// decompress:
///         mov bx, es              ; bx = mem_start + dest_len
///         mov ax, ds
///         dec ax                  ; move back 1 paragraph (equivalent of skip_len == 1)
///         mov ds, ax              ; ds = exepack_start - 1
///         mov es, ax              ; es = exepack_start - 1 (scratch; used for the upcoming scasb)
///         mov di, 15              ; di = final byte in final paragraph
///         mov cx, 16
///         mov al, 0xff
///         repe scasb              ; scan es:di backwards for first non-0xff byte
///         inc di
///         mov si, di              ; ds:si points to the final byte of the compressed data in the original buffer
///         mov ax, bx
///         dec ax
///         mov es, ax              ; es = mem_start + dest_len - 1
///         mov di, 15              ; es:di points to the final byte of the decompression buffer
/// ; src =  ds:si
/// ; dest = es:di
/// .loop:
///         mov cl, 4
///         ; adjust ds:si so that si is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep movsb" may wrap around the segment
///         mov ax, si
///         not ax
///         shr ax, cl
///         je .si_full             ; if (si < 0xfff0)
///         mov dx, ds
///         sub dx, ax              ; underflow possible here
///         mov ds, dx              ; ds -= (0xffff - si) >> 4
///         or si, 0xfff0           ; si |= 0xfff0
/// .si_full:
///         ; adjust es:di so that di is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
///         mov ax, di
///         not ax
///         shr ax, cl
///         je .di_full             ; if (di < 0xfff0)
///         mov dx, es
///         sub dx, ax              ; underflow possible here
///         mov es, dx              ; es -= (0xffff - di) >> 4
///         or di, 0xfff0           ; di |= 0xfff0
/// .di_full:
///         ; dl = command byte
///         ; cx = length
///         lodsb
///         mov dl, al              ; command = *(uint8_t *) si--
///         dec si                  ; (uint8_t *) si--
///         lodsw
///         mov cx, ax              ; length = *(uint16_t *) si--
///         inc si                  ; (uint8_t *) si++
///         mov al, dl
///         and al, 0xfe
/// .try_b0:
///         cmp al, 0xb0
///         jne .try_b2             ; if (command & 0xfe) == 0xb0
///         lodsb                   ; al = *(uint8_t *) si--
///         rep stosb               ; copy length copies of al backwards into es:di
///         jmp .loop_end
///         nop
/// .try_b2:
///         cmp al, 0xb2
///         jne error               ; if (command & 0xfe) == 0xb2
///         rep movsb               ; copy length bytes backward into es:di from ds:si
/// .loop_end:
///         mov al, dl
///         test al, 1
///         je .loop                ; repeat until (command & 0x01) == 1
///
///         mov si, (relocation_entries - exepack_start)
///         push cs
///         pop ds                  ; ds = exepack_start
///         mov bx, word [mem_start]        ; bx = mem_start
///         cld                     ; copy operations go forwards
///         xor dx, dx              ; section_start = 0
/// apply_relocations:
///         ; dx = current section start (increments by 0x1000)
///         ; cx = number of entries in current section
/// .loop:
///         lodsw
///         mov cx, ax              ; num_entries = *(uint16_t *) si++
///         jcxz .next_section      ; if (num_entries > 0)
///         mov ax, dx
///         add ax, bx
///         mov es, ax              ; es = mem_start + section_start
/// .next_address:                  ; while (num_entries > 0)
///         lodsw
///         mov di, ax              ; addr = *(uint16_t *) si++
///         cmp di, 0xffff
///         je .write_relocation_ffff       ; address with offset of 0xffff needs special handling
///         ; else write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
/// .relocation_written:
///         loop .next_address
/// .next_section:
///         cmp dx, 0xf000
///         je .loop_end            ; if (section_start == 0xf000) break
///         add dx, 0x1000          ; else section_start += 0x1000 and repeat
///         jmp .loop
/// .write_relocation_ffff:
///         ; handle addr == 0xffff
///         ; otherwise the two-byte write would write the second byte at address 0 in the same segment
///         mov ax, es
///         inc ax
///         mov es, ax              ; adjust segment and offset
///         sub di, 0x10            ; so that di == 0xffef
///         ; write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
///         dec ax
///         mov es, ax              ; restore segment to what it was
///         jmp .relocation_written ; back to address loop
/// .loop_end:
///         mov ax, bx              ; ax = mem_start
///         mov di, word [real_SP]  ; di = real_SP
///         mov si, word [real_SS]
///         add si, ax              ; si = mem_start + real_SS
///         add word [real_CS], ax  ; real_CS += mem_start
///         sub ax, 0x10
///         mov ds, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov es, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov bx, real_IP         ; bx points to the 4-byte long pointer real_CS:real_IP.
///         cli
///         mov ss, si              ; ss = mem_start + real_SS
///         mov sp, di              ; sp = real_SP
///         sti
///         jmp far [cs:bx]         ; jump to real_CS:real_IP
///
/// error:
///         mov ah, 0x40            ; ah=0x40 => write to file handle
///         mov bx, 2               ; file handle 2 (stderr)
///         mov cx, 0x16            ; 22 bytes of data (strlen("Packed file is corrupt"))
///         mov dx, cs
///         mov ds, dx              ; ds = cs
///         mov dx, .errmsg         ; ds:dx is address of string to write
///         int 0x21                ; syscall
///         mov ax, 0x4cff          ; ah=0x4c => exit program; al=0xff => exit code -1
///         int 0x21                ; syscall
/// .errmsg:        db      'Packed file is corrupt'
///
/// relocation_entries:
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///
/// exepack_end:
/// ```
pub const STUB_277: &[u8] = b"\
\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\x8e\xc0\
\x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x50\xb8\x32\x00\
\x50\xcb\x8c\xc3\x8c\xd8\x48\x8e\xd8\x8e\xc0\xbf\x0f\x00\xb9\x10\
\x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x48\x8e\xc0\xbf\x0f\x00\
\xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x74\x09\x8c\xda\x2b\xd0\x8e\xda\
\x83\xce\xf0\x8b\xc7\xf7\xd0\xd3\xe8\x74\x09\x8c\xc2\x2b\xd0\x8e\
\xc2\x83\xcf\xf0\xac\x8a\xd0\x4e\xad\x8b\xc8\x46\x8a\xc2\x24\xfe\
\x3c\xb0\x75\x06\xac\xf3\xaa\xeb\x07\x90\x3c\xb2\x75\x6b\xf3\xa4\
\x8a\xc2\xa8\x01\x74\xba\xbe\x25\x01\x0e\x1f\x8b\x1e\x04\x00\xfc\
\x33\xd2\xad\x8b\xc8\xe3\x13\x8b\xc2\x03\xc3\x8e\xc0\xad\x8b\xf8\
\x83\xff\xff\x74\x11\x26\x01\x1d\xe2\xf3\x81\xfa\x00\xf0\x74\x16\
\x81\xc2\x00\x10\xeb\xdc\x8c\xc0\x40\x8e\xc0\x83\xef\x10\x26\x01\
\x1d\x48\x8e\xc0\xeb\xe2\x8b\xc3\x8b\x3e\x08\x00\x8b\x36\x0a\x00\
\x03\xf0\x01\x06\x02\x00\x2d\x10\x00\x8e\xd8\x8e\xc0\xbb\x00\x00\
\xfa\x8e\xd6\x8b\xe7\xfb\x2e\xff\x2f\xb4\x40\xbb\x02\x00\xb9\x16\
\x00\x8c\xca\x8e\xda\xba\x0f\x01\xcd\x21\xb8\xff\x4c\xcd\x21Packed file is corrupt";

/// Uses an implicit `skip_len`. Saves and restores the `ax` register. Fixes the
/// negative-segment wraparound bug.
///
/// Sample:
///
/// - <https://archive.org/download/MicroCom_20_Hog_Bear_Adventure/MicroCom_20_Hog_Bear_Adventure.zip/hogbear.exe>
///
/// LINK.EXE that apparently produces this stub:
///
/// - <https://archive.org/download/RevisedJonesAs/Revised%20Jones%20As.iso/LINK.EXE>
///
/// NASM source code to make an equivalent of this stub:
///
/// ```nasm,ignore
/// BITS 16
///
/// exepack_start:
///
/// real_IP:        dw      0x0000
/// real_CS:        dw      0x0000
/// mem_start:      dw      0x0000  ; uninitialized and filled in by the EXEPACK code
/// exepack_size:   dw      (exepack_end - exepack_start)
/// real_SP:        dw      0x0000
/// real_SS:        dw      0x0000
/// dest_len:       dw      0x0000
/// signature:      db      'RB'
///
/// ; On load, es is set to the segment of the 256-byte Program Segment Prefix (PSP).
/// ; cs is set to exepack_start (beginning of EXEPACK header).
/// ; ip is set to copy_decompressor_stub.
/// copy_decompressor_stub:
///         mov bp, ax              ; save ax
///         mov ax, es
///         add ax, word 0x10       ; ax = es + 0x10 (segment immediately after the PSP)
///         push cs
///         pop ds                  ; ds = cs (exepack_start)
///         mov [mem_start], ax
///         add ax, [dest_len]
///         mov es, ax              ; es = mem_start + dest_len
///         mov cx, [exepack_size]
///         mov di, cx              ; cx = exepack_size
///         dec di
///         mov si, di              ; si = exepack_size - 1
///         std                     ; copy operations go backwards
///         rep movsb               ; copy exepack_size bytes from ds (exepack_start; i.e., this code) to es (mem_start + dest_len)
///         push ax                 ; segment to jump to (mem_start + dest_len)
///         mov ax, (decompress - exepack_start)
///         push ax                 ; offset to jump to (i.e., label "decompress" in the copied block of code)
///         retf
///
/// decompress:
///         mov bx, es              ; bx = mem_start + dest_len
///         mov ax, ds
///         dec ax                  ; move back 1 paragraph (equivalent of skip_len == 1)
///         mov ds, ax              ; ds = exepack_start - 1
///         mov es, ax              ; es = exepack_start - 1 (scratch; used for the upcoming scasb)
///         mov di, 15              ; di = final byte in final paragraph
///         mov cx, 16
///         mov al, 0xff
///         repe scasb              ; scan es:di backwards for first non-0xff byte
///         inc di
///         mov si, di              ; ds:si points to the final byte of the compressed data in the original buffer
///         mov ax, bx
///         dec ax
///         mov es, ax              ; es = mem_start + dest_len - 1
///         mov di, 15              ; es:di points to the final byte of the decompression buffer
/// ; src =  ds:si
/// ; dest = es:di
/// .loop:
///         mov cl, 4
///         ; adjust ds:si so that si is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep movsb" may wrap around the segment
///         mov ax, si
///         not ax
///         shr ax, cl              ; shift right by 4
///         mov dx, ds
///         sub dx, ax              ; new_seg = old_seg - ((0xffff - si) >> 4)
///         jae .ds_ok              ; if (new_seg < 0)
///         mov ax, ds              ; ax = old_seg
///         sub dx, dx              ; new_seg = 0
/// .ds_ok:
///         shl ax, cl
///         add si, ax
///         mov ds, dx
///         ; adjust es:di so that di is as high as possible in the segment (without changing the address pointed to)
///         ; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
///         mov ax, di
///         not ax
///         shr ax, cl
///         mov dx, es
///         sub dx, ax              ; new_seg = old_seg - ((0xffff - si) >> 4)
///         jae .es_ok              ; if (new_seg < 0)
///         mov ax, es              ; ax = old_seg
///         sub dx, dx              ; new_seg = 0
/// .es_ok:
///         shl ax, cl
///         add di, ax
///         mov es, dx              ; es -= (0xffff - di) >> 4
/// .di_full:
///         ; dl = command byte
///         ; cx = length
///         lodsb
///         mov dl, al              ; command = *(uint8_t *) si--
///         dec si                  ; (uint8_t *) si--
///         lodsw
///         mov cx, ax              ; length = *(uint16_t *) si--
///         inc si                  ; (uint8_t *) si++
///         mov al, dl
///         and al, 0xfe
/// .try_b0:
///         cmp al, 0xb0
///         jne .try_b2             ; if (command & 0xfe) == 0xb0
///         lodsb                   ; al = *(uint8_t *) si--
///         rep stosb               ; copy length copies of al backwards into es:di
///         jmp .loop_end
///         nop
/// .try_b2:
///         cmp al, 0xb2
///         jne error               ; if (command & 0xfe) == 0xb2
///         rep movsb               ; copy length bytes backward into es:di from ds:si
/// .loop_end:
///         mov al, dl
///         test al, 1
///         je .loop                ; repeat until (command & 0x01) == 1
///
///         mov si, (relocation_entries - exepack_start)
///         push cs
///         pop ds                  ; ds = exepack_start
///         mov bx, word [mem_start]        ; bx = mem_start
///         cld                     ; copy operations go forwards
///         xor dx, dx              ; section_start = 0
/// apply_relocations:
///         ; dx = current section start (increments by 0x1000)
///         ; cx = number of entries in current section
/// .loop:
///         lodsw
///         mov cx, ax              ; num_entries = *(uint16_t *) si++
///         jcxz .next_section      ; if (num_entries > 0)
///         mov ax, dx
///         add ax, bx
///         mov es, ax              ; es = mem_start + section_start
/// .next_address:                  ; while (num_entries > 0)
///         lodsw
///         mov di, ax              ; addr = *(uint16_t *) si++
///         cmp di, 0xffff
///         je .write_relocation_ffff       ; address with offset of 0xffff needs special handling
///         ; else write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
/// .relocation_written:
///         loop .next_address
/// .next_section:
///         cmp dx, 0xf000
///         je .loop_end            ; if (section_start == 0xf000) break
///         add dx, 0x1000          ; else section_start += 0x1000 and repeat
///         jmp .loop
/// .write_relocation_ffff:
///         ; handle addr == 0xffff
///         ; otherwise the two-byte write would write the second byte at address 0 in the same segment
///         mov ax, es
///         inc ax
///         mov es, ax              ; adjust segment and offset
///         sub di, 0x10            ; so that di == 0xffef
///         ; write the relocation entry
///         add word [es:di], bx    ; *addr += mem_start
///         dec ax
///         mov es, ax              ; restore segment to what it was
///         jmp .relocation_written ; back to address loop
/// .loop_end:
///         mov ax, bx              ; ax = mem_start
///         mov di, word [real_SP]  ; di = real_SP
///         mov si, word [real_SS]
///         add si, ax              ; si = mem_start + real_SS
///         add word [real_CS], ax  ; real_CS += mem_start
///         sub ax, 0x10
///         mov ds, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov es, ax              ; es = mem_start - 0x10 (segment of start of PSP)
///         mov bx, real_IP         ; bx points to the 4-byte long pointer real_CS:real_IP.
///         cli
///         mov ss, si              ; ss = mem_start + real_SS
///         mov sp, di              ; sp = real_SP
///         sti
///         mov ax, bp              ; restore ax
///         jmp far [cs:bx]         ; jump to real_CS:real_IP
///
/// error:
///         mov ah, 0x40            ; ah=0x40 => write to file handle
///         mov bx, 2               ; file handle 2 (stderr)
///         mov cx, 0x16            ; 22 bytes of data (strlen("Packed file is corrupt"))
///         mov dx, cs
///         mov ds, dx              ; ds = cs
///         mov dx, .errmsg         ; ds:dx is address of string to write
///         int 0x21                ; syscall
///         mov ax, 0x4cff          ; ah=0x4c => exit program; al=0xff => exit code -1
///         int 0x21                ; syscall
/// .errmsg:        db      'Packed file is corrupt'
///
/// relocation_entries:
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///         dw      0x0000
///
/// exepack_end:
/// ```
pub const STUB_290: &[u8] = b"\
\x8b\xe8\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\
\x8e\xc0\x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x50\xb8\
\x34\x00\x50\xcb\x8c\xc3\x8c\xd8\x48\x8e\xd8\x8e\xc0\xbf\x0f\x00\
\xb9\x10\x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x48\x8e\xc0\xbf\
\x0f\x00\xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x8c\xda\x2b\xd0\x73\x04\
\x8c\xd8\x2b\xd2\xd3\xe0\x03\xf0\x8e\xda\x8b\xc7\xf7\xd0\xd3\xe8\
\x8c\xc2\x2b\xd0\x73\x04\x8c\xc0\x2b\xd2\xd3\xe0\x03\xf8\x8e\xc2\
\xac\x8a\xd0\x4e\xad\x8b\xc8\x46\x8a\xc2\x24\xfe\x3c\xb0\x75\x05\
\xac\xf3\xaa\xeb\x06\x3c\xb2\x75\x6d\xf3\xa4\x8a\xc2\xa8\x01\x74\
\xb1\xbe\x32\x01\x0e\x1f\x8b\x1e\x04\x00\xfc\x33\xd2\xad\x8b\xc8\
\xe3\x13\x8b\xc2\x03\xc3\x8e\xc0\xad\x8b\xf8\x83\xff\xff\x74\x11\
\x26\x01\x1d\xe2\xf3\x81\xfa\x00\xf0\x74\x16\x81\xc2\x00\x10\xeb\
\xdc\x8c\xc0\x40\x8e\xc0\x83\xef\x10\x26\x01\x1d\x48\x8e\xc0\xeb\
\xe2\x8b\xc3\x8b\x3e\x08\x00\x8b\x36\x0a\x00\x03\xf0\x01\x06\x02\
\x00\x2d\x10\x00\x8e\xd8\x8e\xc0\xbb\x00\x00\xfa\x8e\xd6\x8b\xe7\
\xfb\x8b\xc5\x2e\xff\x2f\xb4\x40\xbb\x02\x00\xb9\x16\x00\x8c\xca\
\x8e\xda\xba\x1c\x01\xcd\x21\xb8\xff\x4c\xcd\x21Packed file is corrupt";
