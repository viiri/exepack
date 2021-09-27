; EXEPACK decompression stub.
; This one aims to be compatible with Microsoft EXEPACK, while fixing
; the segment underflow (A20 gate) and relocation-at-offset-0xffff bugs,
; and fitting into what appears to be the most common size of 283 bytes.
;
; Constraints:
; * EXEPACK header is 18 bytes (i.e., includes a skip_len field).
; * EXEPACK header fields other than mem_start have the same meaning as
;   in Microsoft EXEPACK.
; * Total size is exactly 283 bytes exclusive of relocations; i.e. label
;   relocation_entries is at offset 283.
; * Ends with "Packed file is corrupt".

cpu	8086
org	18	; EXEPACK header is 18 bytes.

; Offsets of fields in the EXEPACK header.
; http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#EXEPACK_variables
real_ip		equ	0
real_cs		equ	2
mem_start	equ	4	; unused
exepack_size	equ	6	; will have the value 18 + 283 + len(relocations)
real_sp		equ	8
real_ss		equ	10
dest_len	equ	12
skip_len	equ	14	; unused; will have the value 1
signature	equ	16	; unused

; We do one-byte-at-a-time reads and copies. Instead of shifting
; segments in an attempt to do maximal-length "rep lodsb" and
; "rep movsb", which has the risk of underflowing the segment (A20 bug),
; we call dec_lod_ds_si and dec_sto_es_di in loops. These functions
; never decrease ds or es by more than 1.

; On load,
; * ds and es are set to the segment of the Program Segment Prefix
;   (PSP). The compressed data starts 256 bytes beyond that, at an
;   address we call mem_start.
; * cs is set to the beginning of the EXEPACK header.
; * ip is set to copy_exepack_block.
; * ax contains a value that we must restore before jumping to the
;   decompressed program.
copy_exepack_block:
	mov bp, ax		; save ax

	mov bx, es
	add bx, 0x10		; bx = es+16 (mem_start, 256 bytes past PSP, beginning of compressed data)

	push cs
	pop ds			; ds = cs (beginning of EXEPACK variables, end of compressed data)

	mov cx, [exepack_size]	; cx = size of the EXEPACK block (variables+code+relocations)

	; We must copy the EXEPACK block (ds:0000 to ds:exepack_size)
	; past the decompression buffer, so that it will not overwrite
	; itself while it is running the decompression algorithm. But we
	; must also copy the EXEPACK block past its own current
	; location, or else it will partially overwrite itself in the
	; copy operation. (This can happen when the file was compressed
	; by only a little, less than the size of the EXEPACK block.) We
	; set es to the maximum of mem_start + dest_len (the end of
	; uncompressed data) and ds + ceil(exepack_size/16) (the end of
	; the EXEPACK block).
	;
	; We could technically avoid the copy in the case that the
	; EXEPACK block is already fully past the decompression buffer;
	; i.e. when ds >= mem_start + dest_len. But that case only
	; arises when the input was highly incompressible--it decreased
	; in size by less than 16 bytes (exclusive of the EXEPACK
	; block). Even already EXEPACK-compressed files are usually more
	; compressible than that (because of redundancy in the EXEPACK
	; block) so it's not worth complicating the logic for.
	mov ax, cx
	add ax, 15
	rcr ax, 1		; shift in the carry flag, in case (exepack_size + 15) overflowed
	shr al, 1
	shr al, 1
	shr al, 1
	mov dx, ds
	add ax, dx		; ax = ds + ceil(exepack_size/16)
				; ignore possible overflow (possible only when ds >= 0xff00)

	mov dx, bx
	add dx, [dest_len]	; dx = mem_start + dest_len
				; ignore possible overflow

	cmp ax, dx
	jae .ax_max
	mov ax, dx
.ax_max:
	mov es, ax

	xor si, si		; ds:si points to the source buffer, the EXEPACK block
	xor di, di		; es:di points to the destination buffer
	rep movsb		; copy exepack_size bytes from ds:si to es:di

	mov es, dx		; es = mem_start + dest_len (destination for decompression)
	push ax			; segment to jump to (where we copied the EXEPACK block to)
	mov ax, decompress
	push ax			; offset to jump to (i.e., label "decompress" in the copied EXEPACK block)
	retf			; jump into the copied code

; Decrement ds:si, re-normalizing on underflow of si, and load al = [ds:si].
dec_lod_ds_si:
	sub si, 1
	jnc .si_ok		; did si wrap to 0xffff?
	mov si, ds
	dec si
	mov ds, si
	mov si, 0xf		; ds:ffff -> (ds-1):000f
.si_ok:
	mov al, [ds:si]
	ret

; Decrement es:di, re-normalizing on underflow of di, and store [es:di] = al.
dec_sto_es_di:
	sub di, 1
	jnc .di_ok		; did di wrap to 0xffff?
	mov di, es
	dec di
	mov es, di
	mov di, 0xf		; es:ffff -> (es-1):000f
.di_ok:
	mov [es:di], al
	ret

decompress:
	xor si, si		; ds:si points to the EXEPACK block, one byte past the end of the compressed data + padding
	; Skip past 0xff padding.
.padding_loop:
	call dec_lod_ds_si
	cmp al, 0xff
	jz .padding_loop
	inc si
	; ds:si points one byte past the final byte of the compressed data

	xor di, di
	; es:di points one byte past the final byte of the decompression buffer

; src  = ds:si
; dest = es:di
.loop:
	; dl = command byte
	call dec_lod_ds_si
	mov dl, al

	; cx = length
	call dec_lod_ds_si
	mov ch, al
	call dec_lod_ds_si
	mov cl, al

	mov al, dl
	and al, 0xfe
.try_b0:
	cmp al, 0xb0		; 0xb0 fill command
	jne .try_b2		; if (command & 0xfe) == 0xb0

	call dec_lod_ds_si	; al = fill byte

	jcxz .loop_end
.fill_loop:			; fill for length of cx
	call dec_sto_es_di
	loop .fill_loop

	jmp .loop_end

.try_b2:
	cmp al, 0xb2		; 0xb2 copy command
	jne error		; if (command & 0xfe) == 0xb2

	jcxz .loop_end
.copy_loop:			; copy for length of cx
	call dec_lod_ds_si	; al = byte to copy
	call dec_sto_es_di	; store it
	loop .copy_loop

.loop_end:
	test dl, 0x01
	je .loop		; repeat until (command & 0x01) == 1

	push cs
	pop ds			; ds = beginning of EXEPACK block
	mov si, relocation_entries	; ds:si points to the beginning of the packed relocation table
	; dx = current relocation segment (increments by 0x1000)
	xor dx, dx
apply_relocations:
	lodsw
	; cx = number of entries in the current segment
	mov cx, ax
	jcxz .next_segment
.next_address:			; while (cx > 0)
	lodsw			; read next relocation offset
	mov di, ax
	; Normalize the es:di pointer to avoid a wraparound problem when
	; the offset is 0xffff.
	and di, 0x000f		; keep the lower 4 bits of the offset
	shr ax, 1		; shift the upper 12 bits into the segment
	shr ax, 1
	shr ax, 1
	shr ax, 1
	add ax, dx		; dx is current relocation segment (this addition cannot overflow)
	add ax, bx		; bx is mem_start from the beginning
				; ignore possible overflow
	mov es, ax		; es:di points to relocation target word
	add [es:di], bx		; *target += mem_start
	loop .next_address

.next_segment:
	add dh, 0x10		; next relocation segment
	jne apply_relocations	; repeat until we wrap from 0xf000 back to 0x0000

execute_decompressed_program:
	mov si, [real_ss]
	add si, bx		; si = relocated real_ss
				; ignore possible overflow
	mov di, [real_sp]	; di = real_sp
	add [real_cs], bx	; real_cs = relocated real_cs
				; ignore possible overflow
	sub bx, 0x10
	mov ds, bx		; ds = mem_start - 0x10 (start of PSP)
	mov es, bx		; es = mem_start - 0x10 (start of PSP)
	cli
	mov ss, si		; ss = real_ss + mem_start
	mov sp, di		; sp = real_sp
	sti
	mov ax, bp		; restore original ax
	mov bx, real_ip		; bx points to the 4-byte long pointer real_cs:real_ip.
	jmp far [cs:bx]		; jump to real_cs:real_ip.

; Pad to make the total size 283 bytes.
times	283-(relocation_entries-error)-($-$$)	nop

error:
	mov ah, 0x40		; ah=0x40 => write to file handle
	mov bx, 2		; file handle 2 (stderr)
	mov cx, .errmsg_len	; length of string to write
	mov dx, cs
	mov ds, dx		; ds = cs
	mov dx, .errmsg		; ds:dx is address of string to write
	int 0x21		; syscall
	mov ax, 0x4cff		; ah=0x4c => exit program; al=0xff => exit code -1
	int 0x21		; syscall
.errmsg:	db	'Packed file is corrupt'
.errmsg_len	equ	$-.errmsg

relocation_entries:
