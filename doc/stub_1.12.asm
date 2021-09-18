;"\x89\xc5\x8c\xc3\x83\xc3\x10\x0e\x1f\x8b\x0e\x06\x00\x8c\xda\x89\
; \xc8\x83\xc0\x0f\xd1\xd8\xc1\xe8\x03\x01\xd0\x89\xda\x03\x16\x0c\
; \x00\x39\xd0\x73\x02\x89\xd0\x8e\xc0\x31\xf6\x31\xff\xf3\xa4\x8e\
; \xc2\x50\x68\x60\x00\xcb\x4e\x79\x08\x8c\xde\x4e\x8e\xde\xbe\x0f\
; \x00\xc3\x4f\x79\x08\x8c\xc7\x4f\x8e\xc7\xbf\x0f\x00\xc3\x31\xf6\
; \xe8\xe3\xff\x3e\x8a\x04\x3c\xff\x74\xf6\x31\xff\xe8\xe3\xff\x3e\
; \x8a\x14\xe8\xd1\xff\x3e\x8a\x2c\xe8\xcb\xff\x3e\x8a\x0c\xe8\xc5\
; \xff\x88\xd0\x24\xfe\x3c\xb0\x75\x12\x3e\x8a\x04\xe8\xb7\xff\xe3\
; \x1e\x26\x88\x05\xe8\xbb\xff\xe2\xf8\xeb\x14\x3c\xb2\x75\x60\xe3\
; \x0e\x3e\x8a\x04\xe8\x9f\xff\x26\x88\x05\xe8\xa5\xff\xe2\xf2\xf6\
; \xc2\x01\x74\xbb\x0e\x1f\xbe\x2d\x01\x31\xd2\xad\x89\xc1\xe3\x14\
; \xad\x89\xc7\x83\xe7\x0f\xc1\xe8\x04\x01\xd8\x01\xd0\x8e\xc0\x26\
; \x01\x1d\xe2\xec\x80\xc6\x10\x75\xe2\x89\xd8\x8b\x36\x0a\x00\x01\
; \xc6\x8b\x3e\x08\x00\x01\x06\x02\x00\x83\xe8\x10\x8e\xd8\x8e\xc0\
; \xfa\x8e\xd6\x89\xfc\xfb\x89\xe8\xbb\x00\x00\x2e\xff\x2f\x90\xb4\
; \x40\xbb\x02\x00\xb9\x16\x00\x8c\xca\x8e\xda\xba\x17\x01\xcd\x21\
; \xb8\xff\x4c\xcd\x21Packed file is corrupt"
;
; This is the decompression stub used by exepack in versions
; v0.4.0 through v1.2.0. In version v1.3.0 it was changed to fix an
; overflow bug when there are many relocations, and to use only
; 8086-compatible instructions.
;
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

bits	16
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

; We use stupid and slow segment:offset addressing. Instead of shifting
; segments in attempt to do maximal-length "rep lodsb" and "rep movsb",
; we call dec_ds_si and dec_es_di in loops. dec_ds_si and dec_es_di
; normalize the segment:offset format so that decrementing never
; decreases ds or es by more than 1.

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

	; We have to copy the EXEPACK block (ds:0000 to ds:exepack_size)
	; out of the way, so that it is not overwritten neither during
	; decompression nor during the copy itself. We set es to the
	; maximum of mem_start + dest_len (the end of uncompressed data)
	; and ds + ceil(exepack_size/16) (the end of the EXEPACK block).
	mov dx, ds
	mov ax, cx
	add ax, 15
	shr ax, 4
	add ax, dx		; ax = ds + ceil(exepack_size/16)

	mov dx, bx
	add dx, [dest_len]	; dx = mem_start + dest_len

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
	push decompress		; offset to jump to (i.e., label "decompress" in the copied EXEPACK block)
	retf			; jump into the copied code

; Decrement a normalized ds:si.
dec_ds_si:
	dec si
	jns .si_ok	; here we assume si was not negative to begin with
	mov si, ds
	dec si
	mov ds, si
	mov si, 0xf
.si_ok:
	ret

; Decrement a normalized es:di.
dec_es_di:
	dec di
	jns .di_ok	; here we assume di was not negative to begin with
	mov di, es
	dec di
	mov es, di
	mov di, 0xf
.di_ok:
	ret

decompress:
	; Skip past 0xff padding.
	xor si, si		; ds:si = real_ip, just past the end of the compressed data + padding
.padding_loop:
	call dec_ds_si
	mov al, [ds:si]
	cmp al, 0xff
	je .padding_loop
	; ds:si now points to the final byte of compressed data in the original buffer

	xor di, di
	call dec_es_di
	; es:di now points to the final byte of the decompression buffer

; src  = ds:si
; dest = es:di
.loop:
	; dl = command byte
	mov dl, [ds:si]
	call dec_ds_si

	; cx = length
	mov ch, [ds:si]
	call dec_ds_si
	mov cl, [ds:si]
	call dec_ds_si

	mov al, dl
	and al, 0xfe
.try_b0:
	cmp al, 0xb0		; 0xb0 fill command
	jne .try_b2		; if (command & 0xfe) == 0xb0

	mov al, [ds:si]		; read fill byte
	call dec_ds_si

	jcxz .loop_end
.fill_loop:			; fill for length of cx
	mov [es:di], al
	call dec_es_di
	loop .fill_loop

	jmp .loop_end

.try_b2:
	cmp al, 0xb2		; 0xb2 copy command
	jne error		; if (command & 0xfe) == 0xb2

	jcxz .loop_end
.copy_loop:			; copy for length of cx
	mov al, [ds:si]
	call dec_ds_si
	mov [es:di], al
	call dec_es_di
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
	shr ax, 4		; shift the upper 12 bits into the segment
	add ax, bx		; bx is mem_start from the beginning
	add ax, dx		; dx is current relocation segment
	mov es, ax		; es:di points to relocation target word
	add [es:di], bx		; *target += mem_start
	loop .next_address

.next_segment:
	add dh, 0x10		; next relocation segment
	jne apply_relocations	; repeat until we wrap from 0xf000 back to 0x0000

execute_decompressed_program:
	mov ax, bx		; ax = mem_start
	mov si, [real_ss]
	add si, ax		; si = relocated real_ss
	mov di, [real_sp]	; di = real_sp
	add [real_cs], ax	; real_cs = relocated real_cs
	sub ax, 0x10
	mov ds, ax		; ds = mem_start - 0x10 (start of PSP)
	mov es, ax		; es = mem_start - 0x10 (start of PSP)
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
