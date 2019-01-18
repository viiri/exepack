;"\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\x8e\xc0\
; \x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x50\xb8\x32\x00\
; \x50\xcb\x8c\xc3\x8c\xd8\x48\x8e\xd8\x8e\xc0\xbf\x0f\x00\xb9\x10\
; \x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x48\x8e\xc0\xbf\x0f\x00\
; \xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x74\x09\x8c\xda\x2b\xd0\x8e\xda\
; \x83\xce\xf0\x8b\xc7\xf7\xd0\xd3\xe8\x74\x09\x8c\xc2\x2b\xd0\x8e\
; \xc2\x83\xcf\xf0\xac\x8a\xd0\x4e\xad\x8b\xc8\x46\x8a\xc2\x24\xfe\
; \x3c\xb0\x75\x06\xac\xf3\xaa\xeb\x07\x90\x3c\xb2\x75\x6b\xf3\xa4\
; \x8a\xc2\xa8\x01\x74\xba\xbe\x25\x01\x0e\x1f\x8b\x1e\x04\x00\xfc\
; \x33\xd2\xad\x8b\xc8\xe3\x13\x8b\xc2\x03\xc3\x8e\xc0\xad\x8b\xf8\
; \x83\xff\xff\x74\x11\x26\x01\x1d\xe2\xf3\x81\xfa\x00\xf0\x74\x16\
; \x81\xc2\x00\x10\xeb\xdc\x8c\xc0\x40\x8e\xc0\x83\xef\x10\x26\x01\
; \x1d\x48\x8e\xc0\xeb\xe2\x8b\xc3\x8b\x3e\x08\x00\x8b\x36\x0a\x00\
; \x03\xf0\x01\x06\x02\x00\x2d\x10\x00\x8e\xd8\x8e\xc0\xbb\x00\x00\
; \xfa\x8e\xd6\x8b\xe7\xfb\x2e\xff\x2f\xb4\x40\xbb\x02\x00\xb9\x16\
; \x00\x8c\xca\x8e\xda\xba\x0f\x01\xcd\x21\xb8\xff\x4c\xcd\x21Packed file is corrupt"
;
; Identical to stub_279 except that it has a shorter encoding for the
; two instances of the "or di, 0xfff0" instruction: "83cff0" instead of
; "81cff0ff".
;
; Sample:
; https://archive.org/download/MicroCom_374_Cash-Track/MicroCom_374_Cash-Track.zip/cashtrac.exe

BITS 16

exepack_start:

real_IP:	dw	0x0000
real_CS:	dw	0x0000
mem_start:	dw	0x0000	; uninitialized and filled in by the EXEPACK code
exepack_size:	dw	(exepack_end - exepack_start)
real_SP:	dw	0x0000
real_SS:	dw	0x0000
dest_len:	dw	0x0000
signature:	db	'RB'

; On load, es is set to the segment of the 256-byte Program Segment Prefix (PSP).
; cs is set to exepack_start (beginning of EXEPACK header).
; ip is set to copy_decompressor_stub.
copy_decompressor_stub:
	mov ax, es
	add ax, word 0x10	; ax = es + 0x10 (segment immediately after the PSP)
	push cs
	pop ds			; ds = cs (exepack_start)
	mov [mem_start], ax
	add ax, [dest_len]
	mov es, ax		; es = mem_start + dest_len
	mov cx, [exepack_size]
	mov di, cx		; cx = exepack_size
	dec di
	mov si, di		; si = exepack_size - 1
	std			; copy operations go backwards
	rep movsb		; copy exepack_size bytes from ds (exepack_start; i.e., this code) to es (mem_start + dest_len)
	push ax			; segment to jump to (mem_start + dest_len)
	mov ax, (decompress - exepack_start)
	push ax			; offset to jump to (i.e., label "decompress" in the copied block of code)
	retf

decompress:
	mov bx, es		; bx = mem_start + dest_len
	mov ax, ds
	dec ax			; move back 1 paragraph (equivalent of skip_len == 1)
	mov ds, ax		; ds = exepack_start - 1
	mov es, ax		; es = exepack_start - 1 (scratch; used for the upcoming scasb)
	mov di, 15		; di = final byte in final paragraph
	mov cx, 16
	mov al, 0xff
	repe scasb		; scan es:di backwards for first non-0xff byte
	inc di
	mov si, di		; ds:si points to the final byte of the compressed data in the original buffer
	mov ax, bx
	dec ax
	mov es, ax		; es = mem_start + dest_len - 1
	mov di, 15		; es:di points to the final byte of the decompression buffer
; src =  ds:si
; dest = es:di
.loop:
	mov cl, 4
	; adjust ds:si so that si is as high as possible in the segment (without changing the address pointed to)
	; because lengths can be as large as 0xffff and "rep movsb" may wrap around the segment
	mov ax, si
	not ax
	shr ax, cl
	je .si_full		; if (si < 0xfff0)
	mov dx, ds
	sub dx, ax		; underflow possible here
	mov ds, dx		; ds -= (0xffff - si) >> 4
	or si, 0xfff0		; si |= 0xfff0
.si_full:
	; adjust es:di so that di is as high as possible in the segment (without changing the address pointed to)
	; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
	mov ax, di
	not ax
	shr ax, cl
	je .di_full		; if (di < 0xfff0)
	mov dx, es
	sub dx, ax		; underflow possible here
	mov es, dx		; es -= (0xffff - di) >> 4
	or di, 0xfff0		; di |= 0xfff0
.di_full:
	; dl = command byte
	; cx = length
	lodsb
	mov dl, al		; command = *(uint8_t *) si--
	dec si			; (uint8_t *) si--
	lodsw
	mov cx, ax		; length = *(uint16_t *) si--
	inc si			; (uint8_t *) si++
	mov al, dl
	and al, 0xfe
.try_b0:
	cmp al, 0xb0
	jne .try_b2		; if (command & 0xfe) == 0xb0
	lodsb			; al = *(uint8_t *) si--
	rep stosb		; copy length copies of al backwards into es:di
	jmp .loop_end
	nop
.try_b2:
	cmp al, 0xb2
	jne error		; if (command & 0xfe) == 0xb2
	rep movsb		; copy length bytes backward into es:di from ds:si
.loop_end:
	mov al, dl
	test al, 1
	je .loop		; repeat until (command & 0x01) == 1

	mov si, (relocation_entries - exepack_start)
	push cs
	pop ds			; ds = exepack_start
	mov bx, word [mem_start]	; bx = mem_start
	cld			; copy operations go forwards
	xor dx, dx		; section_start = 0
apply_relocations:
	; dx = current section start (increments by 0x1000)
	; cx = number of entries in current section
.loop:
	lodsw
	mov cx, ax		; num_entries = *(uint16_t *) si++
	jcxz .next_section	; if (num_entries > 0)
	mov ax, dx
	add ax, bx
	mov es, ax		; es = mem_start + section_start
.next_address:			; while (num_entries > 0)
	lodsw
	mov di, ax		; addr = *(uint16_t *) si++
	cmp di, 0xffff
	je .write_relocation_ffff	; address with offset of 0xffff needs special handling
	; else write the relocation entry
	add word [es:di], bx	; *addr += mem_start
.relocation_written:
	loop .next_address
.next_section:
	cmp dx, 0xf000
	je .loop_end		; if (section_start == 0xf000) break
	add dx, 0x1000		; else section_start += 0x1000 and repeat
	jmp .loop
.write_relocation_ffff:
	; handle addr == 0xffff
	; otherwise the two-byte write would write the second byte at address 0 in the same segment
	mov ax, es
	inc ax
	mov es, ax		; adjust segment and offset
	sub di, 0x10		; so that di == 0xffef
	; write the relocation entry
	add word [es:di], bx	; *addr += mem_start
	dec ax
	mov es, ax		; restore segment to what it was
	jmp .relocation_written ; back to address loop
.loop_end:
	mov ax, bx		; ax = mem_start
	mov di, word [real_SP]	; di = real_SP
	mov si, word [real_SS]
	add si, ax		; si = mem_start + real_SS
	add word [real_CS], ax	; real_CS += mem_start
	sub ax, 0x10
	mov ds, ax		; es = mem_start - 0x10 (segment of start of PSP)
	mov es, ax		; es = mem_start - 0x10 (segment of start of PSP)
	mov bx, real_IP		; bx points to the 4-byte long pointer real_CS:real_IP.
	cli
	mov ss, si		; ss = mem_start + real_SS
	mov sp, di		; sp = real_SP
	sti
	jmp far [cs:bx]		; jump to real_CS:real_IP

error:
	mov ah, 0x40		; ah=0x40 => write to file handle
	mov bx, 2		; file handle 2 (stderr)
	mov cx, 0x16		; 22 bytes of data (strlen("Packed file is corrupt"))
	mov dx, cs
	mov ds, dx		; ds = cs
	mov dx, .errmsg		; ds:dx is address of string to write
	int 0x21		; syscall
	mov ax, 0x4cff		; ah=0x4c => exit program; al=0xff => exit code -1
	int 0x21		; syscall
.errmsg:	db	'Packed file is corrupt'

relocation_entries:
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000
	dw	0x0000

exepack_end:
