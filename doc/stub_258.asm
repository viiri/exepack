;"\x8c\xc0\x05\x10\x00\x0e\x1f\xa3\x04\x00\x03\x06\x0c\x00\x8e\xc0\
; \x8b\x0e\x06\x00\x8b\xf9\x4f\x8b\xf7\xfd\xf3\xa4\x50\xb8\x32\x00\
; \x50\xcb\x8c\xc3\x8c\xd8\x48\x8e\xd8\x8e\xc0\xbf\x0f\x00\xb9\x10\
; \x00\xb0\xff\xf3\xae\x47\x8b\xf7\x8b\xc3\x48\x8e\xc0\xbf\x0f\x00\
; \xb1\x04\x8b\xc6\xf7\xd0\xd3\xe8\x74\x0a\x8c\xda\x2b\xd0\x8e\xda\
; \x81\xce\xf0\xff\x8b\xc7\xf7\xd0\xd3\xe8\x74\x0a\x8c\xc2\x2b\xd0\
; \x8e\xc2\x81\xcf\xf0\xff\xac\x8a\xd0\x4e\xad\x8b\xc8\x46\x8a\xc2\
; \x24\xfe\x3c\xb0\x75\x06\xac\xf3\xaa\xeb\x07\x90\x3c\xb2\x75\x56\
; \xf3\xa4\x8a\xc2\xa8\x01\x74\xb8\xbe\x12\x01\x0e\x1f\x8b\x1e\x04\
; \x00\xfc\x33\xd2\xad\x8b\xc8\xe3\x0e\x8b\xc2\x03\xc3\x8e\xc0\xad\
; \x8b\xf8\x26\x01\x1d\xe2\xf8\x81\xfa\x00\xf0\x74\x06\x81\xc2\x00\
; \x10\xeb\xe1\x8b\xc3\x8b\x3e\x08\x00\x8b\x36\x0a\x00\x03\xf0\x01\
; \x06\x02\x00\x2d\x10\x00\x8e\xd8\x8e\xc0\xbb\x00\x00\xfa\x8e\xd6\
; \x8b\xe7\xfb\x2e\xff\x2f\xb4\x40\xbb\x02\x00\xb9\x16\x00\x8c\xca\
; \x8e\xda\xba\xfc\x00\xcd\x21\xb8\xff\x4c\xcd\x21Packed file is corrupt"
;
; Similar to stub_283, except that the EXEPACK header lacks the skip_len
; field (and hence is 16 rather than 18 bytes). Instead, it always acts
; as if skip_len were 1; i.e., no space between the end of compressed
; data and the beginning of the EXEPACK header. It also has a bug when a
; relocation entry is 0xffff: the first byte of the altered value will
; be written at offset 0xffff in the es segment, but the second byte
; will wrap around and be written at offset 0 in the same segment,
; instead of offset 0 in the following segment.
;
; UNP calls this version "EXEPACK V4.00", because it has 8ec0bf0f00
; (mov es,ax; mov di,15) ending at offset 0x50; 26011d (add [es:di],bx)
; at offset 0xb2; and 2eff2f (jmp far [cs:bx]) at offset 0xe3. From
; exe/eexpk.asm in http://unp.bencastricum.nl/unp4-src.zip:
; dw 0050h, 00B2h, 00E3h, EXEPACK, _V4_00                          , 0
;
; Sample:
; https://archive.org/download/TheAdventuresOfCaptainComic/AdventuresOfCaptainComicEpisode1The-PlanetOfDeathsw1988michaelA.Denioaction.zip/COMIC.EXE
;
; This stub's decompress subroutine matches the one in the left-hand
; (pre-hotpatch) listing at
; https://blogs.technet.microsoft.com/uktechnet/2013/08/12/the-original-appcompat-solving-a-20-year-old-mystery-for-me/.
; (Archived listing graphic at
; https://web.archive.org/web/20170115043824/http://www.microsoft.com/security/portal/blog-images/a/exepack.png.)
; The right-hand side shows how the code is hotpatched to remove pointer
; underflow and reliance on specific address wrapping behavior. It still
; has the built-in assumption that skip_len = 1.
;
; decompress:
; 	push es			; mem_start + dest_len
; 	mov ax, ds
; 	dec ax			; move back 1 paragraph (equivalent of skip_len == 1)
; 	mov ds, ax
;	mov es, ax		; scratch; used for the upcoming scasb
; 	mov di, 15		; di = final byte in final paragraph
; 	push di
; 	mov cx, 16
; 	mov al, 0xff
; 	repe scasb		; scan es:di backwards for first non-0xff byte
; 	inc di
; 	mov si, di		; ds:si points to the final byte of the compressed data in the original buffer
; 	pop di			; es:di points to the final byte of the decompression buffer
; 	pop ax			; ax = mem_start + dest_len
; 	dec ax
; 	mov es, ax		; es = mem_start + dest_len - 1
; ; src =  ds:si
; ; dest = es:di
; .loop:
; 	mov cx, 0x0204
; 	; adjust ds:si and es:di so that si/di are as high as possible in their respective segments (without changing the addresses pointed to)
; 	; because lengths can be as large as 0xffff and "rep stosb" and "rep movsb" may wrap around the segment
; 	; we run this operation twice (ch=0x02): the first time for ds:si, the second for es:di
; 	mov ax, si
; 	not ax
; 	shr ax, cl		; shift right by 4
; 	je .offset_ok		; if (si < 0xfff0)
; 	mov dx, ds
; 	or si, 0xfff0		; si |= 0xfff0
; 	sub dx, ax		; new_seg = old_seg - ((0xffff - si) >> 4)
; 	jnb .segment_ok		; if (new_seg < 0) shrink si instead (fix for A20 bug)
; 	neg dx
; 	shl dx, cl
; 	sub si, dx		; si -= (0xffff - new_seg)
; 	xor dx, dx		; new_seg = 0
; .segment_ok:
; 	mov ds, dx
; .offset_ok:
; 	; swap ds:si and es:di
; 	xchg si, di
; 	push ds
; 	push es
; 	pop ds
; 	pop es
; 	dec ch
; 	jne .loop		; do it again for the other pair of registers
;
; 	; dl = command byte
; 	; cx = length
; 	lodsb
; 	xchg dx, ax		; command = *(uint8_t *) si--
; 	dec si			; (uint8_t *) si--
; 	lodsw
; 	mov cx, ax		; length = *(uint16_t *) si--
; 	inc si			; (uint8_t *) si++
; 	mov al, dl
; 	and al, 0xfe
; .try_b0:
; 	cmp al, 0xb0
; 	jne .try_b2		; if (command & 0xfe) == 0xb0
; 	lodsb			; al = *(uint8_t *) si--
; 	rep stosb		; copy length copies of al backwards into es:di
; 	jmp .loop_end
; .try_b2:
; 	cmp al, 0xb2
; 	jne error		; if (command & 0xfe) == 0xb2
; 	rep movsb		; copy length bytes backward into es:di from ds:si
; .loop_end:
; 	xchg dx, ax
; 	test al, 1
; 	je .loop		; repeat until (command & 0x01) == 1
; 	nop
; 	nop

BITS 16
ORG 16	; EXEPACK header is 16 bytes.

; Offsets of fields in the EXEPACK header.
real_IP		equ	0
real_CS		equ	2
mem_start	equ	4
exepack_size	equ	6
real_SP		equ	8
real_SS		equ	10
dest_len	equ	12
signature	equ	14	; unused

; On load,
; * ds and es are set to the segment of the Program Segment Prefix
;   (PSP). The compressed data starts 256 bytes beyond that, at an
;   address we call mem_start.
; * cs is set to real_IP (beginning of EXEPACK header).
; * ip is set to copy_exepack_block.
copy_exepack_block:
	mov ax, es
	add ax, 0x10		; ax = es+16 (mem_start, 256 bytes past PSP, beginning of compressed data)
	push cs
	pop ds			; ds = cs (beginning of EXEPACK variables, end of compressed data)
	mov [mem_start], ax
	add ax, [dest_len]
	mov es, ax		; es = mem_start + dest_len
	mov cx, [exepack_size]
	mov di, cx		; cx = exepack_size
	dec di
	mov si, di		; si = exepack_size - 1
	std			; copy operations go backwards
	rep movsb		; copy exepack_size bytes from ds (i.e., this code) to es (mem_start + dest_len)
	push ax			; segment to jump to (mem_start + dest_len)
	mov ax, decompress
	push ax			; offset to jump to (i.e., label "decompress" in the copied block of code)
	retf

decompress:
	mov bx, es		; bx = mem_start + dest_len
	mov ax, ds
	dec ax			; move back 1 paragraph (equivalent of skip_len == 1)
	mov ds, ax
	mov es, ax		; scratch; used for the upcoming scasb
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

	mov si, relocation_entries
	push cs
	pop ds			; ds = beginning of EXEPACK block
	mov bx, [mem_start]	; bx = mem_start
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
	; write the relocation entry (bug if di == 0xffff)
	add [es:di], bx		; *addr += mem_start
	loop .next_address
.next_section:
	cmp dx, 0xf000
	je .loop_end		; if (section_start == 0xf000) break
	add dx, 0x1000		; else section_start += 0x1000 and repeat
	jmp .loop
.loop_end:
	mov ax, bx		; ax = mem_start
	mov di, [real_SP]	; di = real_SP
	mov si, [real_SS]
	add si, ax		; si = mem_start + real_SS
	add [real_CS], ax	; real_CS += mem_start
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
