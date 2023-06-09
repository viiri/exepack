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
; UNP calls this version "LINK V3.60, V3.64, V3.65, or V5.01.21 /EXEPACK",
; because it has 8ec0bf0f00 (mov es,ax; mov di,15) ending at offset
; 0x50; 26011d (add [es:di],bx) at offset 0xb5; and 2eff2f
; (jmp far [cs:bx]) at offset 0xf6. From exe/eexpk.asm in
; https://bencastricum.nl/unp/unp4-src.zip:
; dw 0050h, 00B5h, 00F6h, LINK, _V3_60, C, _V3_64, C, _V3_65
; dw                      _or, _V5_01_21, _, FwdS, EXEPACK         , 0
;
; This also the stub produced by:
; * LINK /EXEPACK 3.61 from Microsoft C 5.0 and Microsoft QuickBASIC Compiler 4.00
; * LINK /EXEPACK 5.01.20 from Microsoft Macro Assembler 5.1
; Thanks to Dennis Luehring for providing executables for testing.
;
; This is the stub produced by LINK /EXEPACK 3.10, 3.60, and 3.64 from
; MASM 5.00 and 5.10:
; https://www.pcjs.org/software/pcx86/lang/microsoft/masm/5.00/
; https://www.pcjs.org/software/pcx86/lang/microsoft/masm/5.10/
; https://www.pcjs.org/software/pcx86/lang/microsoft/masm/5.10x/
;
; Sample:
; https://archive.org/download/MicroCom_374_Cash-Track/MicroCom_374_Cash-Track.zip/cashtrac.exe

cpu	8086
org	16	; EXEPACK header is 16 bytes.

; Offsets of fields in the EXEPACK header.
real_ip		equ	0
real_cs		equ	2
mem_start	equ	4
exepack_size	equ	6
real_sp		equ	8
real_ss		equ	10
dest_len	equ	12
signature	equ	14	; unused

; On load,
; * ds and es are set to the segment of the Program Segment Prefix
;   (PSP). The compressed data starts 256 bytes beyond that, at an
;   address we call mem_start.
; * cs is set to real_ip (beginning of EXEPACK header).
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
	; because lengths may be as large as 0xfff0 and "rep movsb" may wrap around the segment
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
	; because lengths may be as large as 0xfff0 and "rep stosb" and "rep movsb" may wrap around the segment
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
	cmp di, 0xffff
	je .write_relocation_ffff	; address with offset of 0xffff needs special handling
	; else write the relocation entry
	add [es:di], bx		; *addr += mem_start
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
	add [es:di], bx	; *addr += mem_start
	dec ax
	mov es, ax		; restore segment to what it was
	jmp .relocation_written ; back to address loop
.loop_end:
	mov ax, bx		; ax = mem_start
	mov di, [real_sp]	; di = real_sp
	mov si, [real_ss]
	add si, ax		; si = mem_start + real_ss
	add [real_cs], ax	; real_cs += mem_start
	sub ax, 0x10
	mov ds, ax		; es = mem_start - 0x10 (segment of start of PSP)
	mov es, ax		; es = mem_start - 0x10 (segment of start of PSP)
	mov bx, real_ip		; bx points to the 4-byte long pointer real_cs:real_ip.
	cli
	mov ss, si		; ss = mem_start + real_ss
	mov sp, di		; sp = real_sp
	sti
	jmp far [cs:bx]		; jump to real_cs:real_ip

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
