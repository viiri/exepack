cpu	8086

section	code
	mov ah, 0x40		; write to file handle
	mov bx, 1		; stdout
	mov cx, msg_len		; length of string
	mov dx, cs
	mov ds, dx
	mov dx, msg		; ds:dx points to string
	int 0x21

	lea si, [numbers]
	mov cx, num_numbers
.loop:
	mov dl, ' '		; character to write
	mov ah, 0x02		; write character to stdout
	int 0x21

	; output high nibble
	xor bx, bx
	mov bl, [si]
	shr bx, 1		; high nibble
	shr bx, 1
	shr bx, 1
	shr bx, 1
	mov dl, [hexdigits+bx]	; character to write
	mov ah, 0x02		; write character to stdout
	int 0x21

	; output low nibble
	xor bx, bx
	mov bl, [si]
	and bx, 0xf		; low nibble 
	mov dl, [hexdigits+bx]	; character to write
	mov ah, 0x02		; write character to stdout
	int 0x21

	inc si			; next number
	loop .loop

	mov ax, 0x4c00		; terminate with status 0
	int 0x21

numbers:
	; this array is meant to be overwritten by relocation
	; cannot have a non-zero relocated constant: https://bugzilla.nasm.us/show_bug.cgi?id=3392783
	dw	code, code
num_numbers	equ $ - numbers

hexdigits:
	db "0123456789abcdef"
msg:
	db `Hello, DOS\r\nLucky numbers`
msg_len	equ	$ - msg

; low-entropy padding to make the program compressible by Microsoft EXEPACK.EXE
times	256	db	0

section	_	stack align=16
	resb	128
