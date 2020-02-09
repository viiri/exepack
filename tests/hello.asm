BITS 16

main:
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
	shr bx, 4		; high nibble
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
	; these numbers are meant to be overwritten by relocation
	db	0x12, 0x34, 0xab, 0xcd
num_numbers	equ $ - numbers

hexdigits:
	db "0123456789abcdef"
msg:
	db `Hello, DOS\r\nLucky numbers`
msg_len	equ	$ - msg
