BITS 16

main:
	mov ah, 0x40		; write to file handle
	mov bx, 1		; stdout
	mov cx, msg_len		; length of string
	mov dx, cs
	mov ds, dx
	mov dx, msg		; ds:dx points to string
	int 0x21

	mov si, numbers
	mov cx, 4
.loop:
	mov ah, 0x02		; write character to stdout
	mov dl, ' '		; character to write
	int 0x21

	xor bx, bx
	mov bl, [si]
	shr bx, 4		; high nibble
	mov dl, [hexdigits+bx]
	mov ah, 0x02
	int 0x21

	xor bx, bx
	mov bl, [si]
	and bx, 0xf		; low nibble 
	mov dl, [hexdigits+bx]
	mov ah, 0x02
	int 0x21

	inc si
	loop .loop

	mov ax, 0x4c00		; terminate with status 0
	int 0x21

numbers:
	db	0x12, 0x34, 0xab, 0xcd

hexdigits:
	db "0123456789abcdef"
msg:
	db "Hello, DOS", 13, 10, "Lucky numbers"
msg_len	equ	$ - msg
