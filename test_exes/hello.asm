BITS 16

main:
	mov ah, 0x40		; write to file handle
	mov bx, 1		; stdout
	mov cx, .msg_end-.msg	; length of string
	mov dx, cs
	mov ds, dx
	mov dx, .msg		; ds:dx points to string
	int 0x21
	mov ax, 0x4c00
	int 0x21

.msg:
	db 'Hello, DOS'
.msg_end:
