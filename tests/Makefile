# https://nasm.us/
NASM ?= nasm
# http://www.delorie.com/djgpp/16bit/djlink/
DJLINK ?= djlink

all: hello.exe

%.exe: %.obj
	$(DJLINK) -o "$@" "$<"

%.obj: %.asm
	$(NASM) -O2 -f obj -o "$@" "$<"

.PHONY: all

.DELETE_ON_ERROR:
