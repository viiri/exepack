# https://nasm.us/
NASM ?= nasm
# http://www.delorie.com/djgpp/16bit/djlink/
DJLINK ?= djlink

all: hello.exe

%.exe: %.obj
	$(DJLINK) -o "$@" "$<"

%.obj: %.asm
	$(NASM) -O2 -f obj -o "$@" "$<"

# See README for instructions on reproducing these files.
hello-%-link.exe: hello.obj
	rm -f OUT.EXE
	dosbox -c 'mount c .' -c 'c:' -c '$*\LINK.EXE /EXEPACK $<,OUT.EXE;' -c 'exit'
	mv OUT.EXE "$@" || rm -f OUT.EXE
hello-%-exepack.exe: hello.exe
	rm -f OUT.EXE
	dosbox -c 'mount c .' -c 'c:' -c '$*\EXEPACK.EXE $< OUT.EXE' -c 'exit'
	mv OUT.EXE "$@" || rm -f OUT.EXE

.PHONY: all

.DELETE_ON_ERROR:
