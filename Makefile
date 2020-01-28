all: src/stub.bin
	cargo build

clean:
	rm -f src/stub.bin

src/stub.bin: src/stub.asm
	nasm -O2 -fbin -o "$@" "$<"

.PHONY: all
