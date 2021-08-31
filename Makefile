all: src/stub.bin
	cargo build --release

src/stub.bin: src/stub.asm
	nasm -O2 -fbin -o "$@" "$<"

clean:
	rm -f src/stub.bin

.PHONY: all clean
