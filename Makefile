all: src/stub.in
	cargo build

clean:
	rm -f src/stub.in

src/stub.in: src/stub.asm
	( \
		echo "// Automatically generated from $$(basename "$<")."; \
		printf "b\""; \
		nasm -O2 -fbin -o /dev/stdout "$<" \
			| od -An -v -tu1 \
			| xargs printf "\\\\x%02x"; \
		printf "\"\\n"; \
	) > "$@"

.PHONY: all
