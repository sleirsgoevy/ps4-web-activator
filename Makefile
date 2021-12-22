all: payload.js

clean:
	rm payload.elf payload.bin payload.js

sdk/lib/lib.a:
	cd sdk/lib; make

payload.elf: sdk/lib/lib.a main.c
	gcc -isystem sdk/freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static sdk/lib/lib.a main.c libjbc/*.c -Wl,-gc-sections -o payload.elf -g -fPIE

payload.bin: payload.elf
	objcopy payload.elf --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary payload.bin
	file payload.bin | fgrep -q 'payload.bin: DOS executable (COM)'

payload.js: payload.bin
	python3 gen_mira_blob.py payload.bin > payload.js
