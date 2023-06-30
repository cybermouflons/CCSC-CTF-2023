build:
		gcc -m64 -O2 chall.c -lcrypto -o public/chall
		gcc -m64 -O2 encrypt.c -lcrypto -o encrypt
		nasm -f elf64 shellcode.asm -o shellcode.o
		ld shellcode.o -o shellcode
clean:
		rm public/chall
		rm shellcode.o
		rm shellcode
