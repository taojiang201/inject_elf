all:inject_code target
inject_code:inject_code.o
	ld -m elf_x86_64 -g -Ttext-segment=0x0 -dynamic-linker /lib64/ld-linux-x86-64.so.2  inject_code.o -o inject_code
inject_code.o:inject_code.s
	as -64 -g ./inject_code.s -a=inject_code.lst -o inject_code.o
target:host.c
	gcc -m64 -g -o target host.c -lpthread -Wl,-Ttext-segment=0x0
clean:
	rm -f *.o ./inject_code ./target ./*.lst
