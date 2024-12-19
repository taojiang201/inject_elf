all:reverse_text target
reverse_text: reverse_text.o
	ld -m elf_x86_64 -g -Ttext-segment=0x0 -dynamic-linker /lib64/ld-linux-x86-64.so.2  reverse_text.o -o reverse_text
reverse_text.o:reverse_text.s
	as -64 -g ./reverse_text.s -a=reverse_text.lst -o reverse_text.o
target:host.c
	gcc -m64 -g -o target host.c -lpthread -Wl,-Ttext-segment=0x0
clean:
	rm -f *.o ./reverse_text ./target ./*.lst
