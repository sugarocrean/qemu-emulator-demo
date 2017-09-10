all: runkvm guest.bin

runkvm: runkvm.o
	gcc runkvm.c -o runkvm -lpthread -g

guest.bin: guest.o
	ld -m elf_i386 --oformat binary -N -e _start -Ttext 0x1000 -o guest.bin guest.o

guest.o: guest.s
	as -32 guest.s -o guest.o

clean:
	rm *.o *.bin runkvm -f
