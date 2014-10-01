all: tnet

tiny-network.o: network.h network.c
	gcc -c -O3 network.c
	
libtnet.a: network.o
	ar rcs libtnet.a network.o
	
clean:
	rm -f *.o *a
