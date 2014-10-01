all: libtnet

tiny-network.o: network.h network.c
	gcc -c -O3 network.c
	
libtnet: network.o
	ar rcs libtnet.a network.o
	
clean:
	rm -f *.o *a
