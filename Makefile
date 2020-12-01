all: tcp-block

tcp-block: tcp-block.o main.o
	g++ -o tcp-block tcp-block.o main.o -lpcap

tcp-block.o: tcp-block.h tcp-block.cpp
	g++ -c -o tcp-block.o tcp-block.cpp

main.o: tcp-block.h main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f tcp-block
	rm -f *.o