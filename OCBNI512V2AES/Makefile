CC=g++
CFLAGS= -march=native 
LIB= -O3
SOURCES= OCBNI512V2AESV2.cpp timing_x86.cpp
SOURCES2= OCBNI512V2AESV2.cpp timing_clock.cpp

all: 
	$(CC) -o timing_x86 $(SOURCES) $(LIB) $(CFLAGS) 
	$(CC) -o timing_clocks $(SOURCES2) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 

