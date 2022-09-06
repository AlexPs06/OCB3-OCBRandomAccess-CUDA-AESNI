CC=gcc
CFLAGS= -march=native 
LIB= -O3
SOURCES= ocb3.c timing_x86.c
SOURCES2= ocb3.c timing_clock.c

all: 
	$(CC) -o timing_x86 $(SOURCES) $(LIB) $(CFLAGS) 
	$(CC) -o timing_clocks $(SOURCES2) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 

