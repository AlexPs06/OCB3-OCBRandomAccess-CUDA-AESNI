CC=g++
CFLAGS= -march=native 
LIB= -O3
SOURCES= OCB3NI256.cpp timing_x86.cpp
SOURCES2= OCB3NI256.cpp timing_clock.cpp
SOURCES3= OCB3NI256.cpp test.cpp
EXECNAME= OCB3NI256

all: 
	$(CC) -o timing_x86 $(SOURCES) $(LIB) $(CFLAGS) 
	$(CC) -o timing_clocks $(SOURCES2) $(LIB) $(CFLAGS) 
	$(CC) -o $(EXECNAME) $(SOURCES3) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 

