CC=nvcc
CFLAGS= -O3 -gencode arch=compute_61,code=sm_61
LIB=
SOURCES= OCB3.cu
EXECNAME=OCB3

all: 
	$(CC) $(SOURCES) -o $(EXECNAME)  $(LIB) $(CFLAGS) 

clean: 
	rm *.o 

