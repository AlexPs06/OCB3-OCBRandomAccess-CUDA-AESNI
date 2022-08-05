CC=nvcc
CFLAGS=-rdc=true
# -gencode arch=compute_80,code=sm_80
LIB= 
# -lineinfo -lcudadevrt 
# -rdc=true
SOURCES= OCB3.cu
EXECNAME=OCB3
all: 
	$(CC) -o $(EXECNAME) $(SOURCES) $(LIB) $(CFLAGS) 

clean: 
	rm *.o 

