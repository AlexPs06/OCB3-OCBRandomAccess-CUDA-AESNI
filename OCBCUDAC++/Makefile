SM := 35

CC := gcc
NVCC := nvcc

CFLAGS = -std=c99
NVCCFLAGS = -O3

GENCODE_FLAGS = -gencode arch=compute_$(SM),code=sm_$(SM)
LIB_FLAGS = -lcudadevrt -lcudart

BUILDDIR = build

TARGET = stencil
all: $(TARGET)

$(TARGET): $(BUILDDIR)/dlink.o $(BUILDDIR)/main.o $(BUILDDIR)/$(TARGET).o
	$(CC) $(CFLAGS) $^ -o $@ $(LIB_FLAGS)

$(BUILDDIR)/dlink.o: $(BUILDDIR)/$(TARGET).o 
	$(NVCC) $(NVCCFLAGS) $^ -o $@ $(GENCODE_FLAGS) -dlink

$(BUILDDIR)/main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(TARGET).o: kernal.cu
	$(NVCC) -c $(NVCCFLAGS) $< -o $@ $(GENCODE_FLAGS) 

clean:
	rm -f $(BUILDDIR)/*.o $(TARGET) 