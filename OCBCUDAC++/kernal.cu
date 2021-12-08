#include <stdio.h>
__device__ void test(float * a){
    a[0]=20;
}

__global__ void kernel(float * a, float * b, const int N) {
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;
    size_t j = blockIdx.y * blockDim.y + threadIdx.y;
    size_t k = blockIdx.z * blockDim.z + threadIdx.z;
    printf("%f, lleguer \n",a[0]);
    test(a);
    a[0]=20;
}


extern "C" void perform_stencil(float * a, float * b, const int N) {
    cudaSetDevice(0);

    float * d_a;
    float * d_b;

    cudaEvent_t start, stop;
    float       elapsedTime;
    
    /* begin timing */
    cudaEventCreate(&start);
    cudaEventRecord(start, 0);

    cudaMalloc(&d_a, sizeof(float) * N * N * N);
    cudaMalloc(&d_b, sizeof(float) * N * N * N);

    cudaMemcpy(d_a, a, sizeof(float) * N * N * N, cudaMemcpyHostToDevice);
    cudaMemcpy(d_b, b, sizeof(float) * N * N * N, cudaMemcpyHostToDevice);

    dim3 threadsPerBlock(1);
    dim3 numBlocks(1);

    // printf("%f\n", d_a[0]);

    kernel <<<numBlocks, threadsPerBlock>>>(d_a, d_b, N);
    cudaMemcpy(a,d_a, sizeof(float) * N * N * N, cudaMemcpyDeviceToHost);
    /* end timing */
    cudaEventCreate(&stop);
    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);


    cudaEventElapsedTime(&elapsedTime, start, stop);
    printf("Execution time: %f seconds\n", elapsedTime / 1000);
    cudaFree(d_a);
    cudaFree(d_b);
}

extern "C" void getDevices() {
    int nDevices;

    cudaGetDeviceCount(&nDevices);
    for (int i = 0; i < nDevices; i++) {
        cudaDeviceProp prop;
        cudaGetDeviceProperties(&prop, i);
        printf("Device Number: %d\n", i);
        printf("  Device name: %s\n", prop.name);
        printf("  Memory Clock Rate (KHz): %d\n",
            prop.memoryClockRate);
        printf("  Memory Bus Width (bits): %d\n",
            prop.memoryBusWidth);
        printf("  Peak Memory Bandwidth (GB/s): %f\n\n",
            2.0*prop.memoryClockRate*(prop.memoryBusWidth/8)/1.0e6);
    }

}