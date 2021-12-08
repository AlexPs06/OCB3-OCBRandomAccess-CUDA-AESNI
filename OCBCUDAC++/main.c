#include <stdio.h>
#include <stdlib.h>

#define N 8
#define MIN 10 
#define MAX 1000

void initialize_matrices(float * a, float * b);
extern void perform_stencil(float * a, float * b, const int n);
extern void getDevices();
int main() {
    float * a = (float *)malloc(N * N * N * sizeof(float));
    float * b = (float *)malloc(N * N * N * sizeof(float));

    initialize_matrices(a, b);
    // printf("%f antes, \n",a[0]);
    
    perform_stencil(a, b, N);
    // printf("%f despues, \n",a[0]);
    getDevices();
    return 0;
}

void initialize_matrices(float * a, float * b) {
    for (int i = 0; i < N * N * N; i ++) {
        a[i] = 0.0;
        b[i] = MIN + (MAX - MIN) * (rand() / (float)RAND_MAX);
    }
}