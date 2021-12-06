#include <stdio.h>
#include <stdlib.h>

#define N 256
#define MIN 0 
#define MAX 1000

void initialize_matrices(float * a, float * b);
extern void perform_stencil(float * a, float * b, const int n);

int main() {
    float * a = (float *)malloc(N * N * N * sizeof(float));
    float * b = (float *)malloc(N * N * N * sizeof(float));

    initialize_matrices(a, b);
    perform_stencil(a, b, N);
    return 0;
}

void initialize_matrices(float * a, float * b) {
    for (int i = 0; i < N * N * N; i ++) {
        a[i] = 0.0;
        b[i] = MIN + (MAX - MIN) * (rand() / (float)RAND_MAX);
    }
}