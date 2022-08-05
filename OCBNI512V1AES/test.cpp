#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ae.h"

#define M 15
#define N 64

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

#if __INTEL_COMPILER
  #define STAMP ((unsigned)__rdtsc())
#elif (__GNUC__ && (__x86_64__ || __amd64__ || __i386__))
  #define STAMP ({unsigned res; __asm__ __volatile__ ("rdtsc" : "=a"(res) : : "edx"); res;})
#elif (_M_IX86)
  #include <intrin.h>
  #pragma intrinsic(__rdtsc)
  #define STAMP ((unsigned)__rdtsc())
#else
  #error -- Architechture not supported!
#endif


#define DO(x) do { \
int i; \
for (i = 0; i < M; i++) { \
unsigned c2, c1;\
x;x;\
c1 = STAMP;\
for (j = 0; j <= N; j++) { x; }\
c1 = STAMP - c1;\
x;x;\
c2 = STAMP;\
x;\
c2 = STAMP - c2;\
median_next(c1-c2);\
} } while (0)

unsigned values[M];
int num_values = 0;

extern char infoString[];  /* Each AE implementation must have a global one */

#ifndef MAX_ITER
#define MAX_ITER 512
#endif

int comp(const void *x, const void *y) { return *(unsigned *)x - *(unsigned *)y; }
void median_next(unsigned x) { values[num_values++] = x; }
unsigned median_get(void) {
    unsigned res;
    /*for (res = 0; res < num_values; res++)
    //   printf("%d ", values[res]);
    //printf("\n");*/
    qsort(values, num_values, sizeof(unsigned), comp);
    res = values[num_values/2];
    num_values = 0;
    return res;
}
void median_print(void) {
    int res;
    qsort(values, num_values, sizeof(unsigned), comp);
    for (res = 0; res < num_values; res++)
       printf("%d ", values[res]);
    printf("\n");
}

extern void validate();

void imprimiArreglo(int tam, unsigned char *in )
{

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
    }
    printf("\n" );

}

void print_hex_string(unsigned char* buf, int len)
{
    int i;

    if (len==0) { printf("<empty string>"); return; }
    if (len>=40 ) {
        for (i = 0; i < 10; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" ... ");
        for (i = len-10; i < len; i++)
             printf("%02x", *((unsigned char *)buf + i));
        printf(" [%d bytes]", len);
        return;
    }
    for (i = 0; i < len; i++)
        printf("%02x", *((unsigned char *)buf + i));
}
ALIGN(64) unsigned char pt[MAX_ITER+16] = {0,};
char outbuf[MAX_ITER*15+1024+4096];

int main(int argc, char **argv)
{
	/* Allocate locals */
	ALIGN(16) unsigned char tag[16] ={0,};
	ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
	ALIGN(16) unsigned char nonce[] = {
        0x32, 0x43, 0xf6, 0xa8,
        0X88, 0X5a, 0X30, 0X8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x35,
    };
	int iter_list[MAX_ITER]; /* Populate w/ test lengths, -1 terminated */
	ae_ctx* ctx = ae_allocate(NULL);
	char *outp = outbuf;
	int i, j, len;
	double Hz;
	double ipi=0, tmpd;

	/* populate iter_list, terminate list with negative number */
	for (i=0; i<MAX_ITER; ++i)
		iter_list[i] = i+1;
	if (MAX_ITER < 44) iter_list[i++] = 44;
	if (MAX_ITER < 552) iter_list[i++] = 552;
	if (MAX_ITER < 576) iter_list[i++] = 576;
	if (MAX_ITER < 1500) iter_list[i++] = 1500;
	if (MAX_ITER < 4096) iter_list[i++] = 4096;
	iter_list[i] = -1;

    /* Create file for writing data */
	FILE *fp = NULL;
    char str_time[25];
	time_t tmp_time = time(NULL);
	struct tm *tp = localtime(&tmp_time);
	strftime(str_time, sizeof(str_time), "%F %R", tp);
	if ((argc < 2) || (argc > 3)) {
		printf("Usage: %s MHz [output_filename]\n", argv[0]);
		return 0;
	} else {
		Hz = 1e6 * strtol(argv[1], (char **)NULL, 10); (void)Hz;
		if (argc == 3)
			fp = fopen(argv[2], "w");
	}
	
    outp += sprintf(outp, "%s ", infoString);
    #if __INTEL_COMPILER
        outp += sprintf(outp, "- Intel C %d.%d.%d ",
            (__ICC/100), ((__ICC/10)%10), (__ICC%10));
    #elif _MSC_VER
        outp += sprintf(outp, "- Microsoft C %d.%d ",
            (_MSC_VER/100), (_MSC_VER%100));
    #elif __clang_major__
        outp += sprintf(outp, "- Clang C %d.%d.%d ",
            __clang_major__, __clang_minor__, __clang_patchlevel__);
    #elif __clang__
        outp += sprintf(outp, "- Clang C 1.x ");
    #elif __GNUC__
        outp += sprintf(outp, "- GNU C %d.%d.%d ",
            __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
    #endif

    #if __x86_64__ || _M_X64
    outp += sprintf(outp, "x86_64 ");
    #elif __i386__ || _M_IX86
    outp += sprintf(outp, "x86_32 ");
    #elif __ARM_ARCH_7__ || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH_7M__
    outp += sprintf(outp, "ARMv7 ");
    #elif __ARM__ || __ARMEL__
    outp += sprintf(outp, "ARMv5 ");
    #elif (__MIPS__ || __MIPSEL__) && __LP64__
    outp += sprintf(outp, "MIPS64 ");
    #elif __MIPS__ || __MIPSEL__
    outp += sprintf(outp, "MIPS32 ");
    #elif __ppc64__
    outp += sprintf(outp, "PPC64 ");
    #elif __ppc__
    outp += sprintf(outp, "PPC32 ");
    #elif __sparc__ && __LP64__
    outp += sprintf(outp, "SPARC64 ");
    #elif __sparc__
    outp += sprintf(outp, "SPARC32 ");
    #endif

    outp += sprintf(outp, "- Run %s\n\n",str_time);

	outp += sprintf(outp, "Context: %d bytes\n", ae_ctx_sizeof());
    // DO(ae_init(ctx, key, 16, 12, 16));
    // num_values = 0;
    // DO(ae_init(ctx, key, 16, 12, 16));
    outp += sprintf(outp, "Key setup: %d cycles\n\n", (int)((median_get())/(double)N));
        
	/*
	 * Get times over different lengths
	 */
	i=0;
	len = iter_list[0];
	while (true) {
        int j=0;
        
        len = MAX_ITER;
        unsigned char k2[16] ={ 
        0x2b, 0x7e, 0x15, 0x16, 
        0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
        };
        unsigned long long adlen = 0;

         unsigned char ad[adlen];
        for(j=0;j<adlen; j++){
            ad[j]=j;
        }

        for(j=0;j<len; j++){
            pt[j]=j;
        }
        for(j=0;j<16; j++){
            nonce[j]=j;
        }

        printf("----------------------------Encrypt----------------------------\n ");

        printf("nonce   ");
        imprimiArreglo(16,nonce);
        printf("\n---------------------------\n");
        printf("pt      ");
        print_hex_string(pt,len);
        printf("\n---------------------------\n");

        printf("key     ");
        print_hex_string(k2,16);
        printf("\n---------------------------\n");

        printf("len   %i", len);
        printf("\n---------------------------\n");

        for(j=0;j<adlen; j++){
            ad[j]=j;
        }

        for(j=0;j<len; j++){
            pt[j]=j;
        }
        
        ae_init(ctx, k2, 16, 12, MAX_ITER,16);
        ae_encrypt(ctx, nonce, pt, len, ad, adlen, pt, tag, 1);
            
        printf("Ciphertext   ");
        print_hex_string(pt,len);
        printf("\n---------------------------\n");
        printf("tag          ");
        imprimiArreglo(16,tag);
        printf("\n---------------------------\n");


        for(j=0;j<16; j++){
            nonce[j]=j;
        }

        // printf("----------------------------Decrypt----------------------------\n ");

        // printf("nonce   ");
        // imprimiArreglo(16,nonce);
        // printf("\n---------------------------\n");
        // printf("pt      ");
        // print_hex_string(pt,len);
        // printf("\n---------------------------\n");

        // printf("key     ");
        // print_hex_string(k2,16);
        // printf("\n---------------------------\n");
        // ae_init(ctx, k2, 16, 12, MAX_ITER,16);

        // ae_decrypt(ctx, nonce, pt, len, ad, adlen, pt, tag, 1);

        // printf("len   %i", len);
        // printf("\n---------------------------\n");
        // printf("Ciphertext   ");
        // print_hex_string(pt,len);
        // printf("\n---------------------------\n");
        // printf("tag          ");
        // imprimiArreglo(16,tag);
        // printf("\n---------------------------\n");
        
        break;
	}	

    
    
	return ((pt[0]==12) && (pt[10]==34) && (pt[20]==56) && (pt[30]==78));
}












// #include <stdio.h>
// #include <time.h>
// #include <stdlib.h>
// #include "ae.h"

// #define M 15
// #define N 64

// #if __GNUC__
// #define ALIGN(n)      __attribute__ ((aligned(n))) 
// #elif _MSC_VER
// #define ALIGN(n)      __declspec(align(n))
// #else
// #define ALIGN(n)
// #endif

// #if __INTEL_COMPILER
//   #define STAMP ((unsigned)__rdtsc())
// #elif (__GNUC__ && (__x86_64__ || __amd64__ || __i386__))
//   #define STAMP ({unsigned res; __asm__ __volatile__ ("rdtsc" : "=a"(res) : : "edx"); res;})
// #elif (_M_IX86)
//   #include <intrin.h>
//   #pragma intrinsic(__rdtsc)
//   #define STAMP ((unsigned)__rdtsc())
// #else
//   #error -- Architechture not supported!
// #endif


// #define DO(x) do { \
// int i; \
// for (i = 0; i < M; i++) { \
// unsigned c2, c1;\
// x;x;\
// c1 = STAMP;\
// for (j = 0; j <= N; j++) { x; }\
// c1 = STAMP - c1;\
// x;x;\
// c2 = STAMP;\
// x;\
// c2 = STAMP - c2;\
// median_next(c1-c2);\
// } } while (0)

// unsigned values[M];
// int num_values = 0;

// extern char infoString[];  /* Each AE implementation must have a global one */

// #ifndef MAX_ITER
// #define MAX_ITER 4096
// #endif

// int comp(const void *x, const void *y) { return *(unsigned *)x - *(unsigned *)y; }
// void median_next(unsigned x) { values[num_values++] = x; }
// unsigned median_get(void) {
//     unsigned res;
//     /*for (res = 0; res < num_values; res++)
//     //   printf("%d ", values[res]);
//     //printf("\n");*/
//     qsort(values, num_values, sizeof(unsigned), comp);
//     res = values[num_values/2];
//     num_values = 0;
//     return res;
// }
// void median_print(void) {
//     int res;
//     qsort(values, num_values, sizeof(unsigned), comp);
//     for (res = 0; res < num_values; res++)
//        printf("%d ", values[res]);
//     printf("\n");
// }

// extern void validate();


// void print_hex_string(unsigned char* buf, int len)
// {
//     int i;

//     if (len==0) { printf("<empty string>"); return; }
//     if (len>=40) {
//         for (i = 0; i < 10; i++)
//              printf("%02x", *((unsigned char *)buf + i));
//         printf(" ... ");
//         for (i = len-10; i < len; i++)
//              printf("%02x", *((unsigned char *)buf + i));
//         printf(" [%d bytes]", len);
//         return;
//     }
//     for (i = 0; i < len; i++)
//         printf("%02x", *((unsigned char *)buf + i));
// }

// int main(int argc, char **argv)
// {
// 	/* Allocate locals */
// 	ALIGN(16) char pt[MAX_ITER] = {0};
// 	ALIGN(16) char tag[16];
// 	ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
// 	ALIGN(16) unsigned char nonce[] = "abcdefghijklmnop";
//     char outbuf[MAX_ITER*15+1024];
// 	int iter_list[MAX_ITER]; /* Populate w/ test lengths, -1 terminated */
// 	ae_ctx* ctx = ae_allocate(NULL);
// 	char *outp = outbuf;
// 	int i, j, len;
// 	double Hz;
// 	double ipi=0, tmpd;

// 	/* populate iter_list, terminate list with negative number */
// 	for (i=0; i<MAX_ITER; ++i)
// 		iter_list[i] = i+1;
// 	if (MAX_ITER < 44) iter_list[i++] = 44;
// 	if (MAX_ITER < 552) iter_list[i++] = 552;
// 	if (MAX_ITER < 576) iter_list[i++] = 576;
// 	if (MAX_ITER < 1500) iter_list[i++] = 1500;
// 	if (MAX_ITER < 4096) iter_list[i++] = 4096;
// 	iter_list[i] = -1;

//     /* Create file for writing data */
// 	FILE *fp = NULL;
//     char str_time[25];
// 	time_t tmp_time = time(NULL);
// 	struct tm *tp = localtime(&tmp_time);
// 	strftime(str_time, sizeof(str_time), "%F %R", tp);
// 	if ((argc < 2) || (argc > 3)) {
// 		printf("Usage: %s MHz [output_filename]\n", argv[0]);
// 		return 0;
// 	} else {
// 		Hz = 1e6 * strtol(argv[1], (char **)NULL, 10); (void)Hz;
// 		if (argc == 3)
// 			fp = fopen(argv[2], "w");
// 	}
	
//     outp += sprintf(outp, "%s ", infoString);
//     #if __INTEL_COMPILER
//         outp += sprintf(outp, "- Intel C %d.%d.%d ",
//             (__ICC/100), ((__ICC/10)%10), (__ICC%10));
//     #elif _MSC_VER
//         outp += sprintf(outp, "- Microsoft C %d.%d ",
//             (_MSC_VER/100), (_MSC_VER%100));
//     #elif __clang_major__
//         outp += sprintf(outp, "- Clang C %d.%d.%d ",
//             __clang_major__, __clang_minor__, __clang_patchlevel__);
//     #elif __clang__
//         outp += sprintf(outp, "- Clang C 1.x ");
//     #elif __GNUC__
//         outp += sprintf(outp, "- GNU C %d.%d.%d ",
//             __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
//     #endif

//     #if __x86_64__ || _M_X64
//     outp += sprintf(outp, "x86_64 ");
//     #elif __i386__ || _M_IX86
//     outp += sprintf(outp, "x86_32 ");
//     #elif __ARM_ARCH_7__ || __ARM_ARCH_7A__ || __ARM_ARCH_7R__ || __ARM_ARCH_7M__
//     outp += sprintf(outp, "ARMv7 ");
//     #elif __ARM__ || __ARMEL__
//     outp += sprintf(outp, "ARMv5 ");
//     #elif (__MIPS__ || __MIPSEL__) && __LP64__
//     outp += sprintf(outp, "MIPS64 ");
//     #elif __MIPS__ || __MIPSEL__
//     outp += sprintf(outp, "MIPS32 ");
//     #elif __ppc64__
//     outp += sprintf(outp, "PPC64 ");
//     #elif __ppc__
//     outp += sprintf(outp, "PPC32 ");
//     #elif __sparc__ && __LP64__
//     outp += sprintf(outp, "SPARC64 ");
//     #elif __sparc__
//     outp += sprintf(outp, "SPARC32 ");
//     #endif

//     outp += sprintf(outp, "- Run %s\n\n",str_time);

// 	outp += sprintf(outp, "Context: %d bytes\n", ae_ctx_sizeof());
//     DO(ae_init(ctx, key, 16, 12, 16));
//     num_values = 0;
//     DO(ae_init(ctx, key, 16, 12, 16));
//     outp += sprintf(outp, "Key setup: %d cycles\n\n", (int)((median_get())/(double)N));
        
// 	/*
// 	 * Get times over different lengths
// 	 */
// 	i=0;
// 	len = iter_list[0];
// 	while (len >= 0) {
        
//         DO(ae_encrypt(ctx, nonce, pt, len, NULL, 0, pt, tag, 1); nonce[11] += 1);


//         tmpd = ((median_get())/(len*(double)N));
// 		outp += sprintf(outp, "%5d  %6.2f\n", len, tmpd);
// 		if (len==44) {
// 			ipi += 0.05 * tmpd;
// 		} else if (len==552) {
// 			ipi += 0.15 * tmpd;
// 		} else if (len==576) {
// 			ipi += 0.2 * tmpd;
// 		} else if (len==1500) {
// 			ipi += 0.6 * tmpd;
// 		}
		
// 		++i;
// 		len = iter_list[i];
// 	}	
// 	outp += sprintf(outp, "ipi %.2f\n", ipi);
// 	if (fp) {
//         fprintf(fp, "%s", outbuf);
//         fclose(fp);
//     } else
//         fprintf(stdout, "%s", outbuf);
    
    
// 	return ((pt[0]==12) && (pt[10]==34) && (pt[20]==56) && (pt[30]==78));
// }
