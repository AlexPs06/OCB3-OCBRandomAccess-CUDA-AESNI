#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "ae.h"

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif

extern char infoString[];  /* Each AE implementation must have a global one */

#ifndef MAX_ITER
#define MAX_ITER 10
#endif


const unsigned long long size =  1073741824+1073741824/2;

ALIGN(32) unsigned char pt[size];

int main(int argc, char **argv)
{
	/* Allocate locals */
	// ALIGN(64) char pt[1073741824+1073741824/2] = {0};
	ALIGN(16) char tag[16];
	ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
	ALIGN(16) unsigned char nonce[] = "abcdefghijklmnop";
	char outbuf[MAX_ITER*15+1024+4096];
	int iter_list[2048]; /* Populate w/ test lengths, -1 terminated */
	ae_ctx* ctx = ae_allocate(NULL);
	char *outp = outbuf;
	int iters, i, j, len;
	double Hz,sec;
	double ipi=0, tmpd;
	clock_t c;

	/* populate iter_list, terminate list with negative number */
	for (i=0; i<MAX_ITER; ++i)
		iter_list[i] = i+1;
	if (MAX_ITER < 44) iter_list[i++] = 44;
	if (MAX_ITER < 552) iter_list[i++] = 552;
	if (MAX_ITER < 576) iter_list[i++] = 576;
	if (MAX_ITER < 1500) iter_list[i++] = 1500;
	if (MAX_ITER < 4096) iter_list[i++] = 4096;
	if (MAX_ITER < 8192) iter_list[i++] = 8192;
	if (MAX_ITER < 8192*2) iter_list[i++] = 8192*2;
	if (MAX_ITER < 1048576) iter_list[i++] = 1048576;
	if (MAX_ITER < 2097152) iter_list[i++] = 2097152;
	if (MAX_ITER < 4194304) iter_list[i++] = 4194304;
	if (MAX_ITER < 4194304*4) iter_list[i++] = 4194304*4;
	if (MAX_ITER < (4194304*4)*4) iter_list[i++] = (4194304*4)*4;
	if (MAX_ITER < 1073741824) iter_list[i++] = 1073741824;
	if (MAX_ITER < 1073741824+1073741824/2) iter_list[i++] = 1073741824+1073741824/2;
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
		Hz = 1e6 * strtol(argv[1], (char **)NULL, 10);
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
    #elif __MIPS__ || __MIPSEL__
    outp += sprintf(outp, "MIPS32 ");
    #elif __ppc64__
    outp += sprintf(outp, "PPC64 ");
    #elif __ppc__
    outp += sprintf(outp, "PPC32 ");
    #elif __sparc__
    outp += sprintf(outp, "SPARC ");
    #endif

    outp += sprintf(outp, "- Run %s\n\n",str_time);

	outp += sprintf(outp, "Context: %d bytes\n", ae_ctx_sizeof());
	
	printf("Starting run...\n");fflush(stdout);

	/*
	 * Get time for key setup
	 */
	iters = (int)(Hz/520);

	do {
	
		ae_init(ctx, key, 16, 12, 16);
		c = clock();
		for (j = 0; j < iters; j++) {
			ae_init(ctx, key, 16, 12, 16);
		}
		c = clock() - c;
		sec = c/(double)CLOCKS_PER_SEC;
		tmpd = (sec * Hz) / (iters);
		
		if ((sec < 1.2)||(sec > 1.3))
			iters = (int)(iters * 5.0/(4.0 * sec));
		printf("%f\n", sec);
	} while ((sec < 1.2) || (sec > 1.3));
	
	printf("key -- %.2f (%d cycles)\n",sec,(int)tmpd);fflush(stdout);
	outp += sprintf(outp, "Key setup: %d cycles\n\n", (int)tmpd);

	/*
	 * Get times over different lengths
	 */
	iters = (int)(Hz/1000);
	printf("iteracioes -- %i\n\n",iters);fflush(stdout);

	i=0;
	len = iter_list[0];
	double prom_time = 0;

	while (len >= 0) {
	
		do {
		
			ae_encrypt(ctx, nonce, pt, len, NULL, 0, pt, tag, 1);
			c = clock();
			for (j = 0; j < iters; j++) {
				ae_encrypt(ctx, nonce, pt, len, NULL, 0, pt, tag, 1);
				nonce[11] += 1;
			}
			c = clock() - c;
			sec = c/(double)CLOCKS_PER_SEC;
			tmpd = (sec * Hz) / ((double)len * iters);
			prom_time = sec/iters;
			
			if (len == 1073741824 || len == 1073741824+1073741824/2 ){
				break;
			}
			if ((sec < 1.2)||(sec > 1.3))
				iters = (int)(iters * 5.0/(4.0 * sec));
			
		} while ((sec < 1.2) || (sec > 1.3));
		
		printf("%d -- %.5f  (%6.5f cpb) time_prom %6.10f seconds\n",len,sec,tmpd,prom_time );fflush(stdout);
		outp += sprintf(outp,"%d -- %.5f  (%6.5f cpb) time_prom %6.10f seconds\n",len,sec,tmpd,prom_time);fflush(stdout);
		// outp += sprintf(outp, "%5d  %6.2f\n", len, tmpd);
		if (len==44) {
			ipi += 0.05 * tmpd;
		} else if (len==552) {
			ipi += 0.15 * tmpd;
		} else if (len==576) {
			ipi += 0.2 * tmpd;
		} else if (len==1500) {
			ipi += 0.6 * tmpd;
		}
		
		++i;
		len = iter_list[i];
	}
	outp += sprintf(outp, "ipi %.2f\n", ipi);
	if (fp) {
        fprintf(fp, "%s", outbuf);
        fclose(fp);
    } else
        fprintf(stdout, "%s", outbuf);

	return ((pt[0]==12) && (pt[10]==34) && (pt[20]==56) && (pt[30]==78));
}
