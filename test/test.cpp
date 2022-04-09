#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <iostream>
#include <tmmintrin.h>
#include <immintrin.h>
#include <xmmintrin.h>              
#include <emmintrin.h> 
using namespace std;
typedef __m128i block;
typedef __m512i block512;

typedef struct { __m128i rd_key[11]; } AES_KEY;
#define ROUNDS(ctx) (10)
typedef struct { __m512i rd_key[11]; } AES_KEY_512;
#define MAX_ITER 196608 * 2
#define BPI 8
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define xor_block_512(x,y)        _mm512_xor_si512(x,y)

#if __GNUC__
#define ALIGN(n)      __attribute__ ((aligned(n))) 
#elif _MSC_VER
#define ALIGN(n)      __declspec(align(n))
#else
#define ALIGN(n)
#endif


#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)


static void AES_128_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2;
    __m128i *kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x0,255,1);   kp[1]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,2);   kp[2]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,4);   kp[3]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,8);   kp[4]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,16);  kp[5]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,32);  kp[6]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,64);  kp[7]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,128); kp[8]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,27);  kp[9]  = x0;
    EXPAND_ASSIST(x0,x1,x2,x0,255,54);  kp[10] = x0;
}





static int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
    if (bits == 128) 
        AES_128_Key_Expansion (userKey,key);
    return 0;
}

static inline void AES_ecb_encrypt_blks_512(block512 *blks, unsigned nblks, AES_KEY_512 *key) {
    unsigned i,j,rnds=ROUNDS(key);
	const __m512i *sched = ((__m512i *)(key->rd_key));
    for (i=0; i<nblks; ++i){
	    blks[i] =_mm512_xor_si512(blks[i], sched[0]);
    }
	for(j=1; j<rnds; ++j){
	    for (i=0; i<nblks; ++i){
		    blks[i] = _mm512_aesenc_epi128(blks[i], sched[j]);
        }
    }
    for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_aesenclast_epi128(blks[i], sched[j]);
        
}

static inline void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
    unsigned i,j,rnds=ROUNDS(key);
	const __m128i *sched = ((__m128i *)(key->rd_key));
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_xor_si128(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm_aesenc_si128(blks[i], sched[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_aesenclast_si128(blks[i], sched[j]);
}

void print_hex_string(unsigned char* buf, int len)
{
    int i;

    if (len==0) { printf("<empty string>"); return; }
    if (len>=40) {
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

static int AES_cast_128_to_512_key(AES_KEY *key, AES_KEY_512 *key512)
{   

    for(int i = 0; i< 11; i++ ){
        
        key512->rd_key[i] = _mm512_castsi128_si512( key->rd_key[i] );
        key512->rd_key[i] = _mm512_inserti64x2(key512->rd_key[i], key->rd_key[i], 1 );
        key512->rd_key[i] = _mm512_inserti64x2(key512->rd_key[i], key->rd_key[i], 2 );
        key512->rd_key[i] = _mm512_inserti64x2(key512->rd_key[i], key->rd_key[i], 3 );
    }
    return 0;
}
int main(){
        ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
        ALIGN(16) unsigned char pt128[MAX_ITER] = {0,};
        ALIGN(16) unsigned char ct128[MAX_ITER] = {0,};
        ALIGN(64) unsigned char pt512[MAX_ITER] = {0,};
        ALIGN(64) unsigned char ct512[MAX_ITER] = {0,};
        int j, i;
        int len= MAX_ITER;
        AES_KEY encrypt_key;
        AES_KEY_512 encrypt_key_512;
        for(j=0;j<16; j++){
            key[j]=j;
        }
    	AES_set_encrypt_key((unsigned char *)key, 16*8, &encrypt_key);
        AES_cast_128_to_512_key(&encrypt_key, &encrypt_key_512);

        for(j=0;j<MAX_ITER; j++){
            pt128[j]=0;
            ct128[j]=0;
            pt512[j]=0;
            ct512[j]=0;
        }

        
       
        block512  oa[BPI];
        block     oa128[BPI];

        long double time_spent = 0.0;
        int repeticiones=10000;
        clock_t begin = clock();
        clock_t end = clock();


        printf("\n----------------------------AES-512----------------------------------\n");
        print_hex_string(pt512, len);
         printf("\n");
        for(i=0;i<repeticiones; i++){

            block512       * ctp512 = (block512 *)ct512;
            block512       * ptp512 = (block512 *)pt512;
            
            for(j=0;j<MAX_ITER; j++){
                pt512[j]=0;
            }
            
            begin = clock();
            for(j=0; j<(MAX_ITER/(64*BPI));  j++){
                
                for(int k=0; k<BPI;  k++){
                    oa[k]=ptp512[k];
                }
                AES_ecb_encrypt_blks_512(oa, BPI, &encrypt_key_512);

                for(int k=0; k<BPI;  k++){
                    ctp512[k]=oa[k];
                }
                ptp512 += BPI;
                ctp512 += BPI;
            }
            end = clock();
            time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
        }
        print_hex_string(ct512, len);
        printf("\nThe elapsed time is %08Lf  seconds\n", time_spent/repeticiones);

         for(j=0;j<MAX_ITER; j++){
            pt128[j]=0;
            ct128[j]=0;
            pt512[j]=0;
            ct512[j]=0;
        }

        printf("\n----------------------------AES-128----------------------------------\n");
        print_hex_string(pt128, len);
        printf("\n");
        
        time_spent = 0.0;
        for(i=0;i<repeticiones; i++){

            block          * ptp128 = (block *)pt128;
            block          * ctp128 = (block *)ct128;
            
            for(j=0;j<MAX_ITER; j++){
                pt128[j]=0;
            }
            begin = clock();
            for(j=0; j<(MAX_ITER/(16*BPI));  j++){
                for(int k=0; k<BPI;  k++){
                    oa128[k]=ptp128[k];
                }
                AES_ecb_encrypt_blks(oa128, BPI, &encrypt_key);

                for(int k=0; k<BPI;  k++){
                    ctp128[k]=oa128[k];
                }
                ctp128 += BPI;
                ptp128 += BPI;
            }
            end = clock();
            time_spent += (double)(end - begin) / CLOCKS_PER_SEC;
        }
        print_hex_string(ct128, len);
        printf("\nThe elapsed time is %08Lf  seconds\n", time_spent/repeticiones);
return 0;
}