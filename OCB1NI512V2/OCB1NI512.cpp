/*------------------------------------------------------------------------
/ OCB Version 3 Reference Code (Optimized C)     Last modified 12-JUN-2013
/-------------------------------------------------------------------------
/ Copyright (c) 2013 Ted Krovetz.
/
/ Permission to use, copy, modify, and/or distribute this software for any
/ purpose with or without fee is hereby granted, provided that the above
/ copyright notice and this permission notice appear in all copies.
/
/ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
/ WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
/ MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
/ ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
/ WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
/ ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
/ OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/
/ Phillip Rogaway holds patents relevant to OCB. See the following for
/ his patent grant: http://www.cs.ucdavis.edu/~rogaway/ocb/grant.htm
/
/ Special thanks to Keegan McAllister for suggesting several good improvements
/
/ Comments are welcome: Ted Krovetz <ted@krovetz.net> - Dedicated to Laurel K
/------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* Usage notes                                                             */
/* ----------------------------------------------------------------------- */

/* - When AE_PENDING is passed as the 'final' parameter of any function,
/    the length parameters must be a multiple of (BPI*16).
/  - When available, SSE or AltiVec registers are used to manipulate data.
/    So, when on machines with these facilities, all pointers passed to
/    any function should be 16-byte aligned.
/  - Plaintext and ciphertext pointers may be equal (ie, plaintext gets
/    encrypted in-place), but no other pair of pointers may be equal.
/  - This code assumes all x86 processors have SSE2 and SSSE3 instructions
/    when compiling under MSVC. If untrue, alter the #define.
/  - This code is tested for C99 and recent versions of GCC and MSVC.      */

/* ----------------------------------------------------------------------- */
/* User configuration options                                              */
/* ----------------------------------------------------------------------- */

/* Set the AES key length to use and length of authentication tag to produce.
/  Setting either to 0 requires the value be set at runtime via ae_init().
/  Some optimizations occur for each when set to a fixed value.            */
#define OCB_KEY_LEN         16  /* 0, 16, 24 or 32. 0 means set in ae_init */
#define OCB_TAG_LEN         16  /* 0 to 16. 0 means set in ae_init         */

/* This implementation has built-in support for multiple AES APIs. Set any
/  one of the following to non-zero to specify which to use.               */
#define USE_OPENSSL_AES      0  /* http://openssl.org                      */
#define USE_REFERENCE_AES    0  /* Internet search: rijndael-alg-fst.c     */
#define USE_AES_NI           1  /* Uses compiler's intrinsics              */

/* During encryption and decryption, various "L values" are required.
/  The L values can be precomputed during initialization (requiring extra
/  space in ae_ctx), generated as needed (slightly slowing encryption and
/  decryption), or some combination of the two. L_TABLE_SZ specifies how many
/  L values to precompute. L_TABLE_SZ must be at least 3. L_TABLE_SZ*16 bytes
/  are used for L values in ae_ctx. Plaintext and ciphertexts shorter than
/  2^L_TABLE_SZ blocks need no L values calculated dynamically.            */
#define L_TABLE_SZ          31

/* Set L_TABLE_SZ_IS_ENOUGH non-zero iff you know that all plaintexts
/  will be shorter than 2^(L_TABLE_SZ+4) bytes in length. This results
/  in better performance.                                                  */
#define L_TABLE_SZ_IS_ENOUGH 1

/* ----------------------------------------------------------------------- */
/* Includes and compiler specific definitions                              */
/* ----------------------------------------------------------------------- */

#include "ae.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <memory>
#include <math.h>  
#include <wmmintrin.h>
#include <tmmintrin.h>              /* SSSE3 instructions              */
#include <xmmintrin.h>              /* SSE instructions and _mm_malloc */
#include <emmintrin.h>              /* SSE2 instructions               */
#include <immintrin.h>
#define ALIGN(n)

#define bswap32(x)                                              \
    ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
    (((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))

void imprimiArreglo(int tam, unsigned char *in )
{

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
    }
    printf("\n" );

}
void imprimiArreglo(int tam, unsigned int *keys ){
    for (int i = 0; i<tam; i++){
        printf("%08x", keys[i] );
    }
    printf("\n");
}

static inline uint64_t bswap64(uint64_t x) {
    union { uint64_t u64; uint32_t u32[2]; } in, out;
    in.u64 = x;
    out.u32[0] = bswap32(in.u32[1]);
    out.u32[1] = bswap32(in.u32[0]);
    return out.u64;
}

static inline unsigned ntz(unsigned x) {
    static const unsigned char tz_table[32] =
    { 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
        31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
    return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
}

/* ----------------------------------------------------------------------- */
/* Define blocks and operations -- Patch if incorrect on your compiler.    */
/* ----------------------------------------------------------------------- */

typedef __m128i block;
typedef __m512i block512;
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define xor_block_512(x,y)        _mm512_xor_si512(x,y)
#define zero_block()          _mm_setzero_si128()
#define zero_block_512()          _mm512_setzero_si512()
#define unequal_blocks(x,y) \
                        (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
#define swap_if_le(b) \
    _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))

static inline block gen_offset(uint64_t KtopStr[3], unsigned bot) {
    block hi = _mm_load_si128((__m128i *)(KtopStr+0));   /* hi = B A */
    block lo = _mm_loadu_si128((__m128i *)(KtopStr+1));  /* lo = C B */
    __m128i lshift = _mm_cvtsi32_si128(bot);
    __m128i rshift = _mm_cvtsi32_si128(64-bot);
    lo = _mm_xor_si128(_mm_sll_epi64(hi,lshift),_mm_srl_epi64(lo,rshift));
    return _mm_shuffle_epi8(lo,_mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7));
    
}
static inline block double_block(block bl) {
    const __m128i mask = _mm_set_epi32(135,1,1,1);
    __m128i tmp = _mm_srai_epi32(bl, 31);
    tmp = _mm_and_si128(tmp, mask);
    tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
    bl = _mm_slli_epi32(bl, 1);
    return _mm_xor_si128(bl,tmp);
}


#if (OCB_KEY_LEN == 0)
	typedef struct { __m128i rd_key[15]; int rounds; } AES_KEY;
	#define ROUNDS(ctx) ((ctx)->rounds)
#else
	typedef struct { __m128i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY;
	#define ROUNDS(ctx) (6+OCB_KEY_LEN/4)
    typedef struct { __m512i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY_512;
	#define ROUNDS(ctx) (6+OCB_KEY_LEN/4)
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

#define EXPAND192_STEP(idx,aes_const)                                       \
    EXPAND_ASSIST(x0,x1,x2,x3,85,aes_const);                                \
    x3 = _mm_xor_si128(x3,_mm_slli_si128 (x3, 4));                          \
    x3 = _mm_xor_si128(x3,_mm_shuffle_epi32(x0, 255));                      \
    kp[idx] = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(tmp),        \
                                              _mm_castsi128_ps(x0), 68));   \
    kp[idx+1] = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(x0),       \
                                                _mm_castsi128_ps(x3), 78)); \
    EXPAND_ASSIST(x0,x1,x2,x3,85,(aes_const*2));                            \
    x3 = _mm_xor_si128(x3,_mm_slli_si128 (x3, 4));                          \
    x3 = _mm_xor_si128(x3,_mm_shuffle_epi32(x0, 255));                      \
    kp[idx+2] = x0; tmp = x3


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

static void AES_192_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2,x3,tmp,*kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey);
    tmp = x3 = _mm_loadu_si128((__m128i*)(userkey+16));
    EXPAND192_STEP(10,64);
}

static void AES_256_Key_Expansion(const unsigned char *userkey, void *key)
{
    __m128i x0,x1,x2,x3,*kp = (__m128i *)key;
    kp[0] = x0 = _mm_loadu_si128((__m128i*)userkey   );
    kp[1] = x3 = _mm_loadu_si128((__m128i*)(userkey+16));
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0,x1,x2,x3,255,1);  kp[2]  = x0;
    EXPAND_ASSIST(x3,x1,x2,x0,170,1);  kp[3]  = x3;
    EXPAND_ASSIST(x0,x1,x2,x3,255,2);  kp[4]  = x0;
    EXPAND_ASSIST(x3,x1,x2,x0,170,2);  kp[5]  = x3;
    EXPAND_ASSIST(x0,x1,x2,x3,255,4);  kp[6]  = x0;
    EXPAND_ASSIST(x3,x1,x2,x0,170,4);  kp[7]  = x3;
    EXPAND_ASSIST(x0,x1,x2,x3,255,8);  kp[8]  = x0;
    EXPAND_ASSIST(x3,x1,x2,x0,170,8);  kp[9]  = x3;
    EXPAND_ASSIST(x0,x1,x2,x3,255,16); kp[10] = x0;
    EXPAND_ASSIST(x3,x1,x2,x0,170,16); kp[11] = x3;
    EXPAND_ASSIST(x0,x1,x2,x3,255,32); kp[12] = x0;
    EXPAND_ASSIST(x3,x1,x2,x0,170,32); kp[13] = x3;
    EXPAND_ASSIST(x0,x1,x2,x3,255,64); kp[14] = x0;
}

static int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
    if (bits == 128) {
        AES_128_Key_Expansion (userKey,key);
    } else if (bits == 192) {
        AES_192_Key_Expansion (userKey,key);
    } else if (bits == 256) {
        AES_256_Key_Expansion (userKey,key);
    }
    #if (OCB_KEY_LEN == 0)
    	key->rounds = 6+bits/32;
    #endif
    return 0;
}

static void AES_set_decrypt_key_fast(AES_KEY *dkey, const AES_KEY *ekey)
{
    int j = 0;
    int i = ROUNDS(ekey);
    #if (OCB_KEY_LEN == 0)
    	dkey->rounds = i;
    #endif
    dkey->rd_key[i--] = ekey->rd_key[j++];
    while (i)
        dkey->rd_key[i--] = _mm_aesimc_si128(ekey->rd_key[j++]);
    dkey->rd_key[i] = ekey->rd_key[j];
}

static int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
    AES_KEY temp_key;
    AES_set_encrypt_key(userKey,bits,&temp_key);
    AES_set_decrypt_key_fast(key, &temp_key);
    return 0;
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



static inline void AES_encrypt(const unsigned char *in,
                        unsigned char *out, const AES_KEY *key)
{
	int j,rnds=ROUNDS(key);
	const __m128i *sched = ((__m128i *)(key->rd_key));
	__m128i tmp = _mm_load_si128 ((__m128i*)in);
	tmp = _mm_xor_si128 (tmp,sched[0]);
	for (j=1; j<rnds; j++)  tmp = _mm_aesenc_si128 (tmp,sched[j]);
	tmp = _mm_aesenclast_si128 (tmp,sched[j]);
	_mm_store_si128 ((__m128i*)out,tmp);
}

static inline void AES_decrypt(const unsigned char *in,
                        unsigned char *out, const AES_KEY *key)
{
	int j,rnds=ROUNDS(key);
	const __m128i *sched = ((__m128i *)(key->rd_key));
	__m128i tmp = _mm_load_si128 ((__m128i*)in);
	tmp = _mm_xor_si128 (tmp,sched[0]);
	for (j=1; j<rnds; j++)  tmp = _mm_aesdec_si128 (tmp,sched[j]);
	tmp = _mm_aesdeclast_si128 (tmp,sched[j]);
	_mm_store_si128 ((__m128i*)out,tmp);
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

static inline void AES_ecb_encrypt_blks_512(block512 *blks, unsigned nblks, AES_KEY_512 *key) {
    unsigned i,j,rnds=ROUNDS(key);
	
    const __m512i *sched = ((__m512i *)(key->rd_key));

	for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_xor_si512(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm512_aesenc_epi128(blks[i], sched[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_aesenclast_epi128(blks[i], sched[j]);
}
static inline void AES_ecb_decrypt_blks_512(block512 *blks, unsigned nblks, AES_KEY_512 *key) {
    unsigned i,j,rnds=ROUNDS(key);
	const __m512i *sched = ((__m512i *)(key->rd_key));
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_xor_si512(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm512_aesdec_epi128(blks[i], sched[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_aesdeclast_epi128(blks[i], sched[j]);
}
static inline void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
    unsigned i,j,rnds=ROUNDS(key);
	const __m128i *sched = ((__m128i *)(key->rd_key));
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_xor_si128(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm_aesdec_si128(blks[i], sched[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_aesdeclast_si128(blks[i], sched[j]);
}

#define BPI 4  /* Number of blocks in buffer per ECB call   */
               /* Set to 4 for Westmere, 8 for Sandy Bridge */


static void
shift_right(unsigned char *x)
/* 128-bit shift-right by 1 bit:  *x >>= 1                               */
{
    int i;
    for (i = 15; i > 0; i--) {
        x[i] = (x[i] >> 1) | (x[i-1] & 1 ? 0x80u : 0);
    }
    x[0] = (x[0] >> 1);
}

/* ----------------------------------------------------------------------- */
/* Define OCB context structure.                                           */
/* ----------------------------------------------------------------------- */

/*------------------------------------------------------------------------
/ Each item in the OCB context is stored either "memory correct" or
/ "register correct". On big-endian machines, this is identical. On
/ little-endian machines, one must choose whether the byte-string
/ is in the correct order when it resides in memory or in registers.
/ It must be register correct whenever it is to be manipulated
/ arithmetically, but must be memory correct whenever it interacts
/ with the plaintext or ciphertext.
/------------------------------------------------------------------------- */

struct _ae_ctx {
    block offset;                          /* Memory correct               */
    block checksum;                        /* Memory correct               */
    block Lstar;                           /* Memory correct               */
    block Ldollar;                         /* Memory correct               */
    block L[L_TABLE_SZ];                   /* Memory correct               */
    block ad_checksum;                     /* Memory correct               */
    block ad_offset;                       /* Memory correct               */
    block cached_Top;                      /* Memory correct               */
	uint64_t KtopStr[3];                   /* Register correct, each item  */
    uint32_t ad_blocks_processed;
    uint32_t blocks_processed;
    AES_KEY decrypt_key;
    AES_KEY encrypt_key;
    AES_KEY_512 decrypt_key_512;
    AES_KEY_512 encrypt_key_512;
    block L_inv;
    #if (OCB_TAG_LEN == 0)
    unsigned tag_len;
    #endif
};

/* ----------------------------------------------------------------------- */
/* L table lookup (or on-the-fly generation)                               */
/* ----------------------------------------------------------------------- */

#if L_TABLE_SZ_IS_ENOUGH
#define getL(_ctx, _tz) ((_ctx)->L[_tz])
#else
static block getL(const ae_ctx *ctx, unsigned tz)
{
    if (tz < L_TABLE_SZ)
        return ctx->L[tz];
    else {
        unsigned i;
        /* Bring L[MAX] into registers, make it register correct */
        block rval = swap_if_le(ctx->L[L_TABLE_SZ-1]);
        rval = double_block(rval);
        for (i=L_TABLE_SZ; i < tz; i++)
            rval = double_block(rval);
        return swap_if_le(rval);             /* To memory correct */
    }
}
#endif

/* ----------------------------------------------------------------------- */
/* Public functions                                                        */
/* ----------------------------------------------------------------------- */

/* 32-bit SSE2 and Altivec systems need to be forced to allocate memory
   on 16-byte alignments. (I believe all major 64-bit systems do already.) */

ae_ctx* ae_allocate(void *misc)
{
	void *p;
	// (void) misc;                     /* misc unused in this implementation */
	// #if (__SSE2__ && !_M_X64 && !_M_AMD64 && !__amd64__)
    // 	p = _mm_malloc(sizeof(ae_ctx),16);
	// #elif (__ALTIVEC__ && !__PPC64__)
	// 	if (posix_memalign(&p,16,sizeof(ae_ctx)) != 0) p = NULL;
	// #else
		p = malloc(sizeof(ae_ctx));
	// #endif
	return (ae_ctx *)p;
}

void ae_free(ae_ctx *ctx)
{
	#if (__SSE2__ && !_M_X64 && !_M_AMD64 && !__amd64__)
		_mm_free(ctx);
	#else
		free(ctx);
	#endif
}

/* ----------------------------------------------------------------------- */

int ae_clear (ae_ctx *ctx) /* Zero ae_ctx and undo initialization          */
{
	memset(ctx, 0, sizeof(ae_ctx));
	return AE_SUCCESS;
}

int ae_ctx_sizeof(void) { return (int) sizeof(ae_ctx); }

/* ----------------------------------------------------------------------- */

int ae_init(ae_ctx *ctx, const void *key, int key_len, int nonce_len, int tag_len)
{
    unsigned last_bit, i;
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp_blk;
	

    if (nonce_len != 12)
    	return AE_NOT_SUPPORTED;

    /* Initialize encryption & decryption keys */
    #if (OCB_KEY_LEN > 0)
    key_len = OCB_KEY_LEN;
    #endif
    
	AES_set_encrypt_key((unsigned char *)key, key_len*8, &ctx->encrypt_key);
    AES_set_decrypt_key((unsigned char *)key, (int)(key_len*8), &ctx->decrypt_key);
    AES_cast_128_to_512_key(&ctx->encrypt_key, &ctx->encrypt_key_512);
    AES_cast_128_to_512_key(&ctx->decrypt_key, &ctx->decrypt_key_512);

    /* Zero things that need zeroing */
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;

    /* Compute key-dependent values */
    AES_encrypt((unsigned char *)&ctx->cached_Top,
                            (unsigned char *)&tmp_blk.bl, &ctx->encrypt_key);
	
	// imprimiArreglo(16,(unsigned char *)&ctx->Lstar);
	// exit(1);
	ctx->L[0] = tmp_blk.bl;    
    tmp_blk.bl = swap_if_le( tmp_blk.bl);
    for (i = 1; i < L_TABLE_SZ; i++) {
		tmp_blk.bl = double_block(tmp_blk.bl);
    	ctx->L[i] = swap_if_le( tmp_blk.bl);
    }

    /* Precompute L_inv = L . x^{-1} */
    // memcpy(tmp, &ctx->L[0], 16);
    tmp_blk.bl=ctx->L[0];
    
    last_bit = tmp_blk.u8[15] & 0x01;
    shift_right(tmp_blk.u8);
    if (last_bit) {
        tmp_blk.u8[0] ^= 0x80;
        tmp_blk.u8[15] ^= 0x43;
    }
    ctx->L_inv=tmp_blk.bl;
    

    // memcpy(key->L_inv, tmp, 16);

    #if (OCB_TAG_LEN == 0)
    	ctx->tag_len = tag_len;
    #else
    	(void) tag_len;  /* Suppress var not used error */
    #endif

    return AE_SUCCESS;
}

/* ----------------------------------------------------------------------- */

static block gen_offset_from_nonce(ae_ctx *ctx, const void *nonce)
{


    block temp = _mm_loadu_si128(&((__m128i*)nonce)[0]);

    block Offset;
    Offset = xor_block( ctx->L[0], temp); 

    AES_encrypt((unsigned char *)&Offset,
                            (unsigned char *)&Offset, &ctx->encrypt_key);

	return Offset;
}

static void process_ad(ae_ctx *ctx, const void *ad, int ad_len, int final)
{
	int temp_len = ad_len;
	union { uint32_t u32[16]; uint8_t u8[64]; block512 bl; } tmp;
    block512  ad_checksum;
    const block512 *  adp = (block512 *)ad;
	unsigned i,k,tz,remaining;
	unsigned ad_block_num;
	block ad_offset;
    ad_offset = zero_block(); //ctx->ad_offset; 
	
    ad_checksum = 	zero_block_512(); //ctx->ad_checksum;
    i = ad_len/(BPI*16);
    if (i) {
		ad_block_num = ctx->ad_blocks_processed;
		do {
			block512 oa512[BPI];
			block  oa[BPI];
			ad_block_num += BPI;
			tz = ntz(ad_block_num);
			block512 ta[BPI];
			
            for(int j = 0; j<BPI; j++){
				oa[0] = xor_block(ad_offset, ctx->L[0]);
				oa[1] = xor_block(oa[0], ctx->L[1]);
				oa[2] = xor_block(ad_offset, ctx->L[1]);
				ad_offset = oa[3] = xor_block(oa[2], getL(ctx, tz));

                oa512[j] = _mm512_castsi128_si512( oa[0] );
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[1],1);
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[2],2);
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[3],3);
			    ad_block_num += 4;

            }
            
			ta[0] = xor_block_512(oa512[0], adp[0]);
			ta[1] = xor_block_512(oa512[1], adp[1]);
			ta[2] = xor_block_512(oa512[2], adp[2]);
			#if BPI == 4
				ta[3] = xor_block_512(oa512[3], adp[3]);
			#endif
			AES_ecb_encrypt_blks_512(ta,BPI,&ctx->encrypt_key_512);

			ad_checksum = xor_block_512(ad_checksum, ta[3]);
			ad_checksum = xor_block_512(ad_checksum, ta[2]);
			ad_checksum = xor_block_512(ad_checksum, ta[1]);
			ad_checksum = xor_block_512(ad_checksum, ta[0]);

		
			adp += BPI;
		} while (--i);
		// ctx->ad_blocks_processed = ad_block_num;
		ctx->ad_offset = ad_offset;
		// ctx->ad_checksum = ad_checksum;
	}

    if (final) {
		block512 ta[BPI];
		block oa[BPI];
		block512 oa512[BPI];

        /* Process remaining associated data, compute its tag contribution */
        remaining = ((unsigned)ad_len) % (BPI*64);
        if (remaining) {
			k=0;
			
			if (remaining >= 128) {

				for(int j = k; j<k+2; j++){
					oa[0] = xor_block(ctx->ad_offset, ctx->L[0]);
                    oa[1] = xor_block(oa[0], ctx->L[1]);
                    oa[2] = xor_block(oa[1], ctx->L[0]);
                    ctx->ad_offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(ad_block_num)));

                    oa512[j] = _mm512_castsi128_si512( oa[0] );
                    oa512[j] = _mm512_inserti64x2( oa512[j],oa[1],1);
                    oa512[j] = _mm512_inserti64x2( oa512[j],oa[2],2);
                    oa512[j] = _mm512_inserti64x2( oa512[j],oa[3],3);
			        ad_block_num += 4;

                }
				ta[k] = xor_block_512(oa512[k], adp[k]);
				ta[k+1] = xor_block_512(oa512[k+1], adp[k+1]);
				remaining -= 128;
				k+=2;
			}
			if (remaining >= 64) {

				oa[0] = xor_block(ctx->ad_offset, ctx->L[0]);
                oa[1] = xor_block(oa[0], ctx->L[1]);
                oa[2] = xor_block(oa[1], ctx->L[0]);
                ctx->ad_offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(ad_block_num)));

                oa512[k] = _mm512_castsi128_si512( oa[0] );
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[2],2);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[3],3);
                ad_block_num += 4;

				// offset = oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block_512(oa512[k], adp[k]);
				remaining -= 64;
				++k;

			}
			if (remaining) {
				
				tmp.bl = zero_block_512();
				memcpy(tmp.u8, adp+k, remaining);
				tmp.u8[remaining] = (unsigned char)0x80u;

                if(remaining/16==0 || remaining ==16 ){
                    ctx->ad_offset = oa[0] = xor_block(ctx->ad_offset, ctx->L[0]);

					

                    if(remaining%16 !=0)
						ctx->ad_offset = oa[0] = xor_block(oa[0],ctx->Lstar);
                    
					oa512[k] = _mm512_castsi128_si512( oa[0] );
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),1);
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),2);
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),3);
                } else if(remaining/16==1 || remaining == 32){
                   
					
					oa[0] = xor_block(ctx->ad_offset, ctx->L[0]);

                    ctx->ad_offset = oa[1] = xor_block(oa[0], ctx->L[1]);

					if(remaining%16 !=0)
                    ctx->ad_offset = oa[1] = xor_block(oa[0],ctx->Lstar);

					

                    oa512[k] = _mm512_castsi128_si512( oa[0] );
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),2);
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),3);
                } else if(remaining/16==2 || remaining == 48){
                    oa[0] = xor_block(ctx->ad_offset, ctx->L[0]);
                    oa[1] = xor_block(oa[0], ctx->L[1]);
                    ctx->ad_offset = oa[2] = xor_block(oa[1], ctx->L[0]);

                    
					if(remaining%16 !=0)
					ctx->ad_offset = oa[2] = xor_block(oa[1],ctx->Lstar);


                    oa512[k] = _mm512_castsi128_si512( oa[0] );
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[2],2);
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),3);
                }else  if(remaining/16==3){
                    oa[0] = xor_block(ctx->ad_offset, ctx->L[0]);
                    oa[1] = xor_block(oa[0], ctx->L[1]);
                    oa[2] = xor_block(oa[1], ctx->L[0]);
					

                    ctx->ad_offset = oa[3] = xor_block(oa[2],ctx->Lstar);
                    oa512[k] = _mm512_castsi128_si512( oa[0] );
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[2],2);
                    oa512[k] = _mm512_inserti64x2( oa512[k],zero_block(),3);

                }
               
                int index = floor((remaining/16)) * 16;
                memcpy(tmp.u8, adp+k, index );
				ta[k] = xor_block_512(oa512[k],tmp.bl);

				
				++k;


				
			}
			AES_ecb_encrypt_blks_512(ta,k,&ctx->encrypt_key_512);
			
			switch (k) {
				#if (BPI == 8)
				case 8: ad_checksum = xor_block(ad_checksum, ta[7]);
				case 7: ad_checksum = xor_block(ad_checksum, ta[6]);
				case 6: ad_checksum = xor_block(ad_checksum, ta[5]);
				case 5: ad_checksum = xor_block(ad_checksum, ta[4]);
				#endif
				case 4: ad_checksum = xor_block_512(ad_checksum, ta[3]);
				case 3: ad_checksum = xor_block_512(ad_checksum, ta[2]);
				case 2: ad_checksum = xor_block_512(ad_checksum, ta[1]);
				case 1: ad_checksum = xor_block_512(ad_checksum, ta[0]);
			}
			// ctx->ad_checksum = ad_checksum;

			__m128i checksumBlock[4];
			checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)&ad_checksum)[0]);
    		checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)&ad_checksum)[1]);
    		checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)&ad_checksum)[2]);
    		checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)&ad_checksum)[3]);
			__m128i checksumFinal  = _mm_setzero_si128();
			i=0;
			while(temp_len>0 and i<4){
				checksumFinal =  _mm_xor_si128( checksumFinal, checksumBlock[i]);
				temp_len = temp_len-16;
				i++;
			}
			ctx->ad_checksum = checksumFinal;

			
			
		}
	}
}

/* ----------------------------------------------------------------------- */



int ae_encrypt(ae_ctx     *  ctx,
               const void *  nonce,
               const void *pt,
               int         pt_len,
               const void *ad,
               int         ad_len,
               void       *ct,
               void       *tag,
               int         final)
{
    
	int temp_len = pt_len;
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    block512 offset, checksum;
    unsigned i, k;
    i=pt_len/64;
    
    block512  ctp[i];
    //  = (block512 *)ct;
    block512 ptp[i];
    //  = (block512 *)pt;

    for(int j=0; j<i;j++){
        ptp[j] = _mm512_loadu_si512(&((__m512i*)pt)[j] );
    }

	block       *ptp128 = (block *)pt;
    unsigned block_num=1;
    unsigned indice = 0;
    
	/* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        ctx->offset = gen_offset_from_nonce(ctx, nonce);
		
        ctx->ad_offset = ctx->checksum   = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        if (ad_len >= 0)
        	ctx->ad_checksum = zero_block();
    }
	
	/* Process associated data */
	// if (ad_len > 0)
	// 	process_ad(ctx, ad, ad_len, final);


	/* Encrypt plaintext data BPI blocks at a time */
    // offset = ctx->offset;
    offset = _mm512_castsi128_si512( ctx->offset  );
    checksum  =_mm512_castsi128_si512(  ctx->checksum );
    i = pt_len/(BPI*64);
    unsigned temporal = pt_len; 
    if (i) {

    	block oa[BPI];
    	block512 oa512[BPI];
    	
    	oa[BPI-1] = ctx->offset;
		while (temporal>256) {

            
			block512 ta[BPI];
			
            for(int j = 0; j<BPI; j++){
                oa[0] = xor_block(oa[BPI-1], getL(ctx, ntz(block_num)));
                block_num++;
                oa[1] = xor_block(oa[0], getL(ctx, ntz(block_num)));
                block_num++;

                oa[2] = xor_block(oa[1], getL(ctx, ntz(block_num)));
                block_num++;

                oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
                block_num++;

                oa512[j] = _mm512_castsi128_si512( oa[0] );
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[1],1);
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[2],2);
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[3],3);
            }

			ta[0] = xor_block_512(oa512[0], ptp[0]);
			checksum = xor_block_512(checksum, ptp[0]);
			ta[1] = xor_block_512(oa512[1], ptp[1]);
			checksum = xor_block_512(checksum, ptp[1]);
			ta[2] = xor_block_512(oa512[2], ptp[2]);
			checksum = xor_block_512(checksum, ptp[2]);
            ta[3] = xor_block_512(oa512[3], ptp[3]);
            checksum = xor_block_512(checksum, ptp[3]);

			AES_ecb_encrypt_blks_512(ta,BPI,&ctx->encrypt_key_512);
            

            ta[0] = xor_block_512(ta[0], oa512[0]);
            ta[1] = xor_block_512(ta[1], oa512[1]);
            ta[2] = xor_block_512(ta[2], oa512[2]);
			ta[3] = xor_block_512(ta[3], oa512[3]);

            _mm512_storeu_si512(&((__m512i*)ct)[indice + 0],ta[0]);
			_mm512_storeu_si512(&((__m512i*)ct)[indice + 1],ta[1]);
			_mm512_storeu_si512(&((__m512i*)ct)[indice + 2],ta[2]);
			_mm512_storeu_si512(&((__m512i*)ct)[indice + 3],ta[3]);
            
            indice += BPI;
			
            temporal = temporal - 256;
            
		} ;
    	ctx->offset = oa[BPI-1];
	    // ctx->blocks_processed = block_num;
		// ctx->checksum = checksum;
    }
    

    if (final) {

		block oa[4];
	    block512 ta[BPI+1], oa512[BPI+1];
        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = temporal; //((unsigned)pt_len) % (BPI*64);
        printf("%i\n",remaining);
        k = 0;                      /* How many blocks in ta[] need ECBing */
        oa[BPI-1] = ctx->offset;
        block temp128[4];
        block finalptp;

        unsigned l=0;
        if (remaining) {
			
			if (remaining > 128) {
                printf("%i \n", remaining);

				remaining -= 128;
                oa[0] = xor_block(ctx->offset, getL(ctx, ntz(block_num)));
                block_num ++;
                oa[1] = xor_block(oa[0], getL(ctx, ntz(block_num)));
                block_num ++;
                oa[2] = xor_block(oa[1], getL(ctx, ntz(block_num)));
                block_num ++;
                ctx->offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
                block_num ++;
                oa512[k] = _mm512_castsi128_si512( oa[0] );
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[2],2);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[3],3);
			    

                oa[0] = xor_block(ctx->offset, getL(ctx, ntz(block_num)));
                block_num ++;
                oa[1] = xor_block(oa[0], getL(ctx, ntz(block_num)));
                block_num ++;
                oa[2] = xor_block(oa[1], getL(ctx, ntz(block_num)));
                block_num ++;
                ctx->offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
                block_num ++;
                oa512[k+1] = _mm512_castsi128_si512( oa[0] );
                oa512[k+1] = _mm512_inserti64x2( oa512[k+1],oa[1],1);
                oa512[k+1] = _mm512_inserti64x2( oa512[k+1],oa[2],2);
                oa512[k+1] = _mm512_inserti64x2( oa512[k+1],oa[3],3);
			    

				ta[k] = xor_block_512(oa512[k], ptp[k]);
				checksum = xor_block_512(checksum, ptp[k]);
				ta[k+1] = xor_block_512(oa512[k+1], ptp[k+1]);
				checksum = xor_block_512(checksum, ptp[k+1]);
				k+=2;
                finalptp =  _mm_loadu_si128(&((__m128i*)&ptp[k+1])[4]);

			}
			if (remaining > 64) {
				remaining -= 64;

                

                oa[0] = xor_block(ctx->offset, getL(ctx, ntz(block_num)));
                block_num ++;
                oa[1] = xor_block(oa[0], getL(ctx, ntz(block_num)));
                block_num ++;
                oa[2] = xor_block(oa[1], getL(ctx, ntz(block_num)));
                block_num ++;
                ctx->offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
                block_num ++;
                
                

                oa512[k] = _mm512_castsi128_si512( oa[0] );
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[2],2);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[3],3);
                // block_num += 4;

				// offset = oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block_512(oa512[k], ptp[k]);
				checksum = xor_block_512(checksum, ptp[k]);
				++k;
                finalptp =  _mm_loadu_si128(&((__m128i*)&ptp[k])[4]);

			}
            
            if (remaining > 32) {
                
                remaining -= 32;
                
                ta[k]=zero_block_512();

                temp128[l] =  _mm_loadu_si128(&((__m128i*)&ptp[k])[l]);
    	        temp128[l+1] =  _mm_loadu_si128(&((__m128i*)&ptp[k])[l+1]);

                block512 tmp512 = _mm512_castsi128_si512( temp128[l] );
				checksum = xor_block_512(checksum, tmp512);
                
                tmp512 = _mm512_castsi128_si512( temp128[l+1] );
				checksum = xor_block_512(checksum, tmp512);

                 
                

                oa[0] = xor_block(ctx->offset, getL(ctx, ntz(block_num)));
				block_num ++;
                // ta[k] = xor_block(oa[0], temp128[l]);
                ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[0], temp128[l]) ,0); 


				ctx->offset = oa[1] = xor_block(oa[0], getL(ctx, ntz(block_num)));
                block_num ++;

                ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[1], temp128[l+1]) ,1); 
                
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[0],0);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
				// ta[k+1] = xor_block(ctx->offset, ctp[k+1]);
				
                l+=2;
                finalptp =  temp128[l+1];


			}
			if (remaining > 16) {
				remaining -= 16;
                

                temp128[l] =  _mm_loadu_si128(&((__m128i*)&ptp[k])[l]);

                block512 tmp512 = _mm512_castsi128_si512( temp128[l] );
				checksum = xor_block_512(checksum, tmp512);
                
                

				ctx->offset = oa[0] = xor_block(ctx->offset, getL(ctx, ntz(block_num)));
                block_num += 1;

                if(l==0){
                    ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[0], temp128[l]) ,0); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[0],0);
                }

                if(l==2){
                    ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[0], temp128[l]) ,2); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[0],2);
                }
                finalptp =  temp128[l];

				// offset = oa[k] = xor_block(ctx->offset, ctx->L[0]);
				// ta[k] = xor_block(offset, ctp[k]);
				++l;
			}
			if (remaining) {
                
                temp128[l] =  _mm_loadu_si128(&((__m128i*)&ptp[k])[l]);
                finalptp =  temp128[l];
                
                // printf("%i\n",block_num);
                // imprimiArreglo(16,(unsigned char *)&ctx->offset);
                // printf("------------------------------\n");

				oa[0] = ctx->offset = xor_block(ctx->offset,getL(ctx, ntz(block_num)));
                
                


                oa[0] = xor_block(oa[0],ctx->L_inv);
                tmp.bl=oa[0];
                tmp.u8[15] ^= (remaining << 3);
                oa[0]=tmp.bl;

                memcpy(tmp.u8, &temp128[l], remaining);
                if(l==0){
                    ta[k] = _mm512_inserti64x2( ta[k], oa[0] ,0); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],tmp.bl,0);
                }
                if(l==1){
                    ta[k] = _mm512_inserti64x2( ta[k], oa[0] ,1); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],tmp.bl,1);
                }
                if(l==2){
                    ta[k] = _mm512_inserti64x2( ta[k], oa[0] ,2); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],tmp.bl,2);
                }
                if(l==3){
                    ta[k] = _mm512_inserti64x2( ta[k], oa[0] ,3); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],tmp.bl,3);
                }
			}
		}
        k++;

        
		AES_ecb_encrypt_blks_512(ta,k,&ctx->encrypt_key_512);

		__m128i checksumBlock[4];
		checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)&checksum)[0]);
    	checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)&checksum)[1]);
    	checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)&checksum)[2]);
    	checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)&checksum)[3]);
		__m128i checksumFinal  = _mm_setzero_si128();
		i=0;


        tmp.bl = _mm_loadu_si128(&((__m128i*)&ta[k-1])[l]);        
        memcpy(tmp.u8, &finalptp, remaining);
        

		while(temp_len>0 and i<4){
            
			checksumFinal =  _mm_xor_si128( checksumFinal, checksumBlock[i]);
			temp_len = temp_len-16;
			i++;
		}
        checksumFinal =  _mm_xor_si128( checksumFinal,tmp.bl);
		
        checksumFinal = xor_block(ctx->offset, checksumFinal);           /* Part of tag gen */
		AES_ecb_encrypt_blks(&checksumFinal,1,&ctx->encrypt_key);
		checksumFinal = xor_block(checksumFinal, ctx->ad_checksum);   /* Part of tag gen */


		for(int j = 0; j<k; j++){
            ta[j] = xor_block_512(ta[j], oa512[j]);
            

        }
		for(int j = 0; j<k; j++){
			_mm512_storeu_si512(&((__m512i*)ct)[indice+j],ta[j]  );
        }

		
        /* Tag is placed at the correct location
         */
        if (tag) {
			#if (OCB_TAG_LEN == 16)
            	*(block *)tag = checksumFinal;
			#elif (OCB_TAG_LEN > 0)
	            memcpy((char *)tag, &checksumFinal, OCB_TAG_LEN);
			#else
	            memcpy((char *)tag, &checksumFinal, ctx->tag_len);
	        #endif
        } else {
			#if (OCB_TAG_LEN > 0)
	            memcpy((char *)ct + pt_len, &checksumFinal, OCB_TAG_LEN);
            	pt_len += OCB_TAG_LEN;
			#else
	            memcpy((char *)ct + pt_len, &checksumFinal, ctx->tag_len);
            	pt_len += ctx->tag_len;
	        #endif
        }
    }
    return (int) pt_len;
}

/* ----------------------------------------------------------------------- */

/* Compare two regions of memory, taking a constant amount of time for a
   given buffer size -- under certain assumptions about the compiler
   and machine, of course.

   Use this to avoid timing side-channel attacks.

   Returns 0 for memory regions with equal contents; non-zero otherwise. */
static int constant_time_memcmp(const void *av, const void *bv, size_t n) {
    const uint8_t *a = (const uint8_t *) av;
    const uint8_t *b = (const uint8_t *) bv;
    uint8_t result = 0;
    size_t i;

    for (i=0; i<n; i++) {
        result |= *a ^ *b;
        a++;
        b++;
    }

    return (int) result;
}

int ae_decrypt(ae_ctx     *ctx,
               const void *nonce,
               const void *ct,
               int         ct_len,
               const void *ad,
               int         ad_len,
               void       *pt,
               void *tag,
               int         final)
{
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp2;
    block512 checksum;
    block offset;
    unsigned i, k;
    block512       *ctp = (block512 *)ct;
    block512       *ptp = (block512 *)pt;
    block       *ptp128 = (block *)pt;
	unsigned block_num;
    unsigned temp_len = ct_len;
	/* Reduce ct_len tag bundled in ct */
	if ((final) && (!tag))
		#if (OCB_TAG_LEN > 0)
			ct_len -= OCB_TAG_LEN;
		#else
			ct_len -= ctx->tag_len;
		#endif

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        ctx->offset = gen_offset_from_nonce(ctx, nonce);
        ctx->ad_offset = ctx->checksum   = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        if (ad_len >= 0)
        	ctx->ad_checksum = zero_block();
    }

	/* Process associated data */
	if (ad_len > 0)
		process_ad(ctx, ad, ad_len, final);

	/* Encrypt plaintext data BPI blocks at a time */
    offset = ctx->offset;
    checksum  = zero_block_512();
    i = ct_len/(BPI*64);
    if (i) {
    	block oa[BPI];
    	block512 oa512[BPI];
    	block_num = ctx->blocks_processed;
    	oa[BPI-1] = ctx->offset;
		do {
			block512 ta[BPI];
			
            for(int j = 0; j<BPI; j++){
                oa[0] = xor_block(oa[BPI-1], ctx->L[0]);
                oa[1] = xor_block(oa[0], ctx->L[1]);
                oa[2] = xor_block(oa[1], ctx->L[0]);
                oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
                

                oa512[j] = _mm512_castsi128_si512( oa[0] );
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[1],1);
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[2],2);
                oa512[j] = _mm512_inserti64x2( oa512[j],oa[3],3);
			    block_num += 4;
            }

            ta[0] = xor_block_512(oa512[0], ctp[0]);
			ta[1] = xor_block_512(oa512[1], ctp[1]);
			ta[2] = xor_block_512(oa512[2], ctp[2]);
			#if BPI == 4
				ta[3] = xor_block_512(oa512[3], ctp[3]);
			#endif

			AES_ecb_decrypt_blks_512(ta,BPI,&ctx->decrypt_key_512);


            ta[0] = xor_block_512(oa512[0], ta[0]);
			ta[1] = xor_block_512(oa512[1], ta[1]);
			ta[2] = xor_block_512(oa512[2], ta[2]);
            ta[3] = xor_block_512(oa512[3], ta[3]);

			checksum = xor_block_512(checksum, ta[0]);
            checksum = xor_block_512(checksum, ta[1]);
			checksum = xor_block_512(checksum, ta[2]);
			checksum = xor_block_512(checksum, ta[3]);

            _mm512_storeu_si512(&((__m512i*)ctp)[0],ta[0]);
			_mm512_storeu_si512(&((__m512i*)ctp)[1],ta[1]);
			_mm512_storeu_si512(&((__m512i*)ctp)[2],ta[2]);
			_mm512_storeu_si512(&((__m512i*)ctp)[3],ta[3]);
			ptp += BPI;
			ctp += BPI;
		} while (--i);
    	ctx->offset = offset = oa[BPI-1];
	    ctx->blocks_processed = block_num;
		// ctx->checksum = checksum;
    }

    if (final) {
        
        block oa[4];
	    block512 ta[BPI+1], oa512[BPI+1];
        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)ct_len) % (BPI*64);
        k = 0;                      /* How many blocks in ta[] need ECBing */
        oa[BPI-1] = ctx->offset;
        __m128i temp128[4];
		int l = 0;
        if (remaining) {
			
            if (remaining >= 128) {
                for(int j = k; j<k+2; j++){
                    oa[0] = xor_block(ctx->offset, ctx->L[0]);
                    oa[1] = xor_block(oa[0], ctx->L[1]);
                    oa[2] = xor_block(oa[1], ctx->L[0]);
                    ctx->offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));

                    oa512[j] = _mm512_castsi128_si512( oa[0] );
                    oa512[j] = _mm512_inserti64x2( oa512[j],oa[1],1);
                    oa512[j] = _mm512_inserti64x2( oa512[j],oa[2],2);
                    oa512[j] = _mm512_inserti64x2( oa512[j],oa[3],3);
			        block_num += 4;

                }
                ctp += 2;
				ta[k] = xor_block_512(oa512[k], ctp[k]);
				ta[k+1] = xor_block_512(oa512[k+1], ctp[k+1]);
				remaining -= 128;
				k+=2;
			}

            if (remaining >= 64) {
                ctp += 1;

                oa[0] = xor_block(ctx->offset, ctx->L[0]);
                oa[1] = xor_block(oa[0], ctx->L[1]);
                oa[2] = xor_block(oa[1], ctx->L[0]);
                ctx->offset  = oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));

                oa512[k] = _mm512_castsi128_si512( oa[0] );
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[2],2);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[3],3);
                block_num += 4;

				// offset = oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block_512(oa512[k], ctp[k]);
				remaining -= 64;
				++k;

			}
			if (remaining >= 32) {
               
                ta[k]=zero_block_512();

                temp128[l] =  _mm_loadu_si128(&((__m128i*)&ctp[k])[l]);
    	        temp128[l+1] =  _mm_loadu_si128(&((__m128i*)&ctp[k])[l+1]);
    	        block_num += 2;

                oa[0] = xor_block(ctx->offset, ctx->L[0]);
				
                // ta[k] = xor_block(oa[0], temp128[l]);
                ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[0], temp128[l]) ,0); 

				ctx->offset = oa[1] = xor_block(oa[0], ctx->L[1]);

                ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[1], temp128[l+1]) ,1); 
                
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[0],0);
                oa512[k] = _mm512_inserti64x2( oa512[k],oa[1],1);
				// ta[k+1] = xor_block(ctx->offset, ctp[k+1]);
                remaining -= 32;
                l+=2;


			}
			if (remaining >= 16) {
                block_num += 1;
                temp128[l] =  _mm_loadu_si128(&((__m128i*)&ctp[k])[l]);

				ctx->offset = oa[0] = xor_block(ctx->offset, ctx->L[0]);

                if(l==0){
                    ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[0], temp128[l]) ,0); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[0],0);
                }

                if(l==2){
                    ta[k] = _mm512_inserti64x2( ta[k], xor_block(oa[0], temp128[l]) ,2); 
                    oa512[k] = _mm512_inserti64x2( oa512[k],oa[0],2);
                }

				// offset = oa[k] = xor_block(ctx->offset, ctx->L[0]);
				// ta[k] = xor_block(offset, ctp[k]);
				remaining -= 16;
				++l;
			}
			if (remaining) {
                
                temp128[l] =  _mm_loadu_si128(&((__m128i*)&ctp[k])[l]);

				block pad;
				ctx->offset = xor_block(ctx->offset,ctx->Lstar);

				AES_encrypt((unsigned char *)&ctx->offset, tmp.u8, &ctx->encrypt_key);
				pad = tmp.bl;
				memcpy(tmp.u8,(unsigned char *)&temp128[l],remaining);
				tmp.bl = xor_block(tmp.bl, pad);

				tmp.u8[remaining] = (unsigned char)0x80u;

				// memcpy(ptp128+block_num, tmp.u8, remaining);
                
                block512 tmp512 = _mm512_castsi128_si512( tmp.bl );
				checksum = xor_block_512(checksum, tmp512);
			}
		}
        if(k==0){
            k=1;
        }
        
		AES_ecb_decrypt_blks_512(ta,k,&ctx->decrypt_key_512);
     
        for(int i=0;i<k;i++){
            ta[i] = xor_block_512(ta[i], oa512[i]);
            checksum = xor_block_512(checksum, ta[i]);
        }
         
        for(int i=0;i<k;i++){
            _mm512_storeu_si512(&((__m512i*)ptp)[i],ta[i]);
        }
		memcpy(ptp128+block_num, tmp.u8, remaining);


        __m128i checksumBlock[4];
		checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)&checksum)[0]);
    	checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)&checksum)[1]);
    	checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)&checksum)[2]);
    	checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)&checksum)[3]);
		__m128i checksumFinal  = _mm_setzero_si128();
		i=0;
        
		while( i<block_num and i<4){
			checksumFinal =  _mm_xor_si128( checksumFinal, checksumBlock[i]);
			temp_len = temp_len-16;
			i++;
		}
        

        /* Calculate expected tag */
        ctx->offset = xor_block(ctx->offset, ctx->Ldollar);
        tmp2.bl = xor_block(ctx->offset, checksumFinal);


		AES_encrypt(tmp2.u8, tmp2.u8, &ctx->encrypt_key);
		tmp2.bl = xor_block(tmp2.bl, ctx->ad_checksum); /* Full tag */
		
        

          /* Tag is placed at the correct location
         */
        if (tag) {
			#if (OCB_TAG_LEN == 16)
            	*(block *)tag = tmp2.bl;
			#elif (OCB_TAG_LEN > 0)
	            memcpy((char *)tag, &tmp2.bl, OCB_TAG_LEN);
			#else
	            memcpy((char *)tag, &tmp2.bl, ctx->tag_len);
	        #endif
        } else {
			#if (OCB_TAG_LEN > 0)
	            memcpy((char *)ct + ct_len, &tmp2.bl, OCB_TAG_LEN);
            	ct_len += OCB_TAG_LEN;
			#else
	            memcpy((char *)ct + ct_len, &tmp2.bl, ctx->tag_len);
            	ct_len += ctx->tag_len;
	        #endif
        }

		/* Compare with proposed tag, change ct_len if invalid */
		if ((OCB_TAG_LEN == 16) && tag) {
			if (unequal_blocks(tmp2.bl, *(block *)tag))
				ct_len = AE_INVALID;
		} else {
			#if (OCB_TAG_LEN > 0)
				int len = OCB_TAG_LEN;
			#else
				int len = ctx->tag_len;
			#endif
			if (tag) {
				if (constant_time_memcmp(tag,tmp2.u8,len) != 0)
					ct_len = AE_INVALID;
			} else {
				if (constant_time_memcmp((char *)ct + ct_len,tmp2.u8,len) != 0)
					ct_len = AE_INVALID;
			}
		}


        
    }
    return ct_len;
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



int main()
{   	
        ALIGN(16) unsigned char tag[16];
        ALIGN(16) unsigned char tag2[16];
        ALIGN(16) unsigned char key[] = "abcdefghijklmnop";
        ALIGN(16) unsigned char nonce[16] = {
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x01,
        };
        int j=0;
        
        int len = 256;

        ALIGN(16) unsigned char ct[len+64] = {0,};
        ALIGN(16) unsigned char pt[len] = {0};
        ALIGN(16) unsigned char pt2[len] = {0};
        unsigned char k2[16] ={ 
        0x2b, 0x7e, 0x15, 0x16, 
        0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
        };

        const unsigned char ad[16] ={ 
        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c,

        // 0x2b,0x28,0xab,0x09,
        // 0x7e,0xae,0xf7,0xcf,
        // 0x15,0xd2,0x15,0x4f,
        // 0x16,0xa6,0x88,0x3c,
        
    };
    unsigned long long adlen = 16;
        for(j=0;j<len; j++){
            pt[j]=0;
        }
        for(j=0;j<16; j++){
            k2[j]=j;
        }
        

        printf("nonce   ");
        imprimiArreglo(16,nonce);
        printf("---------------------------\n");
        printf("pt      ");
        // imprimiArreglo(len,pt);
        printf("---------------------------\n");

        printf("key     ");
        imprimiArreglo(16,k2);
        printf("---------------------------\n");
		
        printf("len   %i", len);
        printf("\n---------------------------\n");
        ae_ctx* ctx = ae_allocate(NULL);

        ae_init(ctx, k2, 16, 12, 16);
		
        ae_encrypt(ctx, nonce, pt, len, ad, adlen, ct, tag, 1);
        
        printf("Ciphertext   ");
        print_hex_string(ct, len);

        // imprimiArreglo(len,ct);
        printf("\n---------------------------\n");
        printf("tag          ");
        imprimiArreglo(16,tag);
        printf("---------------------------\n");


        // ae_decrypt(ctx, nonce, ct, len, ad, adlen, pt2, tag2, 1);

        // printf("Plaintext   ");
        // imprimiArreglo(len,pt2);
        // printf("\n---------------------------\n");
        // printf("tag          ");
        // imprimiArreglo(16,tag2);
        // printf("\n---------------------------\n");
    return 0;
}

#if USE_AES_NI
char infoString[] = "OCB3 (AES-NI)";
#elif USE_REFERENCE_AES
char infoString[] = "OCB3 (Reference)";
#elif USE_OPENSSL_AES
char infoString[] = "OCB3 (OpenSSL)";
#endif