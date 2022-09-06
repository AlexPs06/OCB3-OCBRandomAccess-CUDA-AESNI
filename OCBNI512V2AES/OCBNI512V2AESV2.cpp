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
#define L_TABLE_SZ          16

/* Set L_TABLE_SZ_IS_ENOUGH non-zero iff you know that all plaintexts
/  will be shorter than 2^(L_TABLE_SZ+4) bytes in length. This results
/  in better performance.                                                  */
#define L_TABLE_SZ_IS_ENOUGH 1

#define AES_ROUNDS 2 /*Number of cuda rounds for the lamda*/

#define ALIGN(n)      __attribute__ ((aligned(n)))
#define BPI 8  /* Number of blocks in buffer per ECB call   */
               /* Set to 4 for Westmere, 8 for Sandy Bridge */
/* ----------------------------------------------------------------------- */
/* Includes and compiler specific definitions                              */
/* ----------------------------------------------------------------------- */

#include "ae.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cmath>
/* Define standard sized integers                                          */
#if defined(_MSC_VER) && (_MSC_VER < 1600)
	typedef unsigned __int8  uint8_t;
	typedef unsigned __int32 uint32_t;
	typedef unsigned __int64 uint64_t;
	typedef          __int64 int64_t;
#else
	#include <stdint.h>
#endif

/* Compiler-specific intrinsics and fixes: bswap64, ntz                    */
#if _MSC_VER
	#define inline __inline        /* MSVC doesn't recognize "inline" in C */
	#define restrict __restrict  /* MSVC doesn't recognize "restrict" in C */
    #define __SSE2__   (_M_IX86 || _M_AMD64 || _M_X64)    /* Assume SSE2  */
    #define __SSSE3__  (_M_IX86 || _M_AMD64 || _M_X64)    /* Assume SSSE3 */
	#include <intrin.h>
	#pragma intrinsic(_byteswap_uint64, _BitScanForward, memcpy)
	#define bswap64(x) _byteswap_uint64(x)
	static inline unsigned ntz(unsigned x) {_BitScanForward(&x,x);return x;}
#elif __GNUC__
	#define inline __inline__            /* No "inline" in GCC ansi C mode */
	#define restrict __restrict__      /* No "restrict" in GCC ansi C mode */
	#define bswap64(x) __builtin_bswap64(x)           /* Assuming GCC 4.3+ */
	#define ntz(x)     __builtin_ctz((unsigned)(x))   /* Assuming GCC 3.4+ */
#else              /* Assume some C99 features: stdint.h, inline, restrict */
	#define bswap32(x)                                              \
	   ((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
		(((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))

	 static inline uint64_t bswap64(uint64_t x) {
		union { uint64_t u64; uint32_t u32[2]; } in, out;
		in.u64 = x;
		out.u32[0] = bswap32(in.u32[1]);
		out.u32[1] = bswap32(in.u32[0]);
		return out.u64;
	}

	#if (L_TABLE_SZ <= 9) && (L_TABLE_SZ_IS_ENOUGH)   /* < 2^13 byte texts */
	static inline unsigned ntz(unsigned x) {
		static const unsigned char tz_table[] = {0,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,7,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,8,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,7,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2};
		return tz_table[x/4];
	}
	#else       /* From http://supertech.csail.mit.edu/papers/debruijn.pdf */
	static inline unsigned ntz(unsigned x) {
		static const unsigned char tz_table[32] =
		{ 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
		 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
		return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
	}
	#endif
#endif

/* ----------------------------------------------------------------------- */
/* Define blocks and operations -- Patch if incorrect on your compiler.    */
/* ----------------------------------------------------------------------- */


    #include <xmmintrin.h>              /* SSE instructions and _mm_malloc */
    #include <emmintrin.h>              /* SSE2 instructions               */
    #include <immintrin.h>
    #include <wmmintrin.h>

    typedef __m128i block;
    typedef __m512i block512;
    #define xor_block(x,y)        _mm_xor_si128(x,y)
    #define xor_block_512(x,y)    _mm512_xor_si512(x,y)
    #define zero_block_512()      _mm512_setzero_si512()
    #define zero_block()          _mm_setzero_si128()
    #define unequal_blocks(x,y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
	#if __SSSE3__ || USE_AES_NI
    #include <tmmintrin.h>              /* SSSE3 instructions              */
    #define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))
    #define swap_if_le512(b) \
      _mm512_shuffle_epi8(b,_mm512_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))//_mm512_shuffle_epi8 _mm512_set_epi8

	#else
    static inline block swap_if_le(block b) {
		block a = _mm_shuffle_epi32  (b, _MM_SHUFFLE(0,1,2,3));
		a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(2,3,0,1));
		a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(2,3,0,1));
		return _mm_xor_si128(_mm_srli_epi16(a,8), _mm_slli_epi16(a,8));
    }
	#endif
	static inline block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		block hi = _mm_load_si128((__m128i *)(KtopStr+0));   /* hi = B A */
		block lo = _mm_loadu_si128((__m128i *)(KtopStr+1));  /* lo = C B */
		__m128i lshift = _mm_cvtsi32_si128(bot);
		__m128i rshift = _mm_cvtsi32_si128(64-bot);
		lo = _mm_xor_si128(_mm_sll_epi64(hi,lshift),_mm_srl_epi64(lo,rshift));
		#if __SSSE3__ || USE_AES_NI
		return _mm_shuffle_epi8(lo,_mm_set_epi8(8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7));
		#else
		return swap_if_le(_mm_shuffle_epi32(lo, _MM_SHUFFLE(1,0,3,2)));
		#endif
	}
	static inline block double_block(block bl) {
		const __m128i mask = _mm_set_epi32(135,1,1,1);
		__m128i tmp = _mm_srai_epi32(bl, 31);
		tmp = _mm_and_si128(tmp, mask);
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
		bl = _mm_slli_epi32(bl, 1);
		return _mm_xor_si128(bl,tmp);
	}


void imprimiArreglo2(int tam, unsigned char *in )
{

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
    }
    printf("\n" );

}
/* ----------------------------------------------------------------------- */
/* AES - Code uses OpenSSL API. Other implementations get mapped to it.    */
/* ----------------------------------------------------------------------- */

/*----------*/
// USE_AES_NI
/*----------*/

#include <wmmintrin.h>
#define AES_ROUNDS_2 2 /*Number of AES rounds for the lamda*/


#if (OCB_KEY_LEN == 0)
	typedef struct { __m128i rd_key[15]; int rounds; } AES_KEY;
	#define ROUNDS(ctx) ((ctx)->rounds)
#else
	typedef struct { __m128i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY;
    typedef struct { ALIGN(64) __m512i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY_512;
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
    x2 = _mm_setzero_si128();
    EXPAND192_STEP(1,1);
    EXPAND192_STEP(4,4);
    EXPAND192_STEP(7,16);
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

    unsigned char tem[704];

    for(int i = 0; i< 11; i++ ){
        _mm_storeu_si128(&((__m128i*)tem)[i*4],key->rd_key[i]);
        _mm_storeu_si128(&((__m128i*)tem)[i*4 +1],key->rd_key[i]);
        _mm_storeu_si128(&((__m128i*)tem)[i*4 +2],key->rd_key[i]);
        _mm_storeu_si128(&((__m128i*)tem)[i*4 +3],key->rd_key[i]);
    }
    for(int i = 0; i< 11; i++ ){
        key512->rd_key[i] =  _mm512_loadu_si512(&((__m512i*)&tem)[i]);
    }
    return 0;
}

static AES_KEY_512 AES_cast_128_to_512_key2(AES_KEY *key)
{
    union {block oa128[4]; block512 oa512;} oa;
    AES_KEY_512 temporal;
    for(int i = 0; i< 11; i++ ){
        oa.oa128[0] = key->rd_key[i];
        oa.oa128[1] = key->rd_key[i];
        oa.oa128[2] = key->rd_key[i];
        oa.oa128[3] = key->rd_key[i];
        temporal.rd_key[i]=oa.oa512;
    }

    return temporal;
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

static inline void AES_ecb_encrypt_blks_ROUNDS(block *blks, unsigned nblks, AES_KEY *key,unsigned rounds) {
    unsigned i,j,rnds=rounds;
	const __m128i *sched = ((__m128i *)(key->rd_key));
	for(j=1; j<rnds+1; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm_aesenc_si128(blks[i], sched[j]);
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

static inline void AES_ecb_encrypt_blks_512(block512 *blks, unsigned nblks, AES_KEY_512 *key) {
    unsigned i,j,rnds=ROUNDS(key);
	const __m512i *sched = ((__m512i *)(key->rd_key));
    for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_xor_si512(blks[i], sched[0]);//4cc
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm512_aesenc_epi128(blks[i], sched[j]); //80cc
    for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_aesenclast_epi128(blks[i], sched[j]);
}


static inline void AES_ecb_encrypt_blks_512_ROUNDS(block512 *blks, unsigned nblks, AES_KEY_512 *key,unsigned rounds) {
    unsigned i,j,rnds=rounds+1;
	const __m512i *sched = ((__m512i *)(key->rd_key));
	for(j=1; j<rnds; ++j){
			for (i=0; i<nblks; ++i){
		    	blks[i] = _mm512_aesenc_epi128(blks[i], sched[j]);
		}
	}

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
    block checksum;                        /* Memory correct               */
    block ad_checksum;                     /* Memory correct               */
    block512 *nonces;                         /* Memory correct               */
    long long int num_of_nonces;              /* Memory correct               */
    uint32_t ad_blocks_processed;
    uint32_t blocks_processed;
    AES_KEY decrypt_key;
    AES_KEY encrypt_key;
    AES_KEY_512 *encrypt_key_512;
    AES_KEY_512 decrypt_key_512;
    block512 *Two_rounds_key;
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
	(void) misc;                     /* misc unused in this implementation */
	#if (__SSE2__ && !_M_X64 && !_M_AMD64 && !__amd64__)
    	p = _mm_malloc(sizeof(ae_ctx),16);
	#elif (__ALTIVEC__ && !__PPC64__)
		if (posix_memalign(&p,16,sizeof(ae_ctx)) != 0) p = NULL;
	#else
		p = malloc(sizeof(ae_ctx));
	#endif
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

int ae_init(ae_ctx *ctx, const void *key, int key_len, int nonce_len, unsigned long long int pt_len,int tag_len)
{
    unsigned i;
    block tmp_blk;


    if (nonce_len != 12)
    	return AE_NOT_SUPPORTED;

    /* Initialize encryption & decryption keys */
    #if (OCB_KEY_LEN > 0)
    key_len = OCB_KEY_LEN;
    #endif

    AES_set_encrypt_key((unsigned char *)key, key_len*8, &ctx->encrypt_key);
    #if USE_AES_NI
    AES_set_decrypt_key_fast(&ctx->decrypt_key,&ctx->encrypt_key);
    #else
    AES_set_decrypt_key((unsigned char *)key, (int)(key_len*8), &ctx->decrypt_key);
    #endif
    int num_blocks = 0;
    long long int deltasize = 0;
    #if AES_ROUNDS == 2
        num_blocks = pt_len/16;
        deltasize= pow(2,30);
        ctx->num_of_nonces = ceil(num_blocks/ deltasize);

		// AES_KEY_512 keys512;
		// keys512 =  AES_cast_128_to_512_key2(&ctx->encrypt_key);
		// ctx->encrypt_key_512 = &keys512;

		// for (int i = 0; i < 11; i++){
		// 	imprimiArreglo2(16,(unsigned char*)&keys512.rd_key[i]);
		// }
		
		// printf("\n-------------------------------\n");
		
		// for (int i = 0; i < 11; i++){
		// 	imprimiArreglo2(16,(unsigned char*)&ctx->encrypt_key_512[0].rd_key[i]);
		// }

		// imprimiArreglo2(64,(unsigned char*)&keys512.rd_key[0]);
		// imprimiArreglo2(64,(unsigned char*)&ctx->encrypt_key_512[0].rd_key[0]);
    	// ctx->decrypt_key_512 =  AES_cast_128_to_512_key2(&ctx->decrypt_key);
		
		// block512 two_keys[2];
		// two_keys[0] = _mm512_set_epi32(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
		// two_keys[1] = _mm512_set_epi32(0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1);
		// AES_ecb_encrypt_blks_512(two_keys, 2, &ctx->encrypt_key_512[0]); 

		// ctx->Two_rounds_key = two_keys;
		// ctx->Two_rounds_key[1] = two_keys[1];
    #else
        num_blocks = pt_len/16;
        deltasize= pow(2,6);
        ctx->num_of_nonces = ceil(num_blocks/ deltasize);
		ctx->encrypt_key_512 =  AES_cast_128_to_512_key2(&ctx->encrypt_key);
    	ctx->decrypt_key_512 =  AES_cast_128_to_512_key2(&ctx->decrypt_key);
		block two_keys[2];
		two_keys[0] = _mm_set_epi32(0,0,0,0);
		AES_ecb_encrypt_blks(two_keys, 1, &ctx->encrypt_key); 
    #endif

    if(pt_len!=0 && ctx->num_of_nonces ==0){
        ctx->num_of_nonces=1;
    }

    #if (OCB_TAG_LEN == 0)
    	ctx->tag_len = tag_len;
    #else
    	(void) tag_len;  /* Suppress var not used error */
    #endif

    return AE_SUCCESS;
}

static void gen_offset_from_nonce(ae_ctx *ctx, const void *nonce)
{
    unsigned i;
    block add1 = _mm_set_epi8 (
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01
    );

    block bloques128[ctx->num_of_nonces];
    block512 bloques512[ctx->num_of_nonces];

    block *tmp_blk = (block *)nonce;
    unsigned char tmp_array[64*ctx->num_of_nonces] ;

    tmp_blk[0] = swap_if_le(tmp_blk[0]);
    for(i = 0; i<ctx->num_of_nonces; i++ ){
        bloques128[i] = swap_if_le(tmp_blk[0]);
        // bloques128[i] = tmp_blk[0];
        tmp_blk[0]=_mm_add_epi32(tmp_blk[0],add1);
    }

    AES_ecb_encrypt_blks(bloques128, ctx->num_of_nonces,&ctx->encrypt_key);

    int j =0;
    for(i = 0; i<ctx->num_of_nonces; i++ ){
        _mm_storeu_si128(&((__m128i*)tmp_array)[j],bloques128[i]  );
        _mm_storeu_si128(&((__m128i*)tmp_array)[j+1],bloques128[i]  );
        _mm_storeu_si128(&((__m128i*)tmp_array)[j+2],bloques128[i]  );
        _mm_storeu_si128(&((__m128i*)tmp_array)[j+3],bloques128[i]  );
        bloques512[i]= _mm512_loadu_si512(&((__m512i*)tmp_array)[i] );
    }
    ctx->nonces= bloques512;
    // imprimiArreglo2(16,(unsigned char * )&ctx->nonces[0]);
//    30 a2 5d 6a 5c 95 dd e2 39 07 58 b1 50 ff 70 38
//    8a a6 b8 a2 f6 fd 98 8c b3 1e fb 6d 78 54 52 15
}

static void process_ad(ae_ctx *ctx, const void *ad, int ad_len, int final)
{
	// union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    // block ad_offset, ad_checksum;
    // const block *  adp = (block *)ad;
	// unsigned i,k,tz,remaining;

    // ad_offset = ctx->ad_offset;
    // ad_checksum = ctx->ad_checksum;
    // i = ad_len/(BPI*16);
	// if (i) {
	// 	unsigned ad_block_num = ctx->ad_blocks_processed;
	// 	do {
	// 		block ta[BPI], oa[BPI];
	// 		ad_block_num += BPI;
	// 		tz = ntz(ad_block_num);
	// 		// imprimiArreglo(16,(unsigned char * )&ad_offset);
	// 		// imprimiArreglo(16,(unsigned char * )&ctx->L[0]);
	// 		oa[0] = xor_block(ad_offset, ctx->L[0]);
	// 		ta[0] = xor_block(oa[0], adp[0]);
	// 		oa[1] = xor_block(oa[0], ctx->L[1]);
	// 		ta[1] = xor_block(oa[1], adp[1]);
	// 		oa[2] = xor_block(ad_offset, ctx->L[1]);
	// 		ta[2] = xor_block(oa[2], adp[2]);
	// 		#if BPI == 4
	// 			ad_offset = xor_block(oa[2], getL(ctx, tz));
	// 			ta[3] = xor_block(ad_offset, adp[3]);
	// 		#elif BPI == 8
	// 			oa[3] = xor_block(oa[2], ctx->L[2]);
	// 			ta[3] = xor_block(oa[3], adp[3]);
	// 			oa[4] = xor_block(oa[1], ctx->L[2]);
	// 			ta[4] = xor_block(oa[4], adp[4]);
	// 			oa[5] = xor_block(oa[0], ctx->L[2]);
	// 			ta[5] = xor_block(oa[5], adp[5]);
	// 			oa[6] = xor_block(ad_offset, ctx->L[2]);
	// 			ta[6] = xor_block(oa[6], adp[6]);
	// 			ad_offset = xor_block(oa[6], getL(ctx, tz));
	// 			ta[7] = xor_block(ad_offset, adp[7]);
	// 		#endif
	// 		// for(int a = 0; a<BPI;a++){
	// 		// 	imprimiArreglo(16,(unsigned char * )&oa[a]);
	// 		// }
	// 		// exit(1);
	// 		// printf("hola mundo \n");

	// 		AES_ecb_encrypt_blks(ta,BPI,&ctx->encrypt_key);
	// 		ad_checksum = xor_block(ad_checksum, ta[0]);
	// 		ad_checksum = xor_block(ad_checksum, ta[1]);
	// 		ad_checksum = xor_block(ad_checksum, ta[2]);
	// 		ad_checksum = xor_block(ad_checksum, ta[3]);
	// 		#if (BPI == 8)
	// 		ad_checksum = xor_block(ad_checksum, ta[4]);
	// 		ad_checksum = xor_block(ad_checksum, ta[5]);
	// 		ad_checksum = xor_block(ad_checksum, ta[6]);
	// 		ad_checksum = xor_block(ad_checksum, ta[7]);
	// 		#endif
	// 		adp += BPI;
	// 	} while (--i);
	// 	ctx->ad_blocks_processed = ad_block_num;
	// 	ctx->ad_offset = ad_offset;
	// 	ctx->ad_checksum = ad_checksum;
	// }

    // if (final) {
	// 	block ta[BPI];

    //     /* Process remaining associated data, compute its tag contribution */
    //     remaining = ((unsigned)ad_len) % (BPI*16);
    //     if (remaining) {
	// 		k=0;
	// 		#if (BPI == 8)
	// 		if (remaining >= 64) {
	// 			// imprimiArreglo(16,(unsigned char * )&ad_offset);

	// 			tmp.bl = xor_block(ad_offset, ctx->L[0]);
	// 			// imprimiArreglo(16,(unsigned char * )&tmp.bl);

	// 			ta[0] = xor_block(tmp.bl, adp[0]);
	// 			tmp.bl = xor_block(tmp.bl, ctx->L[1]);
	// 			// imprimiArreglo(16,(unsigned char * )&tmp.bl);

	// 			ta[1] = xor_block(tmp.bl, adp[1]);
	// 			ad_offset = xor_block(ad_offset, ctx->L[1]);
	// 			// imprimiArreglo(16,(unsigned char * )&ad_offset);

	// 			ta[2] = xor_block(ad_offset, adp[2]);
	// 			ad_offset = xor_block(ad_offset, ctx->L[2]);
	// 			// imprimiArreglo(16,(unsigned char * )&ad_offset);

	// 			ta[3] = xor_block(ad_offset, adp[3]);
	// 			remaining -= 64;
	// 			k=4;

	// 			// printf("hola mundo \n");
	// 			// for(int a = 0; a<4;a++){
	// 			// 		imprimiArreglo(16,(unsigned char * )&ta[a]);
	// 			// }
	// 			// exit(1);
	// 		}
	// 		#endif
	// 		if (remaining >= 32) {
	// 			ad_offset = xor_block(ad_offset, ctx->L[0]);
	// 			ta[k] = xor_block(ad_offset, adp[k]);
	// 			ad_offset = xor_block(ad_offset, getL(ctx, ntz(k+2)));
	// 			ta[k+1] = xor_block(ad_offset, adp[k+1]);
	// 			remaining -= 32;
	// 			k+=2;
	// 		}
	// 		if (remaining >= 16) {
	// 			ad_offset = xor_block(ad_offset, ctx->L[0]);

	// 			// imprimiArreglo(16,(unsigned char * )&ctx->L[0]);


	// 			ta[k] = xor_block(ad_offset, adp[k]);
	// 			remaining = remaining - 16;
	// 			++k;
	// 		}
	// 		if (remaining) {
	// 			ad_offset = xor_block(ad_offset,ctx->Lstar);
	// 			tmp.bl = zero_block();
	// 			memcpy(tmp.u8, adp+k, remaining);
	// 			tmp.u8[remaining] = (unsigned char)0x80u;
	// 			ta[k] = xor_block(ad_offset, tmp.bl);
	// 			++k;
	// 		}


	// 		AES_ecb_encrypt_blks(ta,k,&ctx->encrypt_key);



	// 		switch (k) {
	// 			#if (BPI == 8)
	// 			case 8: ad_checksum = xor_block(ad_checksum, ta[7]);
	// 			case 7: ad_checksum = xor_block(ad_checksum, ta[6]);
	// 			case 6: ad_checksum = xor_block(ad_checksum, ta[5]);
	// 			case 5: ad_checksum = xor_block(ad_checksum, ta[4]);
	// 			#endif
	// 			case 4: ad_checksum = xor_block(ad_checksum, ta[3]);
	// 			case 3: ad_checksum = xor_block(ad_checksum, ta[2]);
	// 			case 2: ad_checksum = xor_block(ad_checksum, ta[1]);
	// 			case 1: ad_checksum = xor_block(ad_checksum, ta[0]);
	// 		}
	// 		ctx->ad_checksum = ad_checksum;



	// 	}

	// }
	// printf("S       ");
	// imprimiArreglo(16,(unsigned char * )&ad_checksum);
    // printf("---------------------------\n");

	// exit(1);
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
	// if(pt_len==0){
	// 	return 0;
	// }
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;

	union { uint32_t u32[16]; uint8_t u8[64] = {0,} ; block512 bl; block bl128[4]; } tmp512;
    union {block512  checksum512; block checksum128[4];} checksum;
    union {block bl128[4]; block512 bl512;} add_nonce;

    unsigned temp_len = pt_len;
    block offset;
    unsigned i, k;
    // block       * ctp = (block *)ct;
    const block * ptp128 = (block *)pt;
    block512       * ctp = (block512 *)ct;
    const block512 * ptp = (block512 *)pt;

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        gen_offset_from_nonce(ctx, nonce);
        // ctx->checksum   = zero_block_512();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        // if (ad_len >= 0)
        // 	ctx->ad_checksum = zero_block_512();
    }

	/* Process associated data */
	if (ad_len > 0)
		process_ad(ctx, ad, ad_len, final);

	/* Encrypt plaintext data BPI blocks at a time */


    AES_KEY_512 keys512 =  AES_cast_128_to_512_key2(&ctx->encrypt_key);


	#if AES_ROUNDS_2 == 2

		AES_KEY_512 keys512_two_round;
		AES_KEY keys_two_round;
		
		union {block bl128[8]; block512 bl512[2];} two_keys; 

		two_keys.bl512[0] = _mm512_set_epi32(0,0,0,2,0,0,0,2,0,0,0,2,0,0,0,2);
		two_keys.bl512[1] = _mm512_set_epi32(0,0,0,3,0,0,0,3,0,0,0,3,0,0,0,3);

		
		AES_ecb_encrypt_blks_512(two_keys.bl512, 2, &keys512); 

		keys512_two_round.rd_key[1]=two_keys.bl512[0];
		keys512_two_round.rd_key[2]=two_keys.bl512[1];
		
		

		keys_two_round.rd_key[1]=two_keys.bl128[0];  
		keys_two_round.rd_key[2]=two_keys.bl128[4];  
	#else
		AES_KEY_512 keys512_two_round;
		AES_KEY keys_two_round;
		
		union {block bl128[4]; block512 bl512[1];} two_keys; 

		two_keys.bl512[0] = _mm512_set_epi32(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

		AES_ecb_encrypt_blks_512(two_keys.bl512, 1, &keys512); 

		keys512_two_round.rd_key[1]=two_keys.bl512[0];
		keys_two_round.rd_key[1]=two_keys.bl128[0];  
	#endif
	
	// for (int i = 0; i < 11; i++){
	// 	imprimiArreglo2(16,(unsigned char*)&keys512.rd_key[i]);
	// }
	// printf("\n-------------------------------\n");
	// for (int i = 0; i < 11; i++){
	// 	imprimiArreglo2(16,(unsigned char*)&ctx->encrypt_key_512[0].rd_key[i]);
	// }

	// imprimiArreglo2(64,(unsigned char*)&keys512_two_round.rd_key[1]);
	// imprimiArreglo2(64,(unsigned char*)&keys512_two_round.rd_key[2]);

	// imprimiArreglo2(16,(unsigned char*)&keys_two_round.rd_key[1]);
	// imprimiArreglo2(16,(unsigned char*)&keys_two_round.rd_key[2]);
	// exit(1);

    add_nonce.bl512 = _mm512_set_epi32 (
        0x03, 0x03, 0x03, 0x03,
        0x02, 0x02, 0x02, 0x02,
        0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00

    );

    block512 add4 = _mm512_set_epi32 (
        0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04
    );


    unsigned index;

    // offset = ctx->offset;
    checksum.checksum512  = zero_block_512();
    i = pt_len/(BPI*64);

	// exit(1);

	ctx->nonces[index]=swap_if_le512(ctx->nonces[index]);
    if (i) {
        block512 ta[BPI];
        block512 delta[BPI];
    	unsigned block_num = ctx->blocks_processed;

		do {
            for(int j = 0; j<BPI; j++){
               delta[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
               add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
               delta[j]=swap_if_le512(delta[j]);
            }
			// imprimiArreglo2(64, (unsigned char *)&two_keys.bl512[0]);
			// imprimiArreglo2(64, (unsigned char *)&delta[7]);

            AES_ecb_encrypt_blks_512_ROUNDS(delta, BPI, &keys512_two_round, AES_ROUNDS_2);
			// imprimiArreglo2(64, (unsigned char *)&delta[7]);
            
			for(int j = 0; j<BPI; j++){
			    ta[j] = xor_block_512(delta[j], ptp[j]);
			    checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[j]);
            }
			// imprimiArreglo2(64, (unsigned char *)&ta[7]);


			AES_ecb_encrypt_blks_512(ta,BPI,&keys512);

			// imprimiArreglo2(64, (unsigned char *)&ta[7]);

            for(int j = 0; j<BPI; j++){
                ctp[j]= xor_block_512(ta[j], delta[j]);
            }
			// imprimiArreglo2(64, (unsigned char *)&ctp[7]);


            ptp += BPI;
			ctp += BPI;
            block_num+=32;

		} while (--i);

	    ctx->blocks_processed = block_num;
    }
    if (final) {

		union {block ta128[4*BPI]; block512 ta512[BPI];} ta;
		union {block deltak128[4*BPI]; block512 deltak512[BPI];} delta;
        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)pt_len) % (BPI*64);
        k = 0;                      /* How many blocks in ta[] need ECBing */
		unsigned block_num = ctx->blocks_processed;
		int indexBlock;
        if (remaining) {

			#if (BPI == 8)
			if (remaining >= 256) {
				for(int j = 0; j<4; j++){
			    	checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[j]);

					delta.deltak512[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[j]=swap_if_le512(delta.deltak512[j]);
            	}
				remaining -= 256;
				k = 4;
				block_num += 16;
			}
			#endif
			if (remaining >= 128) {

				for(int j = k; j<k+2; j++){
			    	checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[j]);
					delta.deltak512[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[j]=swap_if_le512(delta.deltak512[j]);
            	}
				remaining -= 128;
				k += 2;

				block_num += 8;
			}
			if (remaining >= 64) {
			    checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k]);
				delta.deltak512[k] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
				add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
				delta.deltak512[k]=swap_if_le512(delta.deltak512[k]);
				block_num += 4;
				remaining -= 64;
				++k;
			}
			if (remaining) {

				if(remaining%16==0){
					block_num = block_num  + remaining/16;
			    	checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k]);
					remaining=remaining-remaining;

					delta.deltak512[k] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[k]=swap_if_le512(delta.deltak512[k]);
				}
				else{
					delta.deltak512[k] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);

					block_num = block_num  + ceil(remaining/16)+1;

					block add1 = _mm_set_epi32 (0x01, 0x01, 0x01, 0x01);
					indexBlock = floor(remaining/16);
					delta.deltak128[4*k +indexBlock] = _mm_add_epi32(add1,delta.deltak128[4*k +indexBlock]);

					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[k]=swap_if_le512(delta.deltak512[k]);



					ALIGN(16) unsigned char temp[16]={0,};
					temp[remaining%16]=1;
					block * temp128 = (block *)temp;

					memcpy(tmp512.u8, ptp+k, remaining);
					tmp512.bl128[indexBlock] = _mm_xor_si128(temp128[0],tmp512.bl128[indexBlock] );
					checksum.checksum128[0] = xor_block(checksum.checksum128[0], tmp512.bl128[indexBlock]);

				}

				++k;
			}
			ctx->blocks_processed = block_num;
		}

		AES_ecb_encrypt_blks_512_ROUNDS(delta.deltak512, k, &keys512_two_round, AES_ROUNDS);
		
		for(int j = 0; j<k; j++){
			ta.ta512[j] = xor_block_512(delta.deltak512[j], ptp[j]);
		}

		if (remaining) {
			ta.ta128[4*(k-1) + indexBlock] = delta.deltak128[4*(k-1) + indexBlock];
		}
		
		AES_ecb_encrypt_blks_512(ta.ta512,k,&keys512);

		if (remaining) {
			--k;

			ta.ta128[4*(k) + indexBlock] = _mm_xor_si128( ta.ta128[4*(k) + indexBlock], tmp512.bl128[indexBlock]);

			delta.deltak128[4*(k) + indexBlock] = zero_block();

			ctp[k] = xor_block_512(delta.deltak512[k], ta.ta512[k]);

		}

		switch (k) {
			#if (BPI == 8)
			case 7: ctp[6] = xor_block_512(delta.deltak512[6], ta.ta512[6]);
			case 6: ctp[5] = xor_block_512(delta.deltak512[5], ta.ta512[5]);
			case 5: ctp[4] = xor_block_512(delta.deltak512[4], ta.ta512[4]);
			case 4: ctp[3] = xor_block_512(delta.deltak512[3], ta.ta512[3]);
			#endif
			case 3: ctp[2] = xor_block_512(delta.deltak512[2], ta.ta512[2]);
			case 2: ctp[1] = xor_block_512(delta.deltak512[1], ta.ta512[1]);
			case 1: ctp[0] = xor_block_512(delta.deltak512[0], ta.ta512[0]);
		}



        __m128i checksumFinal  = _mm_setzero_si128();
        i=0;

        while( temp_len>0 && i<4){
            checksumFinal =  _mm_xor_si128( checksumFinal, checksum.checksum128[i]);
            temp_len = temp_len-16;
            i++;
        }
		tmp512.bl=ctx->nonces[index];
        block nonce128 = tmp512.bl128[index];

        int index_nonce_checksum =ctx->blocks_processed%4;
        block add3;
		if(index_nonce_checksum==0)
			add3 = _mm_set_epi32 (0x03, 0x03, 0x03, 0x03);
		else
			add3 = _mm_set_epi32 (-1, -1, -1, -1);



        add_nonce.bl128[index_nonce_checksum] = _mm_add_epi32 (add_nonce.bl128[index_nonce_checksum], add3);
        nonce128 = _mm_add_epi32 (nonce128, add_nonce.bl128[index_nonce_checksum]);
        nonce128 =  swap_if_le(nonce128);
	
        AES_ecb_encrypt_blks_ROUNDS(&nonce128, 1, &keys_two_round ,AES_ROUNDS);

        checksumFinal = xor_block(nonce128, checksumFinal);           /* Part of tag gen */
		
		AES_ecb_encrypt_blks(&checksumFinal,1,&ctx->encrypt_key);
		
		offset = xor_block(checksumFinal, ctx->ad_checksum);   /* Part of tag gen */

        if (tag) {
			#if (OCB_TAG_LEN == 16)
            	*(block *)tag = offset;
			#elif (OCB_TAG_LEN > 0)
	            memcpy((char *)tag, &offset, OCB_TAG_LEN);
			#else
	            memcpy((char *)tag, &offset, ctx->tag_len);
	        #endif
        } else {
			#if (OCB_TAG_LEN > 0)
	            memcpy((char *)ct + pt_len, &offset, OCB_TAG_LEN);
            	pt_len += OCB_TAG_LEN;
			#else
	            memcpy((char *)ct + pt_len, &offset, ctx->tag_len);
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
               const void *tag,
               int         final)
{
	// if(pt_len==0){
	// 	return 0;
	// }
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;

	union { uint32_t u32[16]; uint8_t u8[64] = {0,} ; block512 bl; block bl128[4]; } tmp512;
    union {block512  checksum512; block checksum128[4];} checksum;
    union {block bl128[4]; block512 bl512;} add_nonce;

    unsigned temp_len = ct_len;
    block offset;
    unsigned i, k;
    // block       * ctp = (block *)ct;
    const block * ctp128 = (block *)ct;
    const block512       * ctp = (block512 *)ct;
    block512 * ptp = (block512 *)pt;

    /* Non-null nonce means start of new message, init per-message values */
    if (nonce) {
        gen_offset_from_nonce(ctx, nonce);

        // ctx->checksum   = zero_block_512();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        // if (ad_len >= 0)
        // 	ctx->ad_checksum = zero_block_512();
    }

	/* Process associated data */
	if (ad_len > 0)
		process_ad(ctx, ad, ad_len, final);

	/* Encrypt plaintext data BPI blocks at a time */


    AES_KEY_512 keys_encrypt_512 =  AES_cast_128_to_512_key2(&ctx->encrypt_key);
    AES_KEY_512 keys_decrypt_512 =  AES_cast_128_to_512_key2(&ctx->decrypt_key);


    add_nonce.bl512 = _mm512_set_epi32 (
        0x03, 0x03, 0x03, 0x03,
        0x02, 0x02, 0x02, 0x02,
        0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00

    );

    block512 add4 = _mm512_set_epi32 (
        0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04
    );


    unsigned index;

    // offset = ctx->offset;
    checksum.checksum512  = zero_block_512();
    i = ct_len/(BPI*64);

	// imprimiArreglo2(16,(unsigned char *)&ctx->nonces[index]);

	ctx->nonces[index]=swap_if_le512(ctx->nonces[index]);
    if (i) {
        block512 ta[BPI];
        block512 delta[BPI];
    	unsigned block_num = ctx->blocks_processed;

		do {
            for(int j = 0; j<BPI; j++){
               delta[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
               add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
               delta[j]=swap_if_le512(delta[j]);
            }

            AES_ecb_encrypt_blks_512_ROUNDS(delta, BPI, &keys_encrypt_512,AES_ROUNDS);

            for(int j = 0; j<BPI; j++){
			    ta[j] = xor_block_512(delta[j], ctp[j]);
            }

			AES_ecb_decrypt_blks_512(ta,BPI,&keys_decrypt_512);
            for(int j = 0; j<BPI; j++){
                ptp[j]= xor_block_512(ta[j], delta[j]);
				checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[j]);

            }

            ptp += BPI;
			ctp += BPI;
            block_num+=32;

		} while (--i);

	    ctx->blocks_processed = block_num;
    }
	// printf("soy block_num %i\n,",ctx->blocks_processed );

    if (final) {

		union {block ta128[4*BPI]; block512 ta512[BPI];} ta;
		union {block deltak128[4*BPI]; block512 deltak512[BPI];} delta;
        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)ct_len) % (BPI*64);
        k = 0;                      /* How many blocks in ta[] need ECBing */
		unsigned block_num = ctx->blocks_processed;

		int indexBlock;
        if (remaining) {

			#if (BPI == 8)
			if (remaining >= 256) {
				for(int j = 0; j<4; j++){

					delta.deltak512[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[j]=swap_if_le512(delta.deltak512[j]);
            	}
				remaining -= 256;
				k = 4;
				block_num += 16;
			}
			#endif
			if (remaining >= 128) {

				for(int j = k; j<k+2; j++){
					delta.deltak512[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[j]=swap_if_le512(delta.deltak512[j]);
            	}
				remaining -= 128;
				k += 2;

				block_num += 8;
			}
			if (remaining >= 64) {
				delta.deltak512[k] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
				add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
				delta.deltak512[k]=swap_if_le512(delta.deltak512[k]);
				block_num += 4;
				remaining -= 64;
				++k;
			}
			if (remaining) {

				if(remaining%16==0){

					block_num = block_num  + remaining/16;
			    	// checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k]);
					remaining=remaining-remaining;


					delta.deltak512[k] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);
					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[k]=swap_if_le512(delta.deltak512[k]);

				}
				else{
					delta.deltak512[k] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);

					block_num = block_num  + ceil(remaining/16)+1;

					block add1 = _mm_set_epi32 (0x01, 0x01, 0x01, 0x01);
					indexBlock = floor(remaining/16);
					delta.deltak128[4*k +indexBlock] = _mm_add_epi32(add1,delta.deltak128[4*k +indexBlock]);

					add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);
					delta.deltak512[k]=swap_if_le512(delta.deltak512[k]);



					ALIGN(16) unsigned char temp[16]={0,};
					temp[remaining%16]=1;
					block * temp128 = (block *)temp;

					memcpy(tmp512.u8, ptp+k, remaining);
					tmp512.bl128[indexBlock] = _mm_xor_si128(temp128[0],tmp512.bl128[indexBlock] );
					// checksum.checksum128[0] = xor_block(checksum.checksum128[0], tmp512.bl128[indexBlock]);

				}

				++k;
			}
			ctx->blocks_processed = block_num;
		}

		// for(int j = 0; j<k; j++){

		// 	delta[j] = _mm512_add_epi32 (ctx->nonces[index],add_nonce.bl512);

		// 	add_nonce.bl512=_mm512_add_epi32 (add4,add_nonce.bl512);

		// 	delta[j]=swap_if_le512(delta[j]);
        // }
		// imprimiArreglo2(16,(unsigned char *)&delta.deltak512);
		// ctx->nonces[index] =swap_if_le512(ctx->nonces[index]);

		// imprimiArreglo2(16,(unsigned char *)&ctx->nonces[index]);

		AES_ecb_encrypt_blks_512_ROUNDS(delta.deltak512, k, &keys_encrypt_512,AES_ROUNDS);

		for(int j = 0; j<k; j++){
			ta.ta512[j] = xor_block_512(delta.deltak512[j], ptp[j]);
		}

		if (remaining) {
			ta.ta128[4*(k-1) + indexBlock] = delta.deltak128[4*(k-1) + indexBlock];
		}
		// printf("%i\n",indexBlock);
		// printf("%i\n",k);
		// printf("%i\n",4*(k-1) + indexBlock);
		// imprimiArreglo2(16,(unsigned char *)&ta.ta128[4*(k-1) + indexBlock]  );
		// imprimiArreglo2(16,(unsigned char *)&ta.ta128[0]  );

		AES_ecb_decrypt_blks_512(ta.ta512,k,&keys_decrypt_512);



		// imprimiArreglo2(16,(unsigned char *)&ta.ta128[0]  );
		// exit(1);
		if (remaining) {
			--k;

			ta.ta128[4*(k) + indexBlock] = _mm_xor_si128( ta.ta128[4*(k) + indexBlock], tmp512.bl128[indexBlock]);

			delta.deltak128[4*(k) + indexBlock] = zero_block();

			ptp[k] = xor_block_512(delta.deltak512[k], ta.ta512[k]);
			checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k]);

			// imprimiArreglo2(16,(unsigned char *)&ptp[k]  );
		}

		switch (k) {
			#if (BPI == 8)
			case 7:
					ptp[6] = xor_block_512(delta.deltak512[6], ta.ta512[6]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[6]);
					break;
			case 6:
					ptp[5] = xor_block_512(delta.deltak512[5], ta.ta512[5]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[5]);
					break;
			case 5:
					ptp[4] = xor_block_512(delta.deltak512[4], ta.ta512[4]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[4]);
					break;
			case 4:
					ptp[3] = xor_block_512(delta.deltak512[3], ta.ta512[3]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[3]);
					break;
			#endif
			case 3:
					ptp[2] = xor_block_512(delta.deltak512[2], ta.ta512[2]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[2]);
					break;
			case 2:
					ptp[1] = xor_block_512(delta.deltak512[1], ta.ta512[1]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[1]);
					break;
			case 1:
					ptp[0] = xor_block_512(delta.deltak512[0], ta.ta512[0]);
					checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[0]);
					// imprimiArreglo2(16,(unsigned char *)&ptp[0]  );


					break;
		}




        __m128i checksumFinal  = _mm_setzero_si128();
        i=0;

        while( temp_len>0 && i<4){
            checksumFinal =  _mm_xor_si128( checksumFinal, checksum.checksum128[i]);
            temp_len = temp_len-16;
            i++;
        }
		// imprimiArreglo2(16,(unsigned char *)&checksumFinal  );

		tmp512.bl=ctx->nonces[index];
        block nonce128 = tmp512.bl128[index];
		//  _mm_loadu_si128(&((__m128i*)&ctx->nonces[index])[0]);

        int index_nonce_checksum =ctx->blocks_processed%4;
        block add3;
		if(index_nonce_checksum==0)
			add3 = _mm_set_epi32 (0x03, 0x03, 0x03, 0x03);
		else
			add3 = _mm_set_epi32 (-1, -1, -1, -1);


		// imprimiArreglo2(16,(unsigned char *)&add_nonce.bl128[index_nonce_checksum]  );

        add_nonce.bl128[index_nonce_checksum] = _mm_add_epi32 (add_nonce.bl128[index_nonce_checksum], add3);

		// imprimiArreglo2(16,(unsigned char *)&add_nonce.bl128[index_nonce_checksum]  );
		// imprimiArreglo2(16,(unsigned char *)&nonce128 );

        nonce128 = _mm_add_epi32 (nonce128, add_nonce.bl128[index_nonce_checksum]);
        nonce128 =  swap_if_le(nonce128);

		// imprimiArreglo2(16,(unsigned char *)&nonce128  );


        AES_ecb_encrypt_blks_ROUNDS(&nonce128, 1, &ctx->encrypt_key ,AES_ROUNDS);
		// imprimiArreglo2(16,(unsigned char *)&nonce128  );

        checksumFinal = xor_block(nonce128, checksumFinal);           /* Part of tag gen */


		AES_ecb_encrypt_blks(&checksumFinal,1,&ctx->encrypt_key);
		offset = xor_block(checksumFinal, ctx->ad_checksum);   /* Part of tag gen */
		// imprimiArreglo2(16,(unsigned char *)&offset );

		 if (tag) {
			#if (OCB_TAG_LEN == 16)
            	*(block *)tag = offset;
			#elif (OCB_TAG_LEN > 0)
	            memcpy((char *)tag, &offset, OCB_TAG_LEN);
			#else
	            memcpy((char *)tag, &offset, ctx->tag_len);
	        #endif
        } else {
			#if (OCB_TAG_LEN > 0)
	            memcpy((char *)ct + ct_len, &offset, OCB_TAG_LEN);
            	ct_len += OCB_TAG_LEN;
			#else
	            memcpy((char *)ct + pt_len, &offset, ctx->tag_len);
            	pt_len += ctx->tag_len;
	        #endif
        }

        // if ((OCB_TAG_LEN == 16) && tag) {
		// 	if (unequal_blocks(offset, *(block *)tag))
		// 		ct_len = AE_INVALID;
		// } else {
		// 	#if (OCB_TAG_LEN > 0)
		// 		int len = OCB_TAG_LEN;
		// 	#else
		// 		int len = ctx->tag_len;
		// 	#endif
		// 	if (tag) {
		// 		if (constant_time_memcmp(tag,tmp.u8,len) != 0)
		// 			ct_len = AE_INVALID;
		// 	} else {
		// 		if (constant_time_memcmp((char *)ct + ct_len,tmp.u8,len) != 0)
		// 			ct_len = AE_INVALID;
		// 	}
		// }
    }

    return ct_len;
 }



#if USE_AES_NI
char infoString[] = "OCB2R AVX512(AES-NI)";
#elif USE_REFERENCE_AES
char infoString[] = "OCB3 (Reference)";
#elif USE_OPENSSL_AES
char infoString[] = "OCB3 (OpenSSL)";
#endif