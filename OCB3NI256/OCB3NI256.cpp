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
#define BPI 8  /* Number of blocks in buffer per ECB call   */
               /* Set to 4 for Westmere, 8 for Sandy Bridge */
/* ----------------------------------------------------------------------- */
/* Includes and compiler specific definitions                              */
/* ----------------------------------------------------------------------- */

#include "ae.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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
    typedef __m256i block256;
    #define xor_block(x,y)        _mm_xor_si128(x,y)
    #define xor_block_512(x,y)    _mm512_xor_si512(x,y)
    #define xor_block_256(x,y)    _mm256_xor_si256(x,y)
    #define zero_block_512()      _mm512_setzero_si512()
    #define zero_block_256()      _mm256_setzero_si256()
    #define zero_block()          _mm_setzero_si128()
    #define unequal_blocks(x,y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
	#if __SSSE3__ || USE_AES_NI
    #include <tmmintrin.h>              /* SSSE3 instructions              */
    #define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))
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

#if (OCB_KEY_LEN == 0)
	typedef struct { __m128i rd_key[15]; int rounds; } AES_KEY;
	#define ROUNDS(ctx) ((ctx)->rounds)
#else
	typedef struct { __m128i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY;
    typedef struct { __m512i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY_512;
    typedef struct { __m256i rd_key[7+OCB_KEY_LEN/4]; } AES_KEY_256;
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
static AES_KEY_256 AES_cast_128_to_256_key2(AES_KEY *key)
{
    union {block oa128[2]; block256 oa256;} oa;
    AES_KEY_256 temporal;
    for(int i = 0; i< 11; i++ ){
        oa.oa128[0] = key->rd_key[i];
        oa.oa128[1] = key->rd_key[i];
        // oa.oa128[2] = key->rd_key[i];
        // oa.oa128[3] = key->rd_key[i];
        temporal.rd_key[i]=oa.oa256;
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
	    blks[i] =_mm512_xor_si512(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm512_aesenc_epi128(blks[i], sched[j]);
    for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_aesenclast_epi128(blks[i], sched[j]);
}

static inline void AES_ecb_encrypt_blks_256(block256 *blks, unsigned nblks, AES_KEY_256 *key) {
    unsigned i,j,rnds=ROUNDS(key);
	const __m256i *sched = ((__m256i *)(key->rd_key));
    for (i=0; i<nblks; ++i)
	    blks[i] =_mm256_xor_si256(blks[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm256_aesenc_epi128(blks[i], sched[j]);
    for (i=0; i<nblks; ++i)
	    blks[i] =_mm256_aesenclast_epi128(blks[i], sched[j]);
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

int ae_init(ae_ctx *ctx, const void *key, int key_len, int nonce_len, int tag_len)
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



    /* Zero things that need zeroing */
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;

    /* Compute key-dependent values */
    AES_encrypt((unsigned char *)&ctx->cached_Top,
                            (unsigned char *)&ctx->Lstar, &ctx->encrypt_key);

	tmp_blk = swap_if_le(ctx->Lstar);
    tmp_blk = double_block(tmp_blk);
    ctx->Ldollar = swap_if_le(tmp_blk);
    tmp_blk = double_block(tmp_blk);
    ctx->L[0] = swap_if_le(tmp_blk);
    for (i = 1; i < L_TABLE_SZ; i++) {
		tmp_blk = double_block(tmp_blk);
    	ctx->L[i] = swap_if_le(tmp_blk);
    }


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
	const union { unsigned x; unsigned char endian; } little = { 1 };
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
	unsigned idx;
	uint32_t tagadd;

	/* Replace cached nonce Top if needed */
    #if (OCB_TAG_LEN > 0)
        if (little.endian)
            tmp.u32[0] = 0x01000000 + ((OCB_TAG_LEN * 8 % 128) << 1);
        else
            tmp.u32[0] = 0x00000001 + ((OCB_TAG_LEN * 8 % 128) << 25);
    #else
        if (little.endian)
            tmp.u32[0] = 0x01000000 + ((ctx->tag_len * 8 % 128) << 1);
        else
            tmp.u32[0] = 0x00000001 + ((ctx->tag_len * 8 % 128) << 25);
    #endif


	tmp.u32[1] = ((uint32_t *)nonce)[0];
	tmp.u32[2] = ((uint32_t *)nonce)[1];
	tmp.u32[3] = ((uint32_t *)nonce)[2];
	idx = (unsigned)(tmp.u8[15] & 0x3f);   /* Get low 6 bits of nonce  */
	tmp.u8[15] = tmp.u8[15] & 0xc0;        /* Zero low 6 bits of nonce */


	if ( unequal_blocks(tmp.bl,ctx->cached_Top) )   { /* Cached?       */

		ctx->cached_Top = tmp.bl;          /* Update cache, KtopStr    */
		AES_encrypt(tmp.u8, (unsigned char *)&ctx->KtopStr, &ctx->encrypt_key);
		if (little.endian) {               /* Make Register Correct    */
			ctx->KtopStr[0] = bswap64(ctx->KtopStr[0]);
			ctx->KtopStr[1] = bswap64(ctx->KtopStr[1]);
		}
		ctx->KtopStr[2] = ctx->KtopStr[0] ^
						 (ctx->KtopStr[0] << 8) ^ (ctx->KtopStr[1] >> 56);
	}
	return gen_offset(ctx->KtopStr, idx);
}

static void process_ad(ae_ctx *ctx, const void *ad, int ad_len, int final)
{
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    block ad_offset, ad_checksum;
    const block *  adp = (block *)ad;
	unsigned i,k,tz,remaining;

    ad_offset = ctx->ad_offset;
    ad_checksum = ctx->ad_checksum;
    i = ad_len/(BPI*16);
	if (i) {
		unsigned ad_block_num = ctx->ad_blocks_processed;
		do {
			block ta[BPI], oa[BPI];
			ad_block_num += BPI;
			tz = ntz(ad_block_num);
			oa[0] = xor_block(ad_offset, ctx->L[0]);
			ta[0] = xor_block(oa[0], adp[0]);
			oa[1] = xor_block(oa[0], ctx->L[1]);
			ta[1] = xor_block(oa[1], adp[1]);
			oa[2] = xor_block(ad_offset, ctx->L[1]);
			ta[2] = xor_block(oa[2], adp[2]);
			#if BPI == 4
				ad_offset = xor_block(oa[2], getL(ctx, tz));
				ta[3] = xor_block(ad_offset, adp[3]);
			#elif BPI == 8
				oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(oa[3], adp[3]);
				oa[4] = xor_block(oa[1], ctx->L[2]);
				ta[4] = xor_block(oa[4], adp[4]);
				oa[5] = xor_block(oa[0], ctx->L[2]);
				ta[5] = xor_block(oa[5], adp[5]);
				oa[6] = xor_block(ad_offset, ctx->L[2]);
				ta[6] = xor_block(oa[6], adp[6]);
				ad_offset = xor_block(oa[6], getL(ctx, tz));
				ta[7] = xor_block(ad_offset, adp[7]);
			#endif

			AES_ecb_encrypt_blks(ta,BPI,&ctx->encrypt_key);
			ad_checksum = xor_block(ad_checksum, ta[0]);
			ad_checksum = xor_block(ad_checksum, ta[1]);
			ad_checksum = xor_block(ad_checksum, ta[2]);
			ad_checksum = xor_block(ad_checksum, ta[3]);
			#if (BPI == 8)
			ad_checksum = xor_block(ad_checksum, ta[4]);
			ad_checksum = xor_block(ad_checksum, ta[5]);
			ad_checksum = xor_block(ad_checksum, ta[6]);
			ad_checksum = xor_block(ad_checksum, ta[7]);
			#endif
			adp += BPI;
		} while (--i);
		ctx->ad_blocks_processed = ad_block_num;
		ctx->ad_offset = ad_offset;
		ctx->ad_checksum = ad_checksum;
	}

    if (final) {
		block ta[BPI];

        /* Process remaining associated data, compute its tag contribution */
        remaining = ((unsigned)ad_len) % (BPI*16);
        if (remaining) {
			k=0;
			#if (BPI == 8)
			if (remaining >= 64) {

				tmp.bl = xor_block(ad_offset, ctx->L[0]);
				ta[0] = xor_block(tmp.bl, adp[0]);
				tmp.bl = xor_block(tmp.bl, ctx->L[1]);
				ta[1] = xor_block(tmp.bl, adp[1]);
				ad_offset = xor_block(ad_offset, ctx->L[1]);
				ta[2] = xor_block(ad_offset, adp[2]);
				ad_offset = xor_block(ad_offset, ctx->L[2]);
				ta[3] = xor_block(ad_offset, adp[3]);
				remaining -= 64;
				k=4;
			}
			#endif
			if (remaining >= 32) {
				ad_offset = xor_block(ad_offset, ctx->L[0]);
				ta[k] = xor_block(ad_offset, adp[k]);
				ad_offset = xor_block(ad_offset, getL(ctx, ntz(k+2)));
				ta[k+1] = xor_block(ad_offset, adp[k+1]);
				remaining -= 32;
				k+=2;
			}
			if (remaining >= 16) {
				ad_offset = xor_block(ad_offset, ctx->L[0]);
				ta[k] = xor_block(ad_offset, adp[k]);
				remaining = remaining - 16;
				++k;
			}
			if (remaining) {
				ad_offset = xor_block(ad_offset,ctx->Lstar);
				tmp.bl = zero_block();
				memcpy(tmp.u8, adp+k, remaining);
				tmp.u8[remaining] = (unsigned char)0x80u;
				ta[k] = xor_block(ad_offset, tmp.bl);
				++k;
			}


			AES_ecb_encrypt_blks(ta,k,&ctx->encrypt_key);



			switch (k) {
				#if (BPI == 8)
				case 8: ad_checksum = xor_block(ad_checksum, ta[7]);
				case 7: ad_checksum = xor_block(ad_checksum, ta[6]);
				case 6: ad_checksum = xor_block(ad_checksum, ta[5]);
				case 5: ad_checksum = xor_block(ad_checksum, ta[4]);
				#endif
				case 4: ad_checksum = xor_block(ad_checksum, ta[3]);
				case 3: ad_checksum = xor_block(ad_checksum, ta[2]);
				case 2: ad_checksum = xor_block(ad_checksum, ta[1]);
				case 1: ad_checksum = xor_block(ad_checksum, ta[0]);
			}
			ctx->ad_checksum = ad_checksum;



		}

	}
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
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;

	union { uint32_t u32[16]; uint8_t u8[64]; block512 bl; block bl128[4]; } tmp512;
    union {block256  checksum256; block checksum128[2];} checksum;
    unsigned temp_len = pt_len;
    block offset;
    unsigned i, k;
    // block       * ctp = (block *)ct;
    const block * ptp128 = (block *)pt;
    block256       * ctp = (block256 *)ct;
    const block256 * ptp = (block256 *)pt;

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
    

    AES_KEY_256 keys256 =  AES_cast_128_to_256_key2(&ctx->encrypt_key);

    offset = ctx->offset;
    checksum.checksum256  = zero_block_256();
    i = pt_len/(BPI*32);
    if (i) {

    	// block oa[BPI];
    	union {block oa128[2*BPI]; block256 oa256[BPI];} oa;
        block256 ta[BPI];
    	unsigned block_num = ctx->blocks_processed;
    	// oa[BPI-1] = offset;
		do {
            for(int j = 0; j<2*BPI; j=j+4){
                block_num += 4;
			    oa.oa128[j+0] = xor_block(offset, ctx->L[0]);
			    oa.oa128[j+1] = xor_block(oa.oa128[j+0], ctx->L[1]);
			    oa.oa128[j+2] = xor_block(oa.oa128[j+1], ctx->L[0]);
			    offset=oa.oa128[j+3] = xor_block(oa.oa128[j+2], getL(ctx, ntz(block_num)));
            }

			for(int j = 0; j<BPI; j++){
			    ta[j] = xor_block_256(oa.oa256[j], ptp[j]);
			    checksum.checksum256 = xor_block_256(checksum.checksum256, ptp[j]);
            }

			AES_ecb_encrypt_blks_256(ta,BPI,&keys256);

            for(int j = 0; j<BPI; j++){
                ctp[j]= xor_block_256(ta[j], oa.oa256[j]);
            }
            ptp += BPI;
			ctp += BPI;

		} while (--i);
    	ctx->offset = offset = oa.oa128[2*BPI-1];
	    ctx->blocks_processed = block_num;
		// ctx->checksum = checksum;
    }
    if (final) {
    	// union {block oa128[4*BPI]; block512 oa512[BPI];} oa;

		// block512 ta[BPI+1];

        // /* Process remaining plaintext and compute its tag contribution    */
        // unsigned remaining = ((unsigned)pt_len) % (BPI*64);
        // k = 0;                      /* How many blocks in ta[] need ECBing */
		// unsigned block_num = ctx->blocks_processed;

        // if (remaining) {


		// 	#if (BPI == 8)
		// 	if (remaining >= 256) {
		// 		for(int j = 0; j<16; j=j+4){
        //         	block_num += 4;
		// 	    	oa.oa128[j+0] = xor_block(offset, ctx->L[0]);
		// 	    	oa.oa128[j+1] = xor_block(oa.oa128[j+0], ctx->L[1]);
		// 	    	oa.oa128[j+2] = xor_block(oa.oa128[j+1], ctx->L[0]);
		// 	    	offset=oa.oa128[j+3] = xor_block(oa.oa128[j+2], getL(ctx, ntz(block_num)));

		// 		}
		// 		for(int j = 0; j<4; j++){
		// 	    	ta[j] = xor_block_512(oa.oa512[j], ptp[j]);
		// 	    	checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[j]);
        //     	}
		// 		remaining -= 256;
		// 		k = 4;

		// 	}
		// 	#endif
		// 	if (remaining >= 128) {
		// 		int l=k*4;
		// 		for(int j = 0; j<8; j=j+4){
        //         	block_num += 4;
		// 	    	oa.oa128[l+j+0] = xor_block(offset, ctx->L[0]);
		// 	    	oa.oa128[l+j+1] = xor_block(oa.oa128[l+j+0], ctx->L[1]);
		// 	    	oa.oa128[l+j+2] = xor_block(oa.oa128[l+j+1], ctx->L[0]);
		// 	    	offset=oa.oa128[j+3] = xor_block(oa.oa128[l+j+2], getL(ctx, ntz(block_num)));

		// 		}
		// 		for(int j = 0; j<2; j++){
		// 	    	ta[k+j] = xor_block_512(oa.oa512[k+j], ptp[k+j]);
		// 	    	checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k+j]);
        //     	}
		// 		remaining -= 128;
		// 		k += 2;
		// 	}
		// 	if (remaining >= 64) {
		// 		int l=k*4;
		// 		block_num += 4;
		// 		oa.oa128[l+0] = xor_block(offset, ctx->L[0]);
		// 		oa.oa128[l+1] = xor_block(oa.oa128[l+0], ctx->L[1]);
		// 		oa.oa128[l+2] = xor_block(oa.oa128[l+1], ctx->L[0]);
		// 		offset=oa.oa128[l+3] = xor_block(oa.oa128[l+2], getL(ctx, ntz(block_num)));

		// 		ta[k] = xor_block_512(oa.oa512[k], ptp[k]);
		// 	    checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k]);

				
		// 		remaining -= 64;
		// 		++k;
		// 	}
		// 	if (remaining) {

		// 		int l=k*4;
		// 		for(int j = 0; j<remaining/16; j++){
		// 			block_num ++;
		// 			offset=oa.oa128[l+j] = xor_block(offset, getL(ctx, ntz(block_num)));
		// 		}

		// 		// // union { uint32_t u32[16]; uint8_t u8[64]; block512 bl; } tmp512;
				
		// 		// union { uint32_t u32[16]; uint8_t u8[64]; block512 bl; block bl128[4]; } tmp512;


				
		// 		if(remaining%16==0){

		// 			ta[k] = xor_block_512(oa.oa512[k], ptp[k]);
		// 	    	checksum.checksum512 = xor_block_512(checksum.checksum512, ptp[k]);
		// 			remaining=remaining-remaining;

		// 		}
		// 		else{
		// 			tmp512.bl = zero_block_512();
		// 			memcpy(tmp512.u8, ptp+k, remaining);
		// 			tmp512.u8[remaining] = (unsigned char)0x80u;
		// 			int j=0;
		// 			for(j = 0; j<remaining/16; j++){
		// 				checksum.checksum128[j]=xor_block(checksum.checksum128[j],tmp512.bl128[j] );
		// 				tmp512.bl128[j] = xor_block(oa.oa128[l+j], tmp512.bl128[j] );
		// 			}
		// 			checksum.checksum128[0] = xor_block(checksum.checksum128[0], tmp512.bl128[remaining/16]);
		// 			tmp512.bl128[j] = offset = xor_block(offset,ctx->Lstar);
		// 			ta[k]=tmp512.bl;

		// 			memcpy(tmp512.u8, ptp+k, remaining);

		// 			for(j = 0; j<remaining/16; j++){
		// 				tmp512.bl128[j] =oa.oa128[l+j];
		// 			}
		// 		}

				

		// 		++k;
		// 	}
	
		// }

		// AES_ecb_encrypt_blks_512(ta,k,&keys512);

		// if (remaining) {
		// 	--k;
		// 	imprimiArreglo2(16,(unsigned char *)&ta[k]);
		// 	imprimiArreglo2(16,(unsigned char *)&tmp512.bl);

		// 	tmp512.bl = xor_block_512(tmp512.bl, ta[k]);
		// 	memcpy(ctp+k, tmp512.u8, remaining);
		// }
		// switch (k) {
		// 	#if (BPI == 8)
			
		// 	case 7: ctp[6] = xor_block_512(oa.oa512[6], ta[6]);
		// 	case 6: ctp[5] = xor_block_512(oa.oa512[5], ta[5]);
		// 	case 5: ctp[4] = xor_block_512(oa.oa512[4], ta[4]);
		// 	case 4: ctp[3] = xor_block_512(oa.oa512[3], ta[3]);
		// 	#endif
		// 	case 3: ctp[2] = xor_block_512(oa.oa512[2], ta[2]);
		// 	case 2: ctp[1] = xor_block_512(oa.oa512[1], ta[1]);
		// 	case 1: ctp[0] = xor_block_512(oa.oa512[0], ta[0]);
		// }

        __m128i checksumFinal  = _mm_setzero_si128();
        i=0;
        
        while( temp_len>0 && i<2){
            checksumFinal =  _mm_xor_si128( checksumFinal, checksum.checksum128[i]);
            temp_len = temp_len-16;
            i++;
        }

        offset = xor_block(offset, ctx->Ldollar);      /* Part of tag gen */
		checksumFinal = xor_block(offset, checksumFinal);           /* Part of tag gen */
		AES_ecb_encrypt_blks(&checksumFinal,1,&ctx->encrypt_key);
		// for(int i=0; i<k; i++){
        //     printf("------\n");
		// 	imprimiArreglo(16,(unsigned char *)&oa[i]);
		// }
		offset = xor_block(checksumFinal, ctx->ad_checksum);   /* Part of tag gen */
        /* Tag is placed at the correct location
         */
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
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    block offset, checksum;
    unsigned i, k;
    block       *ctp = (block *)ct;
    block       *ptp = (block *)pt;

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
    checksum  = ctx->checksum;
    i = ct_len/(BPI*16);
    if (i) {
    	block oa[BPI];
    	unsigned block_num = ctx->blocks_processed;
    	oa[BPI-1] = offset;
		do {
			block ta[BPI];
			block_num += BPI;
			oa[0] = xor_block(oa[BPI-1], ctx->L[0]);
			ta[0] = xor_block(oa[0], ctp[0]);
			oa[1] = xor_block(oa[0], ctx->L[1]);
			ta[1] = xor_block(oa[1], ctp[1]);
			oa[2] = xor_block(oa[1], ctx->L[0]);
			ta[2] = xor_block(oa[2], ctp[2]);
			#if BPI == 4
				oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
				ta[3] = xor_block(oa[3], ctp[3]);
			#elif BPI == 8
				oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(oa[3], ctp[3]);
				oa[4] = xor_block(oa[1], ctx->L[2]);
				ta[4] = xor_block(oa[4], ctp[4]);
				oa[5] = xor_block(oa[0], ctx->L[2]);
				ta[5] = xor_block(oa[5], ctp[5]);
				oa[6] = xor_block(oa[7], ctx->L[2]);
				ta[6] = xor_block(oa[6], ctp[6]);
				oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
				ta[7] = xor_block(oa[7], ctp[7]);
			#endif
			AES_ecb_decrypt_blks(ta,BPI,&ctx->decrypt_key);
			ptp[0] = xor_block(ta[0], oa[0]);
			checksum = xor_block(checksum, ptp[0]);
			ptp[1] = xor_block(ta[1], oa[1]);
			checksum = xor_block(checksum, ptp[1]);
			ptp[2] = xor_block(ta[2], oa[2]);
			checksum = xor_block(checksum, ptp[2]);
			ptp[3] = xor_block(ta[3], oa[3]);
			checksum = xor_block(checksum, ptp[3]);
			#if (BPI == 8)
			ptp[4] = xor_block(ta[4], oa[4]);
			checksum = xor_block(checksum, ptp[4]);
			ptp[5] = xor_block(ta[5], oa[5]);
			checksum = xor_block(checksum, ptp[5]);
			ptp[6] = xor_block(ta[6], oa[6]);
			checksum = xor_block(checksum, ptp[6]);
			ptp[7] = xor_block(ta[7], oa[7]);
			checksum = xor_block(checksum, ptp[7]);
			#endif
			ptp += BPI;
			ctp += BPI;
		} while (--i);
    	ctx->offset = offset = oa[BPI-1];
	    ctx->blocks_processed = block_num;
		ctx->checksum = checksum;
    }

    if (final) {
		block ta[BPI+1], oa[BPI];

        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)ct_len) % (BPI*16);
        k = 0;                      /* How many blocks in ta[] need ECBing */
        if (remaining) {
			#if (BPI == 8)
			if (remaining >= 64) {
				oa[0] = xor_block(offset, ctx->L[0]);
				ta[0] = xor_block(oa[0], ctp[0]);
				oa[1] = xor_block(oa[0], ctx->L[1]);
				ta[1] = xor_block(oa[1], ctp[1]);
				oa[2] = xor_block(oa[1], ctx->L[0]);
				ta[2] = xor_block(oa[2], ctp[2]);
				offset = oa[3] = xor_block(oa[2], ctx->L[2]);
				ta[3] = xor_block(offset, ctp[3]);
				remaining -= 64;
				k = 4;
			}
			#endif
			if (remaining >= 32) {
				oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block(oa[k], ctp[k]);
				offset = oa[k+1] = xor_block(oa[k], ctx->L[1]);
				ta[k+1] = xor_block(offset, ctp[k+1]);
				remaining -= 32;
				k+=2;
			}
			if (remaining >= 16) {
				// imprimiArreglo(16,(unsigned char *)&ctx->ad_checksum);
				// imprimiArreglo(16,(unsigned char *)&offset);
				// imprimiArreglo(16,(unsigned char *)&ctp[k]);

				offset = oa[k] = xor_block(offset, ctx->L[0]);
				ta[k] = xor_block(offset, ctp[k]);
				remaining -= 16;
				++k;
			}
			if (remaining) {
				block pad;
				offset = xor_block(offset,ctx->Lstar);
				AES_encrypt((unsigned char *)&offset, tmp.u8, &ctx->encrypt_key);
				pad = tmp.bl;
				memcpy(tmp.u8,ctp+k,remaining);
				tmp.bl = xor_block(tmp.bl, pad);



				tmp.u8[remaining] = (unsigned char)0x80u;


				memcpy(ptp+k, tmp.u8, remaining);
				checksum = xor_block(checksum, tmp.bl);
			}
		}



		AES_ecb_decrypt_blks(ta,k,&ctx->decrypt_key);
		switch (k) {
			#if (BPI == 8)
			case 7: ptp[6] = xor_block(ta[6], oa[6]);
				    checksum = xor_block(checksum, ptp[6]);
			case 6: ptp[5] = xor_block(ta[5], oa[5]);
				    checksum = xor_block(checksum, ptp[5]);
			case 5: ptp[4] = xor_block(ta[4], oa[4]);
				    checksum = xor_block(checksum, ptp[4]);
			case 4: ptp[3] = xor_block(ta[3], oa[3]);
				    checksum = xor_block(checksum, ptp[3]);
			#endif
			case 3: ptp[2] = xor_block(ta[2], oa[2]);
				    checksum = xor_block(checksum, ptp[2]);
			case 2: ptp[1] = xor_block(ta[1], oa[1]);
				    checksum = xor_block(checksum, ptp[1]);
			case 1: ptp[0] = xor_block(ta[0], oa[0]);
				    checksum = xor_block(checksum, ptp[0]);
		}

		/* Calculate expected tag */

        offset = xor_block(offset, ctx->Ldollar);
        tmp.bl = xor_block(offset, checksum);
		// imprimiArreglo(16, (unsigned char *)&offset);
		// imprimiArreglo(16,(unsigned char *)&checksum );

		AES_encrypt(tmp.u8, tmp.u8, &ctx->encrypt_key);
		tmp.bl = xor_block(tmp.bl, ctx->ad_checksum); /* Full tag */

		/* Compare with proposed tag, change ct_len if invalid */
		if ((OCB_TAG_LEN == 16) && tag) {
			if (unequal_blocks(tmp.bl, *(block *)tag))
				ct_len = AE_INVALID;
		} else {
			#if (OCB_TAG_LEN > 0)
				int len = OCB_TAG_LEN;
			#else
				int len = ctx->tag_len;
			#endif
			if (tag) {
				if (constant_time_memcmp(tag,tmp.u8,len) != 0)
					ct_len = AE_INVALID;
			} else {
				if (constant_time_memcmp((char *)ct + ct_len,tmp.u8,len) != 0)
					ct_len = AE_INVALID;
			}
		}
    }
    return ct_len;
 }

/* ----------------------------------------------------------------------- */
/* Simple test program                                                     */
/* ----------------------------------------------------------------------- */

#if 0

#include <stdio.h>
#include <time.h>

#if __GNUC__
	#define ALIGN(n) __attribute__ ((aligned(n)))
#elif _MSC_VER
	#define ALIGN(n) __declspec(align(n))
#else /* Not GNU/Microsoft: delete alignment uses.     */
	#define ALIGN(n)
#endif

static void pbuf(void *p, unsigned len, const void *s)
{
    unsigned i;
    if (s)
        printf("%s", (char *)s);
    for (i = 0; i < len; i++)
        printf("%02X", (unsigned)(((unsigned char *)p)[i]));
    printf("\n");
}

static void vectors(ae_ctx *ctx, int len)
{
    ALIGN(16) char pt[128];
    ALIGN(16) char ct[144];
    ALIGN(16) char nonce[] = {0,1,2,3,4,5,6,7,8,9,10,11};
    int i;
    for (i=0; i < 128; i++) pt[i] = i;
    i = ae_encrypt(ctx,nonce,pt,len,pt,len,ct,NULL,AE_FINALIZE);
    printf("P=%d,A=%d: ",len,len); pbuf(ct, i, NULL);
    i = ae_encrypt(ctx,nonce,pt,0,pt,len,ct,NULL,AE_FINALIZE);
    printf("P=%d,A=%d: ",0,len); pbuf(ct, i, NULL);
    i = ae_encrypt(ctx,nonce,pt,len,pt,0,ct,NULL,AE_FINALIZE);
    printf("P=%d,A=%d: ",len,0); pbuf(ct, i, NULL);
}

void validate()
{
    ALIGN(16) char pt[1024];
    ALIGN(16) char ct[1024];
    ALIGN(16) char tag[16];
    ALIGN(16) char nonce[12] = {0,};
    ALIGN(16) char key[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    ae_ctx ctx;
    char *val_buf, *next;
    int i, len;

    val_buf = (char *)malloc(22400 + 16);
    next = val_buf = (char *)(((size_t)val_buf + 16) & ~((size_t)15));

    if (0) {
		ae_init(&ctx, key, 16, 12, 16);
		/* pbuf(&ctx, sizeof(ctx), "CTX: "); */
		vectors(&ctx,0);
		vectors(&ctx,8);
		vectors(&ctx,16);
		vectors(&ctx,24);
		vectors(&ctx,32);
		vectors(&ctx,40);
    }

    memset(key,0,32);
    memset(pt,0,128);
    ae_init(&ctx, key, OCB_KEY_LEN, 12, OCB_TAG_LEN);

    /* RFC Vector test */
    for (i = 0; i < 128; i++) {
        int first = ((i/3)/(BPI*16))*(BPI*16);
        int second = first;
        int third = i - (first + second);

        nonce[11] = i;

        if (0) {
            ae_encrypt(&ctx,nonce,pt,i,pt,i,ct,NULL,AE_FINALIZE);
            memcpy(next,ct,(size_t)i+OCB_TAG_LEN);
            next = next+i+OCB_TAG_LEN;

            ae_encrypt(&ctx,nonce,pt,i,pt,0,ct,NULL,AE_FINALIZE);
            memcpy(next,ct,(size_t)i+OCB_TAG_LEN);
            next = next+i+OCB_TAG_LEN;

            ae_encrypt(&ctx,nonce,pt,0,pt,i,ct,NULL,AE_FINALIZE);
            memcpy(next,ct,OCB_TAG_LEN);
            next = next+OCB_TAG_LEN;
        } else {
            ae_encrypt(&ctx,nonce,pt,first,pt,first,ct,NULL,AE_PENDING);
            ae_encrypt(&ctx,NULL,pt+first,second,pt+first,second,ct+first,NULL,AE_PENDING);
            ae_encrypt(&ctx,NULL,pt+first+second,third,pt+first+second,third,ct+first+second,NULL,AE_FINALIZE);
            memcpy(next,ct,(size_t)i+OCB_TAG_LEN);
            next = next+i+OCB_TAG_LEN;

            ae_encrypt(&ctx,nonce,pt,first,pt,0,ct,NULL,AE_PENDING);
            ae_encrypt(&ctx,NULL,pt+first,second,pt,0,ct+first,NULL,AE_PENDING);
            ae_encrypt(&ctx,NULL,pt+first+second,third,pt,0,ct+first+second,NULL,AE_FINALIZE);
            memcpy(next,ct,(size_t)i+OCB_TAG_LEN);
            next = next+i+OCB_TAG_LEN;

            ae_encrypt(&ctx,nonce,pt,0,pt,first,ct,NULL,AE_PENDING);
            ae_encrypt(&ctx,NULL,pt,0,pt+first,second,ct,NULL,AE_PENDING);
            ae_encrypt(&ctx,NULL,pt,0,pt+first+second,third,ct,NULL,AE_FINALIZE);
            memcpy(next,ct,OCB_TAG_LEN);
            next = next+OCB_TAG_LEN;
        }

    }
    nonce[11] = 0;
    ae_encrypt(&ctx,nonce,NULL,0,val_buf,next-val_buf,ct,tag,AE_FINALIZE);
    pbuf(tag,OCB_TAG_LEN,0);


    /* Encrypt/Decrypt test */
    for (i = 0; i < 128; i++) {
        int first = ((i/3)/(BPI*16))*(BPI*16);
        int second = first;
        int third = i - (first + second);

        nonce[11] = i%128;

        if (1) {
            len = ae_encrypt(&ctx,nonce,val_buf,i,val_buf,i,ct,tag,AE_FINALIZE);
            len = ae_encrypt(&ctx,nonce,val_buf,i,val_buf,-1,ct,tag,AE_FINALIZE);
            len = ae_decrypt(&ctx,nonce,ct,len,val_buf,-1,pt,tag,AE_FINALIZE);
            if (len == -1) { printf("Authentication error: %d\n", i); return; }
            if (len != i) { printf("Length error: %d\n", i); return; }
            if (memcmp(val_buf,pt,i)) { printf("Decrypt error: %d\n", i); return; }
        } else {
            len = ae_encrypt(&ctx,nonce,val_buf,i,val_buf,i,ct,NULL,AE_FINALIZE);
            ae_decrypt(&ctx,nonce,ct,first,val_buf,first,pt,NULL,AE_PENDING);
            ae_decrypt(&ctx,NULL,ct+first,second,val_buf+first,second,pt+first,NULL,AE_PENDING);
            len = ae_decrypt(&ctx,NULL,ct+first+second,len-(first+second),val_buf+first+second,third,pt+first+second,NULL,AE_FINALIZE);
            if (len == -1) { printf("Authentication error: %d\n", i); return; }
            if (memcmp(val_buf,pt,i)) { printf("Decrypt error: %d\n", i); return; }
        }

    }
    printf("Decrypt: PASS\n");
}

int main()
{
    validate();
    return 0;
}
#endif

#if USE_AES_NI
char infoString[] = "OCB3 256 (AES-NI)";
#elif USE_REFERENCE_AES
char infoString[] = "OCB3 (Reference)";
#elif USE_OPENSSL_AES
char infoString[] = "OCB3 (OpenSSL)";
#endif