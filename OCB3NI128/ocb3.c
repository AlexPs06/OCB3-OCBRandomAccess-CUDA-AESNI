/*------------------------------------------------------------------------
/ OCB Version 3 Reference Code (Optimized C)     Last modified DD-MMM-YYYY
/-------------------------------------------------------------------------
/ Copyright (c) 2010 Ted Krovetz.
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
/ Comments are welcome: Ted Krovetz <tdk@acm.org> :: Dedicated to Laurel K
/------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* Usage requirements                                                      */
/* ----------------------------------------------------------------------- */

/* - When AE_PENDING is passed as the 'final' parameter of any function,
/    the length parameters must be a multiple of (BPI*16).
/  - When available, SSE or AltiVec registers are used to manipulate data.
/    So, when on machines with these facilities, all pointers passed to
/    any function should be 16-byte aligned.
/  - Plaintext and ciphertext pointers may be equal (ie, plaintext gets
/    encrypted in-place), but no other pair of pointers may be equal.      */

/* ----------------------------------------------------------------------- */
/* User configuration options                                              */
/* ----------------------------------------------------------------------- */

/* During encryption and decryption, various "L values" are required.
/  The L values can be precomputed during initialization (requiring extra
/  space in ae_ctx), generated as needed (slightly slowing encryption and
/  decryption), or some combination of the two. L_TABLE_SZ specifies how many
/  L values to precomute. L_TABLE_SZ must be at least 1. L_TABLE_SZ*16 bytes
/  are used for L values in ae_ctx. Plaintext and ciphertexts less than
/  2^(L_TABLE_SZ+4) bytes need no L values calculated dynamically.         */
#define L_TABLE_SZ                 64

/* Set L_TABLE_SZ_IS_ENOUGH non-zero iff you know that all plaintexts and
/  ciphertexts will be less than 2^(L_TABLE_SZ+4) bytes in length. This
/  results in better performance.                                          */
#define L_TABLE_SZ_IS_ENOUGH       1

/* This implementation has built-in support for multiple AES APIs. Set any
/  one of the following to non-zero to specify which to use. USE_AES_NI set
/  by itself only supports 128-bit keys. To use AES-NI with 192 or 256 bit
/  keys, set both USE_OPENSSL_AES and USE_AES_NI, in which case OpenSSL
/  handles key setup and AES-NI intrinsics are used for encryption.        */
#if !(USE_OPENSSL_AES || USE_OPENSSL_AES_NI || USE_KASPER_AES || USE_REFERENCE_AES || USE_AES_NI)
#define USE_OPENSSL_AES            0         /* http://openssl.org         */
#define USE_OPENSSL_AES_NI         0         /* http://openssl.org         */
#define USE_KASPER_AES             0         /* http://homes.esat.kuleuven.be/~ekasper/ */
#define USE_REFERENCE_AES          0         /* Google: rijndael-alg-fst.c */
#define USE_AES_NI                 1         /* Uses compiler's intrinsics */
#endif

/* MAX_KEY_BYTES specifies the maximum size key you intend to supply OCB, and
/  *must* be 16, 24, or 32. In *some* AES implementations it is possible to
/  limit internal key-schedule sizes, so keep this as small as possible.   */
#define MAX_KEY_BYTES             16

/* To eliminate the use of vector types, set the following non-zero        */
#define VECTORS_OFF                0

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

/* How to force specific alignment, request inline, restrict pointers      */
#if __GNUC__
	#define GCC_VERSION (__GNUC__ * 10 + __GNUC_MINOR__)
	#define ALIGN(n) __attribute__ ((aligned(n)))
	#define inline __inline__
	#define restrict __restrict__
#elif _MSC_VER
	#define ALIGN(n) __declspec(align(n))
	#define inline __inline
	#define restrict __restrict
#elif __STDC_VERSION__ >= 199901L   /* C99: delete align, keep others      */
	#define ALIGN(n)
#else /* Not GNU/Microsoft/C99: delete alignment/inline/restrict uses.     */
	#define ALIGN(n)
	#define inline
	#define restrict
#endif

/* How to endian reverse a uint64_t                                        */
#if _MSC_VER
	#include <intrin.h>
	#pragma intrinsic(_byteswap_uint64)
	#define bswap64(x) _byteswap_uint64(x)
#elif __GNUC__ && (GCC_VERSION >= 43)
	#define bswap64(x) __builtin_bswap64(x)
#else
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
#endif

/* How to count trailing zeros                                             */
#if _MSC_VER
	#include <intrin.h>
	#pragma intrinsic(_BitScanForward)
	static inline unsigned ntz(unsigned x) {_BitScanForward(&x, x);return x;}
#elif __GNUC__ && (GCC_VERSION >= 34) && ! __sparc__
	#define ntz(x) __builtin_ctz((unsigned)(x))
#elif (L_TABLE_SZ <= 8) && (L_TABLE_SZ_IS_ENOUGH)
	static inline unsigned ntz(unsigned x) {
		static const unsigned char tz_table[] = {0,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,7,
		2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,6,2,3,2,4,2,3,2,5,2,3,2,4,2,3,2,8};
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

/* ----------------------------------------------------------------------- */
/* Derived configuration options - Adjust as needed                        */
/* ----------------------------------------------------------------------- */

/* These determine whether vectors should be used.                         */
#define USE_SSE2    ((__SSE2__ || (_M_IX86_FP>=2) || _M_X64) && !VECTORS_OFF)
#define USE_ALTIVEC (__ALTIVEC__ && !VECTORS_OFF)
#define USE_NEON    (__ARM_NEON__ && !VECTORS_OFF)

/* These determine how to allocate 16-byte aligned vectors, if needed.     */
#define USE_MM_MALLOC      (USE_SSE2 && !(_M_X64 || __amd64__))
#define USE_POSIX_MEMALIGN (USE_ALTIVEC && __GLIBC__ && !__PPC64__)

/* ----------------------------------------------------------------------- */
/* Define blocks and operations -- Patch if incorrect on your compiler.    */
/* ----------------------------------------------------------------------- */

#if USE_SSE2
    #include <xmmintrin.h>              /* SSE instructions and _mm_malloc */
    #include <emmintrin.h>              /* SSE2 instructions               */
    typedef ALIGN(16) __m128i block;
    #define xor_block(x,y)        _mm_xor_si128(x,y)
    #define zero_block()          _mm_setzero_si128()
    #define unequal_blocks(x,y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
	#if __SSSE3__
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
		#if __SSSE3__
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
#elif USE_ALTIVEC
    #include <altivec.h>
    typedef ALIGN(16) vector unsigned block;
    #define xor_block(x,y)         vec_xor(x,y)
    #define zero_block()           vec_splat_u32(0)
    #define unequal_blocks(x,y)    vec_any_ne(x,y)
    #define swap_if_le(b)          (b)
	#if __PPC64__
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		union {uint64_t u64[2]; block bl;} rval;
		rval.u64[0] = (KtopStr[0] << bot) | (KtopStr[1] >> (64-bot));
		rval.u64[1] = (KtopStr[1] << bot) | (KtopStr[2] >> (64-bot));
        return rval.bl;
	}
	#else
	/* Special handling: Shifts are mod 32, and no 64-bit types */
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		const vector unsigned k32 = {32,32,32,32};
		vector unsigned hi = *(vector unsigned *)(KtopStr+0);
		vector unsigned lo = *(vector unsigned *)(KtopStr+2);
		vector unsigned bot_vec;
		if (bot < 32) {
			lo = vec_sld(hi,lo,4);
		} else {
			vector unsigned t = vec_sld(hi,lo,4);
			lo = vec_sld(hi,lo,8);
			hi = t;
			bot = bot - 32;
		}
		if (bot == 0) return hi;
		*(unsigned *)&bot_vec = bot;
		vector unsigned lshift = vec_splat(bot_vec,0);
		vector unsigned rshift = vec_sub(k32,lshift);
		hi = vec_sl(hi,lshift);
		lo = vec_sr(lo,rshift);
		return vec_xor(hi,lo);
	}
	#endif
	static inline block double_block(block b) {
		const vector unsigned char mask = {135,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		const vector unsigned char perm = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0};
		const vector unsigned char shift7  = vec_splat_u8(7);
		const vector unsigned char shift1  = vec_splat_u8(1);
		vector unsigned char c = (vector unsigned char)b;
		vector unsigned char t = vec_sra(c,shift7);
		t = vec_and(t,mask);
		t = vec_perm(t,t,perm);
		c = vec_sl(c,shift1);
		return (block)vec_xor(c,t);
	}
#elif USE_NEON
    #include <arm_neon.h>
    typedef ALIGN(16) int8x16_t block;      /* Yay! Endian-neutral reads! */
    #define xor_block(x,y)             veorq_s8(x,y)
    #define zero_block()               vdupq_n_s8(0)
    static inline int unequal_blocks(block a, block b) {
		int64x2_t t=veorq_s64((int64x2_t)a,(int64x2_t)b);
		return (vgetq_lane_s64(t,0)|vgetq_lane_s64(t,1))!=0;
    }
    #define swap_if_le(b)          (b)  /* Using endian-neutral int8x16_t */
	/* KtopStr is reg correct by 64 bits, return mem correct */
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
		const union { unsigned x; unsigned char endian; } little = { 1 };
		const int64x2_t k64 = {-64,-64};
		uint64x2_t hi = *(uint64x2_t *)(KtopStr+0);   /* hi = A B */
		uint64x2_t lo = *(uint64x2_t *)(KtopStr+1);   /* hi = B C */
		int64x2_t ls = vdupq_n_s64(bot);
		int64x2_t rs = vqaddq_s64(k64,ls);
		block rval = (block)veorq_u64(vshlq_u64(hi,ls),vshlq_u64(lo,rs));
		if (little.endian)
			rval = vrev64q_s8(rval);
		return rval;
	}
	static inline block double_block(block b)
	{
		const block mask = {135,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
		block tmp = vshrq_n_s8(b,7);
		tmp = vandq_s8(tmp, mask);
		tmp = vextq_s8(tmp, tmp, 1);  /* Rotate high byte to end */
		b = vshlq_n_s8(b,1);
		return veorq_s8(tmp,b);
	}
#else
    typedef struct { uint64_t l,r; } block;
    static inline block xor_block(block x, block y) {
    	x.l^=y.l; x.r^=y.r; return x;
    }
    static inline block zero_block(void) { const block t = {0,0}; return t; }
    #define unequal_blocks(x, y)         ((((x).l^(y).l)|((x).r^(y).r)) != 0)
    static inline block swap_if_le(block b) {
		const union { unsigned x; unsigned char endian; } little = { 1 };
    	if (little.endian) {
    		block r;
    		r.l = bswap64(b.l);
    		r.r = bswap64(b.r);
    		return r;
    	} else
    		return b;
    }
	
	/* KtopStr is reg correct by 64 bits, return mem correct */
	block gen_offset(uint64_t KtopStr[3], unsigned bot) {
        block rval;
        if (bot != 0) {
			rval.l = (KtopStr[0] << bot) | (KtopStr[1] >> (64-bot));
			rval.r = (KtopStr[1] << bot) | (KtopStr[2] >> (64-bot));
		} else {
			rval.l = KtopStr[0];
			rval.r = KtopStr[1];
		}
        return swap_if_le(rval);
	}

	#if __GNUC__ && __arm__
	static inline block double_block(block b) {
		__asm__ ("adds %1,%1,%1\n\t"
				 "adcs %H1,%H1,%H1\n\t"
				 "adcs %0,%0,%0\n\t"
				 "adcs %H0,%H0,%H0\n\t"
				 "eorcs %1,%1,#135"
		: "+r"(b.l), "+r"(b.r) : : "cc");
		return b;
	}
	#else
	static inline block double_block(block b) {
		uint64_t t = (uint64_t)((int64_t)b.l >> 63);
		b.l = (b.l + b.l) ^ (b.r >> 63);
		b.r = (b.r + b.r) ^ (t & 135);
		return b;
	}
	#endif
    
#endif

/* Sometimes it is useful to view a block as an array of other types.
/  Doing so is technically undefined, but well supported in compilers.     */
typedef union {
	uint64_t u64[2]; uint32_t u32[4]; uint8_t u8[16]; block bl;
} block_multiview;

/* ----------------------------------------------------------------------- */
/* AES - Code uses OpenSSL API. Other implementations get mapped to it.    */
/* ----------------------------------------------------------------------- */

/*---------------*/
#if USE_OPENSSL_AES
/*---------------*/

#include <openssl/aes.h>                            /* http://openssl.org/ */

/* How to ECB encrypt an array of blocks, in place                         */
static inline void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
	while (nblks) {
		--nblks;
		AES_encrypt((unsigned char *)(blks+nblks), (unsigned char *)(blks+nblks), key);
	}
}

static inline void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
	while (nblks) {
		--nblks;
		AES_decrypt((unsigned char *)(blks+nblks), (unsigned char *)(blks+nblks), key);
	}
}

#define BPI 4  /* Number of blocks in buffer per ECB call */

/*-----------------*/
#elif USE_OPENSSL_AES_NI
/*-----------------*/

/*
#define AES_MAXNR (6 + MAX_KEY_BYTES/4)
typedef struct {
    uint32_t rd_key[4 *(AES_MAXNR + 1)];
    int rounds;
} AES_KEY;
*/

#include <openssl/aes.h>

int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
			      AES_KEY *key);
int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
			      AES_KEY *key);

void aesni_encrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);
void aesni_decrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);

void aesni_ecb_encrypt(const unsigned char *in,
			   unsigned char *out,
			   size_t length,
			   const AES_KEY *key,
			   int enc);

#define AES_set_encrypt_key aesni_set_encrypt_key
#define AES_set_decrypt_key aesni_set_decrypt_key
#define AES_encrypt         aesni_encrypt
#define AES_decrypt         aesni_decrypt

#define AES_ecb_encrypt_blks(blks, nblks, key) \
        aesni_ecb_encrypt((unsigned char *)(blks),(unsigned char *)(blks),(nblks)*16,key,1)
#define AES_ecb_decrypt_blks(blks, nblks, key) \
        aesni_ecb_encrypt((unsigned char *)(blks),(unsigned char *)(blks),(nblks)*16,key,0)

#define BPI 4  /* Number of blocks in buffer per ECB call */

/*-----------------*/
#elif USE_KASPER_AES
/*-----------------*/

typedef struct { ALIGN(16) uint32_t bs_key[11][32]; } AES_KEY;

void kasper_keysetup(AES_KEY *key, const unsigned char *userKey);
void kasper_ecb_encrypt(const AES_KEY* key,const unsigned char* in, 
                        unsigned char* out, uint32_t blks);

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {
	(void)bits;
	kasper_keysetup(key, userKey);
	return 0;
}

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	ALIGN(16) unsigned char buf[8*16];
	kasper_ecb_encrypt(key, in, buf, 8);
	*(block *)out = *(block *)buf;
}

/* The following encrypts ceil(nblks/8)*8 blocks */
#define AES_ecb_encrypt_blks(blks, nblks, key) kasper_ecb_encrypt \
    (key, (unsigned char *)(blks), (unsigned char *)(blks), nblks)

/* Kasper's AES was designed for CTR, so lacks AES decryption. So, to make
/  things compile, we map decryption to encryption.                        */
#define AES_set_decrypt_key     AES_set_encrypt_key
#define AES_ecb_decrypt_blks    AES_ecb_encrypt_blks
#define AES_decrypt             AES_encrypt

#define BPI 8  /* Number of blocks in buffer per ECB call */

/*-------------------*/
#elif USE_REFERENCE_AES
/*-------------------*/

#include "rijndael-alg-fst.h"              /* Barreto's Public-Domain Code */
typedef struct { uint32_t rd_key[MAX_KEY_BYTES+28]; int rounds; } AES_KEY;
#define AES_encrypt(x,y,z)    rijndaelEncrypt((z)->rd_key, (z)->rounds, x, y)
#define AES_decrypt(x,y,z)    rijndaelDecrypt((z)->rd_key, (z)->rounds, x, y)
#define AES_set_encrypt_key(x, y, z) \
 do {rijndaelKeySetupEnc((z)->rd_key, x, y); (z)->rounds = y/32+6;} while (0)
#define AES_set_decrypt_key(x, y, z) \
 do {rijndaelKeySetupDec((z)->rd_key, x, y); (z)->rounds = y/32+6;} while (0)

static void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
	while (nblks) {
		--nblks;
		AES_encrypt((unsigned char *)(blks+nblks), (unsigned char *)(blks+nblks), key);
	}
}

 void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
	while (nblks) {
		--nblks;
		AES_decrypt((unsigned char *)(blks+nblks), (unsigned char *)(blks+nblks), key);
	}
}

#define BPI 4  /* Number of blocks in buffer per ECB call */

/*----------*/
#elif USE_AES_NI
/*----------*/

/* This implemenation only works with 128-bit keys */
#include <wmmintrin.h>

typedef struct { __m128i rd_key[7+MAX_KEY_BYTES/4]; } AES_KEY;
static __m128i assist128(__m128i a, __m128i b)
{
    __m128i tmp = _mm_slli_si128 (a, 0x04);
    a = _mm_xor_si128 (a, tmp);
    tmp = _mm_slli_si128 (tmp, 0x04);
    a = _mm_xor_si128 (_mm_xor_si128 (a, tmp), _mm_slli_si128 (tmp, 0x04));
    return _mm_xor_si128 (a, _mm_shuffle_epi32 (b ,0xff));
}
static void AES_set_encrypt_key(const unsigned char *userKey,
                                const int bits, AES_KEY *key)
{
    __m128i *sched = key->rd_key;
    (void)bits; /* Supress "unused" warning */
    sched[ 0] = _mm_loadu_si128((__m128i*)userKey);
    sched[ 1] = assist128(sched[0], _mm_aeskeygenassist_si128(sched[0],0x1));
    sched[ 2] = assist128(sched[1], _mm_aeskeygenassist_si128(sched[1],0x2));
    sched[ 3] = assist128(sched[2], _mm_aeskeygenassist_si128(sched[2],0x4));
    sched[ 4] = assist128(sched[3], _mm_aeskeygenassist_si128(sched[3],0x8));
    sched[ 5] = assist128(sched[4], _mm_aeskeygenassist_si128(sched[4],0x10));
    sched[ 6] = assist128(sched[5], _mm_aeskeygenassist_si128(sched[5],0x20));
    sched[ 7] = assist128(sched[6], _mm_aeskeygenassist_si128(sched[6],0x40));
    sched[ 8] = assist128(sched[7], _mm_aeskeygenassist_si128(sched[7],0x80));
    sched[ 9] = assist128(sched[8], _mm_aeskeygenassist_si128(sched[8],0x1b));
    sched[10] = assist128(sched[9], _mm_aeskeygenassist_si128(sched[9],0x36));
}
static void AES_NI_set_decrypt_key(__m128i *dkey, const __m128i *ekey)
{
    int i;
    dkey[10] = ekey[0];
    for (i = 1; i <= 9; i++) dkey[10-i] = _mm_aesimc_si128(ekey[i]);
    dkey[0] = ekey[10];
}

static inline void AES_encrypt(const unsigned char *in,
                        unsigned char *out, const AES_KEY *key)
{
	int j;
	const __m128i *sched = ((__m128i *)(key->rd_key));
	__m128i tmp = _mm_load_si128 ((__m128i*)in);
    // imprimiArreglo2(16,(unsigned char *)&tmp[0]);

	tmp = _mm_xor_si128 (tmp,sched[0]);
	
	for (j=1; j<10; j++)  tmp = _mm_aesenc_si128 (tmp,sched[j]);

    // imprimiArreglo2(16,(unsigned char *)&tmp[0]);

	tmp = _mm_aesenclast_si128 (tmp,sched[j]);

    // imprimiArreglo2(16,(unsigned char *)&sched[j]);

	_mm_store_si128 ((__m128i*)out,tmp);

}
static inline void AES_decrypt(const unsigned char *in,
                        unsigned char *out, const AES_KEY *key)
{
	int j;
	const __m128i *sched = ((__m128i *)(key->rd_key));
	__m128i tmp = _mm_load_si128 ((__m128i*)in);
	tmp = _mm_xor_si128 (tmp,sched[0]);
	for (j=1; j<10; j++)  tmp = _mm_aesdec_si128 (tmp,sched[j]);
	tmp = _mm_aesdeclast_si128 (tmp,sched[j]);
	_mm_store_si128 ((__m128i*)out,tmp);
}

 static inline void AES_ecb_encrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
    unsigned i,j;
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_xor_si128(blks[i], ((block*)(key->rd_key))[0]);
	for(j=1; j<10; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm_aesenc_si128(blks[i], ((block*)(key->rd_key))[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm_aesenclast_si128(blks[i], ((block*)(key->rd_key))[j]);
}

void AES_ecb_decrypt_blks(block *blks, unsigned nblks, AES_KEY *key) {
    (void)blks; (void)nblks; (void)key;
}

#define BPI 8  /* Number of blocks in buffer per ECB call */

#endif

/* ----------------------------------------------------------------------- */
/* Define OCB context structure.                                           */
/* ----------------------------------------------------------------------- */

/*------------------------------------------------------------------------
/ Each item in the OCB context is stored either "memory correct" or
/ "register correct". On big-endian machines, this is identical. On
/ little-endian machines, one must choose whether the byte-string
/ is in the corrct order when it resides in memory or in registers.
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
    unsigned ad_blocks_processed;
    unsigned blocks_processed;
    ALIGN(16) AES_KEY encrypt_key;
    ALIGN(16) AES_KEY decrypt_key;
};

/* ----------------------------------------------------------------------- */
/* L table lookup (or on-the-fly generation)                         */
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

/* Some systems do not 16-byte-align dynamic allocations involving 16-byte
/  vectors. Adjust the following if your system is one of these            */

ae_ctx* ae_allocate(void *misc)
{ 
	void *p;
	(void) misc;                     /* misc unused in this implementation */
	#if USE_MM_MALLOC
    	p = _mm_malloc(sizeof(ae_ctx),16); 
	#elif USE_POSIX_MEMALIGN
		if (posix_memalign(&p,16,sizeof(ae_ctx)) != 0) p = NULL;
	#else
		p = malloc(sizeof(ae_ctx)); 
	#endif
	return (ae_ctx *)p;
}

void ae_free(ae_ctx *ctx)
{
	#if USE_MM_MALLOC
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
    
    if ((nonce_len != 12) || (tag_len != 16))
    	return AE_NOT_SUPPORTED;
    
    /* Initialize encryption & decryption keys */
    AES_set_encrypt_key((unsigned char *)key, key_len*8, &ctx->encrypt_key);
    #if !USE_OPENSSL_AES && USE_AES_NI
    AES_NI_set_decrypt_key(ctx->decrypt_key.rd_key,ctx->encrypt_key.rd_key);
    #else
    AES_set_decrypt_key((unsigned char *)key, (int)(key_len*8), &ctx->decrypt_key);
    #endif
    
    /* Zero things that need zeroing */
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;
    
	// unsigned char block[16] ={
	//  0x00, 0x01, 0x02, 0x03, 
    //  0x04, 0x05, 0x06, 0x07, 
    //  0x08, 0x09, 0x0a, 0x0b, 
    //  0x0c, 0x0d, 0x0e, 0x0f, 
	// };

    /* Compute key-dependent values */
    AES_encrypt((unsigned char *)&ctx->cached_Top,(unsigned char *)&ctx->Lstar, &ctx->encrypt_key);
    // AES_encrypt(block,(unsigned char *)&ctx->Lstar, &ctx->encrypt_key);
    // imprimiArreglo2(16,(unsigned char *)&ctx->Lstar[0]);
    // exit(1);
	
	tmp_blk = swap_if_le(ctx->Lstar);
    tmp_blk = double_block(tmp_blk);
    ctx->Ldollar = swap_if_le(tmp_blk);
    tmp_blk = double_block(tmp_blk);
    ctx->L[0] = swap_if_le(tmp_blk);
    for (i = 1; i < L_TABLE_SZ; i++) {
		tmp_blk = double_block(tmp_blk);
    	ctx->L[i] = swap_if_le(tmp_blk);
    }

    return AE_SUCCESS;
}
void imprimiArreglo2(int tam, unsigned char *in )
{

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
    }
    printf("\n" );

}
/* ----------------------------------------------------------------------- */

int ae_encrypt(ae_ctx     *  ctx,
               const void *  nonce,
               const void *pt,
               int         pt_len,
               const void *ad,
               int         ad_len,
               void       *ct,
               void       *  tag,
               int         final)
{
	const union { unsigned x; unsigned char endian; } little = { 1 };
	block_multiview tmp;
    block ad_offset, offset, ad_checksum, checksum, oa[BPI];
    unsigned block_num, ad_block_num, remaining, idx, i, k;
    block       *  ctp = (block *)ct;
    const block *  ptp = (block *)pt;
    const block *  adp = (block *)ad;

	/* When nonce is non-null we know that this is the start of a new message.
	 * If so, update cached AES if needed and initialize offsets/checksums.
	 */
    if (nonce) { /* Indicates start of new message */
		
        /* Replace cached nonce Top if needed */
		tmp.u32[0] = (little.endian?0x01000000:0x00000001);
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
                
        /* Initialize offset and checksum */
        offset = gen_offset(ctx->KtopStr, idx);

        ad_offset = ad_checksum = checksum = zero_block();
        ad_block_num = block_num = 0;

    } else {
        /* If not a new message, restore values from ctx */
        offset       = ctx->offset;
        checksum     = ctx->checksum;
    	block_num    = ctx->blocks_processed;
        ad_offset    = ctx->ad_offset;
        ad_checksum  = ctx->ad_checksum;
        ad_block_num = ctx->ad_blocks_processed;
    }

	/* Handle associated data BPI blocks at a time.
	 */
    for (i = (unsigned)ad_len/(BPI*16); i != 0; --i) {
		block ta[BPI], oa[BPI];
		ad_block_num += BPI;
		unsigned tz = ntz(ad_block_num);
		oa[0] = xor_block(ad_offset, getL(ctx, 0));
		ta[0] = xor_block(oa[0], adp[0]);
		oa[1] = xor_block(oa[0], getL(ctx, 1));
		ta[1] = xor_block(oa[1], adp[1]);
		oa[2] = xor_block(ad_offset, getL(ctx, 1));
		ta[2] = xor_block(oa[2], adp[2]);
    	#if BPI == 4
			ad_offset = xor_block(oa[2], getL(ctx, tz));
			ta[3] = xor_block(ad_offset, adp[3]);
    	#elif BPI == 8
			oa[3] = xor_block(oa[2], getL(ctx, 2));
			ta[3] = xor_block(oa[3], adp[3]);
			oa[4] = xor_block(oa[1], getL(ctx, 2));
			ta[4] = xor_block(oa[4], adp[4]);
			oa[5] = xor_block(oa[0], getL(ctx, 2));
			ta[5] = xor_block(oa[5], adp[5]);
			oa[6] = xor_block(ad_offset, getL(ctx, 2));
			ta[6] = xor_block(oa[6], adp[6]);
			ad_offset = xor_block(oa[6], getL(ctx, tz));
			ta[7] = xor_block(ad_offset, adp[7]);
    	#endif
		
		

    	AES_ecb_encrypt_blks(ta,BPI,&ctx->encrypt_key);
		for (k=0; k<BPI; k+=4) {
			ad_checksum = xor_block(ad_checksum, ta[k]);
			ad_checksum = xor_block(ad_checksum, ta[k+1]);
			ad_checksum = xor_block(ad_checksum, ta[k+2]);
			ad_checksum = xor_block(ad_checksum, ta[k+3]);
		}
        adp += BPI;
    }

	/* Encrypt plaintext data BPI blocks at a time.
	 */
    oa[BPI-1] = offset;
    for (i = (unsigned)pt_len/(BPI*16); i != 0; --i) {
		block ta[BPI];
		block_num += BPI;
		oa[0] = xor_block(oa[BPI-1], getL(ctx, 0));
		ta[0] = xor_block(oa[0], ptp[0]);
		checksum = xor_block(checksum, ptp[0]);
		oa[1] = xor_block(oa[0], getL(ctx, 1));
		ta[1] = xor_block(oa[1], ptp[1]);
		checksum = xor_block(checksum, ptp[1]);
		oa[2] = xor_block(oa[1], getL(ctx, 0));
		ta[2] = xor_block(oa[2], ptp[2]);
		checksum = xor_block(checksum, ptp[2]);
    	#if BPI == 4
			oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
			ta[3] = xor_block(oa[3], ptp[3]);
			checksum = xor_block(checksum, ptp[3]);
    	#elif BPI == 8
			oa[3] = xor_block(oa[2], getL(ctx, 2));
			ta[3] = xor_block(oa[3], ptp[3]);
			checksum = xor_block(checksum, ptp[3]);
			oa[4] = xor_block(oa[1], getL(ctx, 2));
			ta[4] = xor_block(oa[4], ptp[4]);
			checksum = xor_block(checksum, ptp[4]);
			oa[5] = xor_block(oa[0], getL(ctx, 2));
			ta[5] = xor_block(oa[5], ptp[5]);
			checksum = xor_block(checksum, ptp[5]);
			oa[6] = xor_block(oa[7], getL(ctx, 2));
			ta[6] = xor_block(oa[6], ptp[6]);
			checksum = xor_block(checksum, ptp[6]);
			oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
			ta[7] = xor_block(oa[7], ptp[7]);
			checksum = xor_block(checksum, ptp[7]);
    	#endif
		
    	AES_ecb_encrypt_blks(ta,BPI,&ctx->encrypt_key);
		for (k=0; k<BPI; k+=4) {
			ctp[k]   = xor_block(ta[k], oa[k]);
			ctp[k+1] = xor_block(ta[k+1], oa[k+1]);
			ctp[k+2] = xor_block(ta[k+2], oa[k+2]);
			ctp[k+3] = xor_block(ta[k+3], oa[k+3]);
		}
        ptp += BPI;
        ctp += BPI;
    }
    offset = oa[BPI-1];
    
    if (final) {
		block ta[BPI*2], oa[BPI];
		
        /* Process remaining associated data, compute its tag contribution */
        remaining = ((unsigned)ad_len) % (BPI*16);
        if (remaining) {
			for (k=0; k+2 <= remaining/16; k+=2) {
				ad_offset = xor_block(ad_offset, getL(ctx, 0));
				ta[k] = xor_block(ad_offset, adp[k]);
				ad_offset = xor_block(ad_offset, getL(ctx, ntz(k+2)));
				ta[k+1] = xor_block(ad_offset, adp[k+1]);
			}
			remaining = remaining % 32;
			if (remaining >= 16) {
				ad_offset = xor_block(ad_offset, getL(ctx, 0));
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
			tmp.bl = zero_block();
			while (k >= 2) {
				k = k - 2;
				tmp.bl = xor_block(tmp.bl, ta[k]);
				ad_checksum = xor_block(ad_checksum, ta[k+1]);
			}
			ad_checksum = xor_block(ad_checksum, tmp.bl);
			if (k)
				ad_checksum = xor_block(ad_checksum, ta[0]);
		}
		
        /* Process remaining plaintext and compute its tag contribution    */
        remaining = ((unsigned)pt_len) % (BPI*16);

		for (k=0; k+2 <= remaining/16; k+=2) {
			oa[k] = xor_block(offset, getL(ctx, 0));
			ta[k] = xor_block(oa[k], ptp[k]);
			checksum = xor_block(checksum, ptp[k]);
			offset = oa[k+1] = xor_block(oa[k], getL(ctx, ntz(k+2)));
			ta[k+1] = xor_block(offset, ptp[k+1]);
			checksum = xor_block(checksum, ptp[k+1]);
		}
		remaining = remaining % 32;
		if (remaining >= 16) {

			offset = oa[k] = xor_block(offset, getL(ctx, 0));
			ta[k] = xor_block(offset, ptp[k]);
			checksum = xor_block(checksum, ptp[k]);
			remaining = remaining - 16;
			++k;
		}
		if (remaining) {
			tmp.bl = zero_block();
			memcpy(tmp.u8, ptp+k, remaining);
			tmp.u8[remaining] = (unsigned char)0x80u;
			checksum = xor_block(checksum, tmp.bl);
			ta[k] = offset = xor_block(offset,ctx->Lstar);
			++k;
		}
        offset = xor_block(offset, ctx->Ldollar); /* Part of tag gen */
		ta[k] = xor_block(offset, checksum);      /* Part of tag gen */
		AES_ecb_encrypt_blks(ta,k+1,&ctx->encrypt_key);
		offset = xor_block(ta[k], ad_checksum);   /* Part of tag gen */
		if (remaining) {
			--k;
			tmp.bl = xor_block(tmp.bl, ta[k]);
			#if SAFE_OUTPUT_BUFFERS
			ctp[k] = tmp.bl;  /* Security issue? */
			#else
			memcpy(ctp+k, tmp.u8, remaining);
			#endif
		}
		while (k >= 2) {
			k = k - 2;
			ctp[k]   = xor_block(ta[k], oa[k]);
			ctp[k+1] = xor_block(ta[k+1], oa[k+1]);
		}
		if (k)
			ctp[0] = xor_block(ta[0], oa[0]);

        
        /* Tag is placed at the correct location
         */
        if (tag) {
            *(block *)tag = offset;
        } else {
            memcpy((char *)ct + pt_len, &offset, 16);
            pt_len += 16;
        }
        
    } else {
        /* If not done with message, store values to ctx */
        ctx->offset = offset;
        ctx->checksum = checksum;
        ctx->blocks_processed = block_num;
        ctx->ad_offset = ad_offset;
        ctx->ad_checksum = ad_checksum;
        ctx->ad_blocks_processed = ad_block_num;
    }
    return (int) pt_len;
}

/* ----------------------------------------------------------------------- */
/* Simple test program                                                     */
/* ----------------------------------------------------------------------- */

#if 0

#include <stdio.h>
#include <time.h>

static void pbuf(void *p, unsigned len, const void *s)
{
    unsigned i;
    if (s)
        printf("%s", (char *)s);
    for (i = 0; i < len; i++)
        printf("%02X", (unsigned)(((unsigned char *)p)[i]));
    printf("\n");
}

#define VAL_LEN 1024
static void validate()
{
    ALIGN(16) char pt[VAL_LEN];
    ALIGN(16) char ct[VAL_LEN+16];
    ALIGN(16) char tag[16];
    ALIGN(16) char nonce[] = "abcdefghijkl";
    ALIGN(16) char key[] = "abcdefghijklmnop";
    ae_ctx ctx;
    char *val_buf, *next;
    int i;
    
    for (i=0; i < VAL_LEN; i++)
        pt[i] = 'a'+(i%3);   /* abcabcabc... */
    val_buf = (char *)malloc(((VAL_LEN+1)*(VAL_LEN+32))/2 + 16);
    next = val_buf = (char *)(((size_t)val_buf + 16) & ~((size_t)15));
    
    ae_init(&ctx, key, 16, 12, 16);
    /* pbuf(&ctx, sizeof(ctx), "CTX: "); */
    
    for (i = 0; i <= VAL_LEN; i++) {
        int first = ((i/3)/(BPI*16))*(BPI*16);
        int second = first;
        int third = i - (first + second);
        
        nonce[11] = (char)(i % 128);
        
		ae_encrypt(&ctx,nonce,pt,first,pt,first,ct,NULL,AE_PENDING);
	
		ae_encrypt(&ctx,NULL,pt+first,second,pt+first,second,ct+first,NULL,AE_PENDING);
        
        ae_encrypt(&ctx,NULL,pt+first+second,third,pt+first+second,third,
                   ct+first+second,NULL,AE_FINALIZE);

        memcpy(next,ct,(size_t)i+16);
        next = next+i+16;
        /*pbuf(next-16, 16, "Tag: ");*/
    }
    nonce[11] = 'l';
    ae_encrypt(&ctx,nonce,NULL,0,val_buf,next-val_buf,NULL,tag,AE_FINALIZE);
    pbuf(tag, 16, "Validation string: ");
    printf("Should be:         4E5FFF9750AA3B2D3C22E4D4D86F4200\n");
}

int main()
{
    validate();
    return 0;
}
#endif

#if USE_AES_NI && USE_OPENSSL_AES
char infoString[] = "OCB3 (AES-NI w/ OpenSSL Keying)";
#elif USE_AES_NI
char infoString[] = "OCB3 (AES-NI)";
#elif USE_REFERENCE_AES
char infoString[] = "OCB3 (Reference)";
#elif USE_OPENSSL_AES
char infoString[] = "OCB3 (OpenSSL)";
#else
char infoString[] = "OCB3";
#endif
