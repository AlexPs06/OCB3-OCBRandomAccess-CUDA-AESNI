#include<iostream>
#include <cstring>
#include <xmmintrin.h>              /* SSE instructions and _mm_malloc */
#include <emmintrin.h>              /* SSE2 instructions               */
#include <tmmintrin.h>              /* SSSE3 instructions              */

using namespace std;
#define L_TABLE_SZ 31;
#define OCB_TAG_LEN 16;
#define zero_block()          _mm_setzero_si128()
#define xor_block(x,y)        _mm_xor_si128(x,y)
#define getL(_ctx, _tz) ((_ctx)->L[_tz]) //se necesita que se precompute el tamaño correcto de la tabla
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
#define unequal_blocks(x,y) \
    					   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)
typedef __m128i block;
typedef struct { unsigned int keys[11][4]; int round; } AES_KEY;

struct _ae_ctx {
    block offset;                          /* Memory correct               */
    block checksum;                        /* Memory correct               */
    block Lstar;                           /* Memory correct               */
    block Ldollar;                         /* Memory correct               */
    block L[31];                           /* Memory correct               */
    block ad_checksum;                     /* Memory correct               */
    block ad_offset;                       /* Memory correct               */
    block cached_Top;                      /* Memory correct               */
	uint64_t KtopStr[3];                   /* Register correct, each item  */
    uint32_t ad_blocks_processed;
    uint32_t blocks_processed;
    AES_KEY decrypt_key;
    AES_KEY encrypt_key;
    unsigned int tag_len = OCB_TAG_LEN;
} ;
typedef struct _ae_ctx ae_ctx;

class aesBlock
{
public:
    unsigned int block[4] ={0,};
};

class LBlock
{
public:
    unsigned int block[4] ={0};
};

unsigned char matrizCajaS[256]={
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};


void ExpansionKeys128( unsigned int *k,  AES_KEY *aeskeys, AES_KEY *aeskeys_decrypt );
void unsignedCharArrayTounsignedIntArray(const unsigned char *in,unsigned int *out, unsigned long long len, unsigned long long mlen2 );
void unsignedCharArrayTounsignedIntArray(unsigned char *in,unsigned int *out, unsigned long long len, unsigned long long mlen2 );
void imprimiArreglo(int tam, unsigned int *keys );
void imprimiArreglo(int tam, unsigned char *keys );
void imprimiArreglo(int tam, const unsigned char *keys );
void imprimiArreglo(int tam, AES_KEY *aeskeys, int posicion );
void AES128Encrypt(aesBlock *m, unsigned long long mlen, unsigned int *keys);
void shiftRowsMatrix(unsigned int* in, int *shifttab);
unsigned char GF2Redution(unsigned short in );
unsigned char multiplicacionENGF2(int caso , unsigned short numero2);
static inline block double_block(block bl);
static inline block swap_if_le(block bl);
static inline unsigned ntz(unsigned x);
ae_ctx* ae_allocate(void *misc)
{
	void *p;
	(void) misc;                     /* misc unused in this implementation */
    p = _mm_malloc(sizeof(ae_ctx),16);
	return (ae_ctx *)p;
}

int ae_init(ae_ctx *ctx, const unsigned char *k, int key_len, int nonce_len, int tag_len)
{
    unsigned i;
    block tmp_blk;

    if (nonce_len != 12)
    	return 0;//AE_NOT_SUPPORTED

    
    /* Initialize encryption & decryption keys */
    unsigned int key[4];
    unsignedCharArrayTounsignedIntArray(k,key,16,16);

    //Falta las llaves de decifrado
    ExpansionKeys128( key,&ctx->encrypt_key,&ctx->decrypt_key );
    
    // for (i = 0; i < 10; i++) {
    //     imprimiArreglo(4,&ctx->decrypt_key,i);
    //     printf("---------------------------\n");
	// }
    // imprimiArreglo(4,&ctx->encrypt_key,0);
    
    /* Zero things that need zeroing */
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;

    /* Compute key-dependent values */
    aesBlock *tmp_aes_block = new aesBlock[1];
    AES128Encrypt(tmp_aes_block, 16, &ctx->encrypt_key.keys[0][0]);
    
    ctx->Lstar =  _mm_set_epi32 (
        tmp_aes_block[0].block[3],
        tmp_aes_block[0].block[2],
        tmp_aes_block[0].block[1],
        tmp_aes_block[0].block[0]
    );
    tmp_blk = swap_if_le(ctx->Lstar);
    tmp_blk = double_block(tmp_blk);
    ctx->Ldollar = swap_if_le(tmp_blk);
    tmp_blk = double_block(tmp_blk);
    ctx->L[0] = swap_if_le(tmp_blk);
    for (i = 1; i < 31; i++) {
		tmp_blk = double_block(tmp_blk);
    	ctx->L[i] = swap_if_le(tmp_blk);
    }
    // for (i = 0; i < 16; i++) {
	// 	imprimiArreglo(16,(unsigned char *)&ctx->L[i]);
    //     printf("---------------------------\n");
	// }
    // exit(1);

    ctx->tag_len = tag_len;
    

    return 1; //AE_SUCCESS;
}

void imprimiArreglo(int tam, unsigned int *keys ){
    for (int i = 0; i<tam; i++){
        printf("%08x", keys[i] );
    }
    printf("\n");
}
void imprimiArreglo(int tam, unsigned char *keys ){
    for (int i = 0; i<tam; i++){
        printf("%02x", keys[i] );
    }
    printf("\n");
}
void imprimiArreglo(int tam, const unsigned char *keys ){
    for (int i = 0; i<tam; i++){
        printf("%02x", keys[i] );
    }
    printf("\n");
}
void imprimiArreglo(int tam, AES_KEY *aeskeys, int posicion ){
    for (int i = 0; i<tam; i++){
        printf("%08x", aeskeys->keys[posicion][i] );
    }
    printf("\n");

}

void shiftRowsMatrix(unsigned int* in, int *shifttab){
    
    unsigned char * temp;
    unsigned char h[16];
    temp = (unsigned char *) in;
    memcpy(h, temp, 16);

    for(int i = 0; i < 16; i++){
        temp[i] = h[shifttab[i]];
    }
}
void ExpansionKeys128( unsigned int *k,  AES_KEY *aeskeys, AES_KEY *aeskeys_decrypt ){
    
    // imprimiArreglo(16,(unsigned char *)&k[0]);
    // imprimiArreglo(4,k);

    unsigned char RotWordTemp[4];
    const unsigned int matrizRcon[10]={ 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
    memcpy(aeskeys->keys[0], k, 16);
    
    for(int i = 0; i<10; i++){
        RotWordTemp[0]=aeskeys->keys[i][3]>>16;
        RotWordTemp[1]=aeskeys->keys[i][3]>>8;
        RotWordTemp[2]=aeskeys->keys[i][3];
        RotWordTemp[3]=aeskeys->keys[i][3]>>24; 
        
        for(int j = 0;  j < 4; j++ ){
            RotWordTemp[j] = matrizCajaS[ (int) RotWordTemp[j] ];
        }
        int RotWord = 0;
        RotWord = RotWord ^ ( (int) RotWordTemp[0])<<24;
        RotWord = RotWord ^ ( (int) RotWordTemp[1])<<16;
        RotWord = RotWord ^ ( (int) RotWordTemp[2])<<8;
        RotWord = RotWord ^ ( (int) RotWordTemp[3]);
        
        aeskeys->keys[i+1][0] =  RotWord ^ aeskeys->keys[i][0];
        aeskeys->keys[i+1][0] = aeskeys->keys[i+1][0] ^ matrizRcon[i];
        for(int x = 1;  x < 4; x++ ){
            aeskeys->keys[i+1][x] =  aeskeys->keys[i+1][x-1] ^ aeskeys->keys[i][x];
        }
    }

    aeskeys_decrypt->keys[0][0]=aeskeys->keys[10][0];
    aeskeys_decrypt->keys[0][1]=aeskeys->keys[10][1];
    aeskeys_decrypt->keys[0][2]=aeskeys->keys[10][2];
    aeskeys_decrypt->keys[0][3]=aeskeys->keys[10][3];
    unsigned char h[16];
    unsigned char resultado[16];
    int IMC[16]= {
        0x0e, 0x0b, 0x0d, 0x09,
        0x09, 0x0e, 0x0b, 0x0d,
        0x0d, 0x09, 0x0e, 0x0b,
        0x0b, 0x0d, 0x09, 0x0e

    };
    for(int k = 9; k>0;k--){
        memcpy(h, aeskeys->keys[k], 16);
        for (int i = 0; i < 4; i++) { 
            for (int j = 0; j < 4; j++) { 
                unsigned char temp = 0;
                for(int k = 0; k < 4; k++ ){
                    temp= multiplicacionENGF2(IMC[ (j*4)+k ] , h[ (i*4) +3-k ]) ^ temp;
                }
                resultado[ (i*4) +3-j ] = temp;
            }
        }
        unsigned int * temporal = (unsigned int *) resultado;
        aeskeys_decrypt->keys[10-k][0] = temporal[0];
        aeskeys_decrypt->keys[10-k][1] = temporal[1];
        aeskeys_decrypt->keys[10-k][2] = temporal[2];
        aeskeys_decrypt->keys[10-k][3] = temporal[3];
    }
    
    aeskeys_decrypt->keys[10][0]=aeskeys->keys[0][0];
    aeskeys_decrypt->keys[10][1]=aeskeys->keys[0][1];
    aeskeys_decrypt->keys[10][2]=aeskeys->keys[0][2];
    aeskeys_decrypt->keys[10][3]=aeskeys->keys[0][3];
    int shifttab[16]={
        3, 2, 1, 0,
        7, 6, 5, 4,
        11, 10, 9, 8,
        15, 14, 13, 12,
    };
    for(int i = 0; i<11; i++){

        shiftRowsMatrix(aeskeys->keys[i], shifttab);
        shiftRowsMatrix(aeskeys_decrypt->keys[i], shifttab);
    }
}

static inline block double_block(block bl) {
    const __m128i mask = _mm_set_epi32(135,1,1,1);
    __m128i tmp = _mm_srai_epi32(bl, 31);
    tmp = _mm_and_si128(tmp, mask);
    tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));
    bl = _mm_slli_epi32(bl, 1);
    return _mm_xor_si128(bl,tmp);
}


static inline block swap_if_le(block b) {
    block a = _mm_shuffle_epi32  (b, _MM_SHUFFLE(0,1,2,3));
    a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(2,3,0,1));
    a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(2,3,0,1));
    return _mm_xor_si128(_mm_srli_epi16(a,8), _mm_slli_epi16(a,8));
}
static inline block gen_offset(uint64_t KtopStr[3], unsigned bot) {
    block hi = _mm_load_si128((__m128i *)(KtopStr+0));   /* hi = B A */
    block lo = _mm_loadu_si128((__m128i *)(KtopStr+1));  /* lo = C B */
    __m128i lshift = _mm_cvtsi32_si128(bot);
    __m128i rshift = _mm_cvtsi32_si128(64-bot);
    lo = _mm_xor_si128(_mm_sll_epi64(hi,lshift),_mm_srl_epi64(lo,rshift));
    return swap_if_le(_mm_shuffle_epi32(lo, _MM_SHUFFLE(1,0,3,2)));
}
static block gen_offset_from_nonce(ae_ctx *ctx, const unsigned char *nonce)
{
	const union { unsigned x; unsigned char endian; } little = { 1 };
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
	unsigned idx;


	/* Replace cached nonce Top if needed */
   
    if (little.endian)
        tmp.u32[0] = 0x01000000 + ((ctx->tag_len * 8 % 128) << 1);
    else
        tmp.u32[0] = 0x00000001 + ((ctx->tag_len * 8 % 128) << 25);

	tmp.u32[1] = ((uint32_t *)nonce)[0];
	tmp.u32[2] = ((uint32_t *)nonce)[1];
	tmp.u32[3] = ((uint32_t *)nonce)[2];
	idx = (unsigned)(tmp.u8[15] & 0x3f);   /* Get low 6 bits of nonce  */
	tmp.u8[15] = tmp.u8[15] & 0xc0;        /* Zero low 6 bits of nonce */
	
    

    if ( unequal_blocks(tmp.bl,ctx->cached_Top) )   { /* Cached?       */
		ctx->cached_Top = tmp.bl;          /* Update cache, KtopStr    */

        aesBlock *tmp_aes_block = new aesBlock[1];
        _mm_store_si128 ((__m128i*)tmp_aes_block[0].block, (ctx->cached_Top));

        AES128Encrypt(tmp_aes_block, 16, &ctx->encrypt_key.keys[0][0]);
        uint64_t * pDw = (uint64_t *)tmp_aes_block[0].block;
        ctx->KtopStr[0] = pDw[0];
        ctx->KtopStr[1] = pDw[1];
        ctx->KtopStr[2] = pDw[2];
        // imprimiArreglo(16,(unsigned char *)&ctx->KtopStr);
        // imprimiArreglo(4,tmp_aes_block[0].block);

        if (little.endian) {               /* Make Register Correct    */
			ctx->KtopStr[0] = bswap64(ctx->KtopStr[0]);
			ctx->KtopStr[1] = bswap64(ctx->KtopStr[1]);
		}
		ctx->KtopStr[2] = ctx->KtopStr[0] ^
						 (ctx->KtopStr[0] << 8) ^ (ctx->KtopStr[1] >> 56);
	}
	return gen_offset(ctx->KtopStr, idx);
}



__device__ void imprimiArregloCuda(int tam,unsigned char *keys ){
    for (int i = 0; i<tam; i++){
        printf("%02x ", keys[i] );
    }
    printf("\n");

}
__device__ void imprimiArregloCudaInt(int tam,unsigned int *keys ){
    printf("----------------\n" );
    for (int i = 0; i<tam; i++){
        printf("%08x", keys[i] );
    }
    printf("\n");
}
__device__ void XOR_128(unsigned int* A, unsigned int * B )
{
	for (int i = 0; i < 4; i++) { 
        A[i] =A[i] ^  B[i];
    }
}
__device__ void XOR2_128(unsigned int* A, unsigned int * B,unsigned int * C )
{
	for (int i = 0; i < 4; i++) { 
        A[i] =C[i] ^  B[i];
    }
}
__device__ void addRoundKey(unsigned int* in, unsigned int * keys, int round)
{

	for (int i = 0; i < 4; i++) { 
        in[i] =in[i] ^  keys[(round*4) + i];
    }

}
__device__ void subBytes(unsigned int* in, unsigned char * matrizCajaS)
{
    unsigned char * temp;
    temp = (unsigned char *) in;
	for (int i = 0; i < 16; i++) { 
        temp[i] = matrizCajaS[ (int) temp[i]]; 
    }
}

__device__ void shiftRows(unsigned int* in, int *shifttab){
    
    unsigned char * temp;
    unsigned char h[16];
    temp = (unsigned char *) in;
    memcpy(h, temp, 16);

    for(int i = 0; i < 16; i++){
        temp[i] = h[shifttab[i]];
    }
}
unsigned char GF2Redution(unsigned short in ){
    
    unsigned short temp = in ; // numero de prueba
    // temp = temp * 2;
    unsigned char temp1 = temp>>8; //queda FF
    unsigned char temp2 = temp1<<1; //queda FE
    unsigned char temp3 = temp1<<3; //queda F8
    unsigned char temp4 = temp1<<4; //queda F

    unsigned char temp5 = temp>>13;//queda 7
    unsigned char temp6 = temp5<<1;//queda E 
    unsigned char temp7 = temp5<<3;//queda 38
    unsigned char temp8 = temp5<<4;//queda 70

    unsigned char temp9 = temp>>12;//queda F
    unsigned char temp10 = temp9<<1;//queda 1E 
    unsigned char temp11 = temp9<<3;//queda 78
    unsigned char temp12 = temp9<<4;//queda F0
    
    in = temp ^ temp1 ^ temp2 ^ temp3 ^ temp4 ^ temp5 ^ temp6 ^ temp7 ^ temp8 ^ temp9 ^ temp10 ^ temp11 ^ temp12; 
    return in;
}

unsigned char multiplicacionENGF2(int caso , unsigned short numero2){
    switch (caso)
    {
    case 1:
        return numero2;
        break;
    case 2:

        numero2 = GF2Redution(numero2 * 2); 

        return numero2 ;
        break;
    case 3:

        numero2 = GF2Redution((numero2*2)^numero2); 

        return numero2;
        break;
    case 9:

        numero2 = GF2Redution((numero2*8)^numero2); 

        return numero2;
        break;

    case 11:


        numero2 = GF2Redution((numero2*8)) ^ GF2Redution((numero2*2)^numero2) ; 

        return numero2;
        break;
    case 13:


        numero2 = GF2Redution((numero2*8)) ^ GF2Redution((numero2*4)) ^ numero2; 

        return numero2;
        break;
    case 14:


        numero2 = GF2Redution((numero2*8)) ^ GF2Redution((numero2*4)) ^ GF2Redution((numero2*2)); 

        return numero2;
        break;

    default:

        break;
    }
    return 0;

}


__device__ void subBytesMixColumns(unsigned int* in, int * T1, int * T2, int * T3, int * T4){
	unsigned char * temp;
    temp = (unsigned char *) in;
    for (int i = 0; i < 16; i=i+4){
        int tempT1 = T1[(int) temp[i]];
        int tempT2 = T2[(int) temp[i+1]];
        int tempT3 = T3[(int) temp[i+2]];
        int tempT4 = T4[(int) temp[i+3] ];

        int tempT5 = tempT1 ^ tempT2 ^ tempT3 ^ tempT4; 
        in[i/4] = tempT5;
    }
}

__device__ void AES_init( unsigned char  *matrizCajaS, int *T1, int *T2, int *T3, int *T4){
    unsigned char matrizCajaSTemp[256]={
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };
    int T1Temp[256] ={
        0xa56363c6U, 0x847c7cf8U, 0x997777eeU, 0x8d7b7bf6U,
        0x0df2f2ffU, 0xbd6b6bd6U, 0xb16f6fdeU, 0x54c5c591U,
        0x50303060U, 0x03010102U, 0xa96767ceU, 0x7d2b2b56U,
        0x19fefee7U, 0x62d7d7b5U, 0xe6abab4dU, 0x9a7676ecU,
        0x45caca8fU, 0x9d82821fU, 0x40c9c989U, 0x877d7dfaU,
        0x15fafaefU, 0xeb5959b2U, 0xc947478eU, 0x0bf0f0fbU,
        0xecadad41U, 0x67d4d4b3U, 0xfda2a25fU, 0xeaafaf45U,
        0xbf9c9c23U, 0xf7a4a453U, 0x967272e4U, 0x5bc0c09bU,
        0xc2b7b775U, 0x1cfdfde1U, 0xae93933dU, 0x6a26264cU,
        0x5a36366cU, 0x413f3f7eU, 0x02f7f7f5U, 0x4fcccc83U,
        0x5c343468U, 0xf4a5a551U, 0x34e5e5d1U, 0x08f1f1f9U,
        0x937171e2U, 0x73d8d8abU, 0x53313162U, 0x3f15152aU,
        0x0c040408U, 0x52c7c795U, 0x65232346U, 0x5ec3c39dU,
        0x28181830U, 0xa1969637U, 0x0f05050aU, 0xb59a9a2fU,
        0x0907070eU, 0x36121224U, 0x9b80801bU, 0x3de2e2dfU,
        0x26ebebcdU, 0x6927274eU, 0xcdb2b27fU, 0x9f7575eaU,
        0x1b090912U, 0x9e83831dU, 0x742c2c58U, 0x2e1a1a34U,
        0x2d1b1b36U, 0xb26e6edcU, 0xee5a5ab4U, 0xfba0a05bU,
        0xf65252a4U, 0x4d3b3b76U, 0x61d6d6b7U, 0xceb3b37dU,
        0x7b292952U, 0x3ee3e3ddU, 0x712f2f5eU, 0x97848413U,
        0xf55353a6U, 0x68d1d1b9U, 0x00000000U, 0x2cededc1U,
        0x60202040U, 0x1ffcfce3U, 0xc8b1b179U, 0xed5b5bb6U,
        0xbe6a6ad4U, 0x46cbcb8dU, 0xd9bebe67U, 0x4b393972U,
        0xde4a4a94U, 0xd44c4c98U, 0xe85858b0U, 0x4acfcf85U,
        0x6bd0d0bbU, 0x2aefefc5U, 0xe5aaaa4fU, 0x16fbfbedU,
        0xc5434386U, 0xd74d4d9aU, 0x55333366U, 0x94858511U,
        0xcf45458aU, 0x10f9f9e9U, 0x06020204U, 0x817f7ffeU,
        0xf05050a0U, 0x443c3c78U, 0xba9f9f25U, 0xe3a8a84bU,
        0xf35151a2U, 0xfea3a35dU, 0xc0404080U, 0x8a8f8f05U,
        0xad92923fU, 0xbc9d9d21U, 0x48383870U, 0x04f5f5f1U,
        0xdfbcbc63U, 0xc1b6b677U, 0x75dadaafU, 0x63212142U,
        0x30101020U, 0x1affffe5U, 0x0ef3f3fdU, 0x6dd2d2bfU,
        0x4ccdcd81U, 0x140c0c18U, 0x35131326U, 0x2fececc3U,
        0xe15f5fbeU, 0xa2979735U, 0xcc444488U, 0x3917172eU,
        0x57c4c493U, 0xf2a7a755U, 0x827e7efcU, 0x473d3d7aU,
        0xac6464c8U, 0xe75d5dbaU, 0x2b191932U, 0x957373e6U,
        0xa06060c0U, 0x98818119U, 0xd14f4f9eU, 0x7fdcdca3U,
        0x66222244U, 0x7e2a2a54U, 0xab90903bU, 0x8388880bU,
        0xca46468cU, 0x29eeeec7U, 0xd3b8b86bU, 0x3c141428U,
        0x79dedea7U, 0xe25e5ebcU, 0x1d0b0b16U, 0x76dbdbadU,
        0x3be0e0dbU, 0x56323264U, 0x4e3a3a74U, 0x1e0a0a14U,
        0xdb494992U, 0x0a06060cU, 0x6c242448U, 0xe45c5cb8U,
        0x5dc2c29fU, 0x6ed3d3bdU, 0xefacac43U, 0xa66262c4U,
        0xa8919139U, 0xa4959531U, 0x37e4e4d3U, 0x8b7979f2U,
        0x32e7e7d5U, 0x43c8c88bU, 0x5937376eU, 0xb76d6ddaU,
        0x8c8d8d01U, 0x64d5d5b1U, 0xd24e4e9cU, 0xe0a9a949U,
        0xb46c6cd8U, 0xfa5656acU, 0x07f4f4f3U, 0x25eaeacfU,
        0xaf6565caU, 0x8e7a7af4U, 0xe9aeae47U, 0x18080810U,
        0xd5baba6fU, 0x887878f0U, 0x6f25254aU, 0x722e2e5cU,
        0x241c1c38U, 0xf1a6a657U, 0xc7b4b473U, 0x51c6c697U,
        0x23e8e8cbU, 0x7cdddda1U, 0x9c7474e8U, 0x211f1f3eU,
        0xdd4b4b96U, 0xdcbdbd61U, 0x868b8b0dU, 0x858a8a0fU,
        0x907070e0U, 0x423e3e7cU, 0xc4b5b571U, 0xaa6666ccU,
        0xd8484890U, 0x05030306U, 0x01f6f6f7U, 0x120e0e1cU,
        0xa36161c2U, 0x5f35356aU, 0xf95757aeU, 0xd0b9b969U,
        0x91868617U, 0x58c1c199U, 0x271d1d3aU, 0xb99e9e27U,
        0x38e1e1d9U, 0x13f8f8ebU, 0xb398982bU, 0x33111122U,
        0xbb6969d2U, 0x70d9d9a9U, 0x898e8e07U, 0xa7949433U,
        0xb69b9b2dU, 0x221e1e3cU, 0x92878715U, 0x20e9e9c9U,
        0x49cece87U, 0xff5555aaU, 0x78282850U, 0x7adfdfa5U,
        0x8f8c8c03U, 0xf8a1a159U, 0x80898909U, 0x170d0d1aU,
        0xdabfbf65U, 0x31e6e6d7U, 0xc6424284U, 0xb86868d0U,
        0xc3414182U, 0xb0999929U, 0x772d2d5aU, 0x110f0f1eU,
        0xcbb0b07bU, 0xfc5454a8U, 0xd6bbbb6dU, 0x3a16162cU,
    
    
    };
   
    int T2Temp[256] = {



        0x6363c6a5U, 0x7c7cf884U, 0x7777ee99U, 0x7b7bf68dU,
        0xf2f2ff0dU, 0x6b6bd6bdU, 0x6f6fdeb1U, 0xc5c59154U,
        0x30306050U, 0x01010203U, 0x6767cea9U, 0x2b2b567dU,
        0xfefee719U, 0xd7d7b562U, 0xabab4de6U, 0x7676ec9aU,
        0xcaca8f45U, 0x82821f9dU, 0xc9c98940U, 0x7d7dfa87U,
        0xfafaef15U, 0x5959b2ebU, 0x47478ec9U, 0xf0f0fb0bU,
        0xadad41ecU, 0xd4d4b367U, 0xa2a25ffdU, 0xafaf45eaU,
        0x9c9c23bfU, 0xa4a453f7U, 0x7272e496U, 0xc0c09b5bU,
        0xb7b775c2U, 0xfdfde11cU, 0x93933daeU, 0x26264c6aU,
        0x36366c5aU, 0x3f3f7e41U, 0xf7f7f502U, 0xcccc834fU,
        0x3434685cU, 0xa5a551f4U, 0xe5e5d134U, 0xf1f1f908U,
        0x7171e293U, 0xd8d8ab73U, 0x31316253U, 0x15152a3fU,
        0x0404080cU, 0xc7c79552U, 0x23234665U, 0xc3c39d5eU,
        0x18183028U, 0x969637a1U, 0x05050a0fU, 0x9a9a2fb5U,
        0x07070e09U, 0x12122436U, 0x80801b9bU, 0xe2e2df3dU,
        0xebebcd26U, 0x27274e69U, 0xb2b27fcdU, 0x7575ea9fU,
        0x0909121bU, 0x83831d9eU, 0x2c2c5874U, 0x1a1a342eU,
        0x1b1b362dU, 0x6e6edcb2U, 0x5a5ab4eeU, 0xa0a05bfbU,
        0x5252a4f6U, 0x3b3b764dU, 0xd6d6b761U, 0xb3b37dceU,
        0x2929527bU, 0xe3e3dd3eU, 0x2f2f5e71U, 0x84841397U,
        0x5353a6f5U, 0xd1d1b968U, 0x00000000U, 0xededc12cU,
        0x20204060U, 0xfcfce31fU, 0xb1b179c8U, 0x5b5bb6edU,
        0x6a6ad4beU, 0xcbcb8d46U, 0xbebe67d9U, 0x3939724bU,
        0x4a4a94deU, 0x4c4c98d4U, 0x5858b0e8U, 0xcfcf854aU,
        0xd0d0bb6bU, 0xefefc52aU, 0xaaaa4fe5U, 0xfbfbed16U,
        0x434386c5U, 0x4d4d9ad7U, 0x33336655U, 0x85851194U,
        0x45458acfU, 0xf9f9e910U, 0x02020406U, 0x7f7ffe81U,
        0x5050a0f0U, 0x3c3c7844U, 0x9f9f25baU, 0xa8a84be3U,
        0x5151a2f3U, 0xa3a35dfeU, 0x404080c0U, 0x8f8f058aU,
        0x92923fadU, 0x9d9d21bcU, 0x38387048U, 0xf5f5f104U,
        0xbcbc63dfU, 0xb6b677c1U, 0xdadaaf75U, 0x21214263U,
        0x10102030U, 0xffffe51aU, 0xf3f3fd0eU, 0xd2d2bf6dU,
        0xcdcd814cU, 0x0c0c1814U, 0x13132635U, 0xececc32fU,
        0x5f5fbee1U, 0x979735a2U, 0x444488ccU, 0x17172e39U,
        0xc4c49357U, 0xa7a755f2U, 0x7e7efc82U, 0x3d3d7a47U,
        0x6464c8acU, 0x5d5dbae7U, 0x1919322bU, 0x7373e695U,
        0x6060c0a0U, 0x81811998U, 0x4f4f9ed1U, 0xdcdca37fU,
        0x22224466U, 0x2a2a547eU, 0x90903babU, 0x88880b83U,
        0x46468ccaU, 0xeeeec729U, 0xb8b86bd3U, 0x1414283cU,
        0xdedea779U, 0x5e5ebce2U, 0x0b0b161dU, 0xdbdbad76U,
        0xe0e0db3bU, 0x32326456U, 0x3a3a744eU, 0x0a0a141eU,
        0x494992dbU, 0x06060c0aU, 0x2424486cU, 0x5c5cb8e4U,
        0xc2c29f5dU, 0xd3d3bd6eU, 0xacac43efU, 0x6262c4a6U,
        0x919139a8U, 0x959531a4U, 0xe4e4d337U, 0x7979f28bU,
        0xe7e7d532U, 0xc8c88b43U, 0x37376e59U, 0x6d6ddab7U,
        0x8d8d018cU, 0xd5d5b164U, 0x4e4e9cd2U, 0xa9a949e0U,
        0x6c6cd8b4U, 0x5656acfaU, 0xf4f4f307U, 0xeaeacf25U,
        0x6565caafU, 0x7a7af48eU, 0xaeae47e9U, 0x08081018U,
        0xbaba6fd5U, 0x7878f088U, 0x25254a6fU, 0x2e2e5c72U,
        0x1c1c3824U, 0xa6a657f1U, 0xb4b473c7U, 0xc6c69751U,
        0xe8e8cb23U, 0xdddda17cU, 0x7474e89cU, 0x1f1f3e21U,
        0x4b4b96ddU, 0xbdbd61dcU, 0x8b8b0d86U, 0x8a8a0f85U,
        0x7070e090U, 0x3e3e7c42U, 0xb5b571c4U, 0x6666ccaaU,
        0x484890d8U, 0x03030605U, 0xf6f6f701U, 0x0e0e1c12U,
        0x6161c2a3U, 0x35356a5fU, 0x5757aef9U, 0xb9b969d0U,
        0x86861791U, 0xc1c19958U, 0x1d1d3a27U, 0x9e9e27b9U,
        0xe1e1d938U, 0xf8f8eb13U, 0x98982bb3U, 0x11112233U,
        0x6969d2bbU, 0xd9d9a970U, 0x8e8e0789U, 0x949433a7U,
        0x9b9b2db6U, 0x1e1e3c22U, 0x87871592U, 0xe9e9c920U,
        0xcece8749U, 0x5555aaffU, 0x28285078U, 0xdfdfa57aU,
        0x8c8c038fU, 0xa1a159f8U, 0x89890980U, 0x0d0d1a17U,
        0xbfbf65daU, 0xe6e6d731U, 0x424284c6U, 0x6868d0b8U,
        0x414182c3U, 0x999929b0U, 0x2d2d5a77U, 0x0f0f1e11U,
        0xb0b07bcbU, 0x5454a8fcU, 0xbbbb6dd6U, 0x16162c3aU,


 
      } ;
    int T3Temp[256] = {

        0x63c6a563U, 0x7cf8847cU, 0x77ee9977U, 0x7bf68d7bU,
        0xf2ff0df2U, 0x6bd6bd6bU, 0x6fdeb16fU, 0xc59154c5U,
        0x30605030U, 0x01020301U, 0x67cea967U, 0x2b567d2bU,
        0xfee719feU, 0xd7b562d7U, 0xab4de6abU, 0x76ec9a76U,
        0xca8f45caU, 0x821f9d82U, 0xc98940c9U, 0x7dfa877dU,
        0xfaef15faU, 0x59b2eb59U, 0x478ec947U, 0xf0fb0bf0U,
        0xad41ecadU, 0xd4b367d4U, 0xa25ffda2U, 0xaf45eaafU,
        0x9c23bf9cU, 0xa453f7a4U, 0x72e49672U, 0xc09b5bc0U,
        0xb775c2b7U, 0xfde11cfdU, 0x933dae93U, 0x264c6a26U,
        0x366c5a36U, 0x3f7e413fU, 0xf7f502f7U, 0xcc834fccU,
        0x34685c34U, 0xa551f4a5U, 0xe5d134e5U, 0xf1f908f1U,
        0x71e29371U, 0xd8ab73d8U, 0x31625331U, 0x152a3f15U,
        0x04080c04U, 0xc79552c7U, 0x23466523U, 0xc39d5ec3U,
        0x18302818U, 0x9637a196U, 0x050a0f05U, 0x9a2fb59aU,
        0x070e0907U, 0x12243612U, 0x801b9b80U, 0xe2df3de2U,
        0xebcd26ebU, 0x274e6927U, 0xb27fcdb2U, 0x75ea9f75U,
        0x09121b09U, 0x831d9e83U, 0x2c58742cU, 0x1a342e1aU,
        0x1b362d1bU, 0x6edcb26eU, 0x5ab4ee5aU, 0xa05bfba0U,
        0x52a4f652U, 0x3b764d3bU, 0xd6b761d6U, 0xb37dceb3U,
        0x29527b29U, 0xe3dd3ee3U, 0x2f5e712fU, 0x84139784U,
        0x53a6f553U, 0xd1b968d1U, 0x00000000U, 0xedc12cedU,
        0x20406020U, 0xfce31ffcU, 0xb179c8b1U, 0x5bb6ed5bU,
        0x6ad4be6aU, 0xcb8d46cbU, 0xbe67d9beU, 0x39724b39U,
        0x4a94de4aU, 0x4c98d44cU, 0x58b0e858U, 0xcf854acfU,
        0xd0bb6bd0U, 0xefc52aefU, 0xaa4fe5aaU, 0xfbed16fbU,
        0x4386c543U, 0x4d9ad74dU, 0x33665533U, 0x85119485U,
        0x458acf45U, 0xf9e910f9U, 0x02040602U, 0x7ffe817fU,
        0x50a0f050U, 0x3c78443cU, 0x9f25ba9fU, 0xa84be3a8U,
        0x51a2f351U, 0xa35dfea3U, 0x4080c040U, 0x8f058a8fU,
        0x923fad92U, 0x9d21bc9dU, 0x38704838U, 0xf5f104f5U,
        0xbc63dfbcU, 0xb677c1b6U, 0xdaaf75daU, 0x21426321U,
        0x10203010U, 0xffe51affU, 0xf3fd0ef3U, 0xd2bf6dd2U,
        0xcd814ccdU, 0x0c18140cU, 0x13263513U, 0xecc32fecU,
        0x5fbee15fU, 0x9735a297U, 0x4488cc44U, 0x172e3917U,
        0xc49357c4U, 0xa755f2a7U, 0x7efc827eU, 0x3d7a473dU,
        0x64c8ac64U, 0x5dbae75dU, 0x19322b19U, 0x73e69573U,
        0x60c0a060U, 0x81199881U, 0x4f9ed14fU, 0xdca37fdcU,
        0x22446622U, 0x2a547e2aU, 0x903bab90U, 0x880b8388U,
        0x468cca46U, 0xeec729eeU, 0xb86bd3b8U, 0x14283c14U,
        0xdea779deU, 0x5ebce25eU, 0x0b161d0bU, 0xdbad76dbU,
        0xe0db3be0U, 0x32645632U, 0x3a744e3aU, 0x0a141e0aU,
        0x4992db49U, 0x060c0a06U, 0x24486c24U, 0x5cb8e45cU,
        0xc29f5dc2U, 0xd3bd6ed3U, 0xac43efacU, 0x62c4a662U,
        0x9139a891U, 0x9531a495U, 0xe4d337e4U, 0x79f28b79U,
        0xe7d532e7U, 0xc88b43c8U, 0x376e5937U, 0x6ddab76dU,
        0x8d018c8dU, 0xd5b164d5U, 0x4e9cd24eU, 0xa949e0a9U,
        0x6cd8b46cU, 0x56acfa56U, 0xf4f307f4U, 0xeacf25eaU,
        0x65caaf65U, 0x7af48e7aU, 0xae47e9aeU, 0x08101808U,
        0xba6fd5baU, 0x78f08878U, 0x254a6f25U, 0x2e5c722eU,
        0x1c38241cU, 0xa657f1a6U, 0xb473c7b4U, 0xc69751c6U,
        0xe8cb23e8U, 0xdda17cddU, 0x74e89c74U, 0x1f3e211fU,
        0x4b96dd4bU, 0xbd61dcbdU, 0x8b0d868bU, 0x8a0f858aU,
        0x70e09070U, 0x3e7c423eU, 0xb571c4b5U, 0x66ccaa66U,
        0x4890d848U, 0x03060503U, 0xf6f701f6U, 0x0e1c120eU,
        0x61c2a361U, 0x356a5f35U, 0x57aef957U, 0xb969d0b9U,
        0x86179186U, 0xc19958c1U, 0x1d3a271dU, 0x9e27b99eU,
        0xe1d938e1U, 0xf8eb13f8U, 0x982bb398U, 0x11223311U,
        0x69d2bb69U, 0xd9a970d9U, 0x8e07898eU, 0x9433a794U,
        0x9b2db69bU, 0x1e3c221eU, 0x87159287U, 0xe9c920e9U,
        0xce8749ceU, 0x55aaff55U, 0x28507828U, 0xdfa57adfU,
        0x8c038f8cU, 0xa159f8a1U, 0x89098089U, 0x0d1a170dU,
        0xbf65dabfU, 0xe6d731e6U, 0x4284c642U, 0x68d0b868U,
        0x4182c341U, 0x9929b099U, 0x2d5a772dU, 0x0f1e110fU,
        0xb07bcbb0U, 0x54a8fc54U, 0xbb6dd6bbU, 0x162c3a16U,
    };
    int T4Temp[256] = {
        0xc6a56363U, 0xf8847c7cU, 0xee997777U, 0xf68d7b7bU,
        0xff0df2f2U, 0xd6bd6b6bU, 0xdeb16f6fU, 0x9154c5c5U,
        0x60503030U, 0x02030101U, 0xcea96767U, 0x567d2b2bU,
        0xe719fefeU, 0xb562d7d7U, 0x4de6ababU, 0xec9a7676U,
        0x8f45cacaU, 0x1f9d8282U, 0x8940c9c9U, 0xfa877d7dU,
        0xef15fafaU, 0xb2eb5959U, 0x8ec94747U, 0xfb0bf0f0U,
        0x41ecadadU, 0xb367d4d4U, 0x5ffda2a2U, 0x45eaafafU,
        0x23bf9c9cU, 0x53f7a4a4U, 0xe4967272U, 0x9b5bc0c0U,
        0x75c2b7b7U, 0xe11cfdfdU, 0x3dae9393U, 0x4c6a2626U,
        0x6c5a3636U, 0x7e413f3fU, 0xf502f7f7U, 0x834fccccU,
        0x685c3434U, 0x51f4a5a5U, 0xd134e5e5U, 0xf908f1f1U,
        0xe2937171U, 0xab73d8d8U, 0x62533131U, 0x2a3f1515U,
        0x080c0404U, 0x9552c7c7U, 0x46652323U, 0x9d5ec3c3U,
        0x30281818U, 0x37a19696U, 0x0a0f0505U, 0x2fb59a9aU,
        0x0e090707U, 0x24361212U, 0x1b9b8080U, 0xdf3de2e2U,
        0xcd26ebebU, 0x4e692727U, 0x7fcdb2b2U, 0xea9f7575U,
        0x121b0909U, 0x1d9e8383U, 0x58742c2cU, 0x342e1a1aU,
        0x362d1b1bU, 0xdcb26e6eU, 0xb4ee5a5aU, 0x5bfba0a0U,
        0xa4f65252U, 0x764d3b3bU, 0xb761d6d6U, 0x7dceb3b3U,
        0x527b2929U, 0xdd3ee3e3U, 0x5e712f2fU, 0x13978484U,
        0xa6f55353U, 0xb968d1d1U, 0x00000000U, 0xc12cededU,
        0x40602020U, 0xe31ffcfcU, 0x79c8b1b1U, 0xb6ed5b5bU,
        0xd4be6a6aU, 0x8d46cbcbU, 0x67d9bebeU, 0x724b3939U,
        0x94de4a4aU, 0x98d44c4cU, 0xb0e85858U, 0x854acfcfU,
        0xbb6bd0d0U, 0xc52aefefU, 0x4fe5aaaaU, 0xed16fbfbU,
        0x86c54343U, 0x9ad74d4dU, 0x66553333U, 0x11948585U,
        0x8acf4545U, 0xe910f9f9U, 0x04060202U, 0xfe817f7fU,
        0xa0f05050U, 0x78443c3cU, 0x25ba9f9fU, 0x4be3a8a8U,
        0xa2f35151U, 0x5dfea3a3U, 0x80c04040U, 0x058a8f8fU,
        0x3fad9292U, 0x21bc9d9dU, 0x70483838U, 0xf104f5f5U,
        0x63dfbcbcU, 0x77c1b6b6U, 0xaf75dadaU, 0x42632121U,
        0x20301010U, 0xe51affffU, 0xfd0ef3f3U, 0xbf6dd2d2U,
        0x814ccdcdU, 0x18140c0cU, 0x26351313U, 0xc32fececU,
        0xbee15f5fU, 0x35a29797U, 0x88cc4444U, 0x2e391717U,
        0x9357c4c4U, 0x55f2a7a7U, 0xfc827e7eU, 0x7a473d3dU,
        0xc8ac6464U, 0xbae75d5dU, 0x322b1919U, 0xe6957373U,
        0xc0a06060U, 0x19988181U, 0x9ed14f4fU, 0xa37fdcdcU,
        0x44662222U, 0x547e2a2aU, 0x3bab9090U, 0x0b838888U,
        0x8cca4646U, 0xc729eeeeU, 0x6bd3b8b8U, 0x283c1414U,
        0xa779dedeU, 0xbce25e5eU, 0x161d0b0bU, 0xad76dbdbU,
        0xdb3be0e0U, 0x64563232U, 0x744e3a3aU, 0x141e0a0aU,
        0x92db4949U, 0x0c0a0606U, 0x486c2424U, 0xb8e45c5cU,
        0x9f5dc2c2U, 0xbd6ed3d3U, 0x43efacacU, 0xc4a66262U,
        0x39a89191U, 0x31a49595U, 0xd337e4e4U, 0xf28b7979U,
        0xd532e7e7U, 0x8b43c8c8U, 0x6e593737U, 0xdab76d6dU,
        0x018c8d8dU, 0xb164d5d5U, 0x9cd24e4eU, 0x49e0a9a9U,
        0xd8b46c6cU, 0xacfa5656U, 0xf307f4f4U, 0xcf25eaeaU,
        0xcaaf6565U, 0xf48e7a7aU, 0x47e9aeaeU, 0x10180808U,
        0x6fd5babaU, 0xf0887878U, 0x4a6f2525U, 0x5c722e2eU,
        0x38241c1cU, 0x57f1a6a6U, 0x73c7b4b4U, 0x9751c6c6U,
        0xcb23e8e8U, 0xa17cddddU, 0xe89c7474U, 0x3e211f1fU,
        0x96dd4b4bU, 0x61dcbdbdU, 0x0d868b8bU, 0x0f858a8aU,
        0xe0907070U, 0x7c423e3eU, 0x71c4b5b5U, 0xccaa6666U,
        0x90d84848U, 0x06050303U, 0xf701f6f6U, 0x1c120e0eU,
        0xc2a36161U, 0x6a5f3535U, 0xaef95757U, 0x69d0b9b9U,
        0x17918686U, 0x9958c1c1U, 0x3a271d1dU, 0x27b99e9eU,
        0xd938e1e1U, 0xeb13f8f8U, 0x2bb39898U, 0x22331111U,
        0xd2bb6969U, 0xa970d9d9U, 0x07898e8eU, 0x33a79494U,
        0x2db69b9bU, 0x3c221e1eU, 0x15928787U, 0xc920e9e9U,
        0x8749ceceU, 0xaaff5555U, 0x50782828U, 0xa57adfdfU,
        0x038f8c8cU, 0x59f8a1a1U, 0x09808989U, 0x1a170d0dU,
        0x65dabfbfU, 0xd731e6e6U, 0x84c64242U, 0xd0b86868U,
        0x82c34141U, 0x29b09999U, 0x5a772d2dU, 0x1e110f0fU,
        0x7bcbb0b0U, 0xa8fc5454U, 0x6dd6bbbbU, 0x2c3a1616U,

    };
    for(int i=0; i<256;i++){
        matrizCajaS[i] = matrizCajaSTemp[i];
        T1[i] = T1Temp[i];
        T2[i] = T2Temp[i];
        T3[i] = T3Temp[i];
        T4[i] = T4Temp[i];
    }
}
__device__ void AES_init_decrypt( unsigned char  *matrizCajaS, int *T1, int *T2, int *T3, int *T4){
    unsigned char matrizCajaSTemp[256]={
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
    int T1Temp[256] ={

        0x50a7f451U, 0x5365417eU, 0xc3a4171aU, 0x965e273aU,
        0xcb6bab3bU, 0xf1459d1fU, 0xab58faacU, 0x9303e34bU,
        0x55fa3020U, 0xf66d76adU, 0x9176cc88U, 0x254c02f5U,
        0xfcd7e54fU, 0xd7cb2ac5U, 0x80443526U, 0x8fa362b5U,
        0x495ab1deU, 0x671bba25U, 0x980eea45U, 0xe1c0fe5dU,
        0x02752fc3U, 0x12f04c81U, 0xa397468dU, 0xc6f9d36bU,
        0xe75f8f03U, 0x959c9215U, 0xeb7a6dbfU, 0xda595295U,
        0x2d83bed4U, 0xd3217458U, 0x2969e049U, 0x44c8c98eU,
        0x6a89c275U, 0x78798ef4U, 0x6b3e5899U, 0xdd71b927U,
        0xb64fe1beU, 0x17ad88f0U, 0x66ac20c9U, 0xb43ace7dU,
        0x184adf63U, 0x82311ae5U, 0x60335197U, 0x457f5362U,
        0xe07764b1U, 0x84ae6bbbU, 0x1ca081feU, 0x942b08f9U,
        0x58684870U, 0x19fd458fU, 0x876cde94U, 0xb7f87b52U,
        0x23d373abU, 0xe2024b72U, 0x578f1fe3U, 0x2aab5566U,
        0x0728ebb2U, 0x03c2b52fU, 0x9a7bc586U, 0xa50837d3U,
        0xf2872830U, 0xb2a5bf23U, 0xba6a0302U, 0x5c8216edU,
        0x2b1ccf8aU, 0x92b479a7U, 0xf0f207f3U, 0xa1e2694eU,
        0xcdf4da65U, 0xd5be0506U, 0x1f6234d1U, 0x8afea6c4U,
        0x9d532e34U, 0xa055f3a2U, 0x32e18a05U, 0x75ebf6a4U,
        0x39ec830bU, 0xaaef6040U, 0x069f715eU, 0x51106ebdU,
        0xf98a213eU, 0x3d06dd96U, 0xae053eddU, 0x46bde64dU,
        0xb58d5491U, 0x055dc471U, 0x6fd40604U, 0xff155060U,
        0x24fb9819U, 0x97e9bdd6U, 0xcc434089U, 0x779ed967U,
        0xbd42e8b0U, 0x888b8907U, 0x385b19e7U, 0xdbeec879U,
        0x470a7ca1U, 0xe90f427cU, 0xc91e84f8U, 0x00000000U,
        0x83868009U, 0x48ed2b32U, 0xac70111eU, 0x4e725a6cU,
        0xfbff0efdU, 0x5638850fU, 0x1ed5ae3dU, 0x27392d36U,
        0x64d90f0aU, 0x21a65c68U, 0xd1545b9bU, 0x3a2e3624U,
        0xb1670a0cU, 0x0fe75793U, 0xd296eeb4U, 0x9e919b1bU,
        0x4fc5c080U, 0xa220dc61U, 0x694b775aU, 0x161a121cU,
        0x0aba93e2U, 0xe52aa0c0U, 0x43e0223cU, 0x1d171b12U,
        0x0b0d090eU, 0xadc78bf2U, 0xb9a8b62dU, 0xc8a91e14U,
        0x8519f157U, 0x4c0775afU, 0xbbdd99eeU, 0xfd607fa3U,
        0x9f2601f7U, 0xbcf5725cU, 0xc53b6644U, 0x347efb5bU,
        0x7629438bU, 0xdcc623cbU, 0x68fcedb6U, 0x63f1e4b8U,
        0xcadc31d7U, 0x10856342U, 0x40229713U, 0x2011c684U,
        0x7d244a85U, 0xf83dbbd2U, 0x1132f9aeU, 0x6da129c7U,
        0x4b2f9e1dU, 0xf330b2dcU, 0xec52860dU, 0xd0e3c177U,
        0x6c16b32bU, 0x99b970a9U, 0xfa489411U, 0x2264e947U,
        0xc48cfca8U, 0x1a3ff0a0U, 0xd82c7d56U, 0xef903322U,
        0xc74e4987U, 0xc1d138d9U, 0xfea2ca8cU, 0x360bd498U,
        0xcf81f5a6U, 0x28de7aa5U, 0x268eb7daU, 0xa4bfad3fU,
        0xe49d3a2cU, 0x0d927850U, 0x9bcc5f6aU, 0x62467e54U,
        0xc2138df6U, 0xe8b8d890U, 0x5ef7392eU, 0xf5afc382U,
        0xbe805d9fU, 0x7c93d069U, 0xa92dd56fU, 0xb31225cfU,
        0x3b99acc8U, 0xa77d1810U, 0x6e639ce8U, 0x7bbb3bdbU,
        0x097826cdU, 0xf418596eU, 0x01b79aecU, 0xa89a4f83U,
        0x656e95e6U, 0x7ee6ffaaU, 0x08cfbc21U, 0xe6e815efU,
        0xd99be7baU, 0xce366f4aU, 0xd4099feaU, 0xd67cb029U,
        0xafb2a431U, 0x31233f2aU, 0x3094a5c6U, 0xc066a235U,
        0x37bc4e74U, 0xa6ca82fcU, 0xb0d090e0U, 0x15d8a733U,
        0x4a9804f1U, 0xf7daec41U, 0x0e50cd7fU, 0x2ff69117U,
        0x8dd64d76U, 0x4db0ef43U, 0x544daaccU, 0xdf0496e4U,
        0xe3b5d19eU, 0x1b886a4cU, 0xb81f2cc1U, 0x7f516546U,
        0x04ea5e9dU, 0x5d358c01U, 0x737487faU, 0x2e410bfbU,
        0x5a1d67b3U, 0x52d2db92U, 0x335610e9U, 0x1347d66dU,
        0x8c61d79aU, 0x7a0ca137U, 0x8e14f859U, 0x893c13ebU,
        0xee27a9ceU, 0x35c961b7U, 0xede51ce1U, 0x3cb1477aU,
        0x59dfd29cU, 0x3f73f255U, 0x79ce1418U, 0xbf37c773U,
        0xeacdf753U, 0x5baafd5fU, 0x146f3ddfU, 0x86db4478U,
        0x81f3afcaU, 0x3ec468b9U, 0x2c342438U, 0x5f40a3c2U,
        0x72c31d16U, 0x0c25e2bcU, 0x8b493c28U, 0x41950dffU,
        0x7101a839U, 0xdeb30c08U, 0x9ce4b4d8U, 0x90c15664U,
        0x6184cb7bU, 0x70b632d5U, 0x745c6c48U, 0x4257b8d0U,   
    
        };
   
    int T2Temp[256] = {

        0xa7f45150U, 0x65417e53U, 0xa4171ac3U, 0x5e273a96U,
        0x6bab3bcbU, 0x459d1ff1U, 0x58faacabU, 0x03e34b93U,
        0xfa302055U, 0x6d76adf6U, 0x76cc8891U, 0x4c02f525U,
        0xd7e54ffcU, 0xcb2ac5d7U, 0x44352680U, 0xa362b58fU,
        0x5ab1de49U, 0x1bba2567U, 0x0eea4598U, 0xc0fe5de1U,
        0x752fc302U, 0xf04c8112U, 0x97468da3U, 0xf9d36bc6U,
        0x5f8f03e7U, 0x9c921595U, 0x7a6dbfebU, 0x595295daU,
        0x83bed42dU, 0x217458d3U, 0x69e04929U, 0xc8c98e44U,
        0x89c2756aU, 0x798ef478U, 0x3e58996bU, 0x71b927ddU,
        0x4fe1beb6U, 0xad88f017U, 0xac20c966U, 0x3ace7db4U,
        0x4adf6318U, 0x311ae582U, 0x33519760U, 0x7f536245U,
        0x7764b1e0U, 0xae6bbb84U, 0xa081fe1cU, 0x2b08f994U,
        0x68487058U, 0xfd458f19U, 0x6cde9487U, 0xf87b52b7U,
        0xd373ab23U, 0x024b72e2U, 0x8f1fe357U, 0xab55662aU,
        0x28ebb207U, 0xc2b52f03U, 0x7bc5869aU, 0x0837d3a5U,
        0x872830f2U, 0xa5bf23b2U, 0x6a0302baU, 0x8216ed5cU,
        0x1ccf8a2bU, 0xb479a792U, 0xf207f3f0U, 0xe2694ea1U,
        0xf4da65cdU, 0xbe0506d5U, 0x6234d11fU, 0xfea6c48aU,
        0x532e349dU, 0x55f3a2a0U, 0xe18a0532U, 0xebf6a475U,
        0xec830b39U, 0xef6040aaU, 0x9f715e06U, 0x106ebd51U,
        0x8a213ef9U, 0x06dd963dU, 0x053eddaeU, 0xbde64d46U,
        0x8d5491b5U, 0x5dc47105U, 0xd406046fU, 0x155060ffU,
        0xfb981924U, 0xe9bdd697U, 0x434089ccU, 0x9ed96777U,
        0x42e8b0bdU, 0x8b890788U, 0x5b19e738U, 0xeec879dbU,
        0x0a7ca147U, 0x0f427ce9U, 0x1e84f8c9U, 0x00000000U,
        0x86800983U, 0xed2b3248U, 0x70111eacU, 0x725a6c4eU,
        0xff0efdfbU, 0x38850f56U, 0xd5ae3d1eU, 0x392d3627U,
        0xd90f0a64U, 0xa65c6821U, 0x545b9bd1U, 0x2e36243aU,
        0x670a0cb1U, 0xe757930fU, 0x96eeb4d2U, 0x919b1b9eU,
        0xc5c0804fU, 0x20dc61a2U, 0x4b775a69U, 0x1a121c16U,
        0xba93e20aU, 0x2aa0c0e5U, 0xe0223c43U, 0x171b121dU,
        0x0d090e0bU, 0xc78bf2adU, 0xa8b62db9U, 0xa91e14c8U,
        0x19f15785U, 0x0775af4cU, 0xdd99eebbU, 0x607fa3fdU,
        0x2601f79fU, 0xf5725cbcU, 0x3b6644c5U, 0x7efb5b34U,
        0x29438b76U, 0xc623cbdcU, 0xfcedb668U, 0xf1e4b863U,
        0xdc31d7caU, 0x85634210U, 0x22971340U, 0x11c68420U,
        0x244a857dU, 0x3dbbd2f8U, 0x32f9ae11U, 0xa129c76dU,
        0x2f9e1d4bU, 0x30b2dcf3U, 0x52860decU, 0xe3c177d0U,
        0x16b32b6cU, 0xb970a999U, 0x489411faU, 0x64e94722U,
        0x8cfca8c4U, 0x3ff0a01aU, 0x2c7d56d8U, 0x903322efU,
        0x4e4987c7U, 0xd138d9c1U, 0xa2ca8cfeU, 0x0bd49836U,
        0x81f5a6cfU, 0xde7aa528U, 0x8eb7da26U, 0xbfad3fa4U,
        0x9d3a2ce4U, 0x9278500dU, 0xcc5f6a9bU, 0x467e5462U,
        0x138df6c2U, 0xb8d890e8U, 0xf7392e5eU, 0xafc382f5U,
        0x805d9fbeU, 0x93d0697cU, 0x2dd56fa9U, 0x1225cfb3U,
        0x99acc83bU, 0x7d1810a7U, 0x639ce86eU, 0xbb3bdb7bU,
        0x7826cd09U, 0x18596ef4U, 0xb79aec01U, 0x9a4f83a8U,
        0x6e95e665U, 0xe6ffaa7eU, 0xcfbc2108U, 0xe815efe6U,
        0x9be7bad9U, 0x366f4aceU, 0x099fead4U, 0x7cb029d6U,
        0xb2a431afU, 0x233f2a31U, 0x94a5c630U, 0x66a235c0U,
        0xbc4e7437U, 0xca82fca6U, 0xd090e0b0U, 0xd8a73315U,
        0x9804f14aU, 0xdaec41f7U, 0x50cd7f0eU, 0xf691172fU,
        0xd64d768dU, 0xb0ef434dU, 0x4daacc54U, 0x0496e4dfU,
        0xb5d19ee3U, 0x886a4c1bU, 0x1f2cc1b8U, 0x5165467fU,
        0xea5e9d04U, 0x358c015dU, 0x7487fa73U, 0x410bfb2eU,
        0x1d67b35aU, 0xd2db9252U, 0x5610e933U, 0x47d66d13U,
        0x61d79a8cU, 0x0ca1377aU, 0x14f8598eU, 0x3c13eb89U,
        0x27a9ceeeU, 0xc961b735U, 0xe51ce1edU, 0xb1477a3cU,
        0xdfd29c59U, 0x73f2553fU, 0xce141879U, 0x37c773bfU,
        0xcdf753eaU, 0xaafd5f5bU, 0x6f3ddf14U, 0xdb447886U,
        0xf3afca81U, 0xc468b93eU, 0x3424382cU, 0x40a3c25fU,
        0xc31d1672U, 0x25e2bc0cU, 0x493c288bU, 0x950dff41U,
        0x01a83971U, 0xb30c08deU, 0xe4b4d89cU, 0xc1566490U,
        0x84cb7b61U, 0xb632d570U, 0x5c6c4874U, 0x57b8d042U,

    };
    int T3Temp[256] = {

        0xf45150a7U, 0x417e5365U, 0x171ac3a4U, 0x273a965eU,
        0xab3bcb6bU, 0x9d1ff145U, 0xfaacab58U, 0xe34b9303U,
        0x302055faU, 0x76adf66dU, 0xcc889176U, 0x02f5254cU,
        0xe54ffcd7U, 0x2ac5d7cbU, 0x35268044U, 0x62b58fa3U,
        0xb1de495aU, 0xba25671bU, 0xea45980eU, 0xfe5de1c0U,
        0x2fc30275U, 0x4c8112f0U, 0x468da397U, 0xd36bc6f9U,
        0x8f03e75fU, 0x9215959cU, 0x6dbfeb7aU, 0x5295da59U,
        0xbed42d83U, 0x7458d321U, 0xe0492969U, 0xc98e44c8U,
        0xc2756a89U, 0x8ef47879U, 0x58996b3eU, 0xb927dd71U,
        0xe1beb64fU, 0x88f017adU, 0x20c966acU, 0xce7db43aU,
        0xdf63184aU, 0x1ae58231U, 0x51976033U, 0x5362457fU,
        0x64b1e077U, 0x6bbb84aeU, 0x81fe1ca0U, 0x08f9942bU,
        0x48705868U, 0x458f19fdU, 0xde94876cU, 0x7b52b7f8U,
        0x73ab23d3U, 0x4b72e202U, 0x1fe3578fU, 0x55662aabU,
        0xebb20728U, 0xb52f03c2U, 0xc5869a7bU, 0x37d3a508U,
        0x2830f287U, 0xbf23b2a5U, 0x0302ba6aU, 0x16ed5c82U,
        0xcf8a2b1cU, 0x79a792b4U, 0x07f3f0f2U, 0x694ea1e2U,
        0xda65cdf4U, 0x0506d5beU, 0x34d11f62U, 0xa6c48afeU,
        0x2e349d53U, 0xf3a2a055U, 0x8a0532e1U, 0xf6a475ebU,
        0x830b39ecU, 0x6040aaefU, 0x715e069fU, 0x6ebd5110U,
        0x213ef98aU, 0xdd963d06U, 0x3eddae05U, 0xe64d46bdU,
        0x5491b58dU, 0xc471055dU, 0x06046fd4U, 0x5060ff15U,
        0x981924fbU, 0xbdd697e9U, 0x4089cc43U, 0xd967779eU,
        0xe8b0bd42U, 0x8907888bU, 0x19e7385bU, 0xc879dbeeU,
        0x7ca1470aU, 0x427ce90fU, 0x84f8c91eU, 0x00000000U,
        0x80098386U, 0x2b3248edU, 0x111eac70U, 0x5a6c4e72U,
        0x0efdfbffU, 0x850f5638U, 0xae3d1ed5U, 0x2d362739U,
        0x0f0a64d9U, 0x5c6821a6U, 0x5b9bd154U, 0x36243a2eU,
        0x0a0cb167U, 0x57930fe7U, 0xeeb4d296U, 0x9b1b9e91U,
        0xc0804fc5U, 0xdc61a220U, 0x775a694bU, 0x121c161aU,
        0x93e20abaU, 0xa0c0e52aU, 0x223c43e0U, 0x1b121d17U,
        0x090e0b0dU, 0x8bf2adc7U, 0xb62db9a8U, 0x1e14c8a9U,
        0xf1578519U, 0x75af4c07U, 0x99eebbddU, 0x7fa3fd60U,
        0x01f79f26U, 0x725cbcf5U, 0x6644c53bU, 0xfb5b347eU,
        0x438b7629U, 0x23cbdcc6U, 0xedb668fcU, 0xe4b863f1U,
        0x31d7cadcU, 0x63421085U, 0x97134022U, 0xc6842011U,
        0x4a857d24U, 0xbbd2f83dU, 0xf9ae1132U, 0x29c76da1U,
        0x9e1d4b2fU, 0xb2dcf330U, 0x860dec52U, 0xc177d0e3U,
        0xb32b6c16U, 0x70a999b9U, 0x9411fa48U, 0xe9472264U,
        0xfca8c48cU, 0xf0a01a3fU, 0x7d56d82cU, 0x3322ef90U,
        0x4987c74eU, 0x38d9c1d1U, 0xca8cfea2U, 0xd498360bU,
        0xf5a6cf81U, 0x7aa528deU, 0xb7da268eU, 0xad3fa4bfU,
        0x3a2ce49dU, 0x78500d92U, 0x5f6a9bccU, 0x7e546246U,
        0x8df6c213U, 0xd890e8b8U, 0x392e5ef7U, 0xc382f5afU,
        0x5d9fbe80U, 0xd0697c93U, 0xd56fa92dU, 0x25cfb312U,
        0xacc83b99U, 0x1810a77dU, 0x9ce86e63U, 0x3bdb7bbbU,
        0x26cd0978U, 0x596ef418U, 0x9aec01b7U, 0x4f83a89aU,
        0x95e6656eU, 0xffaa7ee6U, 0xbc2108cfU, 0x15efe6e8U,
        0xe7bad99bU, 0x6f4ace36U, 0x9fead409U, 0xb029d67cU,
        0xa431afb2U, 0x3f2a3123U, 0xa5c63094U, 0xa235c066U,
        0x4e7437bcU, 0x82fca6caU, 0x90e0b0d0U, 0xa73315d8U,
        0x04f14a98U, 0xec41f7daU, 0xcd7f0e50U, 0x91172ff6U,
        0x4d768dd6U, 0xef434db0U, 0xaacc544dU, 0x96e4df04U,
        0xd19ee3b5U, 0x6a4c1b88U, 0x2cc1b81fU, 0x65467f51U,
        0x5e9d04eaU, 0x8c015d35U, 0x87fa7374U, 0x0bfb2e41U,
        0x67b35a1dU, 0xdb9252d2U, 0x10e93356U, 0xd66d1347U,
        0xd79a8c61U, 0xa1377a0cU, 0xf8598e14U, 0x13eb893cU,
        0xa9ceee27U, 0x61b735c9U, 0x1ce1ede5U, 0x477a3cb1U,
        0xd29c59dfU, 0xf2553f73U, 0x141879ceU, 0xc773bf37U,
        0xf753eacdU, 0xfd5f5baaU, 0x3ddf146fU, 0x447886dbU,
        0xafca81f3U, 0x68b93ec4U, 0x24382c34U, 0xa3c25f40U,
        0x1d1672c3U, 0xe2bc0c25U, 0x3c288b49U, 0x0dff4195U,
        0xa8397101U, 0x0c08deb3U, 0xb4d89ce4U, 0x566490c1U,
        0xcb7b6184U, 0x32d570b6U, 0x6c48745cU, 0xb8d04257U,

       };
    int T4Temp[256] = {

        0x5150a7f4U, 0x7e536541U, 0x1ac3a417U, 0x3a965e27U,
        0x3bcb6babU, 0x1ff1459dU, 0xacab58faU, 0x4b9303e3U,
        0x2055fa30U, 0xadf66d76U, 0x889176ccU, 0xf5254c02U,
        0x4ffcd7e5U, 0xc5d7cb2aU, 0x26804435U, 0xb58fa362U,
        0xde495ab1U, 0x25671bbaU, 0x45980eeaU, 0x5de1c0feU,
        0xc302752fU, 0x8112f04cU, 0x8da39746U, 0x6bc6f9d3U,
        0x03e75f8fU, 0x15959c92U, 0xbfeb7a6dU, 0x95da5952U,
        0xd42d83beU, 0x58d32174U, 0x492969e0U, 0x8e44c8c9U,
        0x756a89c2U, 0xf478798eU, 0x996b3e58U, 0x27dd71b9U,
        0xbeb64fe1U, 0xf017ad88U, 0xc966ac20U, 0x7db43aceU,
        0x63184adfU, 0xe582311aU, 0x97603351U, 0x62457f53U,
        0xb1e07764U, 0xbb84ae6bU, 0xfe1ca081U, 0xf9942b08U,
        0x70586848U, 0x8f19fd45U, 0x94876cdeU, 0x52b7f87bU,
        0xab23d373U, 0x72e2024bU, 0xe3578f1fU, 0x662aab55U,
        0xb20728ebU, 0x2f03c2b5U, 0x869a7bc5U, 0xd3a50837U,
        0x30f28728U, 0x23b2a5bfU, 0x02ba6a03U, 0xed5c8216U,
        0x8a2b1ccfU, 0xa792b479U, 0xf3f0f207U, 0x4ea1e269U,
        0x65cdf4daU, 0x06d5be05U, 0xd11f6234U, 0xc48afea6U,
        0x349d532eU, 0xa2a055f3U, 0x0532e18aU, 0xa475ebf6U,
        0x0b39ec83U, 0x40aaef60U, 0x5e069f71U, 0xbd51106eU,
        0x3ef98a21U, 0x963d06ddU, 0xddae053eU, 0x4d46bde6U,
        0x91b58d54U, 0x71055dc4U, 0x046fd406U, 0x60ff1550U,
        0x1924fb98U, 0xd697e9bdU, 0x89cc4340U, 0x67779ed9U,
        0xb0bd42e8U, 0x07888b89U, 0xe7385b19U, 0x79dbeec8U,
        0xa1470a7cU, 0x7ce90f42U, 0xf8c91e84U, 0x00000000U,
        0x09838680U, 0x3248ed2bU, 0x1eac7011U, 0x6c4e725aU,
        0xfdfbff0eU, 0x0f563885U, 0x3d1ed5aeU, 0x3627392dU,
        0x0a64d90fU, 0x6821a65cU, 0x9bd1545bU, 0x243a2e36U,
        0x0cb1670aU, 0x930fe757U, 0xb4d296eeU, 0x1b9e919bU,
        0x804fc5c0U, 0x61a220dcU, 0x5a694b77U, 0x1c161a12U,
        0xe20aba93U, 0xc0e52aa0U, 0x3c43e022U, 0x121d171bU,
        0x0e0b0d09U, 0xf2adc78bU, 0x2db9a8b6U, 0x14c8a91eU,
        0x578519f1U, 0xaf4c0775U, 0xeebbdd99U, 0xa3fd607fU,
        0xf79f2601U, 0x5cbcf572U, 0x44c53b66U, 0x5b347efbU,
        0x8b762943U, 0xcbdcc623U, 0xb668fcedU, 0xb863f1e4U,
        0xd7cadc31U, 0x42108563U, 0x13402297U, 0x842011c6U,
        0x857d244aU, 0xd2f83dbbU, 0xae1132f9U, 0xc76da129U,
        0x1d4b2f9eU, 0xdcf330b2U, 0x0dec5286U, 0x77d0e3c1U,
        0x2b6c16b3U, 0xa999b970U, 0x11fa4894U, 0x472264e9U,
        0xa8c48cfcU, 0xa01a3ff0U, 0x56d82c7dU, 0x22ef9033U,
        0x87c74e49U, 0xd9c1d138U, 0x8cfea2caU, 0x98360bd4U,
        0xa6cf81f5U, 0xa528de7aU, 0xda268eb7U, 0x3fa4bfadU,
        0x2ce49d3aU, 0x500d9278U, 0x6a9bcc5fU, 0x5462467eU,
        0xf6c2138dU, 0x90e8b8d8U, 0x2e5ef739U, 0x82f5afc3U,
        0x9fbe805dU, 0x697c93d0U, 0x6fa92dd5U, 0xcfb31225U,
        0xc83b99acU, 0x10a77d18U, 0xe86e639cU, 0xdb7bbb3bU,
        0xcd097826U, 0x6ef41859U, 0xec01b79aU, 0x83a89a4fU,
        0xe6656e95U, 0xaa7ee6ffU, 0x2108cfbcU, 0xefe6e815U,
        0xbad99be7U, 0x4ace366fU, 0xead4099fU, 0x29d67cb0U,
        0x31afb2a4U, 0x2a31233fU, 0xc63094a5U, 0x35c066a2U,
        0x7437bc4eU, 0xfca6ca82U, 0xe0b0d090U, 0x3315d8a7U,
        0xf14a9804U, 0x41f7daecU, 0x7f0e50cdU, 0x172ff691U,
        0x768dd64dU, 0x434db0efU, 0xcc544daaU, 0xe4df0496U,
        0x9ee3b5d1U, 0x4c1b886aU, 0xc1b81f2cU, 0x467f5165U,
        0x9d04ea5eU, 0x015d358cU, 0xfa737487U, 0xfb2e410bU,
        0xb35a1d67U, 0x9252d2dbU, 0xe9335610U, 0x6d1347d6U,
        0x9a8c61d7U, 0x377a0ca1U, 0x598e14f8U, 0xeb893c13U,
        0xceee27a9U, 0xb735c961U, 0xe1ede51cU, 0x7a3cb147U,
        0x9c59dfd2U, 0x553f73f2U, 0x1879ce14U, 0x73bf37c7U,
        0x53eacdf7U, 0x5f5baafdU, 0xdf146f3dU, 0x7886db44U,
        0xca81f3afU, 0xb93ec468U, 0x382c3424U, 0xc25f40a3U,
        0x1672c31dU, 0xbc0c25e2U, 0x288b493cU, 0xff41950dU,
        0x397101a8U, 0x08deb30cU, 0xd89ce4b4U, 0x6490c156U,
        0x7b6184cbU, 0xd570b632U, 0x48745c6cU, 0xd04257b8U,

    };
    for(int i=0; i<256;i++){
        matrizCajaS[i] = matrizCajaSTemp[i];
        T1[i] = T1Temp[i];
        T2[i] = T2Temp[i];
        T3[i] = T3Temp[i];
        T4[i] = T4Temp[i];
    }
}
__device__ void AES_128(aesBlock *m, unsigned long long mlen, unsigned int *keys, int index){
    __shared__ unsigned char matrizCajaS[256];
    __shared__ int T1[256]; 
    __shared__ int T2[256]; 
    __shared__ int T3[256]; 
    __shared__ int T4[256];
        if(threadIdx.x == 0 || index==0 ){ //le damos chance de que cada instancia logre inicializar cada valor minimo una vez
            AES_init(matrizCajaS, T1, T2, T3, T4);
        }
        
        int shifttab[16]= {
            0, 5, 10, 15,   
            4,  9,  14,  3,  
            8,  13,  2,  7,
            12,  1,  6,  11, 
        };
        
        // __syncthreads(); preguntar porque esto hace que nada salga
        unsigned int block[4];

        for (int i = 0 ; i< 4 ; i++){
            block[i]= m[index].block[i];
        }
        addRoundKey( block, keys,0);
        for (int j = 1; j < 10; j++){
            // subBytes(block, matrizCajaS);
            shiftRows(block, shifttab);
            
            //mixColumns(block);
            subBytesMixColumns(block,  T1,  T2,  T3,  T4);
            
            //añadimos llave de ronda
            addRoundKey( block, keys,j); // 
        }

        subBytes(block, matrizCajaS);

        shiftRows(block, shifttab);

        addRoundKey( block, keys,10);
        for (int i = 0 ; i< 4 ; i++){
            m[index].block[i]= block[i];
        }
}

__device__ void AES_128Decrypt(aesBlock *m, unsigned long long mlen, unsigned int *keys, int index ){
    __shared__ unsigned char matrizCajaS[256];
    __shared__ int T1[256]; 
    __shared__ int T2[256]; 
    __shared__ int T3[256]; 
    __shared__ int T4[256];
        if(threadIdx.x == 0 || index==0 ){
            AES_init_decrypt(matrizCajaS, T1, T2, T3, T4);
        }
        
            int shifttab[16]= {
                0, 13,  10,  7,   
                4,  1,   14,  11,  
                8,  5,   2,  15,
                12,  9,   6,  3, 
            };
        
        __syncthreads();
        unsigned int block[4];

        for (int i = 0 ; i< 4 ; i++){
            block[i]= m[index].block[i];
        }

        addRoundKey( block, keys,0);



        for (int j = 1; j < 10; j++){
            // subBytes(block, matrizCajaS);
            shiftRows(block, shifttab);
            
            //mixColumns(block);
            subBytesMixColumns(block,  T1,  T2,  T3,  T4);
            
            //añadimos llave de ronda
            addRoundKey( block, keys,j); // 

        }

        subBytes(block, matrizCajaS);

        shiftRows(block, shifttab);

        addRoundKey( block, keys,10);
        for (int i = 0 ; i< 4 ; i++){
            m[index].block[i]= block[i];
        }

}
__global__ void Encrypt(aesBlock *m, unsigned long long mlen, unsigned int *keys){
    int index = blockDim.x*blockIdx.x + threadIdx.x;
    
    if( index<mlen/16){
        AES_128(m, mlen, keys,index);
    }
}



void AES128Encrypt(aesBlock *m, unsigned long long mlen, unsigned int *keys){
    aesBlock *mCuda;
    unsigned int *keysCuda;

    int sizeMessage = (mlen/16)*sizeof(class aesBlock);
    int sizeKeys = 11*4*sizeof(unsigned int);
    
    cudaMalloc(&mCuda, sizeMessage);
    cudaMalloc(&keysCuda, sizeKeys);

    cudaMemcpy(mCuda,m,sizeMessage,cudaMemcpyDefault);
    cudaMemcpy(keysCuda,keys,sizeKeys,cudaMemcpyDefault);

    dim3 nb( (unsigned int) ceil((double) mlen/16.0) ) ; 
    dim3 nt(2); 

    Encrypt<<<nb, nt>>>(mCuda, mlen,keysCuda);

    cudaMemcpy(m, mCuda, sizeMessage, cudaMemcpyDefault);

    cudaFree(mCuda); cudaFree(keysCuda);  
}


__global__ void OCB128EncryptRandomAcces(aesBlock *m,aesBlock *delta, aesBlock *S,  unsigned long long mlen,unsigned long long mlenReal, unsigned long long deltalen, unsigned int *keys){
    int index = blockDim.x*blockIdx.x + threadIdx.x;
    if( index<mlen){
        __syncthreads();
        if(index == (mlen - 2)){
            if(mlenReal%16==0){
                
                XOR_128(m[index].block,delta[index].block);

                AES_128(m, mlen, keys,index);
        
                XOR_128(m[index].block,delta[index].block);
                
            }else{
                aesBlock *aesTemp = new aesBlock [1];
                
                aesTemp[0].block[0] = delta[index].block[0];
                aesTemp[0].block[1] = delta[index].block[1];
                aesTemp[0].block[2] = delta[index].block[2];
                aesTemp[0].block[3] = delta[index].block[3];

                AES_128( aesTemp, mlen, keys,0);
        
                XOR_128(m[index].block,aesTemp[0].block);
            }

        }
        else{


            XOR_128(m[index].block,delta[index].block);
            
            AES_128(m, mlen, keys,index);
            
            if(index == mlen-1){
                XOR_128(m[index].block,S[0].block);

            }else{
                XOR_128(m[index].block,delta[index].block);
            }

        }
    }
}

__global__ void OCB128EncryptRandomAccesAsociatedData(aesBlock *ad,aesBlock *delta, unsigned long long ad_len_temp, unsigned long long ad_len, unsigned int *keys){
    int index = blockDim.x*blockIdx.x + threadIdx.x;
    if( index<ad_len_temp){
        if(index == ad_len_temp-1){
            if(ad_len%16!=0){
                
	        union { uint32_t u32[4]; uint8_t u8[16]; } tmp;

                tmp.u32[0]=0; 
                tmp.u32[1]=0; 
                tmp.u32[2]=0; 
                tmp.u32[3]=0; 
				memcpy(tmp.u8, ad[index].block, ad_len%16);
				tmp.u8[ad_len%16] = (unsigned char)0x80u;
                
                XOR2_128(ad[index].block, delta[index].block,tmp.u32 );
                AES_128(ad, ad_len, keys,index);
            }else{
                XOR_128(ad[index].block,delta[index].block);
                AES_128(ad, ad_len, keys,index);
            }
        }else{
            XOR_128(ad[index].block,delta[index].block);
            AES_128(ad, ad_len, keys,index);
        }
    }
}

__global__ void OCB128DecryptRandomAcces(aesBlock *m,aesBlock *delta, aesBlock *S,  unsigned long long mlen,unsigned long long mlenReal, unsigned long long deltalen, unsigned int *keys, unsigned int *encrypt_keys ){
    int index = blockDim.x*blockIdx.x + threadIdx.x;
    if( index<mlen){
        __syncthreads();
        if(index == (mlen - 1)){
            if(mlenReal%16==0){
                XOR_128(m[index].block,delta[index].block);
                AES_128Decrypt(m, mlen, keys,index);
                XOR_128(m[index].block,delta[index].block);
                
            }else{
                aesBlock *aesTemp = new aesBlock [1];
                
                aesTemp[0].block[0] = delta[index].block[0];
                aesTemp[0].block[1] = delta[index].block[1];
                aesTemp[0].block[2] = delta[index].block[2];
                aesTemp[0].block[3] = delta[index].block[3];
                AES_128( aesTemp, mlen, encrypt_keys,0);
        
                XOR_128(m[index].block,aesTemp[0].block);
            }

        }
        else{


            XOR_128(m[index].block,delta[index].block);
            
            AES_128Decrypt(m, mlen, keys,index);
            
            XOR_128(m[index].block,delta[index].block);

        }
    }
}
void OCBRandomAccess(aesBlock *m,aesBlock *delta, aesBlock *S, unsigned long long mlen, const unsigned long long mlenReal, unsigned long long deltalen, unsigned int *keys,unsigned int *decrypt_keys, int encrypt){
    aesBlock *mCuda;
    aesBlock *SCuda;
    aesBlock *deltaCuda;
    unsigned int *keysCuda;
    unsigned int *decrypt_keysCuda;

    int sizeMessage = (mlen)*sizeof(class aesBlock);
    int sizeDelta = (deltalen)*sizeof(class aesBlock);
    int sizeS = sizeof(class aesBlock);
    int sizeKeys = 11*4*sizeof(unsigned int);

    cudaMalloc(&mCuda, sizeMessage);
    cudaMalloc(&keysCuda, sizeKeys);
    cudaMalloc(&decrypt_keysCuda, sizeKeys);
    cudaMalloc(&deltaCuda, sizeDelta);
    cudaMalloc(&SCuda, sizeS);

    cudaMemcpy(mCuda,m,sizeMessage,cudaMemcpyDefault);
    cudaMemcpy(deltaCuda,delta,sizeDelta,cudaMemcpyDefault);
    cudaMemcpy(keysCuda,keys,sizeKeys,cudaMemcpyDefault);
    cudaMemcpy(decrypt_keysCuda,decrypt_keys,sizeKeys,cudaMemcpyDefault);
    cudaMemcpy(SCuda,S,sizeS,cudaMemcpyDefault);

    dim3 nb( (unsigned int) ceil((double) mlenReal/16.0 + 1) ) ; 
    dim3 nt(2); 
     
    if(encrypt)
        OCB128EncryptRandomAcces<<<nb, nt>>>(mCuda,deltaCuda,SCuda, mlen, mlenReal, deltalen,keysCuda);
    else
        OCB128DecryptRandomAcces<<<nb, nt>>>(mCuda, deltaCuda, SCuda,mlen, mlenReal, deltalen,decrypt_keysCuda, keysCuda);

    cudaMemcpy(m, mCuda, sizeMessage, cudaMemcpyDefault);

    cudaFree(mCuda); 
    cudaFree(keysCuda);  
    cudaFree(deltaCuda);
    cudaFree(decrypt_keysCuda);
    cudaFree(SCuda);
}

void OCBRandomAccessAsociatedData(aesBlock *ad, aesBlock *delta,  const unsigned long long ad_len_temp, unsigned long long ad_len, unsigned int *keys){

    aesBlock *adCuda;
    aesBlock *deltaCuda;
    unsigned int *keysCuda;

    int sizeAd = ad_len_temp*sizeof(class aesBlock);
    int sizeDelta = (ad_len_temp)*sizeof(class aesBlock);
    int sizeKeys = 11*4*sizeof(unsigned int);

    cudaMalloc(&adCuda, sizeAd);
    cudaMalloc(&keysCuda, sizeKeys);
    cudaMalloc(&deltaCuda, sizeDelta);

    cudaMemcpy(adCuda,ad,sizeAd,cudaMemcpyDefault);
    cudaMemcpy(keysCuda,keys,sizeKeys,cudaMemcpyDefault);
    cudaMemcpy(deltaCuda,delta,sizeDelta,cudaMemcpyDefault);

    dim3 nb( (unsigned int) ceil((double) ad_len/16.0) ) ; 
    dim3 nt(2); 

    OCB128EncryptRandomAccesAsociatedData<<<nb, nt>>>(adCuda, deltaCuda, ad_len_temp, ad_len,keysCuda);
    
    cudaMemcpy(ad, adCuda, sizeAd, cudaMemcpyDefault);

    cudaFree(adCuda); 
    cudaFree(keysCuda);  
    cudaFree(deltaCuda); 
}


__global__ void OCB128DecryptRandomAccesGetTag(aesBlock *m,aesBlock *delta, aesBlock *S, unsigned int *keys){
    int index = blockDim.x*blockIdx.x + threadIdx.x;
    if( index==0){
        __syncthreads();
        //Calculate tag 
        XOR2_128(m[0].block,m[0].block,delta[0].block);
        AES_128(m, 1, keys,0);

        XOR2_128(m[0].block,m[0].block,S[0].block);

    }
}
void OCBRandomAccessGetTag(aesBlock *m,aesBlock *delta, aesBlock *S, unsigned int *keys){
    aesBlock *mCuda;
    aesBlock *SCuda;
    aesBlock *deltaCuda;
    unsigned int *keysCuda;

    int sizeMessage = sizeof(class aesBlock);
    int sizeDelta = sizeof(class aesBlock);
    int sizeS = sizeof(class aesBlock);
    int sizeKeys = 11*4*sizeof(unsigned int);

    cudaMalloc(&mCuda, sizeMessage);
    cudaMalloc(&keysCuda, sizeKeys);
    cudaMalloc(&deltaCuda, sizeDelta);
    cudaMalloc(&SCuda, sizeS);

    cudaMemcpy(mCuda,m,sizeMessage,cudaMemcpyDefault);
    cudaMemcpy(deltaCuda,delta,sizeDelta,cudaMemcpyDefault);
    cudaMemcpy(keysCuda,keys,sizeKeys,cudaMemcpyDefault);
    cudaMemcpy(SCuda,S,sizeS,cudaMemcpyDefault);

    dim3 nb( 1 ) ; 
    dim3 nt(2); 
     

    OCB128DecryptRandomAccesGetTag<<<nb, nt>>>(mCuda,deltaCuda,SCuda,keysCuda);
    
    cudaMemcpy(m, mCuda, sizeMessage, cudaMemcpyDefault);
    
    cudaFree(mCuda); 
    cudaFree(keysCuda);  
    cudaFree(deltaCuda);
    cudaFree(SCuda);
}


static inline unsigned ntz(unsigned x) {
    static const unsigned char tz_table[32] =
    { 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
     31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
    return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
}


void getDelta(ae_ctx *ctx, block offset_temp,  aesBlock* delta, unsigned long long pt_len, int final){
    
    block offset; 
    offset = offset_temp;
    unsigned i,k;
    int BPI=8;
    i = pt_len/(BPI*16);
    int j = 0;


    if (i) {

    	block oa[BPI];
    	oa[BPI-1] = offset;
        unsigned block_num;
		do {
            block_num += BPI;
			oa[0] = xor_block(oa[BPI-1], ctx->L[0]);
			oa[1] = xor_block(oa[0], ctx->L[1]);
			oa[2] = xor_block(oa[1], ctx->L[0]);
			#if BPI == 4
				oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
			#elif BPI == 8
				oa[3] = xor_block(oa[2], ctx->L[2]);
				oa[4] = xor_block(oa[1], ctx->L[2]);
				oa[5] = xor_block(oa[0], ctx->L[2]);
				oa[6] = xor_block(oa[7], ctx->L[2]);
				oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
			#endif

            _mm_store_si128 ((__m128i*)delta[BPI*j].block, oa[0]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 1].block, oa[1]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 2].block, oa[2]);
            #if BPI == 4
                _mm_store_si128 ((__m128i*)delta[BPI*j+ 3].block, oa[3]);
            #elif BPI == 8
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 3].block, oa[3]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 4].block, oa[4]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 5].block, oa[5]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 6].block, oa[6]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 7].block, oa[7]);
            #endif
            j++;
		} while (--i);
    }

    if (final) {
		block oa[BPI];

        /* Process remaining plaintext and compute its tag contribution    */
        unsigned remaining = ((unsigned)pt_len) % (BPI*16);
        k = 0;                      /* How many blocks in ta[] need ECBing */
        if (remaining) {
			#if (BPI == 8)
			if (remaining >= 64) {
				oa[0] = xor_block(offset, ctx->L[0]);
				oa[1] = xor_block(oa[0], ctx->L[1]);
				oa[2] = xor_block(oa[1], ctx->L[0]);
				offset = oa[3] = xor_block(oa[2], ctx->L[2]);
				remaining -= 64;
				k = 4;
			}
			#endif
			if (remaining >= 32) {
				oa[k] = xor_block(offset, ctx->L[0]);
				offset = oa[k+1] = xor_block(oa[k], ctx->L[1]);
				remaining -= 32;
				k+=2;
			}
			if (remaining >= 16) {
				offset = oa[k] = xor_block(offset, ctx->L[0]);
				remaining -= 16;
				++k;

			}
			if (remaining) {
				oa[k] = offset = xor_block(offset,ctx->Lstar);
				++k;
			}
            
            _mm_store_si128 ((__m128i*)delta[BPI*j].block, oa[0]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 1].block, oa[1]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 2].block, oa[2]);
            #if BPI == 4
                _mm_store_si128 ((__m128i*)delta[BPI*j+ 3].block, oa[3]);
            #elif BPI == 8
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 3].block, oa[3]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 4].block, oa[4]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 5].block, oa[5]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 6].block, oa[6]);
            _mm_store_si128 ((__m128i*)delta[BPI*j+ 7].block, oa[7]);
            #endif
		}
        offset = xor_block(offset, ctx->Ldollar);      /* Part of tag gen */

        _mm_store_si128 ((__m128i*)delta[BPI*j + k].block, offset);
    }
}

void copyMessageToAESBlock(aesBlock* encrypt, int numBlocks, unsigned int * m2){
    for(int i = 0; i<numBlocks; i++){
        for (int j = 0; j<4;j++){
            encrypt[i].block[j]=  m2[(i*4)+j];
        }
    }
}

void unsignedCharArrayTounsignedIntArray(const unsigned char *in,unsigned int *out, unsigned long long len, unsigned long long mlen2 )
{
    
    unsigned char h[mlen2]={0};
    unsigned char temp[mlen2]={0};

    memcpy(h, in, len);
    memcpy(temp, in, mlen2);
    
    int shifttab[16]= {
        3, 2, 1, 0,   
        7, 6, 5, 4,  
        11, 10, 9, 8,
        15, 14, 13, 12 
        };
    if(len%16!=0){
        h[len]=0x01;
    }

    for(int i = 0; i < mlen2; i++){
        int index = shifttab[i%16]+(floor(i/16)*16 );
        temp[i] = h[index];
    }
    

    unsigned int * temp2;
    temp2 = (unsigned int *) temp;

    for(int i = 0; i < mlen2/4; i++){
        out[i]=temp2[i];
    }


}


void checksum (aesBlock *in, unsigned long long tam, unsigned long long message_len,unsigned int *out ){
	union { uint32_t u32[4]; uint8_t u8[16]; block bl; } tmp;
    
    for (int i=0; i<tam;i++){
        
        if(i==tam-1){
            if(message_len%16==0){
                out[0] = out[0] ^ in[i].block[0];
                out[1] = out[1] ^ in[i].block[1];
                out[2] = out[2] ^ in[i].block[2];
                out[3] = out[3] ^ in[i].block[3];
            }else{
                tmp.bl = zero_block();
				memcpy(tmp.u8, in[i].block, message_len%16);
				tmp.u8[message_len%16] = (unsigned char)0x80u;

                out[0] = out[0] ^ tmp.u32[0];
                out[1] = out[1] ^ tmp.u32[1];
                out[2] = out[2] ^ tmp.u32[2];
                out[3] = out[3] ^ tmp.u32[3];
            }
        }else{
            out[0] = out[0] ^ in[i].block[0];
            out[1] = out[1] ^ in[i].block[1];
            out[2] = out[2] ^ in[i].block[2];
            out[3] = out[3] ^ in[i].block[3];
        }
        
        
        
        
        


    }
}

static void process_ad(ae_ctx *ctx, aesBlock *S,const unsigned char *ad, int ad_len, int final){
    
    int ad_len_temp = ad_len/16;
    int delta_len = ad_len/16;
    if(ad_len%16!=0){
        delta_len++;
        ad_len_temp++;
    }
    
    aesBlock *delta_ad = new aesBlock[delta_len];
    aesBlock *message_ad = new aesBlock[delta_len];
    copyMessageToAESBlock(message_ad, ad_len_temp, (unsigned int *)&ad[0]);
    getDelta(ctx,ctx->ad_offset, delta_ad, ad_len, 1);
    OCBRandomAccessAsociatedData(message_ad, delta_ad, ad_len_temp, ad_len, &ctx->encrypt_key.keys[0][0]);
    
    checksum (message_ad, ad_len_temp, 16-(ad_len%16)+ (ad_len), S[0].block );

}


int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long ad_len,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k)
{

    int message_len = mlen/16+1;
    int delta_len = mlen/16+1;
    if(mlen%16!=0){
        delta_len++;
        message_len++;
    }
    

    ae_ctx* ctx = ae_allocate(NULL);

    aesBlock *delta = new aesBlock[delta_len];
    aesBlock *message = new aesBlock[delta_len];
    aesBlock *S = new aesBlock[1];
    ae_init(ctx, k, 16, 12, 16);
    if (nsec) {
        ctx->offset = gen_offset_from_nonce(ctx, nsec);
        ctx->ad_offset = ctx->checksum   = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        ctx->ad_checksum = zero_block();
    }
    if (ad_len > 0){
        process_ad(ctx, S,ad,  ad_len, 1);
        
    }

    getDelta(ctx,ctx->offset, delta, mlen, 1);
    copyMessageToAESBlock(message, message_len-1, (unsigned int *)&m[0]);

    checksum (message, message_len-1, mlen, message[message_len-1].block );

    OCBRandomAccess(message, delta, S, message_len, mlen, delta_len, &ctx->encrypt_key.keys[0][0], &ctx->decrypt_key.keys[0][0],1);


    // imprimiArreglo(16,(unsigned char *)&ctx->offset);
   
    cout<<"\n---------------------------Encrypt------------------------------------         \n";
  

    cout<<"Key          ";
    imprimiArreglo(16,k);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"S           ";
    imprimiArreglo(16,(unsigned char *)&S[0].block);
    printf("\n---------------------------");
    cout<<endl;
    cout<<"Nonce        ";

    imprimiArreglo(16,nsec);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Plaintext    ";
    imprimiArreglo(mlen,m);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Ciphertext   ";
    for(int i = 0; i<message_len-1; i++){
        if(i==message_len-2){
            if(mlen%16!=0)
                imprimiArreglo(ceil((mlen%16)),(unsigned char *)&message[i].block);
            else
                imprimiArreglo((16),(unsigned char *)&message[i].block);
        }   
        else{
            imprimiArreglo((16),(unsigned char *)&message[i].block);
        }
    }
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Tag          ";
    imprimiArreglo(16,(unsigned char *)&message[message_len-1].block);
    cout<<endl;

    return 1;
}


int crypto_aead_decrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long ad_len,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k)
{
    int message_len = mlen/16+1;
    int delta_len = mlen/16+1;
    if(mlen%16!=0){
        delta_len++;
        message_len++;
    }
    

    ae_ctx* ctx = ae_allocate(NULL);

    aesBlock *delta = new aesBlock[delta_len];
    aesBlock *message = new aesBlock[delta_len];
    aesBlock *S = new aesBlock[1];
    ae_init(ctx, k, 16, 12, 16);
    if (nsec) {
        ctx->offset = gen_offset_from_nonce(ctx, nsec);
        ctx->ad_offset = ctx->checksum   = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed    = 0;
        	ctx->ad_checksum = zero_block();
    }
    if (ad_len > 0){
        process_ad(ctx, S,ad,  ad_len, 1);
        
    }


    getDelta(ctx,ctx->offset, delta, mlen, 1);

    copyMessageToAESBlock(message, message_len-1, (unsigned int *)&m[0]);

    OCBRandomAccess(message, delta, S, message_len-1, mlen, delta_len, &ctx->encrypt_key.keys[0][0],&ctx->decrypt_key.keys[0][0],0);
    
    checksum (message, message_len-1, mlen, message[message_len-1].block );

    OCBRandomAccessGetTag(&message[message_len-1] ,&delta[message_len-1], S, &ctx->encrypt_key.keys[0][0]);


   
    
    cout<<"\n---------------------------decrypt------------------------------------         \n";
	
    cout<<"Key          ";
    imprimiArreglo(16,k);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"S           ";
    imprimiArreglo(16,(unsigned char *)&S[0].block);
    printf("\n---------------------------");
    cout<<endl;
    cout<<"Nonce        ";

    imprimiArreglo(16,nsec);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Ciphertext    ";
    imprimiArreglo(mlen,m);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Plaintext    ";
    for(int i = 0; i<message_len-1; i++){
        if(i==message_len-2){
            if(mlen%16!=0)
                imprimiArreglo(ceil((mlen%16)),(unsigned char *)&message[i].block);
            else
                imprimiArreglo((16),(unsigned char *)&message[i].block);
        }   
        else{
            imprimiArreglo((16),(unsigned char *)&message[i].block);
        }
    }
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Tag          ";
    imprimiArreglo(16,(unsigned char *)&message[message_len-1].block);
    cout<<endl;
    
    return 1;
}

int main(int argc, char **argv) {
    const unsigned char k[16] ={ 
        0x2b, 0x7e, 0x15, 0x16, 
        0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
    };
    unsigned long long mlen=16;

    const unsigned char m[mlen] ={ 
        0x00,0x01,0x02,0x03, 
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f,
        // 0x10,0x11,0x12,0x13
    };

    const unsigned char m2[mlen] ={ 
        0x7e, 0x86, 0x67, 0xb6, 
        0xa5, 0x5c, 0xdb, 0x9f, 
        0xd2, 0x5f, 0x5a, 0x3e, 
        0x09, 0x5e, 0xda, 0x34,
        // 0x23, 0x32, 0x81, 0x46,
    };

    unsigned char c[16]={
        0x30, 0x88, 0x6c, 0x7f,   
        0x32, 0x7f, 0xfe, 0xad, 
        0xee, 0xdf, 0x75, 0x48,
        0x6f, 0x09, 0xe7, 0xb6,
    };
    unsigned long long *clen;
    unsigned long long adlen = 20;
     
    const unsigned char ad[adlen] ={ 
        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c,

        0x2b,0x28,0xab,0x09,
        // 0x7e,0xae,0xf7,0xcf,
        // 0x15,0xd2,0x15,0x4f,
        // 0x16,0xa6,0x88,0x3c,
        
    };

    const unsigned char nsec[16] = {
        0x00,0x01,0x02,0x03, 
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };
    unsigned char nsec2[16] = {
        0x00,0x01,0x02,0x03, 
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char *npub; 

    crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);

    crypto_aead_decrypt(c, clen, m2, mlen, ad, adlen, nsec, npub, k);

    return 0;
}

