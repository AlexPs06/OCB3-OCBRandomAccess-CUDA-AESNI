#include <iostream>
#include <tmmintrin.h>
#include <xmmintrin.h>              
#include <emmintrin.h> 
using namespace std;
typedef __m128i block;
static inline block double_block(block bl) {
		const __m128i mask = _mm_set_epi32(135,1,1,1);//__m512i _mm512_set_epi32 
		__m128i tmp = _mm_srai_epi32(bl, 31);//_mm512_srai_epi32
		tmp = _mm_and_si128(tmp, mask); //_mm512_and_si512
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));//_mm512_shuffle_epi32
		bl = _mm_slli_epi32(bl, 1);//_mm512_slli_epi32
		return _mm_xor_si128(bl,tmp); //_mm512_xor_si512
	}
#define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))//_mm512_shuffle_epi8 _mm512_set_epi8

static block getL(block a, unsigned tz)
{
    
        unsigned i;
        /* Bring L[MAX] into registers, make it register correct */
        block rval = swap_if_le(a);
        rval = double_block(rval);
        for (i=0; i < tz; i++)
            rval = double_block(rval);
        return swap_if_le(rval);             /* To memory correct */
    
}
static inline unsigned ntz(unsigned x) {
		static const unsigned char tz_table[32] =
		{ 0,  1, 28,  2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17,  4, 8,
		 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18,  6, 11,  5, 10, 9};
		return tz_table[((uint32_t)((x & -x) * 0x077CB531u)) >> 27];
	}

int main(){

    block temp = _mm_set_epi8 (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);



    unsigned char imprimir[16]={0};

    unsigned tz = ntz(16);
    
    temp = double_block(temp);
    temp = getL(temp, tz);

    _mm_storeu_si128(&((__m128i*)imprimir)[0],temp);
    
    cout<<tz <<endl;
    for(int i = 0; i<16; i++){

        printf("%x ", imprimir[i] );
    }


return 0;
}