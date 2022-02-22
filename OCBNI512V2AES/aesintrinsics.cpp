
#include <wmmintrin.h>
#include <immintrin.h>
#include <iostream>
#include <cstring>
using namespace std;

typedef __m512i block;
typedef struct { uint32_t rd_key[60]; int rounds; } AES_KEY;

inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
    temp3 = _mm_slli_si128 (temp1, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp3 = _mm_slli_si128 (temp3, 0x4);
    temp1 = _mm_xor_si128 (temp1, temp3);
    temp1 = _mm_xor_si128 (temp1, temp2);
    return temp1;
}
void AES_128_Key_Expansion (unsigned char *userkey, unsigned char *key)
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)key;
    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}


void imprimiArreglo(int tam, unsigned char *in ){

    for (int i = 0; i<tam; i++){
        printf("%x", in[i] );
    }
}

void print512_num(__m512i var)
{
    unsigned int val[32];
    memcpy(val, &var, sizeof(val));

    for (int i = 0; i<32; i++){
        printf("%x ", val[i] );
    }
    cout<<endl;
}


static inline void AES_ecb_encrypt_blks(block *blks, unsigned nblks, block *key, unsigned rounds) {
    unsigned i,j,rnds=rounds;
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_xor_si512(blks[i], key[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    blks[i] = _mm512_aesenc_epi128(blks[i], key[j]);
	for (i=0; i<nblks; ++i)
	    blks[i] =_mm512_aesenclast_epi128(blks[i], key[j]);
}

void AES_ECB512_encrypt(const unsigned char *in,//pointer to the PLAINTEXT 
unsigned char *out, //pointer to the CIPHERTEXT buffer
unsigned long length,//text length in bytes
unsigned char *key,//pointer to the expanded key schedule
int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m512i tmp;
    __m512i keys;

    int i,j;
    if(length%64)
        length = length/64+1;
    else
        length = length/64;
    for(i=0; i < length; i++){

        tmp = _mm512_loadu_si512(&((__m512i*)in)[i]);
        keys = _mm512_loadu_si512(&((__m512i*)key)[0]);
        tmp = _mm512_xor_si512 (tmp,keys);

        for(j=1; j <number_of_rounds; j++){
            keys = _mm512_loadu_si512(&((__m512i*)key)[j]);
            tmp = _mm512_aesenc_epi128 (tmp,keys);

        }
        keys = _mm512_loadu_si512(&((__m512i*)key)[j]);
        tmp = _mm512_aesenclast_epi128 (tmp,keys);
        _mm512_storeu_si512 (&((__m512i*)out)[i],tmp);
    }
}

// static inline void AES_encrypt(block in, block out, block *key, unsigned rounds)
// {
// 	int j,rnds=rounds;
// 	__m512i tmp;
// 	tmp = _mm512_xor_si512 (in,key[0]);
// 	for (j=1; j<rnds; j++)  tmp = _mm512_aesenc_epi128 (tmp,sched[j]);
// 	tmp = _mm_aesenclast_si128 (tmp,sched[j]);
// 	_mm_store_si128 ((__m128i*)out,tmp);
// }

void AES_OCB512_encrypt(const unsigned char *in,//pointer to the PLAINTEXT 
unsigned char *out, //pointer to the CIPHERTEXT buffer
long length,//text length in bytes
unsigned char *key,//pointer to the expanded key schedule
unsigned char *nsec,//pointer to the NONCE
int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m512i tmp[4];
    __m512i nonce[4];
    __m512i keys[number_of_rounds+1];

    int i,j;
    if(length%64)
        length = length/64+1;
    else
        length = length/64;

    
    for(i=0; i < number_of_rounds+1; i++){
        keys[i] = _mm512_loadu_si512(&((__m512i*)key)[i]);
    }
    for(i=0; i < 4; i++){
        nonce[i] = _mm512_loadu_si512(&((__m512i*)nsec)[0]);
    }
    i=0;

    AES_ecb_encrypt_blks(nonce, 4, keys, 10);
    unsigned char test[64] = {
        0x00, 0x00, 0x00, 0x00,
        0X00, 0X00, 0X00, 0X00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x00, 0x00, 0x01,
        0X00, 0X00, 0X00, 0X01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,

        0x00, 0x00, 0x00, 0x02,
        0X00, 0X00, 0X00, 0X02,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02,

        0x00, 0x00, 0x00, 0x03,
        0X00, 0X00, 0X00, 0X03,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x03
    };

    unsigned char block4[64] = {
        0x00, 0x00, 0x00, 0x04,
        0X00, 0X00, 0X00, 0X04,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x04,

        0x00, 0x00, 0x00, 0x04,
        0X00, 0X00, 0X00, 0X04,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x04,

        0x00, 0x00, 0x00, 0x04,
        0X00, 0X00, 0X00, 0X04,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x04,

        0x00, 0x00, 0x00, 0x04,
        0X00, 0X00, 0X00, 0X04,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x04
    };
    __m512i blockSum = _mm512_loadu_si512(&((__m512i*)test)[0]);
    __m512i blockOnly4 = _mm512_loadu_si512(&((__m512i*)block4)[0]);
    
    
    do{
        unsigned blocks = 0;
        //obtencion de bloques
        tmp[0] = _mm512_loadu_si512(&((__m512i*)in)[i]);
        blocks++;
        if(length>2){
            tmp[1] = _mm512_loadu_si512(&((__m512i*)in)[i+1]);        
            blocks++;
        }
        if(length>3){
            tmp[2] = _mm512_loadu_si512(&((__m512i*)in)[i+2]);
            blocks++;
        }
        if(length>4){
            tmp[3] = _mm512_loadu_si512(&((__m512i*)in)[i+3]);
            blocks++;
        }


        for(j=0; j < blocks; j++){
            //se suma 1 2 3 y 4 a cada nonce correspondiente
            nonce[j] = _mm512_add_epi32 (nonce[j], blockSum );
            blockSum = _mm512_add_epi32 (blockOnly4, blockSum );

            /*
            el primer arreglo debe de sumar  0 1 2 y 3
            el segundo debe de sumar 4 5 6 y 7 
            el tercero 8 9 10 y 11 
            el cuarto  12 13 14 15
            */
        }
        
        AES_ecb_encrypt_blks(nonce, blocks, keys, 3);
        
        
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(nonce[j], tmp[j]);
        }

        AES_ecb_encrypt_blks(tmp, blocks, keys, number_of_rounds);
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(nonce[j], tmp[j]);
        }
        
        _mm512_storeu_si512(&((__m512i*)out)[i],tmp[0]);

        if(length>2)
        _mm512_storeu_si512(&((__m512i*)out)[i+1],tmp[1]);

        if(length>3)
        _mm512_storeu_si512(&((__m512i*)out)[i+2],tmp[2]);
        
        if(length>4)
        _mm512_storeu_si512(&((__m512i*)out)[i+3],tmp[3]);

        cout <<"hola"<<length<<endl;

        i = i+4;
        length = length-4;
    }while(length>4);
}

void key128tokey512(unsigned char Expandkey128[176], unsigned char Expandkey512[704]){
    
    int k=0;
    for(int i=0; i<176; i=i+16){
        for(int j=0; j<16; j++){    
            Expandkey512[(k*64)+j]=Expandkey128[i+j];
            Expandkey512[(k*64)+16+j]=Expandkey128[i+j];
            Expandkey512[(k*64)+32+j]=Expandkey128[i+j];
            Expandkey512[(k*64)+48+j]=Expandkey128[i+j];
        }
        k++;

    }
    
}
int main(){
    unsigned char k[16] = {
        0x2b, 0x7e, 0x15, 0x16, 
        0x28, 0xae, 0xd2, 0xa6, 
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c,
    };
    int number_of_rounds=10;
    unsigned char keys[176] = {0};
    unsigned char Expandkey512[704]={0};

    const unsigned char m[64] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,

        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,

        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,

        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34
    };
    unsigned char nonce[64] = {
        0x32, 0x43, 0xf6, 0xa8,
        0X88, 0X5a, 0X30, 0X8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x35,

        0x32, 0x43, 0xf6, 0xa8,
        0X88, 0X5a, 0X30, 0X8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x35,

        0x32, 0x43, 0xf6, 0xa8,
        0X88, 0X5a, 0X30, 0X8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x35,

        0x32, 0x43, 0xf6, 0xa8,
        0X88, 0X5a, 0X30, 0X8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x35
    };
    unsigned long long mlen=64;
    unsigned char c[128]={0};

    AES_128_Key_Expansion (k, keys);
    key128tokey512(keys, Expandkey512);

    // AES_ECB512_encrypt(m, c, mlen, Expandkey512, number_of_rounds);
  
    AES_OCB512_encrypt(m, c, mlen, Expandkey512, nonce, number_of_rounds);  

    cout<<"Ciphertext   \n";
    for(int i = 0; i<128; i=i+16){
    imprimiArreglo(16,&c[i]);
    printf("\n---------------------------");
    cout<<endl;
    }
   
    return 0;
}