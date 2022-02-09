
#include <wmmintrin.h>
#include <immintrin.h>
#include <iostream>
#include <cstring>
using namespace std;
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

#include <wmmintrin.h>
/* Note – the length of the output buffer is assumed to be a multiple of 16 bytes */
void AES_ECB_encrypt(const unsigned char *in,//pointer to the PLAINTEXT 
unsigned char *out, //pointer to the CIPHERTEXT buffer
unsigned long length,//text length in bytes
unsigned char *key,//pointer to the expanded key schedule
int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m128i tmp;
    int i,j;
    if(length%16)
        length = length/16+1;
    else
        length = length/16;
    for(i=0; i < length; i++){
        tmp = _mm_loadu_si128 (&((__m128i*)in)[i]);
        tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);
        for(j=1; j <number_of_rounds; j++){
            tmp = _mm_aesenc_si128 (tmp,((__m128i*)key)[j]);
        }
        tmp = _mm_aesenclast_si128 (tmp,((__m128i*)key)[j]);
        _mm_storeu_si128 (&((__m128i*)out)[i],tmp);
    }
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
void key128tokey5120(unsigned char Expandkey128[176], unsigned char Expandkey512[704]){
    
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

    unsigned long long mlen=64;
   
    unsigned char c[64]={0};

    AES_128_Key_Expansion (k, keys);
    key128tokey5120(keys, Expandkey512);
    // int i = 10;
    // cout<<"Ciphertext   \n";
    // imprimiArreglo(16,&Expandkey512[(i*64)+0]);
    // printf("\n---------------------------");
    // cout<<endl;
    // imprimiArreglo(16,&Expandkey512[(i*64)+16]);
    // printf("\n---------------------------");
    // cout<<endl;
    // imprimiArreglo(16,&Expandkey512[(i*64)+32]);
    // printf("\n---------------------------");
    // cout<<endl;
    // imprimiArreglo(16,&Expandkey512[(i*64)+48]);
    // printf("\n---------------------------");
    // cout<<endl;

    AES_ECB512_encrypt(m, c, mlen, Expandkey512, number_of_rounds);
    cout<<"Ciphertext   \n";
    imprimiArreglo(16,&c[0]);
    printf("\n---------------------------");
    cout<<endl;
    imprimiArreglo(16,&c[16]);
    printf("\n---------------------------");
    cout<<endl;
    imprimiArreglo(16,&c[32]);
    printf("\n---------------------------");
    cout<<endl;
    imprimiArreglo(16,&c[48]);
    printf("\n---------------------------");
    cout<<endl;

    return 0;
}