
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <iostream>
#include <cstring>
#include <math.h>  
using namespace std;

typedef __m512i block512;

typedef __m128i block128;
void calculateChecksum(block512 *checksum, block512 * nonce, block128 *Stag, unsigned char key128[176], block512 blockSum, int length, int indiceBlockSum, int number_of_rounds);
void calculateAssociatedData(const unsigned char *ad, unsigned char *nsec, long adLength, block512 *keys,unsigned char *key128, block128 *Stag, int number_of_rounds);
void key128tokey512(unsigned char Expandkey128[176], unsigned char Expandkey512[704]);
static inline void AES_ecb128_encrypt_blks(block128 *in, block128 *out, unsigned nblks, unsigned char *key, unsigned rounds);
static inline void getDelta(block512* nonce, unsigned char * in, unsigned char *key, unsigned long long size);
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
void AES_128_Key_Expansion_Decrypt (__m128i * key128Encrypt, __m128i * key128Decrypt){
    key128Decrypt[0] = key128Encrypt[10];
    key128Decrypt[1] = _mm_aesimc_si128(key128Encrypt[9]);
	key128Decrypt[2] = _mm_aesimc_si128(key128Encrypt[8]);
	key128Decrypt[3] = _mm_aesimc_si128(key128Encrypt[7]);
	key128Decrypt[4] = _mm_aesimc_si128(key128Encrypt[6]);
	key128Decrypt[5] = _mm_aesimc_si128(key128Encrypt[5]);
	key128Decrypt[6] = _mm_aesimc_si128(key128Encrypt[4]);
	key128Decrypt[7] = _mm_aesimc_si128(key128Encrypt[3]);
	key128Decrypt[8] = _mm_aesimc_si128(key128Encrypt[2]);
	key128Decrypt[9] = _mm_aesimc_si128(key128Encrypt[1]);
    key128Decrypt[10] = key128Encrypt[0];

}
#define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))//_mm512_shuffle_epi8 _mm512_set_epi8
#define swap_if_le512(b) \
      _mm512_shuffle_epi8(b,_mm512_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))//_mm512_shuffle_epi8 _mm512_set_epi8


void imprimiArreglo(int tam, unsigned char *in ){

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
        
    }
}
void imprimirM128(block128 tmp){
    unsigned char impresion[16] = {0};
    _mm_store_si128 ((__m128i*)impresion,tmp);
    imprimiArreglo(16,&impresion[0]);
    printf("\n---------------------------\n");
}
void imprimiArreglo(int tam, const unsigned char *in ){

    for (int i = 0; i<tam; i++){
        printf("%02x", in[i] );
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


static inline void AES_ecb_encrypt_blks(
block512 *blks, //bloques de entrada 
block512 *out, //bloques de salida
unsigned nblks, //numero de bloques 
block512 *key, //bloque de las llaves
unsigned rounds)//numero de rondas 
{
    unsigned i,j,rnds=rounds;
	for (i=0; i<nblks; ++i)
	    out[i] =_mm512_xor_si512(blks[i], key[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    out[i] = _mm512_aesenc_epi128(out[i], key[j]);
	for (i=0; i<nblks; ++i)
	    out[i] =_mm512_aesenclast_epi128(out[i], key[j]);
}

static inline void AES_ecb_decrypt_blks(
block512 *blks, //bloques de entrada 
block512 *out, //bloques de salida
unsigned nblks, //numero de bloques 
block512 *key, //bloque de las llaves
unsigned rounds)//numero de rondas 
{
    unsigned i,j,rnds=rounds;
	for (i=0; i<nblks; ++i)
	    out[i] =_mm512_xor_si512(blks[i], key[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    out[i] = _mm512_aesdec_epi128(out[i], key[j]);
	for (i=0; i<nblks; ++i)
	    out[i] =_mm512_aesdeclast_epi128(out[i], key[j]);
}

static inline void AES_ecb_encrypt_blks_rounds(
block512 *blks, //bloques de entrada 
block512 *out, //bloques de salida
unsigned nblks, //numero de bloques 
block512 *key, //bloque de las llaves
unsigned rounds)//numero de rondas 
{
    unsigned i,j,rnds=rounds;
    for (i=0; i<nblks; ++i)
	    out[i] = blks[i];
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    out[i] = _mm512_aesenc_epi128(out[i], key[j]);
}
static inline void AES_ecb128_encrypt_blks(block128 *in, block128 *out, unsigned nblks, unsigned char *key, unsigned rounds){
	unsigned i,j,rnds=rounds;
    const __m128i *sched = ((__m128i *)(key));
	for (i=0; i<nblks; ++i)
	    out[i] =_mm_xor_si128(in[i], sched[0]);
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    out[i] = _mm_aesenc_si128(out[i], sched[j]);
	for (i=0; i<nblks; ++i)
	    out[i] =_mm_aesenclast_si128(out[i], sched[j]);
}

static inline void AES_ecb128_decrypt_blks(block128 *in, block128 *out, unsigned nblks, block128 *keys, unsigned rounds){
    unsigned i,j,rnds=rounds;

	for (i=0; i<nblks; ++i)
	    out[i] =_mm_xor_si128(in[i], keys[0]);
    for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    out[i] = _mm_aesdec_si128(out[i], keys[j]);
	for (i=0; i<nblks; ++i)
	    out[i] =_mm_aesdeclast_si128(out[i], keys[j]);
    
   
    
}
static inline void AES_ecb128_encrypt_blks_rounds(block128 *in, block128 *out, unsigned nblks, unsigned char *key, unsigned rounds){
	unsigned i,j,rnds=rounds;
    const __m128i *sched = ((__m128i *)(key));
	for (i=0; i<nblks; ++i)
        out[i] = in[i];
	for(j=1; j<rnds; ++j)
	    for (i=0; i<nblks; ++i)
		    out[i] = _mm_aesenc_si128(out[i], sched[j]);

}

static inline block128 AES_encrypt(block128 in, unsigned char *key, unsigned rounds){
	int j,rnds=rounds;
	const __m128i *sched = ((__m128i *)(key));
	__m128i tmp = in;
	tmp = _mm_xor_si128 (tmp,sched[0]);
	for (j=1; j<rnds; j++)  tmp = _mm_aesenc_si128 (tmp,sched[j]);
	tmp = _mm_aesenclast_si128 (tmp,sched[j]);
	return tmp; 
}

static inline void getDelta(block512* nonce, unsigned char * in, unsigned char *key, unsigned long long size)
{
    __m128i add1 = _mm_set_epi8 (0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    __m128i temp =  _mm_loadu_si128(&((__m128i*)in)[0]);
    add1 =  swap_if_le(add1);
    __m128i delta[size];
    for(int i = 0; i<size; i++){
        delta[i] = temp;
        temp =  swap_if_le(temp);
        
        temp =  _mm_add_epi32( add1,temp);

        temp =  swap_if_le(temp);

    }

    
    // imprimirM128(delta[0]);
    // cout<<endl;
    AES_ecb128_encrypt_blks(delta, delta, size, key, 10);
    // imprimirM128(delta[0]);
    // cout<<endl;
    // exit(1);
    
    for(int i=0; i < size; i++){
        nonce[i] = _mm512_castsi128_si512( delta[i] );
        nonce[i] = _mm512_inserti64x2(nonce[i], delta[i], 1 );
        nonce[i] = _mm512_inserti64x2(nonce[i], delta[i], 2 );
        nonce[i] = _mm512_inserti64x2(nonce[i], delta[i], 3 );
    }
}

void AES_OCB512_encrypt(const unsigned char *in,//pointer to the PLAINTEXT 
unsigned char *out, //pointer to the CIPHERTEXT buffer
const unsigned char *ad,
long adLength,
long length,//text length in bytes
unsigned char *key,//pointer to the expanded key schedule
unsigned char *nsec,//pointer to the NONCE
int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m512i tmp[4];
    __m512i checksum[1]; 
    __m128i Stag[1];
    __m512i cipherNonceTemp[4];
    __m512i nonce[(length/64)+1];
    
    __m512i keys[number_of_rounds+1];
    __m512i keys512Encrypt[number_of_rounds+1];
    for (int i = 0; i<4; i++){
        tmp[i]= _mm512_setzero_epi32();
        nonce[i]= _mm512_setzero_epi32();
        cipherNonceTemp[i]= _mm512_setzero_epi32();
        checksum[0]= _mm512_setzero_epi32();
    }
    int i,j;
    int tempLength=length;

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
    unsigned char key128[176];//pointer to the expanded key schedule for 128

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

    AES_128_Key_Expansion (key, key128);
    
    __m128i *key128Encrypt  = ((__m128i *)(key128));
    for(i=0; i < number_of_rounds+1; i++){
        keys512Encrypt[i] = _mm512_castsi128_si512( key128Encrypt[i] );
        keys512Encrypt[i] = _mm512_inserti64x2(keys512Encrypt[i], key128Encrypt[i], 1 );
        keys512Encrypt[i] = _mm512_inserti64x2(keys512Encrypt[i], key128Encrypt[i], 2 );
        keys512Encrypt[i] = _mm512_inserti64x2(keys512Encrypt[i], key128Encrypt[i], 3 );
    }


    
    if(length%64 == 0)
        tempLength = length/64;
    else
        tempLength = (length + (64 -length%64) ) /64 ;
    
    
    
    __m512i blockSum = _mm512_loadu_si512(&((__m512i*)test)[0]);
    __m512i blockOnly4 = _mm512_loadu_si512(&((__m512i*)block4)[0]);
    getDelta(nonce, nsec, key128, (length/64)+1);


    int indexDelta=0;
    i=0;
    while(tempLength>4){
        unsigned blocks = 0;
        indexDelta = i/64;
        //obtencion de bloques
        for(j = 0; j<4; j++ ){
            tmp[j] = _mm512_loadu_si512(&((__m512i*)in)[i+j]);
            blocks++;
        }
        //Actualizxacioon del checksum
        for(j = 0; j<blocks; j++ ){
            checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
        }
       
        //calculo del nonce
        nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);

        for(j=0; j < blocks; j++){

            cipherNonceTemp[j] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));
            
            blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
        }
        nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);
        //cifrado de dos rondas del nonce
        // AES_ecb_encrypt_blks(cipherNonceTemp,cipherNonceTemp, blocks, keys, 3);
        AES_ecb_encrypt_blks_rounds(cipherNonceTemp,cipherNonceTemp, blocks, keys512Encrypt, 2);
        
        //xor del nonce con el mensaje correspondiente
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
        }

        //cifrado del mensaje 
        AES_ecb_encrypt_blks(tmp,tmp, blocks, keys512Encrypt, number_of_rounds);
        
        //xort del mensaje cifrado con el nonce
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
        }

        //Carga del mensaje cifrado a la salida
        for(j=0; j < blocks; j++){
            _mm512_storeu_si512(&((__m512i*)out)[i+j],tmp[j]);
        }

        //actualizacion de indices
        i = i+4;
        tempLength = tempLength-4;
    }
    indexDelta = i/64;
    
    //final block
    for(j = 0; j<tempLength-1; j++ ){
        tmp[j] = _mm512_loadu_si512(&((__m512i*)in)[i+j]);
    }
    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    blockOnly4 = swap_if_le512(blockOnly4);

    for(j=0; j < tempLength-1; j++){
        cipherNonceTemp[j] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));
        blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
    }

    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    blockOnly4 = swap_if_le512(blockOnly4);

    for(j = 0; j<tempLength-1; j++ ){
        checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
    }

    AES_ecb_encrypt_blks_rounds(cipherNonceTemp,cipherNonceTemp, tempLength-1, keys512Encrypt, 2);
    
    //xor del nonce con el mensaje correspondiente
    for(j=0; j < tempLength-1; j++){
        tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
    }
    
    //cifrado del mensaje 
    AES_ecb_encrypt_blks(tmp,tmp, tempLength-1, keys512Encrypt, number_of_rounds);
    
    //xort del mensaje cifrado con el nonce
    for(j=0; j < tempLength-1; j++){
        tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
    }

    //Carga del mensaje cifrado a la salida
    for(j=0; j < tempLength-1; j++){
        _mm512_storeu_si512(&((__m512i*)out)[i+j],tmp[j]);
    }

    // ultimo bloque de 512

    int finalBlocklenght = 0;
    int sizefinalBlockArray = 0;
    int indiceBlockSum = 0;
    //comprobamos si es completo o no
    if(length%16 == 0){
        
        finalBlocklenght = length%64;
        if(finalBlocklenght == 0)
            finalBlocklenght = 64;
        sizefinalBlockArray = finalBlocklenght/16;
        
    }
    else{
        finalBlocklenght = length%64;
        
        //calculo de los bloquyes de 128 que necesitamos
        sizefinalBlockArray = (finalBlocklenght + (16 -finalBlocklenght%16) ) /16 ;
        

    }

    unsigned char finalblockChar[64] = {0};

    for(j = 0; j<finalBlocklenght; j++){
        finalblockChar[j] = in[(length-finalBlocklenght )+ j ]; 
    }
    if(finalBlocklenght%16 != 0){
        finalblockChar[finalBlocklenght] = 1; //poner 1 en vez de 0
    }

    

    __m128i finalBlock[ sizefinalBlockArray ];
    __m128i delta128[ sizefinalBlockArray ];
    __m128i add1 = _mm_set_epi8 (0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00);
    __m128i tmpfinalBlock[ sizefinalBlockArray ];



    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);

    cipherNonceTemp[0] = swap_if_le512 (_mm512_add_epi32 (nonce[indexDelta], blockSum ));
    
    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);

    for(j=0; j<sizefinalBlockArray; j++){
        finalBlock[j] =  _mm_loadu_si128(&((__m128i*)finalblockChar)[j]);
        delta128[j] =  _mm_loadu_si128(&((__m128i*)cipherNonceTemp)[j]);
    }
    if(finalBlocklenght%16 != 0){
        
        delta128[sizefinalBlockArray-1] =  swap_if_le(delta128[sizefinalBlockArray-1]); 
        add1 =  swap_if_le(add1);

        delta128[sizefinalBlockArray-1] = _mm_add_epi32( add1,delta128[sizefinalBlockArray-1]);

        delta128[sizefinalBlockArray-1] =  swap_if_le(delta128[sizefinalBlockArray-1]); 
        add1 =  swap_if_le(add1);
        // AES_ecb128_encrypt_blks(delta128, delta128, sizefinalBlockArray, key128 , 3);
        AES_ecb128_encrypt_blks_rounds(delta128, delta128, sizefinalBlockArray, key128 , 2);
        
        for(j=0; j<sizefinalBlockArray-1; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],finalBlock[j]);
        }
        tmpfinalBlock[sizefinalBlockArray-1] = delta128[sizefinalBlockArray-1];

        AES_ecb128_encrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128 , 10);
        // _mm_storeu_si128(&((__m128i*)out)[0],tmpfinalBlock[sizefinalBlockArray-1]);

        for(j=0; j<sizefinalBlockArray-1; j++){
            tmpfinalBlock[j] = _mm_xor_si128(tmpfinalBlock[j],delta128[j]);
        }
        tmpfinalBlock[sizefinalBlockArray-1] = _mm_xor_si128(tmpfinalBlock[sizefinalBlockArray-1],finalBlock[sizefinalBlockArray-1]);
        int k = ( (length + (16 -length%16) ) /16 ) - sizefinalBlockArray;
        for(j=0; j < sizefinalBlockArray; j++){
            _mm_storeu_si128(&((__m128i*)out)[k+j],tmpfinalBlock[j]);
        }
    }else{
        // AES_ecb128_encrypt_blks(delta128, delta128, sizefinalBlockArray, key128 , 3);
        AES_ecb128_encrypt_blks_rounds(delta128, delta128, sizefinalBlockArray, key128 , 2);

        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],finalBlock[j]);
        }
        AES_ecb128_encrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128 , 10);

        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],tmpfinalBlock[j]);
        }

        int k = ( (length) /16 ) - sizefinalBlockArray;
        
        for(j=0; j < sizefinalBlockArray; j++){
            _mm_storeu_si128(&((__m128i*)out)[k+j],tmpfinalBlock[j]);
        }
    }

    tmp[0] = _mm512_loadu_si512(&((__m512i*)finalblockChar)[0]);
    checksum[0] = _mm512_xor_si512(checksum[0], tmp[0]);
    
    indiceBlockSum = sizefinalBlockArray; 
    if(sizefinalBlockArray>3){
        blockOnly4 = swap_if_le512(blockOnly4);
        blockSum = swap_if_le512(blockSum);

        blockSum = _mm512_add_epi32 (blockOnly4, blockSum );

        blockOnly4 = swap_if_le512(blockOnly4);
        blockSum = swap_if_le512(blockSum);

        indexDelta = i/64;
        indiceBlockSum=0;
    }
   
    calculateAssociatedData(ad, nsec, adLength, keys512Encrypt, key128, Stag, number_of_rounds);

    calculateChecksum(checksum,&nonce[indexDelta],Stag, key128, blockSum, length,indiceBlockSum, number_of_rounds);
}

void AES_OCB512_decrypt(const unsigned char *in,//pointer to the PLAINTEXT 
unsigned char *out, //pointer to the CIPHERTEXT buffer
const unsigned char *ad,
long adLength,
long length,//text length in bytes
unsigned char *key,//pointer to the expanded key schedule
unsigned char *nsec,//pointer to the NONCE
int number_of_rounds) //number of AES rounds 10,12 or 14
{
    __m512i tmp[4];
    __m512i checksum[1]; 
    __m128i Stag[1];
    __m512i cipherNonceTemp[4];
    __m512i nonce[(length/64)+1];
    
    __m512i keys[number_of_rounds+1];
    __m512i keys512Encrypt[number_of_rounds+1];
    __m512i keys512Decrypt[number_of_rounds+1];
    for (int i = 0; i<4; i++){
        tmp[i]= _mm512_setzero_epi32();
        nonce[i]= _mm512_setzero_epi32();
        cipherNonceTemp[i]= _mm512_setzero_epi32();
        checksum[0]= _mm512_setzero_epi32();
    }
    int i,j;
    int tempLength=length;

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
    unsigned char key128[176];//pointer to the expanded key schedule for 128

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

    AES_128_Key_Expansion (key, key128);
    
    __m128i *key128Encrypt  = ((__m128i *)(key128));
    __m128i key128Decrypt[number_of_rounds+1];
    

    AES_128_Key_Expansion_Decrypt(key128Encrypt,key128Decrypt);


    for(i=0; i < number_of_rounds+1; i++){
        keys512Decrypt[i] = _mm512_castsi128_si512( key128Decrypt[i] );
        keys512Decrypt[i] = _mm512_inserti64x2(keys512Decrypt[i], key128Decrypt[i], 1 );
        keys512Decrypt[i] = _mm512_inserti64x2(keys512Decrypt[i], key128Decrypt[i], 2 );
        keys512Decrypt[i] = _mm512_inserti64x2(keys512Decrypt[i], key128Decrypt[i], 3 );
        
        keys512Encrypt[i] = _mm512_castsi128_si512( key128Encrypt[i] );
        keys512Encrypt[i] = _mm512_inserti64x2(keys512Encrypt[i], key128Encrypt[i], 1 );
        keys512Encrypt[i] = _mm512_inserti64x2(keys512Encrypt[i], key128Encrypt[i], 2 );
        keys512Encrypt[i] = _mm512_inserti64x2(keys512Encrypt[i], key128Encrypt[i], 3 );
    }


    
    if(length%64 == 0)
        tempLength = length/64;
    else
        tempLength = (length + (64 -length%64) ) /64 ;
    
    
    
    __m512i blockSum = _mm512_loadu_si512(&((__m512i*)test)[0]);
    __m512i blockOnly4 = _mm512_loadu_si512(&((__m512i*)block4)[0]);
    getDelta(nonce, nsec, key128, (length/64)+1);


    int indexDelta=0;

    i=0;
    while(tempLength>4){
        unsigned blocks = 0;
        indexDelta=i/64;
        //obtencion de bloques
        for(j = 0; j<4; j++ ){
            tmp[j] = _mm512_loadu_si512(&((__m512i*)in)[i+j]);
            blocks++;
        }

        nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);

        //calculo del nonce
        for(j=0; j < blocks; j++){
            cipherNonceTemp[j] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));
            blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
        }

        nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);
        
        //cifrado de dos rondas del nonce
        // AES_ecb_encrypt_blks(cipherNonceTemp,cipherNonceTemp, blocks, keys, 3);
        AES_ecb_encrypt_blks_rounds(cipherNonceTemp,cipherNonceTemp, blocks, keys512Encrypt, 2);
        
        

        //xor del nonce con el mensaje correspondiente
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
        }
        

        //cifrado del mensaje 
        AES_ecb_decrypt_blks(tmp,tmp, blocks, keys512Decrypt, number_of_rounds);
        
        

        //xort del mensaje cifrado con el nonce
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
        }

        

        //Actualizxacioon del checksum
        for(j = 0; j<blocks; j++ ){
            checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
        }

        //Carga del mensaje cifrado a la salida
        for(j=0; j < blocks; j++){
            _mm512_storeu_si512(&((__m512i*)out)[i+j],tmp[j]);
        }

        //actualizacion de indices
        i = i+4;
        tempLength = tempLength-4;
    }

    indexDelta=i/64;
    
    //final block
    for(j = 0; j<tempLength-1; j++ ){
        tmp[j] = _mm512_loadu_si512(&((__m512i*)in)[i+j]);
    }

    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    blockOnly4 = swap_if_le512(blockOnly4);

    for(j=0; j < tempLength-1; j++){
        cipherNonceTemp[j] = swap_if_le512(_mm512_add_epi32 (nonce[j], blockSum ));
        blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
    }
    
    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    blockOnly4 = swap_if_le512(blockOnly4);

    AES_ecb_encrypt_blks_rounds(cipherNonceTemp,cipherNonceTemp, tempLength-1, keys512Encrypt, 2);
    
    //xor del nonce con el mensaje correspondiente
    for(j=0; j < tempLength-1; j++){
        tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
    }
    
    //cifrado del mensaje 
    AES_ecb_decrypt_blks(tmp,tmp, tempLength-1, keys512Decrypt, number_of_rounds);
    
    //xort del mensaje cifrado con el nonce
    for(j=0; j < tempLength-1; j++){
        tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
    }
    for(j = 0; j<tempLength-1; j++ ){
        checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
    }
    //Carga del mensaje cifrado a la salida
    for(j=0; j < tempLength-1; j++){
        _mm512_storeu_si512(&((__m512i*)out)[i+j],tmp[j]);
    }
    
    // ultimo bloque de 512

    int finalBlocklenght = 0;
    int sizefinalBlockArray = 0;
    int indiceBlockSum = 0;
    //comprobamos si es completo o no
    if(length%16 == 0){
        
        finalBlocklenght = length%64;
        if(finalBlocklenght == 0)
            finalBlocklenght = 64;
        sizefinalBlockArray = finalBlocklenght/16;
    }
    else{
        finalBlocklenght = length%64;
        //calculo de los bloquyes de 128 que necesitamos
        sizefinalBlockArray = (finalBlocklenght + (16 -finalBlocklenght%16) ) /16 ;
    }

    unsigned char finalblockChar[64] = {0};

    for(j = 0; j<finalBlocklenght; j++){
        finalblockChar[j] = in[(length-finalBlocklenght )+ j ]; 
    }
    

    

    __m128i finalBlock[ sizefinalBlockArray ];
    __m128i delta128[ sizefinalBlockArray ];
    __m128i add1 = _mm_set_epi8 (0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00);
    __m128i tmpfinalBlock[ sizefinalBlockArray ];

    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    

    cipherNonceTemp[0] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));
    
    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);

    for(j=0; j<sizefinalBlockArray; j++){
        finalBlock[j] =  _mm_loadu_si128(&((__m128i*)finalblockChar)[j]);
        delta128[j] =  _mm_loadu_si128(&((__m128i*)cipherNonceTemp)[j]);
    }
    if(finalBlocklenght%16 != 0){
        delta128[sizefinalBlockArray-1] =  swap_if_le(delta128[sizefinalBlockArray-1]); 
        add1 =  swap_if_le(add1);

        delta128[sizefinalBlockArray-1] = _mm_add_epi32( add1,delta128[sizefinalBlockArray-1]);
        
        delta128[sizefinalBlockArray-1] =  swap_if_le(delta128[sizefinalBlockArray-1]); 
        add1 =  swap_if_le(add1);

        AES_ecb128_encrypt_blks_rounds(delta128, delta128, sizefinalBlockArray, key128 , 2);
        
        for(j=0; j<sizefinalBlockArray-1; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],finalBlock[j]);
        }
        tmpfinalBlock[sizefinalBlockArray-1] = delta128[sizefinalBlockArray-1];

        AES_ecb128_decrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray-1, key128Decrypt , 10);
        AES_ecb128_encrypt_blks(&tmpfinalBlock[sizefinalBlockArray-1], &tmpfinalBlock[sizefinalBlockArray-1], 1, key128 , 10);

        for(j=0; j<sizefinalBlockArray-1; j++){
            tmpfinalBlock[j] = _mm_xor_si128(tmpfinalBlock[j],delta128[j]);
        }
        tmpfinalBlock[sizefinalBlockArray-1] = _mm_xor_si128(tmpfinalBlock[sizefinalBlockArray-1],finalBlock[sizefinalBlockArray-1]);
      
    }else{
        AES_ecb128_encrypt_blks_rounds(delta128, delta128, sizefinalBlockArray, key128 , 2);

        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],finalBlock[j]);
        }
        AES_ecb128_decrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128Decrypt , 10);

        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],tmpfinalBlock[j]);
        }

    }

    for(j=0; j < sizefinalBlockArray; j++){
        _mm_storeu_si128(&((__m128i*)finalblockChar)[j],tmpfinalBlock[j]);
    }
    if(finalBlocklenght%16 != 0){
        finalblockChar[finalBlocklenght] = 1; //poner 1 en vez de 0
        for(int k = finalBlocklenght+1; k<64;k++)
            finalblockChar[k] = 0; //poner 1 en vez de 0
    }

    tmp[0] = _mm512_loadu_si512(&((__m512i*)finalblockChar)[0]);
    checksum[0] = _mm512_xor_si512(checksum[0], tmp[0]);
    _mm512_storeu_si512(&((__m512i*)out)[i+tempLength-1],tmp[0]);


    indiceBlockSum = sizefinalBlockArray; 
    if(sizefinalBlockArray>3){
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);
        
        blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
        
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);

        indiceBlockSum=0;
        indexDelta=i/64;
    }
   
    calculateAssociatedData(ad, nsec, adLength, keys512Encrypt, key128, Stag, number_of_rounds);

    calculateChecksum(checksum,&nonce[indexDelta],Stag, key128, blockSum, length,indiceBlockSum, number_of_rounds);
}
void calculateAssociatedData(
    const unsigned char *ad, 
    unsigned char *nsec, 
    long adLength, 
    block512 *keys,
    unsigned char *key128, 
    block128 *Stag,
    int number_of_rounds
    )
{   
    __m512i tmp[4];
    __m512i checksum[1]; 
    __m512i nonce[(adLength/64) +1];
    __m512i cipherNonceTemp[4];
    __m512i Ek1[1];
     Ek1[0] = _mm512_set_epi64 (
    0Xffffffffffffffff,0Xffffffffffffffff,
    0Xffffffffffffffff,0Xffffffffffffffff,
    0Xffffffffffffffff,0Xffffffffffffffff,
    0Xffffffffffffffff,0Xffffffffffffffff
    );
    
    int i=0;
    int j=0;
    int tempLength=adLength;

    for (int i = 0; i<4; i++){
        tmp[i]= _mm512_setzero_epi32();
        nonce[i]= _mm512_setzero_epi32();
        cipherNonceTemp[i]= _mm512_setzero_epi32();
        checksum[0]= _mm512_setzero_epi32();
    }

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
    getDelta(nonce, nsec, key128, (adLength/64)+1);

   
    i=0;
    if(adLength%64 == 0)
        tempLength = adLength/64;
    else
        tempLength = (adLength + (64 - adLength%64) ) /64 ;

    AES_ecb_encrypt_blks(Ek1,Ek1, 1, keys, 10);

    int indexDelta = 0;
    while(tempLength>4){
        unsigned blocks = 0;
        indexDelta = i/64;
        //obtencion de bloques
        for(j = 0; j<4; j++ ){
            tmp[j] = _mm512_loadu_si512(&((__m512i*)ad)[i+j]);
            blocks++;
        }
       
        nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);

        //calculo del nonce
        for(j=0; j < blocks; j++){
            cipherNonceTemp[j] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));
            blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
        }

        nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
        blockSum = swap_if_le512(blockSum);
        blockOnly4 = swap_if_le512(blockOnly4);

        //cifrado de dos rondas del nonce
        AES_ecb_encrypt_blks_rounds(cipherNonceTemp,cipherNonceTemp, blocks, keys, 2);
        
        //xor del nonce con Ek1
        for(j=0; j < blocks; j++){
            cipherNonceTemp[j] = _mm512_xor_si512(cipherNonceTemp[j], Ek1[0]);
        }
        //xor del nonce con el mensaje correspondiente
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
        }

        //cifrado del mensaje 
        AES_ecb_encrypt_blks(tmp,tmp, blocks, keys, number_of_rounds);
        
        //Actualizxacioon del checksum
        for(j = 0; j<blocks; j++ ){
            checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
        }
        
        //actualizacion de indices
        i = i+4;
        tempLength = tempLength-4;
    }

    indexDelta = i/64;
     //final block
    for(j = 0; j<tempLength-1; j++ ){
        tmp[j] = _mm512_loadu_si512(&((__m512i*)ad)[i+j]);
    }

    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    blockOnly4 = swap_if_le512(blockOnly4);
    
    for(j=0; j < tempLength-1; j++){
        cipherNonceTemp[j] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));
        blockSum = _mm512_add_epi32 (blockOnly4, blockSum );
    }
    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);
    blockOnly4 = swap_if_le512(blockOnly4); 
   

    //cifrado de dos rondas del nonce
    AES_ecb_encrypt_blks_rounds(cipherNonceTemp,cipherNonceTemp, tempLength-1, keys, 2);
    
    //xor del nonce con Ek1
    for(j=0; j < tempLength-1; j++){
        cipherNonceTemp[j] = _mm512_xor_si512(cipherNonceTemp[j], Ek1[0]);
    }
    
    //cifrado del mensaje 
    AES_ecb_encrypt_blks(tmp,tmp, tempLength-1, keys, number_of_rounds);
    

    for(j = 0; j<tempLength-1; j++ ){
        checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
    }

    // ultimo bloque de 512
    int finalBlocklenght = 0;
    int sizefinalBlockArray = 0;
    //comprobamos si es completo o no
    if(adLength%16 == 0){
        
        finalBlocklenght = adLength%64;
        if(finalBlocklenght == 0)
            finalBlocklenght = 64;
        sizefinalBlockArray = finalBlocklenght/16;
    }
    else{
        finalBlocklenght = adLength%64;
        
        //calculo de los bloquyes de 128 que necesitamos
        sizefinalBlockArray = (finalBlocklenght + (16 -finalBlocklenght%16) ) /16 ;

    }

    unsigned char finalblockChar[64] = {0};

    for(j = 0; j<finalBlocklenght; j++){
        finalblockChar[j] = ad[(adLength-finalBlocklenght )+ j ]; 
    }
    if(finalBlocklenght%16 != 0){
        finalblockChar[finalBlocklenght] = 1; //poner 1 en vez de 0
    }

    __m128i finalBlock[ sizefinalBlockArray ];
    __m128i delta128[ sizefinalBlockArray ];
    __m128i add1 = _mm_set_epi8 (0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00);
    __m128i tmpfinalBlock[ sizefinalBlockArray ];
    __m128i Ek1_128;
    
    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);

    cipherNonceTemp[0] = swap_if_le512(_mm512_add_epi32 (nonce[indexDelta], blockSum ));

    nonce[indexDelta] = swap_if_le512(nonce[indexDelta]);
    blockSum = swap_if_le512(blockSum);

    
    Ek1_128 =  _mm_loadu_si128(&((__m128i*)Ek1)[0]);
    for(j=0; j<sizefinalBlockArray; j++){
        finalBlock[j] =  _mm_loadu_si128(&((__m128i*)finalblockChar)[j]);
        delta128[j] =  _mm_loadu_si128(&((__m128i*)cipherNonceTemp)[j]);
    }
    if(finalBlocklenght%16 != 0){
        delta128[sizefinalBlockArray-1] =  swap_if_le(delta128[sizefinalBlockArray-1]);
        add1 =  swap_if_le(add1);

        delta128[sizefinalBlockArray-1] = _mm_add_epi32( add1,delta128[sizefinalBlockArray-1]);

        delta128[sizefinalBlockArray-1] =  swap_if_le(delta128[sizefinalBlockArray-1]); 
        add1 =  swap_if_le(add1);

        AES_ecb128_encrypt_blks_rounds(delta128, delta128, sizefinalBlockArray, key128 , 2);
        
        

        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],Ek1_128);
        }
        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(finalBlock[j],tmpfinalBlock[j]);
        }

        AES_ecb128_encrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128 , 10);

    }else{
        AES_ecb128_encrypt_blks_rounds(delta128, delta128, sizefinalBlockArray, key128 , 2);

        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(delta128[j],Ek1_128);
        }
        for(j=0; j<sizefinalBlockArray; j++){
            tmpfinalBlock[j] = _mm_xor_si128(finalBlock[j],tmpfinalBlock[j]);
        }

        AES_ecb128_encrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128 , 10);
    }

    __m128i checksumBlock[4];
        checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)checksum)[0]);
        checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)checksum)[1]);
        checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)checksum)[2]);
        checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)checksum)[3]);
        
        
        
        i=0;
         // //suma de las variables de checksum
        __m128i checksumFinal[1];
        checksumFinal[0] = _mm_setzero_si128();

        for(j=0; j<sizefinalBlockArray; j++ ){
            checksumFinal[0] = _mm_xor_si128( checksumFinal[0], tmpfinalBlock[j]); 
        }

        while(adLength>0 and i<4){
            checksumFinal[0] =  _mm_xor_si128( checksumFinal[0], checksumBlock[i]);
            adLength = adLength-16;
            i++;
        }
        Stag[0] = checksumFinal[0];

        

        
}
void calculateChecksum(block512 *checksum, //pointer to the Checksum in 512 block
block512 * nonce, //pointer to the NONCE in 512 block
block128 *Stag,
unsigned char key128[176],//pointer to the expanded key schedule
block512 blockSum, //
int length, //length of final block512  
int indiceBlockSum, //indice of final part of block512 sum
int number_of_rounds)//number of AES rounds 10,12 or 14
{
    int i=0;
    unsigned char impresion[16]={0};
    unsigned char blocktemp[64]={0};

    unsigned char deltaCheck[16] = {
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x03, 
        };

         _mm512_storeu_si512(&((__m512i*)blocktemp)[0],blockSum);

        //divisiond el checksum para poder sumarlo
        __m128i checksumBlock[4];
        checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)checksum)[0]);
        checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)checksum)[1]);
        checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)checksum)[2]);
        checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)checksum)[3]);
        
        __m128i deltaChecksum  =   _mm_loadu_si128(&((__m128i*)deltaCheck)[0]);
        __m128i nonce128       =  _mm_loadu_si128(&((__m128i*)nonce)[0]);
        __m128i addIndice =  _mm_loadu_si128(&((__m128i* )blocktemp)[indiceBlockSum]);
        
        
        addIndice =  swap_if_le(addIndice);
        deltaChecksum =  swap_if_le(deltaChecksum);
        nonce128 =  swap_if_le(nonce128);

        deltaChecksum = _mm_add_epi32(deltaChecksum, nonce128);
        deltaChecksum = _mm_add_epi32(deltaChecksum, addIndice);

        deltaChecksum =  swap_if_le(deltaChecksum);



        // //suma de las variables de checksum
        __m128i checksumFinal  = _mm_setzero_si128();
        i=0;
        while(length>0 and i<4){
            checksumFinal =  _mm_xor_si128( checksumFinal, checksumBlock[i]);
            length = length-16;
            i++;
        }

        imprimirM128(deltaChecksum);

        //Cifrado dos rondas del delta
        // deltaChecksum = AES_encrypt(deltaChecksum, key128, 3);
        AES_ecb128_encrypt_blks_rounds(&deltaChecksum, &deltaChecksum, 1, key128 , 2);
        

        //xor delta checksumn
        checksumFinal =  _mm_xor_si128( checksumFinal, deltaChecksum);

        //cifrado del checksum
        checksumFinal = AES_encrypt(checksumFinal, key128, number_of_rounds);

        checksumFinal = _mm_xor_si128(checksumFinal, Stag[0]); 
        //falta xor con el tag
        
        _mm_store_si128 ((__m128i*)impresion,Stag[0]);
        cout<<"s   \n";
        imprimiArreglo(16,&impresion[0]);
        printf("\n---------------------------");
        cout<<endl;
        
        _mm_store_si128 ((__m128i*)impresion,checksumFinal);
        cout<<"Tag   \n";
        imprimiArreglo(16,&impresion[0]);
        printf("\n---------------------------");
        cout<<endl;

        
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
    
    unsigned long long mlen=32;
    
    const unsigned char m[mlen] = {
        0xe2, 0x9d, 0x49, 0xbe, 
        0x89, 0x3f, 0x49, 0xaf,  
        0x2d, 0x10, 0x3d, 0x92,
        0xc9, 0xc7, 0x01, 0xc1,
        0x2c, 0x89, 0xc6, 0xab,
        0x1c, 0x7d, 0x98, 0xdb, 
        0x92, 0x16, 0xf9, 0xfb, 
        0x73, 0xab, 0x06, 0xd8,
        
    };
    unsigned adlen = 32;
    const unsigned char ad[adlen] = {
        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c,

        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c,
        
    };
    unsigned char nonce[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0X88, 0X5a, 0X30, 0X8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };
    unsigned char c[64]={0};

    

    // AES_ECB512_encrypt(m, c, mlen, Expandkey512, number_of_rounds);
  
    // AES_OCB512_encrypt(m, c, ad, adlen, mlen, k, nonce, number_of_rounds);  
    AES_OCB512_decrypt(m, c, ad, adlen, mlen, k, nonce, number_of_rounds);  
    
    cout<<endl;
    cout<<"Key          ";
    imprimiArreglo(16,k);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Nonce        ";
    imprimiArreglo(16,nonce);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Plaintext    ";
    imprimiArreglo(mlen,m);
    printf("\n---------------------------");
    cout<<endl;

    cout<<"Ciphertext   ";
    imprimiArreglo(mlen,c);
    printf("\n---------------------------");
    cout<<endl;

    // for(int i = 0; i<64; i=i+16){
    // imprimiArreglo(16,&c[i]);
    // printf("\n---------------------------");
    // cout<<endl;
    // }
   
    return 0;
}