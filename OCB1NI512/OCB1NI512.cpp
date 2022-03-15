
#include <wmmintrin.h>
#include <immintrin.h>
#include <emmintrin.h>
#include <iostream>
#include <cstring>
#include <math.h>  
using namespace std;

typedef __m512i block512;

typedef __m128i block128; 

void calculateChecksum(block512 * checksum, block512 nonce, block128 *Stag, unsigned char *key128, block512 tempNonce,int length,int indiceNonce, int number_of_rounds);
void calculateAssociatedData(const unsigned char *ad, unsigned char *nsec, long adLength, block512*keys,unsigned char *key128, block128 *Stag, int number_of_rounds);
void key128tokey512(unsigned char Expandkey128[176], unsigned char Expandkey512[704]);
static inline block512 X16_block512(block512 bl);

static inline block128 double_block(block128 bl);

static inline block512 CalculateNonceBlock(unsigned char *nonce, unsigned char *key, unsigned rounds);

static inline void AES_ecb128_encrypt_blks(block128 *in, block128 *out, unsigned nblks, unsigned char *key, unsigned rounds);

#define swap_if_le(b) \
      _mm_shuffle_epi8(b,_mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))//_mm512_shuffle_epi8 _mm512_set_epi8

#define swap_if_le512(b) \
      _mm512_shuffle_epi8(b,_mm512_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15))//_mm512_shuffle_epi8 _mm512_set_epi8


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
static inline void AES_ecb128_encrypt_blks(block128 *in, block128 *out, unsigned nblks, unsigned char *key, unsigned rounds)
{
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


static inline block128 AES_encrypt(block128 in, unsigned char *key, unsigned rounds){
	int j,rnds=rounds;
	const __m128i *sched = ((__m128i *)(key));
	__m128i tmp = in;
	tmp = _mm_xor_si128 (tmp,sched[0]);
	for (j=1; j<rnds; j++)  tmp = _mm_aesenc_si128 (tmp,sched[j]);
	tmp = _mm_aesenclast_si128 (tmp,sched[j]);
	return tmp; 
}


static inline block128 double_block(block128 bl) 
{
		const __m128i mask = _mm_set_epi32(135,1,1,1);//__m512i _mm512_set_epi32 
		__m128i tmp = _mm_srai_epi32(bl, 31);//_mm512_srai_epi32
		tmp = _mm_and_si128(tmp, mask); //_mm512_and_si512
		tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));//_mm512_shuffle_epi32
		bl = _mm_slli_epi32(bl, 1);//_mm512_slli_epi32
		return _mm_xor_si128(bl,tmp); //_mm512_xor_si512
	}

static inline block512 X16_block512(block512 bl) 
{
		const __m512i mask = _mm512_set_epi32(135,1,1,1, 135,1,1,1, 135,1,1,1, 135,1,1,1);//__m512i _mm512_set_epi32 
		__m512i tmp = _mm512_srai_epi32(bl, 31);//_mm512_srai_epi32
		
        tmp = _mm512_and_si512(tmp, mask); //_mm512_and_si512
		
        tmp = _mm512_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));//_mm512_shuffle_epi32
        
        bl = _mm512_slli_epi32(bl, 1);//_mm512_slli_epi32

        bl = _mm512_xor_si512(bl,tmp);
        

        tmp = _mm512_srai_epi32(bl, 31);//_mm512_srai_epi32
		
        tmp = _mm512_and_si512(tmp, mask); //_mm512_and_si512
		
        tmp = _mm512_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));//_mm512_shuffle_epi32
        
        bl = _mm512_slli_epi32(bl, 1);//_mm512_slli_epi32

        bl = _mm512_xor_si512(bl,tmp);


        tmp = _mm512_srai_epi32(bl, 31);//_mm512_srai_epi32 
		
        tmp = _mm512_and_si512(tmp, mask); //_mm512_and_si512
		
        tmp = _mm512_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));//_mm512_shuffle_epi32
        
        bl = _mm512_slli_epi32(bl, 1);//_mm512_slli_epi32

        bl = _mm512_xor_si512(bl,tmp);
        

        tmp = _mm512_srai_epi32(bl, 31);//_mm512_srai_epi32
		
        tmp = _mm512_and_si512(tmp, mask); //_mm512_and_si512
		
        tmp = _mm512_shuffle_epi32(tmp, _MM_SHUFFLE(2,1,0,3));//_mm512_shuffle_epi32
        
        bl = _mm512_slli_epi32(bl, 1);//_mm512_slli_epi32

        return _mm512_xor_si512(bl,tmp); //_mm512_xor_si512
	}
static inline block512 CalculateNonceBlock(unsigned char *nonce, unsigned char *key, unsigned rounds)
{
    
    __m128i nonce128 = _mm_setzero_si128();
    
   
    // for(int i = 0; i<16; i++){
    //     printf("%x ",nonce[i]);
    // }
    // printf("\n");
    nonce128 = _mm_load_si128((&((__m128i*)nonce)[0]));

    nonce128 = AES_encrypt(nonce128, key, rounds);

    __m128i rval = swap_if_le(nonce128);
    
    unsigned char nonce512[64]={0};
    for (int i=0; i < 4; i++){
        rval = double_block(rval);
        _mm_storeu_si128(&((__m128i*)nonce512)[i],rval);
    }

    __m512i out =  _mm512_loadu_si512(&((__m512i*)nonce512)[0]);
    return swap_if_le512(out);

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
    __m512i nonce;
    __m512i tempNonce;
    __m512i cipherNonceTemp[4];
    
    __m512i keys[number_of_rounds+1];
    nonce = _mm512_setzero_epi32();
    checksum[0]= _mm512_setzero_epi32();
    unsigned char Expandkey512[704]={0};
    unsigned char key128[176];//pointer to the expanded key schedule for 128

    for (int i = 0; i<4; i++){
        tmp[i]= _mm512_setzero_epi32();
        cipherNonceTemp[i]= _mm512_setzero_epi32();
    }

    AES_128_Key_Expansion (key, key128);
    key128tokey512(key128, Expandkey512);

    int i,j;
    int tempLength=length;
    if(length%64 == 0)
        tempLength = length/64;
    else
        tempLength = (length + (64 -length%64) ) /64 ;
    
    for(i=0; i < number_of_rounds+1; i++){
        keys[i] = _mm512_loadu_si512(&((__m512i*)Expandkey512)[i]);
        
    }

    nonce =  CalculateNonceBlock(nsec, key128, number_of_rounds);

   

    i=0;
    while(tempLength>4){
        unsigned blocks = 0;
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
        for(j=0; j < blocks; j++){
            cipherNonceTemp[j] = nonce;
            
            //inversion del nonce
            swap_if_le512(nonce);

            //multiplicacion del nonce x 16
            nonce = X16_block512(nonce);
            
            //inversion del nonce
            swap_if_le512(nonce);
        }
        
        //xor del nonce con el mensaje correspondiente
        for(j=0; j < blocks; j++){
            tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
        }

        //cifrado del mensaje 
        AES_ecb_encrypt_blks(tmp,tmp, blocks, keys, number_of_rounds);
        
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
 
    //final block
    for(j = 0; j<tempLength-1; j++ ){
        tmp[j] = _mm512_loadu_si512(&((__m512i*)in)[i+j]);
    }
    for(j = 0; j<tempLength-1; j++ ){
        checksum[0] = _mm512_xor_si512(checksum[0], tmp[j]);
    }
    
    for(j=0; j < tempLength-1; j++){
        cipherNonceTemp[j] = nonce;
        tempNonce=nonce;
        //inversion del nonce
        swap_if_le512(nonce);

        //multiplicacion del nonce x 16
        nonce = X16_block512(nonce);
        
        //inversion del nonce
        swap_if_le512(nonce);
    }
    

    //xor del nonce con el mensaje correspondiente
    for(j=0; j < tempLength-1; j++){
        tmp[j] = _mm512_xor_si512(cipherNonceTemp[j], tmp[j]);
    }
    
    //cifrado del mensaje 
    AES_ecb_encrypt_blks(tmp,tmp, tempLength-1, keys, number_of_rounds);
    
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
    int indiceNonce = 0;
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
        finalblockChar[finalBlocklenght] = 0; //poner 1 en vez de 0
    }

    
    __m128i finalBlock[ sizefinalBlockArray ];
    __m128i delta128[ sizefinalBlockArray ];
    __m128i tmpfinalBlock[ sizefinalBlockArray ];

    cipherNonceTemp[0] = nonce;
    
    for(j=0; j<sizefinalBlockArray; j++){
        finalBlock[j] =  _mm_loadu_si128(&((__m128i*)finalblockChar)[j]);
        delta128[j] =  _mm_loadu_si128(&((__m128i*)cipherNonceTemp)[j]);
    }

    for(j=0; j<sizefinalBlockArray; j++){
        tmpfinalBlock[j] = _mm_xor_si128(delta128[j],finalBlock[j]);
    }
    AES_ecb128_encrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128 , 10);

    for(j=0; j<sizefinalBlockArray; j++){
        tmpfinalBlock[j] = _mm_xor_si128(delta128[j],tmpfinalBlock[j]);
    }

    if(length%16!=0)
        i = ( (length + (16 -length%16) ) /16 ) - sizefinalBlockArray;
    else
        i = ( (length) /16 ) - sizefinalBlockArray;
    

    for(j=0; j < sizefinalBlockArray; j++){
        _mm_storeu_si128(&((__m128i*)out)[i+j],tmpfinalBlock[j]);
    }

    tmp[0] = _mm512_loadu_si512(&((__m512i*)finalblockChar)[0]);
    checksum[0] = _mm512_xor_si512(checksum[0], tmp[0]);
    
    indiceNonce = sizefinalBlockArray; 
    if(sizefinalBlockArray>3){
        indiceNonce=0;
        tempNonce = nonce;
        //inversion del nonce
        swap_if_le512(nonce);

        //multiplicacion del nonce x 16
        nonce = X16_block512(nonce);
        
        //inversion del nonce
        swap_if_le512(nonce);


    }
   
    calculateAssociatedData(ad, nsec, adLength, keys, key128, Stag, number_of_rounds);

    calculateChecksum(checksum,nonce,Stag, key128, tempNonce, length,indiceNonce, number_of_rounds);
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
    __m512i nonce;
    __m512i cipherNonceTemp[4];
    
    nonce = _mm512_setzero_epi32();
    checksum[0]= _mm512_setzero_epi32();

    for (int i = 0; i<4; i++){
        tmp[i]= _mm512_setzero_epi32();
        cipherNonceTemp[i]= _mm512_setzero_epi32();
    }


    int i,j;
    int tempLength=adLength;
    if(adLength%64 == 0)
        tempLength = adLength/64;
    else
        tempLength = (adLength + (64 -adLength%64) ) /64 ;
    
    nonce =  CalculateNonceBlock(nsec, key128, number_of_rounds);
    
    i=0;
    if(adLength%64 == 0)
        tempLength = adLength/64;
    else
        tempLength = (adLength + (64 - adLength%64) ) /64 ;

    while(tempLength>4){
        unsigned blocks = 0;
        //obtencion de bloques
        for(j = 0; j<4; j++ ){
            tmp[j] = _mm512_loadu_si512(&((__m512i*)ad)[i+j]);
            blocks++;
        }
       
        //calculo del nonce
        for(j=0; j < blocks; j++){
            cipherNonceTemp[j] = nonce;
        
            //inversion del nonce
            swap_if_le512(nonce);

            //multiplicacion del nonce x 16
            nonce = X16_block512(nonce);
            
            //inversion del nonce
            swap_if_le512(nonce);
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

     //final block
    for(j = 0; j<tempLength-1; j++ ){
        tmp[j] = _mm512_loadu_si512(&((__m512i*)ad)[i+j]);
    }
    
    for(j=0; j < tempLength-1; j++){
        cipherNonceTemp[j] = nonce;
        
        //inversion del nonce
        swap_if_le512(nonce);

        //multiplicacion del nonce x 16
        nonce = X16_block512(nonce);
        
        //inversion del nonce
        swap_if_le512(nonce);
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
        finalblockChar[finalBlocklenght] = 0; //poner 1 en vez de 0
    }

    
    __m128i finalBlock[ sizefinalBlockArray ];
    __m128i delta128[ sizefinalBlockArray ];
    __m128i tmpfinalBlock[ sizefinalBlockArray ];

    cipherNonceTemp[0] = nonce;
    
    for(j=0; j<sizefinalBlockArray; j++){
        finalBlock[j] =  _mm_loadu_si128(&((__m128i*)finalblockChar)[j]);
        delta128[j] =  _mm_loadu_si128(&((__m128i*)cipherNonceTemp)[j]);
    }

    

    for(j=0; j<sizefinalBlockArray; j++){
        tmpfinalBlock[j] = _mm_xor_si128(delta128[j],finalBlock[j]);
    }
    AES_ecb128_encrypt_blks(tmpfinalBlock, tmpfinalBlock, sizefinalBlockArray, key128 , 10);
    


    __m128i checksumBlock[4];
    checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)checksum)[0]);
    checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)checksum)[1]);
    checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)checksum)[2]);
    checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)checksum)[3]);
    
    i=0;
        // //suma de las variables de checksum
    __m128i checksumFinal;
    checksumFinal = _mm_setzero_si128();

    for(j=0; j<sizefinalBlockArray; j++ ){
        checksumFinal = _mm_xor_si128( checksumFinal, tmpfinalBlock[j]); 
        
    }

    

    while(adLength>0 and i<4){
        checksumFinal =  _mm_xor_si128( checksumFinal, checksumBlock[i]);
        adLength = adLength-16;
        i++;
    }
    Stag[0] = checksumFinal;

        

        
}
void calculateChecksum(block512 *checksum, //pointer to the Checksum in 512 block
block512 nonce, //pointer to the NONCE in 512 block
block128 *Stag, //resultado del checsksum de los datos asociados ya cifrados
unsigned char *key128, //llaves para 128 bits
block512 tempNonce, //nonce anterior al actual
int length,//tamaño del bloque
int indiceNonce, //indice of final part of block sum
int number_of_rounds) //numero de rondas
{
    int i=0;
    unsigned char impresion[16]={0};
    


    //divisiond el checksum para poder sumarlo
    __m128i checksumBlock[4];
    __m128i deltaChecksum;
    __m128i addIndice;
    checksumBlock[0] =  _mm_loadu_si128(&((__m128i*)checksum)[0]);
    checksumBlock[1] =  _mm_loadu_si128(&((__m128i*)checksum)[1]);
    checksumBlock[2] =  _mm_loadu_si128(&((__m128i*)checksum)[2]);
    checksumBlock[3] =  _mm_loadu_si128(&((__m128i*)checksum)[3]);
    
    if(indiceNonce == 0){
         deltaChecksum =   _mm_loadu_si128(&((__m128i*)&nonce)[0]); 
         addIndice =  _mm_loadu_si128(&((__m128i* )&tempNonce)[3]);
         deltaChecksum =   _mm_xor_si128( deltaChecksum,addIndice ); 
    }
    else{
         deltaChecksum =   _mm_loadu_si128(&((__m128i*)&nonce)[indiceNonce]); 
         addIndice =  _mm_loadu_si128(&((__m128i* )&nonce)[indiceNonce-1]);
         deltaChecksum =   _mm_xor_si128( deltaChecksum,addIndice ); 
    }
        

    // //suma de las variables de checksum
    __m128i checksumFinal  = _mm_setzero_si128();
    i=0;
    while(length>0 and i<4){
        checksumFinal =  _mm_xor_si128( checksumFinal, checksumBlock[i]);
        length = length-16;
        i++;
    }
        

        //xor delta checksumn
        checksumFinal =  _mm_xor_si128( checksumFinal, deltaChecksum);

        

        //cifrado del checksum
        checksumFinal = AES_encrypt(checksumFinal, key128, number_of_rounds);

        checksumFinal = _mm_xor_si128(checksumFinal, Stag[0]); 
        //falta xor con el tag
        
        _mm_store_si128 ((__m128i*)impresion,Stag[0]);
        cout<<"S   \n";
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
    unsigned char keys[176] = {0};
    unsigned char Expandkey512[704]={0};
    unsigned long long mlen=32;
    
    const unsigned char m[mlen] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,

        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,
        
        
    };
    const unsigned char ad[mlen] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,

        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,
        
    };
    unsigned char nonce[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d, 
        0x31, 0x31, 0x98, 0xa2, 
        0xe0, 0x37, 0x07, 0x34,
    };
    unsigned char c[64]={0};

    

    // AES_ECB512_encrypt(m, c, mlen, Expandkey512, number_of_rounds);
  
    AES_OCB512_encrypt(m, c, ad, mlen, mlen, k, nonce, number_of_rounds);  

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

    // for(int i = 0; i<64; i=i+16){
    // imprimiArreglo(16,&c[i]);
    // printf("\n---------------------------");
    // cout<<endl;
    // }
   
    return 0;
}