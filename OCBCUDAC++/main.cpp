#include <stdio.h>
#include <stdlib.h>
#include <cmath>
#include<iostream>
#include <cstring>
using namespace std;

#define N 8
#define MIN 0 
#define MAX 1000
class aesBlock
{
public:
    unsigned int block[4];
};
void initialize_matrices(float * a, float * b);
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
void getDelta(const unsigned int nonce[4],const unsigned long long mlen, aesBlock* delta,unsigned int *keys,unsigned long long deltalen );
void copyMessageToAESBlock(aesBlock* encrypt, int numBlocks,const unsigned int m2[]);
void unsignedCharArrayTounsignedIntArray(const unsigned char *in,unsigned int *out, unsigned long long len);
void checksum (aesBlock *in, unsigned long long tam, unsigned int *out );
void ExpansionKeys128( unsigned int *k,unsigned long long klen,  unsigned int keys[11][4] );
void imprimiArreglo(int tam, unsigned int *keys );
extern void perform_stencil(float * a, float * b, const int n);
extern void AES128Encrypt(aesBlock *m, unsigned long long mlen, unsigned int *keys);
extern void OCBRandomAccess(aesBlock *m,aesBlock *delta, aesBlock *S, const unsigned long long mlen, unsigned long long deltalen, unsigned int *keys);
extern void OCBRandomAccessAsociatedData(aesBlock *ad, aesBlock *delta, aesBlock *Ek1, aesBlock *result, const unsigned long long adlen, unsigned long long deltalen, unsigned int *keys);
extern void OCBRandomAccessDecrypt(aesBlock *m,aesBlock *delta,const unsigned long long mlen, unsigned long long deltalen, unsigned int *keys);

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
int main(int argc, char **argv) {
    // set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.1");
    // set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes");
        // 0x32,0x88,0x31,0xe0,
        // 0x43,0x5a,0x31,0x37,
        // 0xf6,0x30,0x98,0x07,
        // 0xa8,0x8d,0xa2,0x34,

        // 0x3243f6a8,
        // 0X885a308d,
        // 0x313198a2,
        // 0xe0370734,

    const unsigned char k[16] ={ 
        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c
    };
    const unsigned char m[16] ={ 
        0x30, 0x88, 0x6c, 0x7f,   
        0x32, 0x7f, 0xfe, 0xad, 
        0xee, 0xdf, 0x75, 0x48,
        0x6f, 0x09, 0xe7, 0xb6,
        // 0x32,0x88,0x31,0xe0,
        // 0x43,0x5a,0x31,0x37,
        // 0xf6,0x30,0x98,0x07,
        // 0xa8,0x8d,0xa2,0x34,
    };
    const unsigned char m2[32] ={ 
        0x32,0x88,0x31,0xe0,
        0x43,0x5a,0x31,0x37,
        0xf6,0x30,0x98,0x07,
        0xa8,0x8d,0xa2,0x34,
        0x32,0x88,0x31,0xe0,
        0x43,0x5a,0x31,0x37,
        0xf6,0x30,0x98,0x07,
        0xa8,0x8d,0xa2,0x34,
    };
    unsigned long long mlen=32;
    // 3032ee6f 
    // 887fdf09 
    // 6cfe75e7 
    // 7fad48b6 
    unsigned char c[16]={
        0x30, 0x88, 0x6c, 0x7f,   
        0x32, 0x7f, 0xfe, 0xad, 
        0xee, 0xdf, 0x75, 0x48,
        0x6f, 0x09, 0xe7, 0xb6,
    };
    unsigned long long *clen;
     
    const unsigned char ad[32] ={ 
        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c,
        0x2b,0x28,0xab,0x09,
        0x7e,0xae,0xf7,0xcf,
        0x15,0xd2,0x15,0x4f,
        0x16,0xa6,0x88,0x3c
    };
    unsigned long long adlen = 32;

    const unsigned char *nsec;
    unsigned char *nsec2;
    const unsigned char *npub; 

    crypto_aead_encrypt(c, clen, m2, mlen, ad, adlen, nsec, npub, k);
    // unsignedCharArrayTounsignedIntArray(m,m2,mlen);
    // imprimiArreglo(mlen/4,m2);
    // crypto_aead_decrypt(c, clen, nsec2, m, mlen, ad, adlen, npub, k);
    //compile comand -march=native;

    return 0;
}

void initialize_matrices(float * a, float * b) {
    for (int i = 0; i < N * N * N; i ++) {
        a[i] = 0.0;
        b[i] = MIN + (MAX - MIN) * (rand() / (float)RAND_MAX);
    }
}


int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k){


    unsigned long long bloques = (unsigned long long) ceil( (double) mlen/16.0); //cada 4080 salta en 1 el delta
    unsigned long long deltalen = (unsigned long long) ceil( (double) bloques/255.0);
    int numBlocks = mlen/16;
    aesBlock* delta;
    delta = new aesBlock [deltalen];
    aesBlock* encrypt;
    encrypt = new aesBlock [numBlocks+1];//Se le suma uno por el bloque de la sumatoria

    aesBlock* Ek1;
    Ek1 = new aesBlock [1];

    aesBlock* S;
    S = new aesBlock [1];

    int numAdBlocks = adlen/16;
    aesBlock* asociateData;
    asociateData = new aesBlock [numAdBlocks];

    const unsigned int nonce[4] = {
        0x3243f6a8,
        0X885a308d,
        0x313198a2,
        0xe0370734,
    };


    unsigned int message[mlen/4];
    unsigned int adTemp[adlen/4];
    unsigned int keys[11][4];
    unsigned int key[4];
    unsigned int sumcheck[4]={0};

    unsignedCharArrayTounsignedIntArray(k,key,16);
    unsignedCharArrayTounsignedIntArray(m,message,mlen);
    unsignedCharArrayTounsignedIntArray(ad,adTemp,adlen);
    
    for(int i = 0; i<numBlocks; i++){
        for (int j = 0; j<4;j++){
            encrypt[i].block[j]=  message[(i*4)+j];
        }
    }
    for(int i = 0; i<numAdBlocks; i++){
        for (int j = 0; j<4;j++){
            asociateData[i].block[j]=  adTemp[(i*4)+j];
        }
    }

    Ek1[0].block[0] = 0Xffffffff;
    Ek1[0].block[1] = 0Xffffffff;
    Ek1[0].block[2] = 0Xffffffff;
    Ek1[0].block[3] = 0Xffffffff;


    //expansion de llaves
    ExpansionKeys128(key,1, keys);
    //obetencion de la delta por medio del nonce 
    getDelta(nonce , mlen, delta, &keys[0][0],deltalen);

   

    
    //calculo de Ek1 para lamda 5
    AES128Encrypt(Ek1, 16, &keys[0][0]);
    imprimiArreglo(4,Ek1[0].block);
        cout<<endl;
    // OCBRandomAccessAsociatedData(asociateData, delta, Ek1, S, adlen, deltalen, &keys[0][0]);
    // checksum (asociateData, numAdBlocks, S[0].block );



    // // checksum (bloques,encrypt,k, delta,deltalen, asociateData, sumcheck);
    // checksum (encrypt, numBlocks, encrypt[numBlocks].block );

    // OCBRandomAccess(encrypt, delta,S, mlen+16, deltalen, &keys[0][0]);

    // cout<<"Encrypt"<<endl;
    // for(int i = 0; i<numBlocks; i++){
    //     imprimiArreglo(4,encrypt[i].block);
    //     cout<<endl;
    // }
    // cout<<"S"<<endl;
    // imprimiArreglo(4,S[0].block);
    // cout<<"Tag"<<endl;
    // imprimiArreglo(4,encrypt[numBlocks].block);
    return 1;
}
void getDelta(const unsigned int nonce[4],const unsigned long long mlen, aesBlock* delta,unsigned int *keys,unsigned long long deltalen ){
    
    for(int i = 0; i<deltalen; i++){
        
        for (int j = 0; j<4;j++){
            if(j==3){
                delta[i].block[j]= nonce[j]+i;
            }
            else{
                delta[i].block[j]= nonce[j];
            }

        }
    }
    AES128Encrypt(delta, deltalen*16, keys);


}

void copyMessageToAESBlock(aesBlock* encrypt, int numBlocks,const unsigned int m2[]){
    for(int i = 0; i<numBlocks; i++){
        for (int j = 0; j<4;j++){
            encrypt[i].block[j]=  m2[(i*4)+j];
        }
    }
}
void unsignedCharArrayTounsignedIntArray(const unsigned char *in,unsigned int *out, unsigned long long len){
    
    unsigned char h[len];
    unsigned char temp[len];
	
    memcpy(h, in, len);
    memcpy(temp, in, len);
    
    int shifttab[16]= {
        12, 8, 4, 0,   
        13, 9, 5, 1,  
        14, 10, 6, 2,
        15, 11, 7, 3 
        };

    for(int i = 0; i < len; i++){
        int index = shifttab[i%16]+(floor(i/16)*16 );
        temp[i] = h[index];
    }
    unsigned int * temp2;
    temp2 = (unsigned int *) temp;
    for(int i = 0; i < len/4; i++){
        out[i]=temp2[i];
    }
}
void checksum (aesBlock *in, unsigned long long tam, unsigned int *out ){
    for (int i=0; i<tam;i++){
        out[0] = out[0] ^ in[i].block[0];
        out[1] = out[1] ^ in[i].block[1];
        out[2] = out[2] ^ in[i].block[2];
        out[3] = out[3] ^ in[i].block[3];
    }
}
void ExpansionKeys128( unsigned int *k,unsigned long long klen,  unsigned int keys[11][4] ){
    unsigned char RotWordTemp[4];
    const unsigned int matrizRcon[10]={ 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};
    memcpy(&keys[0], k, 16);
    for(int i = 0; i<10; i++){
        RotWordTemp[0]=keys[i][3]>>16;
        RotWordTemp[1]=keys[i][3]>>8;
        RotWordTemp[2]=keys[i][3];
        RotWordTemp[3]=keys[i][3]>>24; 
        
        for(int j = 0;  j < 4; j++ ){
            RotWordTemp[j] = matrizCajaS[ (int) RotWordTemp[j] ];
        }
        int RotWord = 0;
        RotWord = RotWord ^ ( (int) RotWordTemp[0])<<24;
        RotWord = RotWord ^ ( (int) RotWordTemp[1])<<16;
        RotWord = RotWord ^ ( (int) RotWordTemp[2])<<8;
        RotWord = RotWord ^ ( (int) RotWordTemp[3]);
        
        keys[i+1][0] =  RotWord ^ keys[i][0];
        keys[i+1][0] = keys[i+1][0] ^ matrizRcon[i];
        for(int x = 1;  x < 4; x++ ){
            keys[i+1][x] =  keys[i+1][x-1] ^ keys[i][x];
        }
    }
}
void imprimiArreglo(int tam, unsigned int *keys ){
    for (int i = 0; i<tam; i++){
        printf("%x \n", keys[i] );
    }
    printf("\n---------------------------\n");
}