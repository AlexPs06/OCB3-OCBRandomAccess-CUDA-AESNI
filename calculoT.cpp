#include<iostream>
using namespace std;

// d
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
    default:
        break;
    }
    return 0;

}

void mixColumns(unsigned char* in,  int * in1,  int * in2,  int * in3,  int * in4 ){
    // unsigned char T1[4]={in[0],in[4],in[8],in[12] };
    // unsigned char T2[4]={in[1],in[5],in[9],in[13] };
    // unsigned char T3[4]={in[2],in[6],in[10],in[14] };
    // unsigned char T4[4]={in[3],in[7],in[11],in[15] };

    for (int i = 0; i < 256; i++){
        unsigned char T1[4]={in[i],in[i],in[i],in[i] };
        unsigned char T2[4]={in[i],in[i],in[i],in[i] };
        unsigned char T3[4]={in[i],in[i],in[i],in[i] };
        unsigned char T4[4]={in[i],in[i],in[i],in[i] };
    
        T1[0] =  multiplicacionENGF2(2, T1[0]);
        T1[3] =  multiplicacionENGF2(3, T1[3]);

        T2[0] =  multiplicacionENGF2(3, T2[0]);
        T2[1] =  multiplicacionENGF2(2, T2[1]);

        T3[1] =  multiplicacionENGF2(3, T3[1]);
        T3[2] =  multiplicacionENGF2(2, T3[2]);

        T4[2] =  multiplicacionENGF2(3, T4[2]);
        T4[3] =  multiplicacionENGF2(2, T4[3]);

        
        
        


        in1[i]= (T1[0]<<24) ^ (T1[1]<<16) ^ (T1[2]<<8) ^ T1[3];
        
        in2[i]= (T2[0]<<24) ^ (T2[1]<<16) ^ (T2[2]<<8) ^ T2[3];
        in3[i]= (T3[0]<<24) ^ (T3[1]<<16) ^ (T3[2]<<8) ^ T3[3];
        in4[i]= (T4[0]<<24) ^ (T4[1]<<16) ^ (T4[2]<<8) ^ T4[3];
       
    }
    
}

void imprimirMatiz(int columnas,int filas, int * matriz){

    for (int i = 0; i<columnas; i++){
        for (int j = 0; j<columnas; j++){
            printf("0x%x, ",matriz[(columnas * i) + j] & 0xffffffff );
        }
        printf("\n"); 
    } 
}

int main(){
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

    int T1[256];
    int T2[256];
    int T3[256];
    int T4[256];
    mixColumns(matrizCajaS, T1, T2, T3, T4 );
    int tam = 16;
    printf("Caja T4\n"); 

    imprimirMatiz(tam,tam, T4);

    // printf("Caja T2\n"); 

    // imprimirMatiz(tam,tam, T2);

    // printf("Caja T3\n"); 

    // imprimirMatiz(tam,tam, T3);

    // printf("Caja T4\n"); 

    // imprimirMatiz(tam,tam, T4);

    return 0;
}