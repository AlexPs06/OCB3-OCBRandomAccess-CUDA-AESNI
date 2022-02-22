#include <iostream>
#include <immintrin.h>
#include <fstream>
using namespace std; 

int main(){

    unsigned int n = 4096;
    unsigned int dest[n]={0}; 
    FILE *write_ptr;

    write_ptr = fopen("TestFile.bin","wb");  // w for write, b for binary
    fclose(write_ptr);
    
    for(int j=0;j<16000;j++){
    
        for(int k = 0; k<n; k++){
            unsigned int temp = 0;
            _rdrand32_step(&temp);
            dest[k]=temp;
        }
        
        
        write_ptr = fopen("TestFile.bin","ab");  // w for write, b for binary
        fwrite(dest,sizeof(dest),1,write_ptr); // write 4000 bytes from our buffer
        fclose(write_ptr);
        exit(1);
    }
    
    cout<<"bloques de 16 bytes "<<( (16000*n)/ 16)<<endl;
    cout<<"bloques de 16 bytes pero entre 4 "<<( (16000*n)/ 16)/4 <<endl;
    //para visualizar el archivo usamos hexdump
    // hexdump TestFile.bin

    // unsigned char buffer[10];
    // FILE *ptr;

    // ptr = fopen("test.bin","rb");  // r for read, b for binary

    // fread(buffer,sizeof(buffer),1,ptr); // read 10 bytes to our buffer

    return 0;
}

