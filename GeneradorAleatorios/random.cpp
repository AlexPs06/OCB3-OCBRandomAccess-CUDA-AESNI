#include <iostream>
#include <immintrin.h>
#include <fstream>
using namespace std; 

unsigned int rdrand_get_n_uints (unsigned int n, unsigned int *dest);
int generateRamdon (int n, unsigned int * radoms[],unsigned int *dest);

int main(){

    unsigned int n = 113;
    
    unsigned int dest[n]; 
    rdrand_get_n_uints (n,dest);

    
    ofstream myfile;
    myfile.open ("TestFile.txt");
    
    
    for(int i = 1; i<n; i++){
        myfile << hex<<dest[i]<<" ";
        if(i%256 == 0)
            myfile << "\n";
    }
    myfile.close();


    int m =(n*1024*248);
  
    myfile.open ("TestFile256mb.txt");
    for(int i = 1; i<m; i++){
         unsigned int temp = 0;
        _rdrand32_step(&temp);

        myfile << hex<< temp<<" ";
        if(i%256 == 0)
            myfile << "\n";

    }
    myfile.close();

    return 0;
}

int generateRamdon (int n, unsigned int * radoms[],unsigned int *dest)
{


    // unsigned int radoms[n/4096 ][4096];
    
    for(int j = 0; j< n; j++ ){

        unsigned int i;
        uint32_t *lptr= (uint32_t *) dest;

        for (i= 0; i< 4096; i++) {
            if ( ! _rdrand32_step(&dest[i]) ) {
            }
            radoms[j][i]=dest[i];

        }

	    
    }

	return n;
}

unsigned int rdrand_get_n_uints (unsigned int n, unsigned int *dest)
{
	unsigned int i;
	uint32_t *lptr= (uint32_t *) dest;

	for (i= 0; i< n; ++i, ++dest) {
		if ( ! _rdrand32_step(dest) ) {
			return i;
		}
	}

	return n;
}