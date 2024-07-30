/*CS364 Lab 3 
Coded By: ID: 202151188  Name: Dipean Dasgupta*/
//AES-prime is implemented in this code.The AES  has been modified into AES-prime as specified in the assignment.
//In comparison to regular AES-128, the subbyte function and the mix column function are altered in AES-prime.

//Loading the required libraries
#include<stdio.h>
#include <stdbool.h>

//Setting required preprocessors
#define uint16_t unsigned short int
#define uint32_t unsigned long int
#define uint64_t unsigned long long int
#define uchar_t unsigned char

//The binary representation of the AES primitive polynomial
// G(x) = x^8 + x^4 + x^3 + x + 1 = (0000 0001 0001 1011) = 0x11b
const uint16_t G = 0x011b;

//the Subbyte table used in AES
uchar_t Sbyte_t[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

// the round constants for AES-prime, they are exactly similar to AES-128.
const uint32_t Rconst[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

//this function yields the two polynomials' product.
//Since there are two polynomials in the input (deg <= 7), the maximum degree of the output polynomial that can be produced is 15.
uint16_t Pduct(uchar_t a, uchar_t b){
    uint16_t prod = 0; //stores the Pduct
    for(int i = 0; i < 8; i++){            //loop run 0-> 7 as max degree(a)=7
        if((a >> i) & 1){                      
            uint16_t x = b << i;    //checking if a has x^i, if yes then add b << i to the product 
            prod = prod ^ x;      
        }
    }
    return prod;
}
//Implementing the Subbyte function of AES-prime
//The sub-byte function in AES-prime is modified from AES-128.
uchar_t SByte(uchar_t x){
    uchar_t tmp = ((uint16_t) x << 1) ^ 1;  //Multiplied input by x and added 1.
    if((x >> 7) & 1) tmp ^= 27;    
    uint16_t T2 = tmp & 15;    
    uint16_t T1 = tmp >> 4;    
    return Sbyte_t[T1][T2];     //table look-up
}
//Implementing the inverse subbyte function of AES-prime
uchar_t invSByte(uchar_t x){
    uchar_t ivn = 0;
    //finding x = subInp in the look-up table and calcuating y = inverse of x
    for(uchar_t i = 0; i < 16; i++){
        for(uchar_t j = 0; j < 16; j++){
            if(Sbyte_t[i][j] == x){ 
                ivn = ((i << 4) | j);
            }
        }
    }
    if(ivn & 1) ivn = ivn >> 1;    //case where LSB of ivn is set
    else ivn = ((ivn ^ 27) >> 1) | (1 << 7); //case where LSB of ivn is not set

    return ivn;
}

//Implementing Shift Row function, 
//What its does is left circular shift. It shifts the i^th row by i positions.
void SftRw(uchar_t S[4][4]){
    for(int i = 1; i < 4; i++){ //0th row has shift of 0, therefore starting the loop from row 1
        uchar_t tmp[4];    
        for(int j = 0; j < 4; j++) tmp[j] = S[i][j];  //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            S[i][j] = tmp[(j + i) % 4];     //left circular shifting the row ith by i positions
        }
    }
}

//Implementing Inverse Shift Row function, 
//This function does the opposite, right circular shifts the i^th row by i positions
void invSftRw(uchar_t S[4][4]){
    for(int i = 1; i < 4; i++){     //0th row has shift of 0, therefore starting the loop from row 1
        uchar_t tmp[4];
        for(int j = 0; j < 4; j++) tmp[j] = S[i][j];  //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            S[i][j] = tmp[(j + 4 - i) % 4];     //right circular shifting the ith row by i positions
        }
    }
}

uchar_t x2TS(uchar_t x){
    uchar_t tmp = x << 2; //multiplied by x^2
    if((x >> 6) & 1) tmp ^= (0x1b);  //checked if there is x^6 in input, it will result in x^8, hence, to get the remainder, xoring with 0x1b
    if(x >> 7) tmp ^= (0x36);  //checked if there is x^7 in input, it will result in x^9, hence, to get the remainder, xoring with 0x36
    return tmp; 
}


void MColn(uchar_t S[4][4]){
    for(int i = 0; i < 4; i++){ //for each column of input matrix
        //calculating the 4 polynomial according to the mix column matrix
        uchar_t T1 = S[0][i] ^ x2TS(S[1][i]) ^ x2TS(S[2][i]) ^ x2TS(S[3][i]) ^ S[3][i];
        uchar_t T2 = x2TS(S[0][i]) ^ S[0][i] ^ S[1][i] ^ x2TS(S[2][i]) ^ x2TS(S[3][i]);
        uchar_t T3 = x2TS(S[0][i]) ^ x2TS(S[1][i]) ^ S[1][i] ^ S[2][i] ^ x2TS(S[3][i]);
        uchar_t T4 = x2TS(S[0][i]) ^ x2TS(S[1][i]) ^ x2TS(S[2][i]) ^ S[2][i] ^ S[3][i];
        //updating the column of input, with mix column value
        S[0][i] = T1;
        S[1][i] = T2;
        S[2][i] = T3;
        S[3][i] = T4;
    }
}

//Implementing mGx function for calculating modulo G(x), where input= polynomial of degree <= 15.
uchar_t mGx(uint16_t x){
    for(int i = 15; i > 7; i--){  //loop from 15 to 8, because if x^7 or lower bit is set, then it is already mod G(x) 
        if((x >> i) & 1){        //checking if x^i bit is set, i.e, if x^i is in the polynomial     
            x = x ^ (1 << i);  
            x = x ^ (0x1b << (i - 8)); //we need to replace, so first remove x^i, i.e. make ith bit zero.
        }
    }
    return x & 0xff;
}

//The matrix for calculating the inverse of mix columns in AES-prime
const uchar_t MCol_iv[4][4] = {
    {0xa5, 0x07, 0x1a, 0x73},
    {0x73, 0xa5, 0x07, 0x1a},
    {0x1a, 0x73, 0xa5, 0x07},
    {0x07, 0x1a, 0x73, 0xa5}
};

void ivMCols(uchar_t S[4][4]){
    uchar_t tmp[4]; //stores mix column inverse of a column
    uchar_t p = 0xff;

    //matrix multiplication
    for(uint16_t i = 0; i < 4; i++){
        for(uint16_t j = 0; j < 4; j++){
            uint16_t x = (uint16_t)0;
            for(uint16_t k = 0; k < 4; k++){                        //the product() method does not take modulo with G(x)                
                uint16_t y =  Pduct(MCol_iv[j][k], S[k][i]);        //hence, max degree of x here can be 15. Hence, x is uint16_t.
                x = x ^ y;
            }    
            tmp[j] = mGx(x);        //taking modulo from G(x) and storing it in temp
        }
        for(uint16_t j = 0; j < 4; j++){
            S[j][i] = tmp[j];       //updating the input column with its mix column inverse.
        }
    }
}

//function to left circular shift a 32-bit word by 8 bits (or 1 byte)
uint32_t RTWord(uint32_t x){
    uchar_t p = 0xff; 
    uchar_t tmp = (x >> 24) & p; //taking out the most significant byte    
    x = (x << 8) | tmp; 
    return x;
}

//the original Subbyte function of AES-128, inverse not required(key same for encryption and decryption)
uchar_t Sbyte_main(uchar_t x){
    uint16_t T2 = x & 15;       //least significant 4 bits for column number
    uint16_t T1 = x >> 4;       //most significant 4 bits for row number
    return Sbyte_t[T1][T2]; //table look-up
}

//Implementing function for performing subbytes of each byte of the 32-bit word.
//Each word contains 4-bytes and subyte for each byte is performed.
uint32_t SbWord(uint32_t x){
    uchar_t p = 0xff;
    uchar_t x0, x1, x2, x3; 
    x0 = (x >> 24) & p; 
    x1 = (x >> 16) & p; 
    x2 = (x >> 8) & p;
    x3 = x & p;
    //performing SByte on each byte, since Key Scheduling uses original Subbyte function.
    x0 = Sbyte_main(x0);
    x1 = Sbyte_main(x1);
    x2 = Sbyte_main(x2);
    x3 = Sbyte_main(x3);
    //output = SByte(x0) || SByte(x1) || SByte(x2) || SByte(x3)
    x = (x0 << 24) | (x1 << 16) | (x2 << 8) | x3;
    return x;
}

//Implementing KeyScheduling function to generate the round keys for AES-prime, and is exactly similar to AES-128
void KSchedule(uchar_t K[16], uchar_t RKys[11][4][4]){
    uint32_t Wrds[44]; //generated 44 words will be stored here
    uchar_t p = 0xff;
    for(int i = 0; i < 4; i++){  
        Wrds[i] = (K[4*i] << 24) | (K[4*i+1] << 16) | (K[4*i+2] << 8) | (K[4*i+3]);
    }
    //finding remaining Words according to the Key scheduling algorithm
    for(int i = 4; i < 44; i++){
        uint32_t tmp = Wrds[i-1]; 
        if(i % 4 == 0) tmp = SbWord(RTWord(tmp)) ^ (Rconst[i/4 - 1]); 
        Wrds[i] = Wrds[i-4] ^ tmp;
    }    
    //the 11 round keys are stored as 4*4 matrix in column-wise way
    //each roundKey[i] is a round key for round i
    for(int i = 0; i < 11; i++){
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                RKys[i][k][j] = (Wrds[4*i+j] >> (24 - 8 * k)) & p; 
            }
        }
    }
}

//Implementing the round function rFunc of AES-prime
void rFunc(int r, uchar_t S[4][4]){         //the variable r stores which round it is
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            S[i][j] = SByte(S[i][j]);
        }
    }    
    SftRw(S);       //performing shift row    
    if(r < 10) MColn(S);        //if not the last( round 10), perform mix columns.
}

//Implementing the inverse round function  of AES-prime
void invRFunc(int r, uchar_t S[4][4]){    
    if(r != 10) ivMCols(S);     //only not required for 10th round    
    invSftRw(S);                //performing inverse shift row    
    for(int i = 0; i < 4; i++){       //performing Subbyte inverse
        for(int j = 0; j < 4; j++){
            S[i][j] = invSByte(S[i][j]);
        }
    }
}

//Implementing the encAES function for encrypting using the AES-prime algorithm
void encAES(uchar_t PT[16], uchar_t K[16], uchar_t CT[16]){
    uchar_t S[4][4];
    uchar_t k[4][4];

    //Storing the Key and PlainText in 4*4 matrices
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            S[j][i] = PT[i * 4 + j];
            k[j][i] = K[i * 4 + j];
        }
    }    
    uchar_t RKys[11][4][4];
    KSchedule(K, RKys);     //generating roung keys
    //performing encryption
    for(int i = 0; i < 11; i++){        
        for(int j = 0; j < 4; j++){           //mixing the round keys     
            for(int x = 0; x < 4; x++){
                S[j][x] = S[j][x] ^ RKys[i][j][x];
            }
        }               
        if(i < 10) rFunc(i+1, S);  //round function called for 10 times
    }                               //in last iteration only the last round key mixed
    int idx = 0;
    for(int i = 0; i < 4; i++){           //storing the generated ciphertext in a 1-D array.
        for(int j = 0; j < 4; j++){
            CT[idx++] = S[j][i];
        }
    }
}

//Implementing decAES function for decrypting using the AES-prime algorithm
void decAES(uchar_t CT[16], uchar_t K[16], uchar_t dec_txt[16]){
    uchar_t S[4][4];
    uchar_t k[4][4];

    //storing the K and CT in 4*4 matrices
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            S[j][i] = CT[i * 4 + j];
            k[j][i] = K[i * 4 + j];
        }
    }    
    uchar_t RKys[11][4][4]; 
    KSchedule(K, RKys); //generating round keys

    //performing decryption
    for(int i = 10; i >= 0; i--){
        //mixing the round keys
        for(int j = 0; j < 4; j++){
            for(int x = 0; x < 4; x++){
                S[j][x] = S[j][x] ^ RKys[i][j][x];
            }
        }  
        if(i > 0) invRFunc(i, S); //round function called 10 times
    }    
    int idx = 0;                    //storing the generated PlainText in a 1-D array
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            dec_txt[idx++] = S[j][i];
        }
    }
}

//helper function to print the array
void print(uchar_t S[16]){
    for(int i = 0; i < 16; i++){
        printf("%02x", S[i]);
    }
    printf("\n");
}

int main(){
    
    uchar_t PT[20];
    printf("Provide all input in hex form with spaces\n");
    printf("Enter 128-bit PT(m1) : ");
    for(int i = 0; i < 16; i++) {
        scanf("%hhx", &PT[i]);    //taking PlainText as input and its m1
    }
 
    uchar_t K[20]; 
    printf("Enter 128-bit K(m2) : ");
    for(int i = 0; i < 16; i++){
        scanf("%hhx", &K[i]); //taking Key as input and its m2
    }    
    uchar_t CT[16];
    encAES(PT, K, CT);  //calling ecryption function

    printf("\n");
    printf("Plaintext(m1): "); //printing PlainText
    print(PT);
    printf("Key(m2): ");  //print Key
    print(K); 
    printf("\n");
    printf("Ciphertext h(m1||m2): ");
    print(CT); //printing Ciphertext
    
    uchar_t DEC_txt[16];
    decAES(CT, K, DEC_txt); //generating decrypted text to match with plaintext
    printf("Decrypted Text(m1): "); //printing decrypted text
    print(DEC_txt);
    printf("\n");
    uchar_t rnd_ky[20]; 
    printf("Enter 128-bit random Key(m2') : ");
    for(int i = 0; i < 16; i++){
        scanf("%hhx", &rnd_ky[i]); //taking random Key as input as m2'
    }    
    uchar_t dec_txt[16];
    decAES(CT, rnd_ky, dec_txt); //decrypting the Ciphertext with the random Key
    printf("Decrypted Text(m1'): "); //printing decrypted text m1'
    print(dec_txt);    
    printf("\n");
    printf("Second preimage(m1'||m2'): ");  //orinting second preimage
    for(int i = 0; i < 16; i++) {
        printf("%02x ", dec_txt[i]);  
    }
    for(int i = 0; i < 16; i++) {
        printf("%02x ", rnd_ky[i]);        
    }
    printf("\n");
    printf("\n");
    uchar_t enc_txt[16];  //
    encAES(dec_txt, rnd_ky, enc_txt); //encrypting the decrypted text with the random Key
    printf("Encrypted h(m1'||m2'): "); //print encrypted text'
    print(enc_txt);

    printf("Ciphertext h(m1||m2): ");
    print(CT); //printing Ciphertext
    //both the encrypted texts are same, hence the second preimage is correct.
    return 0;
}

//for test example
// P:43 82 9c a6 d3 81 96 c9 f2 ff 67 8a ec bd bf 12
// K: cd 12 9c e8 ba d7 35 62 b0 97 b6 b4 24 39 ca 19
//K2: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c