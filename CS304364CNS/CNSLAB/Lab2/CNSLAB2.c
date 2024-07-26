/*CS364 Lab 2 
Coded By: ID: 202151188  Name: Dipean Dasgupta*/

//Importing/including the required library/header files
#include <stdio.h>

// Defining the substitution box(S_Bx) for the round function.
//Here it is a array/list of 256 values that, using a preset rule or method, replaces input values with corresponding output values.
unsigned char S_Bx[256] = {
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
     //values put in 256 bit array

//This Function to performs left circular rotation on a 32-bit word
unsigned int LCS(unsigned int val, int sft){        //argument taken are val(value) and sft(shift)
    return (val << sft) | (val >> (32 - sft));     //shifts the bits of value to the right by (32 - shift) positions;
}                                                  //returns the value after left circular rotation

//round keys are generated from the user input K using
//This function is round and used for Symmetric  encryption and decryption
unsigned int rF(unsigned int R, unsigned int K){     //The round function(rF) takes two arguments: R and K;both unsigned integers
    unsigned int X = R ^ K;
    unsigned int res = 0;
    for (int i = 0; i < 4; i++)
    {
        res |= (unsigned int)S_Bx[(X >> (i * 8)) & 0xFF] << (i * 8);
    }                                                      //Applying S-box substitution to each byte of (R XOR K) and returning combined results
    return res;
}

// Round keys are generated from the user input ky(key), using the ky scheduling algorithm in generate round ky function
void GRK(unsigned int ky, unsigned int r_k[16]){
    unsigned int Y = ky;                     //storing value of ky in Y
    for (int i = 0; i < 16; i++)
    {
        unsigned int Y_tmp = Y;    //storing value of Y in Y_tmp
        for (int j = 0; j < i; j++)
        {
            Y_tmp = LCS(Y_tmp, 1);  //Rotating/shifting the key in a left circular motion, then storing the outcome as a round key.
        }
        r_k[i] = Y_tmp;       //storing the outcome/result as a round key(r_k[i])
    }
}

//Fiestel Cipher Function for Encrypting the PT (Plain Text) using the ky(key) and returning the Ciphertext (CT)
unsigned long long ENC(unsigned long long PT, unsigned int ky){
    unsigned int r_k[16];       //an Array is required to store the 16 round keys
    GRK(ky, r_k);               //Round key generation using the key scheduling algorithm in GRK

    unsigned int L = PT >> 32;              //spliting the 64-bit Plaintext into two segments of 32 bits each
    unsigned int R = PT & 0xFFFFFFFF;

    for (int i = 0; i < 16; i++)            // Iterating through 16 rounds of Feistel network
    {
        unsigned int temp = R;          // Storing the original value of R
        R = L ^ rF(R, r_k[i]);          //XORing R with the output of the round function
        L = temp;                        // L is updated and becomes original value of temp
    }

    return ((unsigned long long)L << 32) | R;  // Concatenating L and R to form the Ciphertext
}

//Fiestel Function for decrypting the CT (Ciphertext) using the key (K) and returning the PT (Plain Text)
unsigned long long DEC(unsigned long long CT, unsigned int ky){
    unsigned int r_k[16];
    GRK(ky, r_k);               //Round key generation using the key scheduling algorithm in GRK

    unsigned int L = CT >> 32;       //splitted into 2 halves
    unsigned int R = CT & 0xFFFFFFFF;

    for (int i = 15; i >= 0; i--)
    {
        unsigned int temp = L;
        L = R ^ rF(L, r_k[i]);
        R = temp;
    }

    return ((unsigned long long)L << 32) | R;
}

//Main function
int main(){

    unsigned long long PT;
    unsigned int ky;             //variables declared for Plaintext(PT) and key(K)

    //Taking input from the user for PT(plaintext) and ky(Key) in Decimal format
    printf("Enter PlainText (64-bit decimal): ");
    scanf("%llu", &PT);
    printf("Enter Key (32-bit decimal): ");
    scanf("%u", &ky);

    // Calling Encryption function
    unsigned long long CT = ENC(PT, ky);    //arguments passed are PT(plaintext) and ky(key)
    printf("Encrypted Ciphertext(CT): %llu\n", CT);     //performing encryption and printing the CipherText(CT)

    //Calling Decryption function
    unsigned long long decrypt_pt = DEC(CT, ky);       //arguments passed are CT(ciphertext) and ky(key)
    printf("Decrypted Plaintext(PT): %llu\n", decrypt_pt);        //performing decryption and printing the decrypted PlainText(PT)

    return 0;
}