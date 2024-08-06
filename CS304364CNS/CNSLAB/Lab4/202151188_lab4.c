/*CS364 Lab 4 
Coded By: ID: 202151188  Name: Dipean Dasgupta*/

//Importing/including the required library/header files
#include <stdio.h>
#include <stdlib.h>  
#include <time.h>    
//preprocessors
#define uint16_t unsigned short int
#define uint32_t unsigned int
#define uint64_t unsigned long long int
#define uchar_t unsigned char
//The defined curve equation y^(2) = x^(3) + ax + b over Zp*
//given equation in the assignment y^(2) = x^(3) + 449x + 233, matching with defined eqn P = 1021, a = 449, b = 233
const uint32_t P = 1021;
//curve parameters, 
const uint32_t a = 449; 
const uint32_t b = 233;
//Given point at infinity(0,1)
const uint32_t thtaX = 0; //x value (0)
const uint32_t thtaY = 1; //y value (1)

//Alice and Bob will make a mutual decision for the Eliiptic Curve Diffie Hellman Key Exchange and that is the point apa(alpha) 
uint32_t apa[2];

//K used in SHA 256
uint32_t k[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//the SByte table which is utilized in AES 128 eencryption as per assignment
uchar_t subbyte_table[16][16] = {
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

//Initialization Vector set up for encryption in TAES 128 
const uchar_t Iv[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
// Setting the round constants for TAES 128
const uint32_t Rconst[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000};

//This function counts all integer-coordinated points in Zp* that are on the curve y^2 = x^3 + ax + b.
uint32_t cPonCurve(){
    uint32_t cnt = 0; //points counter
    for(uint32_t i = 1; i < P; i++){ //x and y will be between 1 to P-1 (= 1021), inclusive.
        for(uint32_t j = 1; j < P; j++){
            uint32_t LHS = (j * j) % P;  //calculating LHS, i.e. y^2, taking modulo P 
            uint32_t RHS = ((i * i * i) + a * i + b) % P; //calculating RHS, i.e (x^3 + a * x + b) % P
            if(LHS == RHS) cnt++; //If the LHS=RHS, the point lies on the curve; count increments.
        } }
    return cnt;
}

//This function stores all points with integer coordinates in Zp* that lie on the curve y^2 = x^3 + ax + b.
void pointsOnCurve(uint32_t TP, uint32_t points[TP][2]){
    uint32_t idx = 0;
    for(uint32_t i = 1; i < P; i++){ //since, x and y lies between 1 and P-1 (= 1021), both inclusive.
        for(uint32_t j = 1; j < P; j++){
            uint32_t LHS = (j * j) % P; //calculate LHS, i.e. y^2, take modulo P 
            uint32_t RHS = ((i * i * i) + a * i + b) % P; //calculating RHS, i.e (x^3 + a * x + b) % P
            if(LHS == RHS) { //if LHS=RHS, then point on curve, point is stored
                points[idx][0] = i;
                points[idx][1] = j;
                idx++;
            }}}
}
//Implementing the Extended euclidean algorithm for multiplicative inverse of 'a' under modulo 'b'
int ExEuclid(int a, int b, int* p, int* q){
    if(a == 0){
        *p = 0;
        *q = 1;
        return b;
    }
    int p1, q1;
    int gcd = ExEuclid(b % a, a, &p1, &q1);
    *p = q1 - (b/a) * p1;
    *q = p1;
    return gcd;
}
//If the above algorithm returns a negative,it is to be made positive as per requirement
uint32_t InvPve(int a){
    while(a < 0) a += P;
    return (uint32_t) (a % P);
}
//The function below adds two points on the curve y^2 = x^3 + ax + b
//Assumption is not gettting of invalid input
void AddPts(uint32_t z1[2], uint32_t z2[2], uint32_t z3[2]){
    /*Adding points p1 (x1, y1) and p2 (x2, y2), then putting the result in p3 (x3, y3).
    The computation is done in Zp*, so -x represents the additive inverse of x (P-x).
    Similarly, a/b represents a * b^(-1), where b^(-1) is the multiplicative inverse of b (P). */
    uint32_t m; //Storing slope value
    if(z1[0] == 0 || z2[0] == 0){ //case where one point is point at infinity (0, 0), and other point is a valid point on curve, result will be the valid point
        if(z1[0] == 0){   //if p1 is 0, p3 = p2
            z3[0] = z2[0];
            z3[1] = z2[1];
        } else {          //else p3 = p1
            z3[0] = z1[0];
            z3[1] = z1[1];
        }
        return; //return because the point sum is calculated
    } else if ((z1[0] == z2[0]) && (z1[1] == P - z2[1])){ //case where x-coordinate is same, but y co-ordinate is additive inverse of each other
        //the result in this case is point at infinity
        z3[0] = thtaX;
        z3[1] = thtaY;
        return;  //return because the point sum is calculated
    } else if ((z1[0] == z2[0]) && (z1[1] == z2[1])) { //case where both points are same        
        m = (3 * z1[0] * z1[0] + a) % P;   //storing the numerator in m, taking mod P as we need to work on Zp*
        int p, q;
        ExEuclid(2 * z1[1], P, &p, &q); //calculationg inverse  under modulo P
        m = (m * InvPve(p)) % P; // updating m 
    } else { //case where both the coordinates of the two points are different
        //slope calculated as m = (y2 - y1) / (x2 - x1)
        uint32_t numerator = (z2[1] + P - z1[1]) % P;   // calculating (y2 - y1), under mod P
        uint32_t denominator = (z2[0] + P - z1[0]) % P;  // calculating (x2 - x1), under mod P
        int p = 0, q = 0;
        ExEuclid(denominator, P, &p, &q); //finding inverse of (x2 - x1) under modulo P
        m = (numerator * InvPve(p)) % P; //updating m = (y2 - y1) * inverse((x2 - x1) under mod P)        
    }    
    //calculating the point sum for the last two cases
    z3[0] = (m * m + (P - z1[0]) + (P - z2[0])) % P; // x3 = m*m - x1 - x2
    z3[1] = P - ((z1[1] + m * (z3[0] + P - z1[0])) % P); //y3 = y1 + m * (x3 - x1)
}
//PTN(Point Times N) function for computing n times a point on the curve
void PTN(uint32_t n, uint32_t point[2], uint32_t result[2]){
    //The point is X, for which we need to compute n.X.
    //The product will be kept in result(initialized with the point at infinity.)     
    result[0] = thtaX;
    result[1] = thtaY;
    uint32_t temp[2] = {point[0], point[1]}; //temp point
    //computes n.X 
    //convert n to binary, Initiating from least significant bit; if 1, do => result = result + temp, 
    //update temp,move to next bit of n,repeat until n > 0    
    while(n > 0){
        if(n & 1){      //checking bit set or not, if set perform the computation
            uint32_t t[2]; //to store the addition of result and temp on EC
            AddPts(result, temp, t);  //finding (result + temp) 
            result[0] = t[0]; //storing in 'result' 
            result[1] = t[1];
        }
        uint32_t t[2]; //update the temp = 2 * temp
        AddPts(temp, temp, t);
        temp[0] = t[0];
        temp[1] = t[1];
        n = n >> 1; //moving to next bit of n
    }
}
//pdLen(paddedLength) function to find the length of message after padding using SHA256 rules
uint32_t pdLen(uint32_t l){
    //Here, length l is expressed in terms of words, therefore a message of length 2l is actually a 64-bit message.
    uint32_t x = 0; //blck count in the padded message
    //Initially calculate the blck present in the original message, 16 words constitute a block    
    if(l % 16 == 0) x = l/16;   //if length multiple of 16, then blck=l/16
    else x = l/16 + 1;          //other cases, it will be l/16 + 1.     
    //if condition hold, then block number increase, hence x is incremented.
    if(l % 16 == 14 || l % 16 == 15 || l % 16 == 0) x++; 
    return x * 16; //number of words in padded message
}
//RhtRte function to right rotate an integer by 'bits' bits
uint32_t RhtRte(uint32_t x, uint32_t bits){
    return ((x >> bits) | (x << (32 - bits)));
}
//performing SHA256 hashing
// -> the main message(len) < 2^32 - 1.
// -> the message=concatenation of words[32 bits] 
// 0x01 treated as 0x00000001. 
void SHA256(uint32_t length, uint32_t m[length], uint32_t Hsh[8]){
    //message of 'length' words, each of 32 bits,padding is done in SHA256    
    uint32_t pLen = pdLen(length); //finding length of padded message, in terms of 32-bit words
    uint32_t pdMsg[pLen]; //padded message
    for(uint32_t i = 0; i < pLen; i++) pdMsg[i] = 0; //initialised 0, applicable for padding bits too.    
    for(uint32_t i = 0; i < length; i++) pdMsg[i] = m[i]; //copying the message 
    pdMsg[length] = ((uint32_t) 1) << 31; 
    //SHA256 stores the length of the original message in the last 64 bits of the padded message.
    //It is assumed that the original message < 2^32-1. It can only be saved in the final 32 bits.
    pdMsg[pLen - 1] = 32 * length;  //hence, last word (32 bits) of padded message is the length of original message.    
    //Initializing the Hash values:
    uint32_t h0 = 0x6a09e667;  uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;  uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;  uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;  uint32_t h7 = 0x5be0cd19;
    for(uint32_t j = 0; j < pLen/16; j++){ //this loop will be run for each block of the padded message.
        uint32_t words[64] = {0}; //storage of the generated 64 words during each loop 
        for(uint32_t i = 0; i < 16; i++) words[i] = pdMsg[16 * j + i]; 
        for(uint32_t i = 16; i < 64; i++){ //algo for computing remaining words
            uint32_t x = RhtRte(words[i - 15], 7) ^ RhtRte(words[i - 15], 18) ^ (words[i - 15] >> 3); 
            uint32_t y = RhtRte(words[i - 2], 17) ^ RhtRte(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + x + words[i - 7] + y;
        }
        //Initializing working variables to current Hash value:
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        //compression function
        for(uint32_t i = 0; i < 64; i++){
            uint32_t x = RhtRte(e, 6) ^ RhtRte(e, 11) ^ RhtRte(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t tmp1 = h + x + ch + k[i] + words[i];
            uint32_t y = RhtRte(a, 2) ^ RhtRte(a, 13) ^ RhtRte(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t tmp2 = y + mj;
            h = g; g = f;  f = e;
            e = d + tmp1;
            d = c; c = b;  b = a;
            a = tmp1 + tmp2;
        }//inclusion of compressed block to the present Hash value        
        h0 = h0 + a; h1 = h1 + b; 
        h2 = h2 + c; h3 = h3 + d; 
        h4 = h4 + e; h5 = h5 + f;
        h6 = h6 + g; h7 = h7 + h;
    }//the final Hash after processing all blck
    Hsh[0] = h0;  Hsh[1] = h1;
    Hsh[2] = h2;  Hsh[3] = h3;
    Hsh[4] = h4;  Hsh[5] = h5;
    Hsh[6] = h6;  Hsh[7] = h7;
}
//convtint is a helper function for converting unsigned characters to unsigned integers(array)
//for example:  0x45 0x67 0x23 0x89 => 0x45672389
void convtint(uchar_t x[32], uint32_t y[8]){
    for(int i = 0; i < 8; i++){ //for 4 continuous characters convert to unsigned integer
        uint32_t x1 = x[4 * i];   
        uint32_t x2 = x[4 * i + 1]; 
        uint32_t x3 = x[4 * i + 2]; 
        uint32_t x4 = x[4 * i + 3]; 
        y[i] = (x1 << 24) | (x2 << 16) | (x3 << 8) | x4;
    }
}
//convtchar is a helper function for converting unsigned integers to unsigned characters(array)
//for example: 0x45672389 => 0x45 0x67 0x23 0x89
void convtChar(uint32_t Hsh[8], uchar_t key[32]){
    uchar_t z = 0xff; //mask
    for(uint32_t i = 0; i < 8; i++){ //each integer(in array) to 4 successive characters 
        key[i * 4] = Hsh[i] >> 24;  //From left,1 to 8 bits 
        key[i * 4 + 1] = (Hsh[i] >> 16) & z; // 9-16 
        key[i * 4 + 2] = (Hsh[i] >> 8) & z; // 17-24 
        key[i * 4 + 3] = Hsh[i] & z; // 25-32 
    }
}

//genMAC function for generating the MAC as described in the assignment 
void genMAC(uint32_t key[8], uchar_t M[32], uint32_t MAC[8]){ //MAC stores the final MAC
    uint32_t inp[16]; 
    //initial input(inp) stores (key ^ 2) || M
    for(uint32_t i = 0; i < 7; i++){ //storing (key ^ 2) in first 8 words of inp
        inp[i] = key[i];
    }
    inp[7] = key[7] ^ 2;    
    uint32_t convM[8]; //The M received here is a character matrix, while SHA accepts input as an array of words.
    convtint(M, convM); //Thus, we changed M from a char array to an unsigned integer array 'convM'.    
    for(uint32_t i = 8; i < 16; i++){
        inp[i] = convM[i - 8]; //storing convM in last 8 words of inp
    }    
    uint32_t mac1[8]; //mac1 stores SHA256((key ^ 2) concat M)
    SHA256(16, inp, mac1); //calling the SHA256 function    
    for(uint32_t i = 0; i < 7; i++){ //storing (key ^ 1) in first 8 words of inp
        inp[i] = key[i];
    }
    inp[7] = key[7] ^ 1;
    for(uint32_t i = 8; i < 16; i++) inp[i] = mac1[i - 8]; //storing mac1 in last 8 words of inp   
    SHA256(16, inp, MAC); 
}

//the Subbyte function of TAES-128
uchar_t SByte(uchar_t x){
    uint16_t t2 = x & 15; //least significant 4 bits as column number
    uint16_t t1 = x >> 4; //most significant 4 bits as row number
    return subbyte_table[t1][t2];  //table look-up
}
//Inverse of Subbyte function used in TAES-128
uchar_t invSByte(uchar_t x){
    uchar_t inv = 0;
    //find the value in the table, suppose it is at row i, column j, then inverse will be ((i << 4) | j)
    for(uchar_t i = 0; i < 16; i++){
        for(uchar_t j = 0; j < 16; j++){
            if(subbyte_table[i][j] == x){ //if found at row i and column j
                return ((i << 4) | j); //return ((i << 4) | j)
            }
        }
    }
    return 0;
}
//Shift Row function of TAES-128, left circular shifts the i^th row by i positions.
void Sftrow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){ 
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j]; //store the ith row in temp array
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + i) % 4]; //left circular shift of the row ith by i positions
        }
    }
}
//Inverse Shift Row Function of TAES-128, right circular shifts the i^th row by i positions
void invSftRow(uchar_t s[4][4]){
    for(int i = 1; i < 4; i++){ 
        uchar_t temp[4];
        for(int j = 0; j < 4; j++) temp[j] = s[i][j]; //storing the ith row in temp array
        for(int j = 0; j < 4; j++){
            s[i][j] = temp[(j + 4 - i) % 4]; //right circular shift of the ith row by i positions
        }
    }
}
//function to perform a polynomial multiplication of polynomial with x under modulo x^8 + x^4 + x^3 + x + 1
//the polynomial to be multiplied with x, is represeted as a binary byte 'x'
uchar_t xTs(uchar_t x){
    uchar_t temp = x << 1; //multiplied the polynomial by x
    //if the polynomial has x^(7).x=x^8,x^8 + x^4 + x^3 + x + 1, required replace of x^8 with x^4 + x^3 + x + 1,    
    if(x >> 7) temp = temp ^ (0x1b); 
    return temp;
}
//Mix Columns function of TAES-128
void mxCol(uchar_t s[4][4]){
    for(int i = 0; i < 4; i++){ //for each col of input matrix
        //calculating the 4 polynomial according to the mix col mat
        uchar_t t1 = xTs(s[0][i]) ^ xTs(s[1][i]) ^ s[1][i] ^ s[2][i] ^ s[3][i];
        uchar_t t2 = s[0][i] ^ xTs(s[1][i]) ^ xTs(s[2][i]) ^ s[2][i] ^ s[3][i];
        uchar_t t3 = s[0][i] ^ s[1][i] ^ xTs(s[2][i]) ^ xTs(s[3][i]) ^ s[3][i];
        uchar_t t4 = xTs(s[0][i]) ^ s[0][i] ^ s[1][i] ^ s[2][i] ^ xTs(s[3][i]);        
        s[0][i] = t1; //updating the col of input, with mix col value
        s[1][i] = t2;
        s[2][i] = t3;
        s[3][i] = t4;
    }
}
//Inverse Mix Columns Function of TAES-128
void invmxCol(uchar_t s[4][4]){
    //M^4 * S = I, so inverse of M is M^3    
    mxCol(s); 
    mxCol(s);
    mxCol(s);
}
//sbWord function to perform subbytes of each byte of the 32-bit word.
//Each word contains 4-bytes and we have to perform subbytes of each of them
uint32_t sbWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t x0, x1, x2, x3;  //x = x0 || x1 || x2 || x3, x0, x1, x2, x3 are bytes of the 32-bit word.
    x0 = (x >> 24) & z;
    x1 = (x >> 16) & z;
    x2 = (x >> 8) & z;
    x3 = x & z;
    //performing SByte on each byte, since Key Scheduling uses original SByte function.
    x0 = SByte(x0);
    x1 = SByte(x1);
    x2 = SByte(x2);
    x3 = SByte(x3);
    //output = SByte(x0) || SByte(x1) || SByte(x2) || SByte(x3)
    x = (x0 << 24) | (x1 << 16) | (x2 << 8) | x3;
    return x;
}
//rtWord function to left circular shift a 32-bit word by 8 bits (or 1 byte)
uint32_t rtWord(uint32_t x){
    uchar_t z = 0xff;
    uchar_t temp = (x >> 24) & z;   
    x = (x << 8) | temp;
    return x;
}
//Kschedule function generates the round keys for TAES-128
void Kschedule(uchar_t key[32], uchar_t rKys[15][4][4]){    
    uint32_t words[60];   
    uchar_t z = 0xff;
    for(int i = 0; i < 8; i++){  //the first 8 words are similar to key, i.e, if we concatenate the first 8 words, we will get the key
        words[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | (key[4*i+3]);
    }    //finding remaining words according to the key scheduling algorithm
    for(int i = 8; i < 60; i++){
        uint32_t temp = words[i-1];
        if(i % 8 == 0) temp = sbWord(rtWord(temp)) ^ (Rconst[i/8 - 1]);
        else if(i % 8 == 4) temp = sbWord(temp);
        words[i] = words[i - 8] ^ temp;
    }//the 15 round keys are stored as 4*4 matrix in column-wise manner
    //each roundKey[i] is a round key.
    for(int i = 0; i < 15; i++){
        for(int j = 0; j < 4; j++){
            for(int k = 0; k < 4; k++){
                rKys[i][k][j] = (words[4*i+j] >> (24 - 8 * k)) & z;  
            }
        }
    }
}
//rFunc: the round function of TAES-128
void rFunc(int round, uchar_t s[4][4]){
    //the variable round stores which round it is
    // perform SByte(input)
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = SByte(s[i][j]);
        }
    }//performs shift row
    Sftrow(s);
    //if it is not the last,i.e. 14th round, mix columns continue
    if(round < 14) mxCol(s);
}
//invrfunc: the inverse round function f^-1 of TAES-128
void invrfunc(int round, uchar_t s[4][4]){
    //if it is the 14th round, we don't need to to mix column inverse, else we do.
    if(round != 14) invmxCol(s);
    //perform shift row inverse
    invSftRow(s);
    //perform SByte inverse
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            s[i][j] = invSByte(s[i][j]);
        }
    }
}

//function to encrypt plaintext using TAES-128
void TAesEncrypt(int length, uchar_t plaintext[length], uchar_t key[32], uchar_t CT[length + 16]){
    //length here is number bytes (8 bit) in the plaintext
    //For AES-128, length of a block is 16, as 16 * 8 = 128    
    uint32_t indx = 0; //this stores the current index available to put data in the Ciphertext    
    uchar_t rKys[15][4][4];  //storing the round keys
    Kschedule(key, rKys); //generating the round keys
    int blck = length/16;  //finding number of block in the plaintext    
    //this stores the CT corresponding to last block,    
    uchar_t fdb[4][4];
    for(uchar_t i = 0; i < 4; i++){
        for(uchar_t j = 0; j < 4; j++){
            fdb[i][j] = Iv[i][j];
            CT[indx++] = Iv[i][j]; 
        }
    }    
    for(uint32_t k = 0; k < blck; k++){ //encrypting each block of plaintext sequentially        
        uchar_t s[4][4]; //stores plaintext corresponding to current block        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                s[j][i] = plaintext[k * 16 + i * 4 + j]; 
            } }        
        for(uint32_t i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                s[i][j] = s[i][j] ^ fdb[i][j]; 
            } }        
        //performing encryption
        for(uint32_t i = 0; i < 15; i++){
            for(uint32_t j = 0; j < 4; j++){
                for(uint32_t x = 0; x < 4; x++){
                    s[j][x] = s[j][x] ^ rKys[i][j][x]; //adding the key
                } }            
            if(i < 14) rFunc(i+1, s); //calling round functions
            //in the last iteration of the loop, only the last round key is mixed (round function is not called)
        }         
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                fdb[i][j] = s[i][j]; 
                CT[indx++] = s[j][i]; //storing current block's CT it in CT
            }
        }
    }
}

//function to decrypt Ciphertext using Triple AES-128
void TAesDecrypt(uchar_t length, uchar_t CT[length], uchar_t key[32], uchar_t dec_txt[length - 16]){
    //length here is number bytes (8 bit) in the CT
    //since AES-128,length of a block is 16, as 16 * 8 = 128    
    int indx = 0; //storeing the current indx available to put data in the plaintext    
    uchar_t rKys[15][4][4];   //storing the round keys
    Kschedule(key, rKys);  //generating the round keys
    uint32_t blck = length/16 - 1;  
    uchar_t dfb[4][4]; //this stores the Ciphertext corresponding to last block,     
    for(uint32_t k = 0; k < blck; k++){
        uchar_t s[4][4]; //stores CT corresponding to current block        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                s[j][i] = CT[((k + 1) * 16) + i * 4 + j];  //storing the current block of Ciphertext in s
            }}        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                dfb[j][i] = CT[k * 16 + i * 4 + j]; 
            }
        } //performing decryption
        for(int i = 14; i >= 0; i--){
            //first mixing the round keys
            for(uint32_t j = 0; j < 4; j++){
                for(uint32_t x = 0; x < 4; x++){
                    s[j][x] = s[j][x] ^ rKys[i][j][x];
                }}
            //then performing the  inverse round function, since, there are only 14 rounds, therefore
            //inverse round function is called for 14 times only
            if(i > 0) invrfunc(i, s);
            //in the last iteration of the loop, only the last round key mixed 
        }        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                s[i][j] = s[i][j] ^ dfb[i][j]; //mix the decrypted text with previous block's Ciphertext to get original plaintext block
            }}        
        for(uint32_t i = 0; i < 4; i++){
            for(uint32_t j = 0; j < 4; j++){
                dec_txt[indx++] = s[j][i]; //storing original plaintext in the decrypted_text array
            }
        }
    }
}
//helper function to print an unsigned character array of length 'length'
void print(uint32_t length, uchar_t s[length],int pad){
    for(int i = pad; i < length; i++){
        printf("%02x ", s[i]);
    }
    printf("\n");
}

int main(){
    printf("\n");    
    //cnt total number of points with integer coordinates in Zp* lie on the curve y^2 = x^3 + 449*x + 233
    int TP = cPonCurve(); 
    //create an array for storing all the points
    uint32_t points[TP][2];
    //find and store all the points in the array
    pointsOnCurve(TP, points);    
    srand(time(NULL));
    uint32_t idx = (rand() % TP);
    //the point alpha
    apa[0] = points[idx - 1][0];
    apa[1] = points[idx - 1][1];
    printf("Selected point alpha is: (%u, %u)\n", apa[0], apa[1]);
    printf("\n");
    uint32_t nA, nB; //Initiating variables for Alice's and Bob's private key as input
    printf("Enter Alice's Private Key (an integer between 1 and 330 (both inclusive)): ");
    //input value validation
    do{
        scanf("%u", &nA);
        if(nA < 1 || nA > 330){
            printf("Error, number out of range!.\n");
            printf("Enter Alice's Private Key (an integer between 1 and 330 (both inclusive)): ");
        }
    } while(nA > 330 || nA < 1);

    printf("Enter Bob's Private Key (an integer between 1 and 330 (both inclusive)): ");
    //input value validation
    do{
        scanf("%u", &nB);
        if(nB < 1 || nB > 330){
            printf("Error, number out of range!\n");
            printf("Enter Bob's Private Key (an integer between 1 and 330 (both inclusive)): ");
        }
    } while(nB > 330 || nB < 1); 

    //computing Alice's public key and storing it in 'naApa'
    uint32_t naApa[2];
    PTN(nA, apa, naApa);
    //computing Bob's public key and storing it in 'nbApa'
    uint32_t nbApa[2];
    PTN(nB, apa, nbApa);
    //Computing the shared secret key for the communication
    uint32_t naNbAlpha[2]; //the shared secret key computed by Alice 
    uint32_t nbNaAlpha[2]; //the shared secret key computed by Bob
    //essentially naNbAlpha = nbNaAlpha
    PTN(nA, nbApa, naNbAlpha);
    PTN(nB, naApa, nbNaAlpha);
    printf("\n");
    //printing the shared secret key
    printf("The Shared Secret key between Alice and Bob is: (%u, %u)\n", nbNaAlpha[0], nbNaAlpha[1]);
    uint32_t kA[8] = {0}; //Hash of key of Alice
    //the input to Hash is (x1 concat y1) where x1 and y1 are coordinates of shared secret key that Alice holds    
    //since x1=y1=32 bits, so, the message to be hashed is of 64 bits.
    uint32_t msgA[2] = {naNbAlpha[0], naNbAlpha[1]}; 
    
    SHA256(2, msgA, kA); //finding kA = SHA256(msgA)    
    uint32_t kB[8] = {0};  //Hash of key of Bob
    //the input to Hash is (x1 concat y1) where x1 and y1 are coordinates of shared secret key that Bob holds    
    //since x1=y1=32 bits, so, the message to be hashed is of 64 bits.
    uint32_t msgB[2] = {nbNaAlpha[0], nbNaAlpha[1]};

    SHA256(2, msgB, kB); //finding kB = SHA256(msgB)
    printf("\n");
    printf("kA: ");
    for(int i = 0; i < 8; i++) printf("%08x ", kA[i]);    
    printf("\n");
    printf("kB: ");
    for(int i = 0; i < 8; i++) printf("%08x ", kB[i]);
    printf("\n\n");
    //taking the message that Alice will encrypt as input
    uchar_t MA[32];
    printf("Enter Alice's message(128bit hexadecimal, each pair of hex digits separated by spaces): ");
    for(int i = 0; i < 16; i++) {
        scanf("%hhx", &MA[i]);    
    }
    printf("\n");
    printf("mA: ");
    print(16, MA,0);    
    //encrypting the message using Alice's shared secret key
    //the shared secret key of Alice is stored in kA as concatenation of unsigned integers
    //to perform TAES-128 encryption, we need to convert the key as concatenation of unsigned chars
    uchar_t keyA[32]; //kA as unsigned chars
    convtChar(kA, keyA);
    uchar_t CA[48]; //Ciphertext corresponding to Alice's text    
    TAesEncrypt(32, MA, keyA, CA);
    printf("cA: ");
    print(32, CA,16); 
    uint32_t macA[8]; //stores mac for the message MA computed by Alice using kA
    genMAC(kA, MA, macA);    
    printf("macA: ");
    for(int i = 0; i < 8; i++){
        printf("%08x ", macA[i]);
    }
    printf("\n\n");
    //The Ciphertext CA, macA, MA is transferred to Bob by Alice
    uchar_t keyB[32]; //converting Bob's shared secret key to unsigned char
    convtChar(kB, keyB);
    uchar_t MB[32]; //bob now decrypts CA using his key keyB and stores it in MB
    TAesDecrypt(48, CA, keyB, MB);
    printf("mB: ");
    print(16, MB,0);
    uint32_t macB[8]; //from MB, Bob computes macB for the message MB using kB
    genMAC(kB, MB, macB);    
    printf("macB: ");
    for(int i = 0; i < 8; i++){
        printf("%08x ", macB[i]);
    }    
    return 0;
}
