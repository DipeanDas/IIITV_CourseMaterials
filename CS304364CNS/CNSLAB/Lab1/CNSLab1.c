/*CS364 Lab 1 
Coded By: 
ID: 202151188  Name: Dipean Dasgupta*/
#include <stdio.h>  // Importing/including the standard ip/output header library file
#include <string.h> // Including the string header library file

#define ALPH_COUNT 26 // There are total 26 alphabets in English which are included
#define CHAR_SPEC 4 // Total 4 special characters are to be included which are .,?; 
/*So total the size of the list of array will be 26+4=30 characters. These are the characters that will allowed in the 
Playfair cipher matrix creation and also in encryption and decryption. */

//Preparing the Playfair key matrix for playfair encryption
/*With a key string as ip, this function (PFKMatrix) generates a 6x5 Playfair key matrix with the permitted characters.
It adds the remaining permitted characters after copying the key to a larger array (Char_all). 
At last, it inserts characters from Char_all into the key matrix.*/
void PFKMatrix(char key[], char keyMatrix[6][5]) {
    int i, j, k = 0;                           //Initializing the variables i,j,k 
    int klen = strlen(key);                    //Storing the key string length
    char Char_all[ALPH_COUNT + CHAR_SPEC + 1]; // 26 alphabets + 4 special characters + null terminator

    // Copying the provided key to Char_all
    strcpy(Char_all, key);

    // Appending remaining permitted characters to Char_all
    for (i = 0; i < ALPH_COUNT; i++) {
        if (strchr(Char_all, 'A' + i) == NULL) {
            Char_all[klen + k] = 'A' + i;
            k++;
        }
    }
    // Appending the 4 special characters  to Char_all
    Char_all[klen + k] = '.';
    Char_all[klen + k + 1] = ',';
    Char_all[klen + k + 2] = '?';
    Char_all[klen + k + 3] = ';';
    Char_all[klen + k + 4] = '\0';

    /*Filling the key matrix with Char_all characters. It is ensured that first the letters of Key then the rest characters
    and also ensured that no letter/character is repeated twice.*/ 
    k = 0;
    for (i = 0; i < 6; i++) {
        for (j = 0; j < 5; j++) {
            keyMatrix[i][j] = Char_all[k++];
        }
    }
}

//The Function below is for finding the position of a specific character in the Playfair matrix
/*The row and column index of the character in the matrix is returned by the function FPos, which accepts a character and a Playfair matrix as ip. 
Without changing the rw and cl pointers, it returns if the character cannot be located.*/
void FPos(char matrix[6][5], char ch, int *rw, int *cl) {
    int i, j;
    for (i = 0; i < 6; i++) {
        for (j = 0; j < 5; j++) {
            if (matrix[i][j] == ch) {
                *rw = i;             //Storing character row num
                *cl = j;             //Storing the character column num   
                return;
            }
        }
    }
}

//This Function below sets/adjusts the length of the user input plaintext and handle repetition cases
/*An input string in plaintext is modified by the SetPT function to make it compatible with the Playfair cypher encryption. 
Every character in the plaintext string is copied to the SetIP string as iteratively performed. To keep even pairs, a 'X' is placed between two successive characters that are the same. 
And finally, an extra 'X' is appended at the end if the SetIP length is odd.*/
void SetPT(char ip[], char SetIP[]) {
    int len = strlen(ip);
    int k = 0;

    for (int i = 0; i < len; i++) {
        SetIP[k++] = ip[i];
        if (i < len - 1 && ip[i] == ip[i + 1]) {
            SetIP[k++] = 'X';
        }
    }
    if (k % 2 != 0) {
        SetIP[k++] = 'X';
    }
    SetIP[k] = '\0';
}

//Playfair encryption
/*Using the supplied key matrix, this function PFE or PlayFair Encrypt encrypts the modified plaintext using Playfair. 
It uses the positions of the characters in the matrix to cycle through the plaintext in pairs of characters, determining the ciphertext characters based on predetermined rules 
and on whether the characters are in the same row, column, or a different row and column.*/
void PFE(char matrix[6][5], char ip[], char output[]) {
    int len = strlen(ip);
    int k = 0;

    // Encrypting using Playfair cipher
    for (int i = 0; i < len; i += 2) {
        char ch1 = ip[i];
        char ch2 = (i + 1 < len) ? ip[i + 1] : 'X'; // If odd length, append 'X' at the end
        int row1, col1, row2, col2;
        FPos(matrix, ch1, &row1, &col1);         //Finding the  first character position
        FPos(matrix, ch2, &row2, &col2);         //Finding the  second character  position

        //For Same row
        if (row1 == row2) {
            output[k++] = matrix[row1][(col1 + 1) % 5];
            output[k++] = matrix[row2][(col2 + 1) % 5];
        }
        //Incase of Same column
        else if (col1 == col2) {
            output[k++] = matrix[(row1 + 1) % 6][col1];
            output[k++] = matrix[(row2 + 1) % 6][col2];
        }
        // In case of Different row and column
        else {
            output[k++] = matrix[row1][col2];
            output[k++] = matrix[row2][col1];
        }
    }
    output[k] = '\0';
}

// Function for Playfair decryption
/*For decryption, the Playfair cypher and the same key matrix that was used for encryption is used to decrypt ciphertext.
The function goes over the ciphertext in character pairs at a time.*/
void PFD(char matrix[6][5], char ip[], char output[]) {
    int len = strlen(ip);
    int k = 0;

    // Decrypting using Playfair cipher
    for (int i = 0; i < len; i += 2) {
        char ch1 = ip[i];
        char ch2 = (i + 1 < len) ? ip[i + 1] : 'X'; // If odd length, append 'X' at the end
        int row1, col1, row2, col2;
        FPos(matrix, ch1, &row1, &col1);
        FPos(matrix, ch2, &row2, &col2);

        // Same rw
        if (row1 == row2) {
            output[k++] = matrix[row1][(col1 - 1 + 5) % 5];
            output[k++] = matrix[row2][(col2 - 1 + 5) % 5];
        }
        // Same column
        else if (col1 == col2) {
            output[k++] = matrix[(row1 - 1 + 6) % 6][col1];
            output[k++] = matrix[(row2 - 1 + 6) % 6][col2];
        }
        // Different rw and column
        else {
            output[k++] = matrix[row1][col2];
            output[k++] = matrix[row2][col1];
        }
    }
    output[k] = '\0';
}

//Affine encryption Function
/*The function uses the Affine cypher to encrypt plaintext with a given key (a, b, m).
It goes over every character in the plaintext once.
Using the Affine cypher formula, encrypted = (a * x + b) % m, if the character is an uppercase alphabet (A to Z). In this case, x represents the character's numerical position (0–25), and m is the modulus (usually 26 for uppercase alphabets).
To calculate the encrypted character, add encrypted to 'A', then save the result in the output array.*/
void AE(char ip[], char output[], int a, int b, int m) {
    int len = strlen(ip);

    // Encrypt using Affine cipher
    for (int i = 0; i < len; i++) {
        char ch = ip[i];
        if (ch >= 'A' && ch <= 'Z') {
            int x = ch - 'A';
            int encrypted = (a * x + b) % m; // Affine cipher formula implemented
            output[i] = 'A' + encrypted;
        } else {
            output[i] = ch; 
        }
    }
    output[len] = '\0';
}

// Function Affine decryption
/*The Function implements the Affine cypher to decrypt ciphertext using the same key (a, b, m) that was used for encryption.
Firstly, uses the extended Euclidean technique to get the modular multiplicative inverse of a (represented by aInverse). The decryption process requires this value.*/
void AD(char ip[], char output[], int a, int b, int m) {
    int len = strlen(ip);
    int aInverse = 0;

    // Finding the modular multiplicative inverse of 'a'
    for (int i = 1; i < m; i++) {
        if ((a * i) % m == 1) {
            aInverse = i;
            break;
        }
    }

    // Decryption using Affine cipher
    for (int i = 0; i < len; i++) {
        char ch = ip[i];
        if (ch >= 'A' && ch <= 'Z') {
            int x = ch - 'A';
            int decrypted = (aInverse * (x - b + m)) % m; // Affine cipher formula implemented
            output[i] = 'A' + decrypted;
        } else {
            output[i] = ch; 
        }
    }
    output[len] = '\0';
}

//Shift encryption Function
/*Takes inputs shift key, output string, and plaintext.
It goes over every character in the plaintext once.
To handle wraparound, move the character by the key value (k) using modular arithmetic if it is an uppercase alphabet (A–Z).
The encrypted character is obtained by adding the shifted value to 'A' and is then stored in the output string.*/
void SHE(char ip[], char output[], int k) {
    int len = strlen(ip);

    // Encrypt using Shift cipher
    for (int i = 0; i < len; i++) {
        char ch = ip[i];
        if (ch >= 'A' && ch <= 'Z') {
            int x = ch - 'A';
            int encrypted = (x + k) % ALPH_COUNT;   // Shift cipher formula implemented
            output[i] = 'A' + encrypted;
        } else {
            output[i] = ch; 
        }
    }
    output[len] = '\0';
}

//Shift decryption Function
/*Accepts the shift key, output string, and ciphertext as inputs.
Similar to shiftEncrypt, but shifts back by the key using the decryption formula (x - k + ALPH_COUNT) % ALPH_COUNT.*/
void SHD(char ip[], char output[], int k) {
    int len = strlen(ip);

    // Decrypting using Shift cipher
    for (int i = 0; i < len; i++) {
        char ch = ip[i];
        if (ch >= 'A' && ch <= 'Z') {
            int x = ch - 'A';
            int decrypted = (x - k + ALPH_COUNT) % ALPH_COUNT;
            output[i] = 'A' + decrypted;
        } else {
            output[i] = ch; 
        }
    }
    output[len] = '\0';
}

int main() {
    //Takes input for variables for the following: ciphertexts, adjusted texts, playfair matrices, plaintext, key, and decoded texts.
    char plaintext[100], key[100], playfairMatrix[6][5], adjustedText[200], ciphertext1[200], ciphertext2[200], ciphertext3[200];
    char decryptedPlayfair[200], decryptedAffine[200], decryptedShift[200];

    //Taking word input from user as plaintext
    printf("Enter the plaintext: ");
    scanf("%s", plaintext);

    //Adjusting the length of the plaintext and handle repetition
    SetPT(plaintext, adjustedText);
    printf("Adjusted word : %s\n", adjustedText);

    //Taking Input for the key (K1)
    printf("Enter the key (K1): ");
    scanf("%s", key);

    //Generating the Playfair key matrix
    PFKMatrix(key, playfairMatrix);
    printf("Playfair Key Matrix:\n");
    // Print the Playfair key matrix
    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < 5; j++) {
            printf("%c ", playfairMatrix[i][j]);
        }
        printf("\n");
    }

    //calls playfairEncrypt to encrypt the modified text using the playfair matrix saves the ciphertext1 and prints it
    PFE(playfairMatrix, adjustedText, ciphertext1);
    printf("Playfair Encrypted Text (C1): %s\n", ciphertext1);

    //specifies the ciphertext1 to be encrypted using the Affine cypher, saving the result in ciphertext2, and then runs AE with the ciphertext key (a, b, m).
    int a = 11, b = 15, m = ALPH_COUNT; // Affine cipher key (a, b)
    AE(ciphertext1, ciphertext2, a, b, m);
    printf("Affine Encrypted Text (C2): %s\n", ciphertext2);

    // specifies the Shift cypher key (k), uses shiftEncrypt to encrypt Ciphertext 2 using the Shift cypher, and stores the outcome in Ciphertext 3.The ciphertext is printed.
    int k = 5; // Shift cipher key (K3)
    SHE(ciphertext2, ciphertext3, k);
    printf("Shift Encrypted Text (C3): %s\n", ciphertext3);

    //Decrypting using Shift cipher
    SHD(ciphertext3, decryptedShift, k);
    printf("Shift Decrypted Text (C3): %s\n", decryptedShift);

    //Decrypting using Affine cipher
    AD(ciphertext2, decryptedAffine, a, b, m);
    printf("Affine Decrypted Text (C2): %s\n", decryptedAffine);

    //Decrypting the text and verifying with Playfair decryption
    PFD(playfairMatrix, ciphertext1, decryptedPlayfair);
    printf("Playfair Decrypted Text : %s\n", decryptedPlayfair);

    return 0;
}
