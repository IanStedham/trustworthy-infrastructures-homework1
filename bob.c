#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

// function declarations
unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
unsigned char* Hex_to_Bytes(char hexString[], int *outLen);

int main(int argc, char *argv[]) {
    int messageLength;
    int seedLength;

    // Reading the ciphertext and converting from hex to byte array
    unsigned char* cipherTextHex; 
    cipherTextHex = Read_File("Ciphertext.txt", &messageLength);
    unsigned char* cipherText = Hex_to_Bytes(cipherTextHex, &messageLength);
    free(cipherTextHex);

    // Reading the shared seed
    unsigned char* sharedSeed = Read_File("SharedSeed.txt", &seedLength);

    // Creating the PRNG from the shared seed
    unsigned char* prng = PRNG(sharedSeed, seedLength, messageLength);
    free(sharedSeed);

    // Deciphering to plain text
    unsigned char* plainText = malloc(messageLength + 1);
    for (int x = 0; x < messageLength; x++) {
        plainText[x] = cipherText[x] ^ prng[x];
    }
    free(prng);
    free(cipherText);

    // Writing plain text to Plaintext.txt
    Write_File("Plaintext.txt", plainText, messageLength);

    // Computing the hash of the plain text
    unsigned char* hashMessage = Hash_SHA256(plainText, messageLength);
    char* hashHex = (char*)malloc(SHA256_DIGEST_LENGTH * 2 + 1);
    Convert_to_Hex(hashHex, hashMessage, SHA256_DIGEST_LENGTH);
    Write_File("Hash.txt", hashHex, SHA256_DIGEST_LENGTH * 2);
    free(hashHex);

    free(plainText);
    free(hashMessage);

    return 0;
}

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fread(output, 1, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size;
	return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  //fputs(input, pFile);
  fwrite(input, 1, input_length, pFile);
  fclose(pFile);
}

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex (char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

/*============================
        Convert to Hex 
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    printf("Hex format: %s\n", output);  //remove later
}

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    unsigned char nonce[16] = {0};

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);

    unsigned char zeros[prnglen];
    memset(zeros, 0, prnglen);

    int outlen;
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);

    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}

/*============================
        SHA-256 Fucntion
==============================*/
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return hash;
}

/*============================
        hex to bytes 
==============================*/
unsigned char* Hex_to_Bytes(char hexString[], int *outLen)
{
    int len = strlen(hexString);
    *outLen = len / 2;
    unsigned char *bytes = (unsigned char*)malloc(*outLen);
    
    for (int i = 0; i < *outLen; i++) {
        sscanf(&hexString[2*i], "%2hhx", &bytes[i]);
    }
    
    return bytes;
}
