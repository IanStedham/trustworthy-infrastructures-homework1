//Header files
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);


int main(int argc, char *argv[]) {
    // alice
    int messageLength = 51;
    int seedLength = 31;
    unsigned char* messageFile = Read_File("Message.txt", &messageLength);
    unsigned char* seedFile = Read_File("SharedSeed.txt", &seedLength);
    // for (int x = 0; x < messageLength; x++) {
    //     printf("%c", messageFile[x]);
    // }
    // printf("\n");
    // for (int x = 0; x < seedLength; x++) {
    //     printf("%c", seedFile[x]);
    // }
    // printf("\n");

    unsigned char* prng = PRNG(seedFile, seedLength, messageLength);
    // for (int x = 0; x < messageLength; x++) {
    //     printf("%c", prng[x]);
    // }
    // printf("\n");
    // Show_in_Hex("prng", prng, messageLength);

    // unsigned char* hashSHAOuput = Hash_SHA256(prng, messageLength);
    // for (int x = 0; x < messageLength; x++) {
    //     printf("%c", hashSHAOuput[x]);
    // }
    // printf("\n");
    // Show_in_Hex("prng", hashSHAOuput, messageLength);

    unsigned char* cipher = malloc(messageLength);;
    for (int x = 0; x < messageLength; x++) {
        cipher[x] = messageFile[x] ^ prng[x];
    }
    Write_File("Ciphertext.txt", cipher, messageLength);


    // bob
    unsigned char* cipher2 = Read_File("Ciphertext.txt", &messageLength);
    printf("cipher done\n");
    unsigned char* prng2 = PRNG(seedFile, seedLength, messageLength);
    printf("prgn done\n");
    unsigned char* plainText = malloc(messageLength + 1);
    for (int x = 0; x < messageLength; x++) {
        plainText[x] = cipher2[x] ^ prng2[x];
        printf("%c", plainText[x]);
    }
    printf("\n");

    unsigned char* hashMessage = Hash_SHA256(plainText, messageLength);
    Write_File("Hash.txt", hashMessage, sizeof(hashMessage));

    return 0;
}


/*************************************************************
					F u n c t i o n s
**************************************************************/

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
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
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
