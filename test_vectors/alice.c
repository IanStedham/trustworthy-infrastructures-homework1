//Name: Ryan Powers
//Prof: Dr.Yavuz
//Course: Privacy-Preserving and Trustworthy Cyber-Infrastructures
//Date: 1/30/26
//Assignment: HW1 - Chacha20 Implementation

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
//#include <openssl/rand.h>

// function declarations
unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void byte2Hex(char output[], unsigned char input[], int inputlength);
unsigned char* hex2Bytes(char hexString[], int *outLen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);

int main(int argc, char *argv[]) {
    //read arg[1] -> the message
    int messageLength;
    unsigned char* message = Read_File(argv[1], &messageLength); //first arg is the message

    //read arg2 - the sharedseed
    int seedLength;
    unsigned char* seed = Read_File(argv[2], &seedLength); //second arg is seed

    //call PNRG function to generate random numbers
    //we pass in the shared seed, seed length and message length
    //this will create a keystream the same length as the message
    unsigned char* key = PRNG(seed, seedLength, messageLength);

    //convert binary stream to hex
    char* keyHex = (char*)malloc(messageLength * 2 + 1);
    byte2Hex(keyHex, key, messageLength);
    Write_File("Key.txt", keyHex, messageLength * 2);

    //create ciphertext --> XOR message with keystream
    char* ciphertext = (unsigned char*)malloc(messageLength);
    for (int i=0; i < messageLength; i++) {
        ciphertext[i] = message[i]  ^ key[i];
    }
    
    //binary -> hex -> ciphertext.txt
    unsigned char* ciphertextHex = (char*)malloc(messageLength * 2 + 1);
    byte2Hex(ciphertextHex, ciphertext, messageLength);
    Write_File("Ciphertext.txt", ciphertextHex, messageLength * 2);

    sleep(1); //wait for bob to read cipher + send hash.txt
       
    //read bob's hash from file
    int receivedHashLength;
    unsigned char* receivedHashHex = Read_File("Hash.txt", &receivedHashLength);
    unsigned char* receivedHash = hex2Bytes((char*)receivedHashHex, &receivedHashLength); //convert to bytes for comparison
    
    //take hash of original message
    unsigned char* aliceHash = Hash_SHA256(message, messageLength);

    int match = 1;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){ 
        if (aliceHash[i] != receivedHash[i]) { //compare the received hash to original, byte by byte
            match = 0;
            break;
        }
    }

    if (!match) {  //write acknowledgement.txt confirming whether hashs match or not
        unsigned char ack_fail[] = "hash acknowledgement failed";
        //printf(ack_fail);
        Write_File("Acknowledgment.txt", ack_fail, strlen(ack_fail));
    } else {
        unsigned char ack_pass[] = "hash acknowledgement successful";
        //printf(ack_pass);
        Write_File("Acknowledgment.txt", ack_pass, strlen(ack_pass));
    }

    //printf("encryption complete - run bob to decrypt");

    free(seed);
    free(message);
    free(key);
    free(keyHex);
    free(ciphertext);
    free(ciphertextHex);
    free(receivedHashHex);
    free(receivedHash);
    free(aliceHash);
    return 0;
}

/*************************************************************
					F u n c t i o n s
**************************************************************/
/*============================
        Read from File
==============================*/
unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile;
    printf("DEBUG: opening: %s\n", fileName);
    pFile = fopen(fileName, "r");
    if (pFile == NULL)
    {
        printf("Error opening: %s\n", fileName);
        exit(0);
    }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile);
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*)malloc(temp_size + 1);
    fread(output, 1, temp_size, pFile); //changed to fread() for newline consistency/preference
    output[temp_size] = '\0';
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
        convert to Hex 
==============================*/
void byte2Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i = 0; i < inputlength; i++) {
        sprintf(&output[2*i], "%02x", input[i]);
    }
    output[2 * inputlength] = '\0'; 
}

/*============================
        Showing in Hex 
==============================*/
void show_in_Hex (char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}
/*============================
        hex to bytes 
==============================*/
unsigned char* hex2Bytes(char hexString[], int *outLen)
{
    int len = strlen(hexString);
    *outLen = len / 2;
    unsigned char *bytes = (unsigned char*)malloc(*outLen);
    
    for (int i = 0; i < *outLen; i++) {
        sscanf(&hexString[2*i], "%2hhx", &bytes[i]);
    }
    
    return bytes;
}
/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //openSSL state object
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    unsigned char nonce[16] = {0};

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce); //evp init: ciphercontext, cipher=chacha20, key=sharedseed*, nonce/IV = all zeroes

    unsigned char zeros[prnglen]; //allocate buffer for temp array
    memset(zeros, 0, prnglen); //fill buffer with zero bytes

    int outlen;
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen); //create chacha20 keystream
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
