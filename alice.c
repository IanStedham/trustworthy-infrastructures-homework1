#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// function declarations
unsigned char* Read_File(char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void byte2Hex(char output[], unsigned char input[], int inputlength);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
unsigned char* hex2Bytes(char hexString[], int *outLen);

int main(int argc, char *argv[]) {
    // Read the shared seed
    int seedLength;
    unsigned char* seed = Read_File(argv[2], &seedLength);

    //read the message
    int messageLength;
    unsigned char* message = Read_File(argv[1], &messageLength); //Read_file will provide &messageLength

    //generate keystream
    unsigned char* key = PRNG(seed, seedLength, messageLength);

    //convert to hex
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

    sleep(1);

    //verify authenticity of message
    int bobHashLength;
    unsigned char* bobHashHex = Read_File("Hash.txt", &bobHashLength);
    unsigned char* bobHash = hex2Bytes((char*)bobHashHex, &bobHashLength);

    //take hash of original
    unsigned char* aliceHash = Hash_SHA256(message, messageLength);

    int match = 1;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++){
        if (aliceHash[i] != bobHash[i]) {
            match = 0;
            break;
        }
    }

    if (!match) {  // If not matching
        printf("Hash acknowledgement failed\n");
    } else {
        printf("Acknowledgment successful\n");
    }

    free(seed);
    free(message);
    free(key);
    free(keyHex);
    free(ciphertext);
    free(ciphertextHex);
    free(bobHashHex);
    free(bobHash);
    free(aliceHash);

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
    int temp_size = ftell(pFile)+1; //get file size
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size); //messageLength variable from main
	fread(output, 1, temp_size, pFile); //destination, size_of_each_element, number_of_elements, file_pointer
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
