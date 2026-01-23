#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

//rotates bit left by N bits
#define rotate_left(a,b) (((a) << (b)) | ((a) >> (32 - (b)())))

//scrambles words: adds, XOR, than 
void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b;  *d ^= *a;  *d = ROTL(*d, 16);
    *c += *d;  *b ^= *c;  *b = ROTL(*b, 12);
    *a += *b;  *d ^= *a;  *d = ROTL(*d, 8);
    *c += *d;  *b ^= *c;  *b = ROTL(*b, 7);
}

int main(int argc, char *argv[]) {
    // Read the shared seed
    int seedLength;
    unsigned char* seed = Read_File(argv[2], &seedLength);

    //read the message
    int messageLength;
    unsigned char* message = Read_File(argv[1], &messageLength)

    //PNRG component
    unsigned char* key = PNRG(seed, seedLength, messageLength)


}
