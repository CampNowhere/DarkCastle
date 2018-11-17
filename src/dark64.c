#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int keylen = 32;
uint64_t r[8] = {0};
uint64_t j = 0;
uint64_t ct = 0;

uint64_t rotateleft64(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

void dark64_F(uint64_t j, uint64_t ct) {
    int i;
    uint64_t x;
    for (i = 0; i < 8; i++) {
        x = r[i];
	r[i] = (r[i] + r[(i + 1) & 0x07] + j);
	r[i] = r[i] ^ x;
	r[i] = rotateleft64(r[i], 2);
	j = (j + r[i] + ct);
	ct = (ct + 1);
    }
}

void dark64_keysetup(unsigned char *key, unsigned char *nonce) {
    uint64_t n[4];
    int i;
    int m = 0;
    int inc = 8;
    for (i = 0; i < (keylen / 8); i++) {
        r[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }
   
    n[0] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    n[1] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    r[0] = r[0] ^ n[0];
    r[1] = r[1] ^ n[1];


    for (int i = 0; i < 8; i++) {
        j = (j + r[i]);
    }
    for (int i = 0; i < 64; i++) {
        dark64_F(j, ct);
    }
}

void * dark64_crypt(unsigned char * data, unsigned char * key, unsigned char * nonce, long datalen) {
    long c = 0;
    int i = 0;
    int l = 8;
    uint64_t output;
    int k[8] = {0};
    long blocks = datalen / 8;
    long extra = datalen % 8;
    if (extra != 0) {
        blocks += 1;
    }
    dark64_keysetup(key, nonce);
    for (long b = 0; b < blocks; b++) {
        dark64_F(j, ct);
	output = ((((r[1] + r[7]) ^ r[3]) ^ r[5]));
        k[0] = (output & 0x00000000000000FF);
        k[1] = (output & 0x000000000000FF00) >> 8;
        k[2] = (output & 0x0000000000FF0000) >> 16;
        k[3] = (output & 0x00000000FF000000) >> 24;
        k[4] = (output & 0x000000FF00000000) >> 32;
        k[5] = (output & 0x0000FF0000000000) >> 40;
        k[6] = (output & 0x00FF000000000000) >> 48;
        k[7] = (output & 0xFF00000000000000) >> 56;
        if (b == (blocks - 1) && (extra != 0)) {
            l = extra;
        }

	for (i = 0; i < l; i++) {
            data[c] = data[c] ^ k[i];
	    c += 1;
	}
    }
}
