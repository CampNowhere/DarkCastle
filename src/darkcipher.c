#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint32_t r[8] = {0};
uint32_t j = 0;
uint32_t ct = 0;

uint32_t rotate(uint32_t a, uint32_t b) {
    return ((a << b) | (a >> (32 - b)));
}

void F(uint32_t j, uint32_t ct) {
    int i;
    uint32_t x;
    for (i = 0; i < 8; i++) {
        x = r[i];
	r[i] = (r[i] + r[(i + 1) % 8] + j) & 0xFFFFFFFF;
	r[i] = r[i] ^ x;
	r[i] = rotate(r[i], 2) & 0xFFFFFFFF;
	j = (j + r[i] + ct) & 0xFFFFFFFF;
	ct = (ct + 1) & 0xFFFFFFFF;
    }
}

void keysetup(unsigned char *key, unsigned char *nonce) {
    uint32_t n[4];
    r[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    r[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    r[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    r[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    r[4] = (key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19];
    r[5] = (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    r[6] = (key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27];
    r[7] = (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];

    n[0] = (nonce[0] << 24) + (nonce[1] << 16) + (nonce[2] << 8) + nonce[3];
    n[1] = (nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7];
    n[2] = (nonce[8] << 24) + (nonce[9] << 16) + (nonce[10] << 8) + nonce[11];
    n[3] = (nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15];

    r[4] = r[4] ^ n[0];
    r[5] = r[5] ^ n[1];
    r[6] = r[6] ^ n[2];
    r[7] = r[7] ^ n[3];

    for (int i = 0; i < 8; i++) {
        j = (j + r[i]) & 0xFFFFFFFF;
    }
    F(j, ct);
}

void * dark_crypt(unsigned char * data, unsigned char * key, unsigned char * nonce, long datalen) {
    long c = 0;
    int i = 0;
    int l = 4;
    uint32_t output;
    int k[4] = {0};
    long blocks = datalen / 4;
    long extra = datalen % 4;
    if (extra != 0) {
        blocks += 1;
    }
    keysetup(key, nonce);
    for (long b = 0; b < blocks; b++) {
        F(j, ct);
        output = (((((((r[0] + r[6]) ^ r[1]) + r[5]) ^ r[2]) + r[4]) ^ r[3]) + r[7]) & 0xFFFFFFFF;
        k[0] = (output & 0x000000FF);
        k[1] = (output & 0x0000FF00) >> 8;
        k[2] = (output & 0x00FF0000) >> 16;
        k[3] = (output & 0xFF000000) >> 24;
        if (b == (blocks - 1) && (extra != 0)) {
            l = extra;
        }

	for (i = 0; i < l; i++) {
            data[c] = data[c] ^ k[i];
	    c += 1;
	}
    }
}
