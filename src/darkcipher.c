#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint32_t dark_r[8] = {0};
uint32_t dark_j = 0;
uint32_t dark_ct = 0;

uint32_t dark_rotate(uint32_t a, uint32_t b) {
    return ((a << b) | (a >> (32 - b)));
}

void dark_F(uint32_t dark_j, uint32_t dark_ct) {
    int i;
    uint32_t x;
    for (i = 0; i < 8; i++) {
        x = dark_r[i];
	dark_r[i] = (dark_r[i] + dark_r[(i + 1) % 8] + dark_j) & 0xFFFFFFFF;
	dark_r[i] = dark_r[i] ^ x;
	dark_r[i] = dark_rotate(dark_r[i], 2) & 0xFFFFFFFF;
	dark_j = (dark_j + dark_r[i] + dark_ct) & 0xFFFFFFFF;
	dark_ct = (dark_ct + 1) & 0xFFFFFFFF;
    }
}

void dark_keysetup(unsigned char *key, unsigned char *nonce) {
    uint32_t n[4];
    dark_r[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    dark_r[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    dark_r[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    dark_r[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    dark_r[4] = (key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19];
    dark_r[5] = (key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23];
    dark_r[6] = (key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27];
    dark_r[7] = (key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31];

    n[0] = (nonce[0] << 24) + (nonce[1] << 16) + (nonce[2] << 8) + nonce[3];
    n[1] = (nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7];
    n[2] = (nonce[8] << 24) + (nonce[9] << 16) + (nonce[10] << 8) + nonce[11];
    n[3] = (nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15];

    dark_r[4] = dark_r[4] ^ n[0];
    dark_r[5] = dark_r[5] ^ n[1];
    dark_r[6] = dark_r[6] ^ n[2];
    dark_r[7] = dark_r[7] ^ n[3];

    for (int i = 0; i < 8; i++) {
        dark_j = (dark_j + dark_r[i]) & 0xFFFFFFFF;
    }
    dark_F(dark_j, dark_ct);
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
    dark_keysetup(key, nonce);
    for (long b = 0; b < blocks; b++) {
        dark_F(dark_j, dark_ct);
        output = (((((((dark_r[0] + dark_r[6]) ^ dark_r[1]) + dark_r[5]) ^ dark_r[2]) + dark_r[4]) ^ dark_r[3]) + dark_r[7]) & 0xFFFFFFFF;
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
