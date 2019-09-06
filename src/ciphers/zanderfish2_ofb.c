#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void zanderfish2_ofb_crypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    struct zander_state state;
    uint64_t xl;
    uint64_t xr;
    uint8_t output[16];
    xl = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    xr = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    int blocks = msglen / zblocklen;
    int extra = msglen % zblocklen;
    int c = 0;
    int i, b;
    int l = 16;
    zgen_subkeys(&state, key, keylen, iv, ivlen, rounds);
    zgen_sbox(&state, key, keylen);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1)) {
            l = extra;
	}

        zblock_encrypt(&state, &xl, &xr);


        output[0] = (xl & 0xFF00000000000000) >> 56;
        output[1] = (xl & 0x00FF000000000000) >> 48;
        output[2] = (xl & 0x0000FF0000000000) >> 40;
        output[3] = (xl & 0x000000FF00000000) >> 32;
        output[4] = (xl & 0x00000000FF000000) >> 24;
        output[5] = (xl & 0x0000000000FF0000) >> 16;
        output[6] = (xl & 0x000000000000FF00) >> 8;
        output[7] = (xl & 0x00000000000000FF);
        output[8] = (xr & 0xFF00000000000000) >> 56;
        output[9] = (xr & 0x00FF000000000000) >> 48;
        output[10] = (xr & 0x0000FF0000000000) >> 40;
        output[11] = (xr & 0x000000FF00000000) >> 32;
        output[12] = (xr & 0x00000000FF000000) >> 24;
        output[13] = (xr & 0x0000000000FF0000) >> 16;
        output[14] = (xr & 0x000000000000FF00) >> 8;
        output[15] = (xr & 0x00000000000000FF);
        for (b = 0; b < l; b++) {
            msg[c] = msg[c] ^ output[b];
            c += 1;
        }
    }
}
