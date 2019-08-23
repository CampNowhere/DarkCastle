#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void zanderfish_ofb_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    uint32_t xl;
    uint32_t xr;
    uint8_t output[8];
    xl = (iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3];
    xr = (iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7];
    int blocks = msglen / blocklen;
    int extra = msglen % blocklen;
    int c = 0;
    int i, b;
    int l = 8;
    gen_subkeys(key, keylen, iv, ivlen, rounds);
    gen_sbox(key, keylen);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1)) {
            l = extra;
	}

        block_encrypt(&xl, &xr);

        output[0] = (xl & 0xFF000000) >> 24;
        output[1] = (xl & 0x00FF0000) >> 16;
        output[2] = (xl & 0x0000FF00) >> 8;
        output[3] = (xl & 0x000000FF);
        output[4] = (xr & 0xFF000000) >> 24;
        output[5] = (xr & 0x00FF0000) >> 16;
        output[6] = (xr & 0x0000FF00) >> 8;
        output[7] = (xr & 0x000000FF);
        for (b = 0; b < l; b++) {
            msg[c] = msg[c] ^ output[b];
            c += 1;
        }
    }
}
