#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int blocklen = 8;
int rounds = 16;
int S[4][256];
uint32_t K[16] = {0};
uint32_t last[2] = {0};
uint32_t next[2] = {0};

void gen_subkeys(unsigned char * key, int keylen, unsigned char * iv, int ivlen, int rounds) {
    int a = 0;
    int b = 1;
    int c = 2;
    int d = 3;
    int i;
    uint32_t keytemp[(keylen /4)];
    uint32_t temp = 0x00000001;
    for (i = 0; i < (keylen / 4); i++) {
        keytemp[i] = (key[a] << 24) + (key[b] << 16) + (key[c] << 8) + key[d];
	a += 4;
	b += 4;
	c += 4;
	d += 4;
    }
    a = 0;
    b = 1;
    c = 2;
    d = 3;
    for (i = 0; i < (ivlen / 4); i++) {
        keytemp[i] = keytemp[i] ^ ((iv[a] << 24) + (iv[b] << 16) + (iv[c] << 8) + iv[d]);
	a += 4;
	b += 4;
	c += 4;
	d += 4;
    }
    temp = (keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    for (i = 0; i < rounds; i++) {
        temp = (keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
	K[i] = temp;
    }
    temp = (K[0] + keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    last[0] = temp;
    temp = (K[1] + keytemp[0] + keytemp[1] + keytemp[2] + keytemp[3] + temp) & 0xFFFFFFFF;
    last[1] = temp;

}

void gen_sbox(unsigned char * key, int keylen) {
    int i;
    int s;
    int j = 0;
    int temp;
    for (s = 0; s < 4; s++) {
        for (i = 0; i < 256; i++) {
            S[s][i] = i;
        }
    }
    for (s = 0; s < 4; s++) {
        for (i = 0; i < 256; i++) {
            j = (j + key[i % keylen]) & 0xFF;
            temp = S[s][i];
            S[s][i] = S[s][j];
            S[s][j] = temp;
        }
    }
}

uint32_t F(uint32_t xr) {
    int v, x, y, z, a;
    v = (xr & 0xFF000000) >> 24;
    x = (xr & 0x00FF0000) >> 16;
    y = (xr & 0x0000FF00) >> 8;
    z = (xr & 0x000000FF);

    v = v ^ S[0][v];
    x = x ^ S[1][x];
    y = y ^ S[2][y];
    z = z ^ S[3][z];

    v = v ^ S[1][z] + S[2][v];
    x = x ^ S[2][y];
    y = y ^ S[3][x];
    z = z ^ S[0][v];
    xr = (v << 24) + (x << 16) + (y << 8) + z;
    return xr;
}

uint32_t block_encrypt(uint32_t *xl, uint32_t *xr) {
    int i;
    uint32_t temp;
    uint32_t Xl;
    uint32_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = 0; i < rounds; i++) {
        Xr = Xr ^ K[i];
        Xl = Xl ^ F(Xr);

        temp = Xl;
        Xl = Xr;
        Xr = temp;

    }
    temp = Xl;
    Xl = Xr;
    Xr = temp;

    *xl = Xl;
    *xr = Xr;
}

uint32_t block_decrypt(uint32_t *xl, uint32_t *xr) {
    int i;
    uint32_t temp;
    uint32_t Xl;
    uint32_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = (rounds - 1); i != -1; i--) {
        Xl = Xl ^ F(Xr);
        Xr = Xr ^ K[i];

        temp = Xl;
        Xl = Xr;
        Xr = temp;

    }
    temp = Xl;
    Xl = Xr;
    Xr = temp;
    
    *xl = Xl;
    *xr = Xr;
}

void zanderfish_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    uint32_t xl;
    uint32_t xr;
    int blocks = msglen / blocklen;
    int c = 0;
    int i;
    gen_subkeys(key, keylen, iv, ivlen, rounds);
    gen_sbox(key, keylen);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1)) {
            for (int p = 0; p < extrabytes; p++) {
                msg[(msglen-1)-p] = (unsigned char *)extrabytes;
	    }
	}
	        
        xl = (msg[c] << 24) + (msg[c+1] << 16) + (msg[c+2] << 8) + msg[c+3];
        xr = (msg[c+4] << 24) + (msg[c+5] << 16) + (msg[c+6] << 8) + msg[c+7];

	xl = xl ^ last[0];
	xr = xr ^ last[1];

        block_encrypt(&xl, &xr);

	last[0] = xl;
	last[1] = xr;

	msg[c] = (xl & 0xFF000000) >> 24;
        msg[c+1] = (xl & 0x00FF0000) >> 16;
        msg[c+2] = (xl & 0x0000FF00) >> 8;
        msg[c+3] = (xl & 0x000000FF);
        msg[c+4] = (xr & 0xFF000000) >> 24;
        msg[c+5] = (xr & 0x00FF0000) >> 16;
        msg[c+6] = (xr & 0x0000FF00) >> 8;
        msg[c+7] = (xr & 0x000000FF);
	c += 8;
    }
}

int zanderfish_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    int count = 0;
    uint32_t xl;
    uint32_t xr;
    int blocks = msglen / blocklen;
    int c = 0;
    int i;
    gen_subkeys(key, keylen, iv, ivlen, rounds);
    gen_sbox(key, keylen);
    for (i = 0; i < blocks; i++) {
        xl = (msg[c] << 24) + (msg[c+1] << 16) + (msg[c+2] << 8) + msg[c+3];
        xr = (msg[c+4] << 24) + (msg[c+5] << 16) + (msg[c+6] << 8) + msg[c+7];
        
	next[0] = xl;
	next[1] = xr;

        block_decrypt(&xl, &xr);

	xl = xl ^ last[0];
	xr = xr ^ last[1];
	last[0] = next[0];
	last[1] = next[1];

	msg[c] = (xl & 0xFF000000) >> 24;
        msg[c+1] = (xl & 0x00FF0000) >> 16;
        msg[c+2] = (xl & 0x0000FF00) >> 8;
        msg[c+3] = (xl & 0x000000FF);
        msg[c+4] = (xr & 0xFF000000) >> 24;
        msg[c+5] = (xr & 0x00FF0000) >> 16;
        msg[c+6] = (xr & 0x0000FF00) >> 8;
        msg[c+7] = (xr & 0x000000FF);
	c += 8;

	if (i == (blocks - 1)) {
	    int padcheck = msg[msglen - 1];
	    int g = msglen - 1;
	    for (int p = 0; p < padcheck; p++) {
                if ((int)msg[g] == padcheck) {
                    count += 1;
		}
		g = g - 1;
            }
	}
    }
    return count;
}

