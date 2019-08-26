#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct spock_state {
    uint32_t Ka[40];
    uint32_t Kb[40];
    uint32_t d[40][4];
};

uint32_t spock_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t spock_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void roundF(struct spock_state *state, uint32_t *xla, uint32_t *xlb, uint32_t *xra, uint32_t *xrb, int rounds) {
    uint32_t a, b, c, d;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = 0; r < rounds; r++) {
        a = spock_rotr(a, 8);
	a += d;
        a ^= state->Ka[r];
        b = spock_rotr(b, 7);
	b += c;
        b ^= state->Kb[r];
	c = spock_rotl(c, 2);
	c ^= b;
	d = spock_rotl(d, 3);
	d ^= a;
	a += b;
	b += a;
	a += state->d[r][0];
	b += state->d[r][1];
	c += state->d[r][2];
	d += state->d[r][3];
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void roundB(struct spock_state *state, uint32_t *xla, uint32_t *xlb, uint32_t *xra, uint32_t *xrb, int rounds) {
    uint32_t a, b, c, d;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = rounds; r --> 0;) {
	d -= state->d[r][3];
	c -= state->d[r][2];
	b -= state->d[r][1];
	a -= state->d[r][0];
	b -= a;
	a -= b;
	d ^= a;
	d = spock_rotr(d, 3);
	c ^= b;
	c = spock_rotr(c, 2);
        b ^= state->Kb[r];
	b -= c;
        b = spock_rotl(b, 7);
        a ^= state->Ka[r];
	a -= d;
        a = spock_rotl(a, 8);
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void spock_ksa(struct spock_state *state, unsigned char * key) {
    uint32_t *k[4];
    uint32_t temp = 0x00000001;
    struct spock_state tempstate;
    k[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    k[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    k[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    k[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];
    
    int c = 0;
    for (int r = 0; r < (40 / 4); r++) {
        tempstate.Ka[c] = k[0];
        tempstate.Ka[c+1] = k[1];
        tempstate.Ka[c+2] = k[2];
        tempstate.Ka[c+3] = k[3];
        tempstate.Kb[c] = k[0];
        tempstate.Kb[c+1] = k[1];
        tempstate.Kb[c+2] = k[2];
        tempstate.Kb[c+3] = k[3];
	c += 4;
    }
    c = 0;
    for (int r = 0; r < 40; r++) {
        for (int i = 0; i < 4; i++) {
            state->d[r][i] = 0;
	    tempstate.d[r][i] = k[i];
        }
    }
    c = 0;
    for (int r = 0; r < (40 / 4); r++) {
	roundF(&tempstate, &k[0], &k[1], &k[2], &k[3], 40);
        state->Ka[c] = k[0];
        state->Ka[c+1] = k[1];
        state->Ka[c+2] = k[2];
        state->Ka[c+3] = k[3];
	roundF(&tempstate, &k[0], &k[1], &k[2], &k[3], 40);
        state->Kb[c] = k[0];
        state->Kb[c+1] = k[1];
        state->Kb[c+2] = k[2];
        state->Kb[c+3] = k[3];
	c += 4;
    }
    for (int r = 0; r < 40; r++) {
	roundF(&tempstate, &k[0], &k[1], &k[2], &k[3], 40);
        state->d[r][0] = k[0];
        state->d[r][1] = k[1];
        state->d[r][2] = k[2];
        state->d[r][3] = k[3];
    }
}

void spock_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    uint8_t k[16];
    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct spock_state state;
    int iv_length = 16;
    int rounds = 40;
    int c = 0;
    spock_ksa(&state, key);
    int v = 16;
    int x, i;
    int t = 0;
    int ii;
    long ctr = 0;
    long ctrtwo = 0;
    int blocks = msglen / 16;
    int msglen_extra = extrabytes;
    int padsize = msglen + msglen_extra;
    unsigned char data[v];
    if (extrabytes != 0) {
        blocks += 1;
    }
    for (int i = 0; i < 4; i++) {
        last[i] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
        c += 4;
    }
    for (i = 0; i < (blocks); i++) {
        for (ii = 0; ii < v; ii++) {
            data[ii] = msg[ctr];
            ctr = ctr + 1;
        }
        if (i == (blocks - 1)) {
            int g = 15;
            for (int b = 0; b < msglen_extra; b++) {
                data[g] = msglen_extra;
	        g = (g - 1);
            }
        }
        block[0] = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
        block[1] = (data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7];
        block[2] = (data[8] << 24) + (data[9] << 16) + (data[10] << 8) + data[11];
        block[3] = (data[12] << 24) + (data[13] << 16) + (data[14] << 8) + data[15];
        for (int r = 0; r < 4; r++) {
            block[r] = block[r] ^ last[r];
        }
        roundF(&state, &block[0], &block[1], &block[2], &block[3], rounds);
        for (int r = 0; r < 4; r++) {
            last[r] = block[r];
        }
        k[3] = (block[0] & 0x000000FF);
        k[2] = (block[0] & 0x0000FF00) >> 8;
        k[1] = (block[0] & 0x00FF0000) >> 16;
        k[0] = (block[0] & 0xFF000000) >> 24;
        k[7] = (block[1] & 0x000000FF);
        k[6] = (block[1] & 0x0000FF00) >> 8;
        k[5] = (block[1] & 0x00FF0000) >> 16;
        k[4] = (block[1] & 0xFF000000) >> 24;
        k[11] = (block[2] & 0x000000FF);
        k[10] = (block[2] & 0x0000FF00) >> 8;
        k[9] = (block[2] & 0x00FF0000) >> 16;
        k[8] = (block[2] & 0xFF000000) >> 24;
        k[15] = (block[3] & 0x000000FF);
        k[14] = (block[3] & 0x0000FF00) >> 8;
        k[13] = (block[3] & 0x00FF0000) >> 16;
        k[12] = (block[3] & 0xFF000000) >> 24;
        for (ii = 0; ii < v; ii++) {
            msg[ctrtwo] = k[ii];
            ctrtwo = ctrtwo + 1;
        }
    }
}

int spock_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    uint8_t k[16];
    uint32_t block[4];
    uint32_t last[4];
    uint32_t next[4];
    struct spock_state state;
    int iv_length = 16;
    int rounds = 40;
    int c = 0;
    spock_ksa(&state, key);
    int v = 16;
    int x, i;
    int t = 0;
    int ctr = 0;
    int ctrtwo = 0;
    int ii;
    unsigned char data[v];
    int blocks = msglen / 16;
    int extra = 0;
    for (int i = 0; i < 4; i++) {
        last[i] = (iv[c] << 24) + (iv[c+1] << 16) + (iv[c+2] << 8) + iv[c+3];
        c += 4;
    }
    for (i = 0; i < (blocks); i++) {
        for (ii = 0; ii < v; ii++) {
            data[ii] = msg[ctr];
            ctr = ctr + 1;
        }
        block[0] = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
        block[1] = (data[4] << 24) + (data[5] << 16) + (data[6] << 8) + data[7];
        block[2] = (data[8] << 24) + (data[9] << 16) + (data[10] << 8) + data[11];
        block[3] = (data[12] << 24) + (data[13] << 16) + (data[14] << 8) + data[15];
        for (int r = 0; r < 4; r++) {
            next[r] = block[r];
        }
        roundB(&state, &block[0], &block[1], &block[2], &block[3], rounds);
        for (int r = 0; r < 4; r++) {
            block[r] = block[r] ^ last[r];
            last[r] = next[r];
        }
        k[3] = (block[0] & 0x000000FF);
        k[2] = (block[0] & 0x0000FF00) >> 8;
        k[1] = (block[0] & 0x00FF0000) >> 16;
        k[0] = (block[0] & 0xFF000000) >> 24;
        k[7] = (block[1] & 0x000000FF);
        k[6] = (block[1] & 0x0000FF00) >> 8;
        k[5] = (block[1] & 0x00FF0000) >> 16;
        k[4] = (block[1] & 0xFF000000) >> 24;
        k[11] = (block[2] & 0x000000FF);
        k[10] = (block[2] & 0x0000FF00) >> 8;
        k[9] = (block[2] & 0x00FF0000) >> 16;
        k[8] = (block[2] & 0xFF000000) >> 24;
        k[15] = (block[3] & 0x000000FF);
        k[14] = (block[3] & 0x0000FF00) >> 8;
        k[13] = (block[3] & 0x00FF0000) >> 16;
        k[12] = (block[3] & 0xFF000000) >> 24;
        for (ii = 0; ii < v; ii++) {
            msg[ctrtwo] = k[ii];
            ctrtwo = ctrtwo + 1;
        }
        if (i == (blocks-1)) {
           int count = 0;
           int padcheck = k[15];
           int g = 15;
           for (int m = 0; m < padcheck; m++) {
               if ((int)k[g] == padcheck) {
                   count += 1;
               }
               g = (g - 1);
           }
           if (count == padcheck) {
               return count;
           }
           return padcheck;
        }
    }
}
