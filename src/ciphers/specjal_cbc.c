#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct specjal_state {
    uint64_t Ka[80];
    uint64_t Kb[80];
    uint64_t Kc[80];
    uint64_t Kd[80];
    uint64_t d[80][4];
};

struct ksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t specjal_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t specjal_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *specjal_F(struct ksa_state *state) {
    int r;
    for (r = 0; r < 10; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = specjal_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = specjal_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = specjal_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = specjal_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = specjal_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];
    }
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void SroundF(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb, int rounds) {
    uint64_t a, b, c, d;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = 0; r < rounds; r++) {
	a += d;
        a = specjal_rotr(a, 13);
        a ^= state->Ka[r];
	b += c;
        b = specjal_rotr(b, 9);
        b ^= state->Kb[r];
	c += b;
	c = specjal_rotl(c, 12);
        c ^= state->Kc[r];
	d += a;
	d = specjal_rotl(d, 7);
        d ^= state->Kd[r];
	a += b;
	b += a;
        c += d;
        d += c;
	a ^= state->d[r][0];
	b ^= state->d[r][1];
	c ^= state->d[r][2];
	d ^= state->d[r][3];
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void SroundB(struct specjal_state *state, uint64_t *xla, uint64_t *xlb, uint64_t *xra, uint64_t *xrb, int rounds) {
    uint64_t a, b, c, d;
    a = *xla;
    b = *xlb;
    c = *xra;
    d = *xrb;
    for (int r = rounds; r --> 0;) {
	d ^= state->d[r][3];
	c ^= state->d[r][2];
	b ^= state->d[r][1];
	a ^= state->d[r][0];
        d -= c;
        c -= d;
	b -= a;
	a -= b;
        d ^= state->Kd[r];
	d = specjal_rotr(d, 7);
        c ^= state->Kc[r];
	d -= a;
	c = specjal_rotr(c, 12);
	c -= b;
        b ^= state->Kb[r];
        b = specjal_rotl(b, 9);
	b -= c;
        a ^= state->Ka[r];
        a = specjal_rotl(a, 13);
	a -= d;
    }
    *xla = a;
    *xlb = b;
    *xra = c;
    *xrb = d;
}

void specjal_ksa(struct specjal_state *state, unsigned char * key, int keylen, int rounds) {
    uint64_t temp = 0x00000001;
    struct specjal_state tempstate;
    struct ksa_state kstate;
    int m = 0;
    int b;
    int inc = keylen / 8;
    int step = 8;
    uint64_t *k[inc];
    for (int i = 0; i < inc; i++) {
        k[i] = 0;
        k[i] = ((uint64_t)key[m] << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += step;
    }
    for (int i = 0; i < inc; i++) {
        kstate.r[i] = 0;
        kstate.r[i] = ((uint64_t)key[m] << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += step;
    }
    
    int c = 0;
    for (int r = 0; r < (rounds / inc); r++) {
        for (int i = 0; i < inc; i++) {
            tempstate.Ka[c] = k[i];
            tempstate.Kb[c] = k[i];
            tempstate.Kc[c] = k[i];
            tempstate.Kd[c] = k[i];
	    c += 1;
        }
    }
    c = 0;
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 4; i++) {
            state->d[r][i] = 0;
	    tempstate.d[r][i] = k[i];
        }
    }
    c = 0;
    b = 0;
    for (int r = 0; r < (rounds / inc); r++) {
        m = 0;
        for (int i = 0; i < (inc / 4); i++) {
	    SroundF(&tempstate, &k[m], &k[m+1], &k[m+2], &k[m+3], rounds);
            m += 4;
        }
        for (int i = 0; i < inc; i++) {
            state->Ka[c] = k[i];
	    c += 1;
        }
        m = 0;
        for (int i = 0; i < (inc / 4); i++) {
	    SroundF(&tempstate, &k[m], &k[m+1], &k[m+2], &k[m+3], rounds);
            m += 4;
        }
        for (int i = 0; i < inc; i++) {
            state->Kb[b] = k[i];
	    b += 1;
        }
    }
    for (int r = 0; r < rounds; r++) {
        m = 0;
        for (int i = 0; i < (inc / 4); i++) {
	    SroundF(&tempstate, &k[m], &k[m+1], &k[m+2], &k[m+3], rounds);
            m += 4;
        }
        m = 0;
        for (int i = 0; i < (inc / 4); i++) {
            state->d[r][0] = k[m+1];
            state->d[r][1] = k[m+2];
            state->d[r][2] = k[m+3];
            state->d[r][3] = k[m+4];
            m += 4;
        }
    }
    memset(kstate.r, 0, (16*(sizeof(uint64_t))));
    for (int i = 0; i < 16; i++) {
        kstate.r[i] = 0;
    }
    for (int i = 0; i < 16; i++) {
        kstate.r[i] ^= state->Ka[i];
        kstate.r[i] ^= state->Kb[i];
    }
    kstate.o = 0x0000000000000000;
    for (int i = 0; i < rounds; i++) {
        specjal_F(&kstate);
        state->Kc[i] = 0;
        state->Kc[i] = kstate.o;
        specjal_F(&kstate);
        state->Kd[i] = 0;
        state->Kd[i] = kstate.o;
    }
    for (int i = 0; i < rounds; i++) {
        state->Ka[i] ^= state->Kc[i];
        state->Kd[i] ^= state->Kb[i];
        state->Kb[i] ^= state->Kc[i];
        state->Kc[i] ^= state->Kd[i];
    }
}

void specjal_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    uint8_t k[32];
    uint64_t block[4];
    uint64_t last[4];
    uint64_t next[4];
    struct specjal_state state;
    int iv_length = 32;
    int rounds = (keylen / 8) + 64;
    int c = 0;
    int m = 0;
    specjal_ksa(&state, key, keylen, rounds);
    int v = 32;
    int x, i;
    int t = 0;
    int ii;
    long ctr = 0;
    long ctrtwo = 0;
    int blocks = msglen / 32;
    int msglen_extra = extrabytes;
    int padsize = msglen + msglen_extra;
    unsigned char data[v];
    if (extrabytes != 0) {
        blocks += 1;
    }
    m = 0;
    for (int i = 0; i < 4; i++) {
        last[i] = ((uint64_t)(iv[m]) << 56) + ((uint64_t)iv[m+1] << 48) + ((uint64_t)iv[m+2] << 40) + ((uint64_t)iv[m+3] << 32) + ((uint64_t)iv[m+4] << 24) + ((uint64_t)iv[m+5] << 16) + ((uint64_t)iv[m+6] << 8) + (uint64_t)iv[m+7];
        m += 8;
    }
    for (i = 0; i < (blocks); i++) {
        for (ii = 0; ii < v; ii++) {
            data[ii] = msg[ctr];
            ctr = ctr + 1;
        }
        if (i == (blocks - 1)) {
            int g = 31;
            for (int b = 0; b < msglen_extra; b++) {
                data[g] = msglen_extra;
	        g = (g - 1);
            }
        }
        m = 0;
        for (int x = 0; x < 4; x++) {
            block[x] = ((uint64_t)(data[m]) << 56) + ((uint64_t)data[m+1] << 48) + ((uint64_t)data[m+2] << 40) + ((uint64_t)data[m+3] << 32) + ((uint64_t)data[m+4] << 24) + ((uint64_t)data[m+5] << 16) + ((uint64_t)data[m+6] << 8) + (uint64_t)data[m+7];
            m += 8;
        }
        for (int r = 0; r < 4; r++) {
            block[r] = block[r] ^ last[r];
        }
        SroundF(&state, &block[0], &block[1], &block[2], &block[3], rounds);
        for (int r = 0; r < 4; r++) {
            last[r] = block[r];
        }
        k[0] = (block[0] & 0xFF00000000000000) >> 56;
        k[1] = (block[0] & 0x00FF000000000000) >> 48;
        k[2] = (block[0] & 0x0000FF0000000000) >> 40;
        k[3] = (block[0] & 0x000000FF00000000) >> 32;
        k[4] = (block[0] & 0x00000000FF000000) >> 24;
        k[5] = (block[0] & 0x0000000000FF0000) >> 16;
        k[6] = (block[0] & 0x000000000000FF00) >> 8;
        k[7] = (block[0] & 0x00000000000000FF);
        k[8] = (block[1] & 0xFF00000000000000) >> 56;
        k[9] = (block[1] & 0x00FF000000000000) >> 48;
        k[10] = (block[1] & 0x0000FF0000000000) >> 40;
        k[11] = (block[1] & 0x000000FF00000000) >> 32;
        k[12] = (block[1] & 0x00000000FF000000) >> 24;
        k[13] = (block[1] & 0x0000000000FF0000) >> 16;
        k[14] = (block[1] & 0x000000000000FF00) >> 8;
        k[15] = (block[1] & 0x00000000000000FF);
        k[16] = (block[2] & 0xFF00000000000000) >> 56;
        k[17] = (block[2] & 0x00FF000000000000) >> 48;
        k[18] = (block[2] & 0x0000FF0000000000) >> 40;
        k[19] = (block[2] & 0x000000FF00000000) >> 32;
        k[20] = (block[2] & 0x00000000FF000000) >> 24;
        k[21] = (block[2] & 0x0000000000FF0000) >> 16;
        k[22] = (block[2] & 0x000000000000FF00) >> 8;
        k[23] = (block[2] & 0x00000000000000FF);
        k[24] = (block[3] & 0xFF00000000000000) >> 56;
        k[25] = (block[3] & 0x00FF000000000000) >> 48;
        k[26] = (block[3] & 0x0000FF0000000000) >> 40;
        k[27] = (block[3] & 0x000000FF00000000) >> 32;
        k[28] = (block[3] & 0x00000000FF000000) >> 24;
        k[29] = (block[3] & 0x0000000000FF0000) >> 16;
        k[30] = (block[3] & 0x000000000000FF00) >> 8;
        k[31] = (block[3] & 0x00000000000000FF);
        for (ii = 0; ii < v; ii++) {
            msg[ctrtwo] = k[ii];
            ctrtwo = ctrtwo + 1;
        }
    }
}

int specjal_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    uint8_t k[32];
    uint64_t block[4];
    uint64_t last[4];
    uint64_t next[4];
    struct specjal_state state;
    int iv_length = 32;
    int rounds = (keylen / 8) + 64;
    int c = 0;
    int m = 0;
    specjal_ksa(&state, key, keylen, rounds);
    int v = 32;
    int x, i;
    int t = 0;
    int ctr = 0;
    int ctrtwo = 0;
    int ii;
    unsigned char data[v];
    int blocks = msglen / 32;
    int extra = 0;
    m = 0;
    for (int i = 0; i < 4; i++) {
        last[i] = ((uint64_t)(iv[m]) << 56) + ((uint64_t)iv[m+1] << 48) + ((uint64_t)iv[m+2] << 40) + ((uint64_t)iv[m+3] << 32) + ((uint64_t)iv[m+4] << 24) + ((uint64_t)iv[m+5] << 16) + ((uint64_t)iv[m+6] << 8) + (uint64_t)iv[m+7];
        m += 8;
    }
    for (i = 0; i < (blocks); i++) {
        for (ii = 0; ii < v; ii++) {
            data[ii] = msg[ctr];
            ctr = ctr + 1;
        }
        m = 0;
        for (int x = 0; x < 4; x++) {
            block[x] = ((uint64_t)(data[m]) << 56) + ((uint64_t)data[m+1] << 48) + ((uint64_t)data[m+2] << 40) + ((uint64_t)data[m+3] << 32) + ((uint64_t)data[m+4] << 24) + ((uint64_t)data[m+5] << 16) + ((uint64_t)data[m+6] << 8) + (uint64_t)data[m+7];
            m += 8;
        }
        for (int r = 0; r < 4; r++) {
            next[r] = block[r];
        }
        SroundB(&state, &block[0], &block[1], &block[2], &block[3], rounds);
        for (int r = 0; r < 4; r++) {
            block[r] = block[r] ^ last[r];
            last[r] = next[r];
        }
        k[0] = (block[0] & 0xFF00000000000000) >> 56;
        k[1] = (block[0] & 0x00FF000000000000) >> 48;
        k[2] = (block[0] & 0x0000FF0000000000) >> 40;
        k[3] = (block[0] & 0x000000FF00000000) >> 32;
        k[4] = (block[0] & 0x00000000FF000000) >> 24;
        k[5] = (block[0] & 0x0000000000FF0000) >> 16;
        k[6] = (block[0] & 0x000000000000FF00) >> 8;
        k[7] = (block[0] & 0x00000000000000FF);
        k[8] = (block[1] & 0xFF00000000000000) >> 56;
        k[9] = (block[1] & 0x00FF000000000000) >> 48;
        k[10] = (block[1] & 0x0000FF0000000000) >> 40;
        k[11] = (block[1] & 0x000000FF00000000) >> 32;
        k[12] = (block[1] & 0x00000000FF000000) >> 24;
        k[13] = (block[1] & 0x0000000000FF0000) >> 16;
        k[14] = (block[1] & 0x000000000000FF00) >> 8;
        k[15] = (block[1] & 0x00000000000000FF);
        k[16] = (block[2] & 0xFF00000000000000) >> 56;
        k[17] = (block[2] & 0x00FF000000000000) >> 48;
        k[18] = (block[2] & 0x0000FF0000000000) >> 40;
        k[19] = (block[2] & 0x000000FF00000000) >> 32;
        k[20] = (block[2] & 0x00000000FF000000) >> 24;
        k[21] = (block[2] & 0x0000000000FF0000) >> 16;
        k[22] = (block[2] & 0x000000000000FF00) >> 8;
        k[23] = (block[2] & 0x00000000000000FF);
        k[24] = (block[3] & 0xFF00000000000000) >> 56;
        k[25] = (block[3] & 0x00FF000000000000) >> 48;
        k[26] = (block[3] & 0x0000FF0000000000) >> 40;
        k[27] = (block[3] & 0x000000FF00000000) >> 32;
        k[28] = (block[3] & 0x00000000FF000000) >> 24;
        k[29] = (block[3] & 0x0000000000FF0000) >> 16;
        k[30] = (block[3] & 0x000000000000FF00) >> 8;
        k[31] = (block[3] & 0x00000000000000FF);
        for (ii = 0; ii < v; ii++) {
            msg[ctrtwo] = k[ii];
            ctrtwo = ctrtwo + 1;
        }
        if (i == (blocks-1)) {
           int count = 0;
           int padcheck = k[31];
           int g = 31;
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
