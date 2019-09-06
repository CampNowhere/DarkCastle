#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int zUblocklen = 16;

int S0[256] = {

3, 247, 135, 7, 73, 184, 107, 78, 6, 180, 189, 167, 133, 142, 121, 84, 76, 149, 19, 18, 49, 37, 8, 24, 2, 56, 246, 105, 146, 125, 177, 203, 33, 178, 74, 139, 108, 12, 104, 114, 169, 28, 224, 71, 220, 41, 119, 69, 229, 46, 128, 208, 168, 95, 181, 66, 82, 228, 1, 197, 5, 230, 194, 219, 231, 60, 112, 38, 201, 211, 51, 91, 227, 61, 152, 10, 115, 137, 174, 87, 11, 179, 188, 182, 117, 85, 218, 123, 31, 23, 163, 150, 216, 52, 29, 34, 36, 245, 164, 27, 204, 39, 140, 158, 191, 124, 175, 30, 249, 122, 241, 205, 116, 138, 126, 171, 94, 240, 232, 63, 154, 157, 131, 148, 251, 45, 92, 118, 221, 242, 206, 4, 187, 210, 173, 97, 162, 102, 70, 207, 99, 215, 20, 43, 250, 22, 127, 129, 252, 77, 101, 202, 186, 58, 54, 196, 50, 234, 255, 166, 161, 55, 109, 239, 190, 160, 106, 233, 40, 93, 225, 64, 86, 130, 65, 165, 236, 244, 217, 75, 25, 81, 214, 213, 248, 16, 193, 26, 134, 253, 68, 235, 238, 176, 88, 198, 47, 14, 170, 57, 62, 185, 144, 145, 222, 132, 153, 9, 151, 42, 212, 243, 159, 155, 237, 80, 83, 90, 120, 15, 79, 183, 35, 141, 44, 98, 195, 67, 0, 226, 192, 136, 89, 113, 100, 103, 156, 32, 223, 199, 13, 48, 111, 200, 110, 209, 254, 96, 21, 72, 53, 172, 17, 143, 147, 59 
};

int S1[256] = {

96, 84, 227, 86, 193, 34, 125, 253, 191, 54, 103, 238, 97, 140, 73, 177, 164, 59, 225, 17, 11, 31, 3, 246, 135, 29, 200, 56, 163, 178, 55, 71, 172, 139, 235, 146, 7, 128, 138, 130, 52, 183, 224, 53, 1, 167, 85, 88, 94, 15, 249, 4, 30, 199, 16, 185, 187, 114, 204, 111, 109, 210, 232, 99, 252, 151, 58, 175, 102, 241, 202, 165, 237, 150, 145, 157, 48, 184, 124, 22, 98, 116, 106, 142, 2, 182, 5, 233, 198, 212, 20, 243, 216, 27, 214, 155, 134, 166, 207, 186, 174, 161, 60, 131, 168, 82, 43, 23, 62, 38, 192, 188, 245, 122, 24, 220, 195, 13, 44, 205, 105, 69, 169, 144, 66, 93, 46, 80, 179, 87, 74, 64, 107, 110, 217, 244, 132, 78, 91, 171, 40, 173, 92, 154, 45, 77, 228, 170, 190, 33, 68, 10, 65, 218, 158, 215, 47, 213, 79, 8, 113, 126, 255, 76, 95, 42, 41, 101, 100, 133, 223, 123, 118, 136, 21, 226, 230, 112, 219, 180, 25, 181, 234, 49, 119, 18, 0, 197, 61, 189, 254, 251, 176, 129, 194, 156, 239, 137, 83, 153, 57, 162, 104, 247, 222, 121, 236, 70, 196, 67, 81, 72, 127, 37, 206, 211, 117, 250, 14, 160, 143, 26, 147, 148, 201, 231, 39, 51, 141, 75, 19, 209, 208, 229, 50, 28, 115, 240, 90, 152, 9, 242, 6, 35, 36, 63, 89, 221, 149, 159, 32, 108, 120, 248, 203, 12
};

struct zanderU_state {
    int S[8][256];
    int SB[8][256];
    uint64_t K[16];
    uint64_t KB[16];
    uint64_t KP[16];
    uint64_t KQ[16];
    uint64_t last[2];
    uint64_t next[2];
};

struct zUksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t zU_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zU_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *zU_F(struct zUksa_state *state) {
    int r;
    for (r = 0; r < 10; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = zU_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = zU_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = zU_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = zU_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = zU_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];
    }
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void zUgen_subkeys(struct zanderU_state * state, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int zrounds) {
    struct zUksa_state kstate;
    int c = 0;
    int i;
    uint64_t keytemp[(keylen /8)];
    memset(state->K, 0, 16*sizeof(uint64_t));
    memset(state->KB, 0, 16*sizeof(uint64_t));
    memset(state->KP, 0, 16*sizeof(uint64_t));
    memset(state->KQ, 0, 16*sizeof(uint64_t));
    memset(&kstate.r, 0, 16*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));
    memset(state->last, 0, 2*sizeof(uint64_t));
    memset(state->next, 0, 2*sizeof(uint64_t));

    for (i = 0; i < (keylen / 8); i++) {
        keytemp[i] = 0;
        keytemp[i] = ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        kstate.r[i] = ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    c = 0;
    for (i = 0; i < (ivlen / 8); i++) {
        state->last[i] = 0;
        state->last[i] = ((uint64_t)iv[c] << 56) + ((uint64_t)iv[c+1] << 48) + ((uint64_t)iv[c+2] << 40) + ((uint64_t)iv[c+3] << 32) + ((uint64_t)iv[c+4] << 24) + ((uint64_t)iv[c+5] << 16) + ((uint64_t)iv[c+6] << 8) + (uint64_t)iv[c+7];
	c += 8;
    }
    for (i = 0; i < 256; i++) {
        kstate.r[i & 0x0F] ^= C0[i];
        kstate.r[i & 0x0F] ^= C1[i];
    }
    for (i = 0; i < zrounds; i++) {
        zU_F(&kstate);
        state->K[i] = 0;
	state->K[i] = kstate.o;
    }
    for (i = 0; i < zrounds; i++) {
        state->KB[i] = 0;
        state->KB[i] ^= state->K[i];
    }
    for (i = 0; i < zrounds; i++) {
        zU_F(&kstate);
        state->K[i] = 0;
	state->K[i] = kstate.o;
    }
    for (i = 0; i < 256; i++) {
        state->K[i & 0x0F] ^= C2[i];
        state->KB[i & 0x0F] ^= C3[i];
    }
    for (i = 0; i < zrounds; i++) {
	state->KP[i] = kstate.r[i];
    }
    for (i = 0; i < zrounds; i++) {
        zU_F(&kstate);
	state->KP[i] ^= kstate.o;
    }
    for (i = 0; i < zrounds; i++) {
	state->KQ[i] = kstate.r[i];
    }
    for (i = 0; i < zrounds; i++) {
        zU_F(&kstate);
	state->KQ[i] ^= kstate.o;
    }
}

void zUgen_sbox(struct zanderU_state * state, unsigned char * key, int keylen, unsigned char * crosskey) {
    int i, o, c;
    int s;
    int j = 0;
    int temp;
    int k[256];
    int kb[256];
    for (i = 0; i < 256; i++) {
        kb[i] = 0;
        k[i] = i;
        k[i] ^= key[c];
        kb[i] = k[i];
        c = (c + 1) % keylen;
        
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            state->S[s][i] = 0;
            state->S[s][i] = i;
        }
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            j = k[j];
            k[j] = (k[c] + k[j]) & 0xff;
            o = (k[k[j]] + k[j]) & 0xff;
            o = ((uint8_t)C2[o] << 48);
            temp = state->S[s][o];
            state->S[s][o] = state->S[s][o];
            state->S[s][o] = temp;
        }
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            j = k[j];
            k[j] = (k[c] + k[j]) & 0xff;
            o = (k[k[j]] + k[j]) & 0xff;
            temp = state->S[s][o];
            state->S[s][o] = state->S[s][o];
            state->S[s][o] = temp;
        }
    }
    for (i = 0; i < 256; i++) {
        k[i] ^= kb[i];
        crosskey[i] = k[i];
    }
}

void zUgen_sboxB(struct zanderU_state * state, unsigned char * key, int keylen, unsigned char * crosskey) {
    int i, o, c;
    int s;
    int j = 0;
    int temp;
    int k[256];
    for (i = 0; i < 256; i++) {
        k[i] = i;
        k[i] ^= crosskey[i];
        
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            state->SB[s][i] = 0;
            state->SB[s][i] = i;
        }
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            j = k[j];
            k[j] = (k[c] + k[j]) & 0xff;
            o = (k[k[j]] + k[j]) & 0xff;
            o = o ^ (uint8_t)C3[o];
            temp = state->SB[s][o];
            state->SB[s][o] = state->SB[s][o];
            state->SB[s][o] = temp;
        }
    }
    for (s = 0; s < 8; s++) {
        for (i = 0; i < 256; i++) {
            j = k[j];
            k[j] = (k[c] + k[j]) & 0xff;
            o = (k[k[j]] + k[j]) & 0xff;
            temp = state->SB[s][o];
            state->SB[s][o] = state->SB[s][o];
            state->SB[s][o] = temp;
        }
    }
}


uint64_t zUF(struct zanderU_state * state, uint64_t xr) {
    int v, x, y, z, a, b, c, d;
    v = (xr & 0xFF00000000000000) >> 56;
    x = (xr & 0x00FF000000000000) >> 48;
    y = (xr & 0x0000FF0000000000) >> 40;
    z = (xr & 0x000000FF00000000) >> 32;
    a = (xr & 0x00000000FF000000) >> 24;
    b = (xr & 0x0000000000FF0000) >> 16;
    c = (xr & 0x000000000000FF00) >> 8;
    d = (xr & 0x00000000000000FF);

    a = a ^ state->S[4][a];
    b = b ^ state->S[5][b];
    c = c ^ state->S[6][c];
    d = d ^ state->S[7][d];

    a = a ^ state->S[7][d] + state->S[6][a];
    b = b ^ state->S[6][c] + state->S[4][d];
    c = c ^ state->S[5][b];
    d = d ^ state->S[4][a];

    a = a ^ y;
    b = b ^ v;
    c = c ^ z;
    d = d ^ x;
    
    v = v ^ state->S[0][v];
    x = x ^ state->S[1][x];
    y = y ^ state->S[2][y];
    z = z ^ state->S[3][z];

    v = v ^ state->S[1][z] + state->S[2][v];
    x = x ^ state->S[2][y];
    y = y ^ state->S[3][x];
    z = z ^ state->S[0][v];
    
    a = a ^ S1[x];
    b = b ^ S0[d];
    c = c ^ S1[y];
    d = d ^ S0[a];
    v = v ^ S1[c];
    x = x ^ S0[z];
    y = y ^ S1[v];
    z = z ^ S0[b];

    xr = ((uint64_t)v << 56) + ((uint64_t)x << 48) + ((uint64_t)y << 40) + ((uint64_t)z << 32) + ((uint64_t)a << 24) + ((uint64_t)b << 16) + ((uint64_t)c << 8) + d;
    return xr;
}

uint64_t zUF2(struct zanderU_state * state, uint64_t xr) {
    int v, x, y, z, a, b, c, d;
    v = (xr & 0xFF00000000000000) >> 56;
    x = (xr & 0x00FF000000000000) >> 48;
    y = (xr & 0x0000FF0000000000) >> 40;
    z = (xr & 0x000000FF00000000) >> 32;
    a = (xr & 0x00000000FF000000) >> 24;
    b = (xr & 0x0000000000FF0000) >> 16;
    c = (xr & 0x000000000000FF00) >> 8;
    d = (xr & 0x00000000000000FF);

    a = a ^ state->SB[4][a];
    b = b ^ state->SB[5][b];
    c = c ^ state->SB[6][c];
    d = d ^ state->SB[7][d];

    a = a ^ state->SB[7][d] + state->SB[6][a];
    b = b ^ state->SB[6][c];
    c = c ^ state->SB[5][b];
    d = d ^ state->SB[4][a];

    a = a ^ v;
    b = b ^ x;
    c = c ^ y;
    d = d ^ z;

    v = v ^ state->SB[0][v];
    x = x ^ state->SB[1][x];
    y = y ^ state->SB[2][y];
    z = z ^ state->SB[3][z];

    v = v ^ state->SB[1][z] + state->SB[2][v];
    x = x ^ state->SB[2][y];
    y = y ^ state->SB[3][x];
    z = z ^ state->SB[0][v];
    
    a = a ^ S0[x];
    b = b ^ S1[d];
    c = c ^ S0[y];
    d = d ^ S1[a];
    v = v ^ S0[c];
    x = x ^ S1[z];
    y = y ^ S0[v];
    z = z ^ S1[b];
    
    xr = ((uint64_t)v << 56) + ((uint64_t)x << 48) + ((uint64_t)y << 40) + ((uint64_t)z << 32) + ((uint64_t)a << 24) + ((uint64_t)b << 16) + ((uint64_t)c << 8) + d;
    return xr;
}

uint64_t zUF2_B(struct zanderU_state * state, uint64_t xr) {
    int v, x, y, z, a, b, c, d;
    v = (xr & 0xFF00000000000000) >> 56;
    x = (xr & 0x00FF000000000000) >> 48;
    y = (xr & 0x0000FF0000000000) >> 40;
    z = (xr & 0x000000FF00000000) >> 32;
    a = (xr & 0x00000000FF000000) >> 24;
    b = (xr & 0x0000000000FF0000) >> 16;
    c = (xr & 0x000000000000FF00) >> 8;
    d = (xr & 0x00000000000000FF);

    a = a ^ state->SB[4][a];
    b = b ^ state->SB[5][b];
    c = c ^ state->SB[6][c];
    d = d ^ state->SB[7][d];

    a = a ^ state->SB[7][d] + state->SB[6][a];
    b = b ^ state->SB[6][c];
    c = c ^ state->SB[5][b];
    d = d ^ state->SB[4][a];

    a = a ^ v;
    b = b ^ x;
    c = c ^ y;
    d = d ^ z;

    v = v ^ state->SB[0][v];
    x = x ^ state->SB[1][x];
    y = y ^ state->SB[2][y];
    z = z ^ state->SB[3][z];

    v = v ^ state->SB[1][z] + state->SB[2][v];
    x = x ^ state->SB[2][y];
    y = y ^ state->SB[3][x];
    z = z ^ state->SB[0][v];
    
    a = a ^ S0[a];
    b = b ^ S1[b];
    c = c ^ S0[c];
    d = d ^ S1[d];
    v = v ^ S0[v];
    x = x ^ S1[x];
    y = y ^ S0[y];
    z = z ^ S1[z];
    
    xr = ((uint64_t)v << 56) + ((uint64_t)x << 48) + ((uint64_t)y << 40) + ((uint64_t)z << 32) + ((uint64_t)a << 24) + ((uint64_t)b << 16) + ((uint64_t)c << 8) + d;
    return xr;
}

uint64_t zUblock_encrypt(struct zanderU_state * state, uint64_t *xl, uint64_t *xr) {
    int i;
    uint64_t temp;
    uint64_t Xl;
    uint64_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = 0; i < zrounds; i++) {
        Xl = Xl ^ state->KP[i];
        Xr = Xr + state->K[i];
        Xr = Xr ^ state->KB[i];
        Xl = zU_rotl(Xl, 9);
        Xl = Xl ^ zUF(state, Xr);
        Xl = Xl + zUF2(state, Xr);
        Xr = Xr + state->KQ[i];
        Xl += Xr;
        Xr += Xl;

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

uint64_t zUblock_decrypt(struct zanderU_state * state, uint64_t *xl, uint64_t *xr) {
    int i;
    uint64_t temp;
    uint64_t Xl;
    uint64_t Xr;

    Xl = *xl;
    Xr = *xr;
    for (i = (zrounds - 1); i != -1; i--) {
        Xr -= Xl;
        Xl -= Xr;
        Xr = Xr - state->KQ[i];
        Xl = Xl - zUF2(state, Xr);
        Xl = Xl ^ zUF(state, Xr);
        Xl = zU_rotr(Xl, 9);
        Xr = Xr ^ state->KB[i];
        Xr = Xr - state->K[i];
        Xl = Xl ^ state->KP[i];

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

void zanderfishU_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    struct zanderU_state state;
    uint64_t xl;
    uint64_t xr;
    unsigned char crosskey[256];
    int blocks = msglen / zUblocklen;
    int c = 0;
    int i;
    zUgen_subkeys(&state, key, keylen, iv, ivlen, zrounds);
    zUgen_sbox(&state, key, keylen, &crosskey);
    zUgen_sboxB(&state, key, keylen, &crosskey);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1)) {
            for (int p = 0; p < extrabytes; p++) {
                msg[(msglen-1)-p] = (unsigned char *)extrabytes;
	    }
	}
	 
        xl = ((uint64_t)msg[c] << 56) + ((uint64_t)msg[c+1] << 48) + ((uint64_t)msg[c+2] << 40) + ((uint64_t)msg[c+3] << 32) + ((uint64_t)msg[c+4] << 24) + ((uint64_t)msg[c+5] << 16) + ((uint64_t)msg[c+6] << 8) + (uint64_t)msg[c+7];
        xr = ((uint64_t)msg[c+8] << 56) + ((uint64_t)msg[c+9] << 48) + ((uint64_t)msg[c+10] << 40) + ((uint64_t)msg[c+11] << 32) + ((uint64_t)msg[c+12] << 24) + ((uint64_t)msg[c+13] << 16) + ((uint64_t)msg[c+14] << 8) + (uint64_t)msg[c+15];
       
	xl = xl ^ state.last[0];
	xr = xr ^ state.last[1];

        zUblock_encrypt(&state, &xl, &xr);

	state.last[0] = xl;
	state.last[1] = xr;
        
        msg[c] = (xl & 0xFF00000000000000) >> 56;
        msg[c+1] = (xl & 0x00FF000000000000) >> 48;
        msg[c+2] = (xl & 0x0000FF0000000000) >> 40;
        msg[c+3] = (xl & 0x000000FF00000000) >> 32;
        msg[c+4] = (xl & 0x00000000FF000000) >> 24;
        msg[c+5] = (xl & 0x0000000000FF0000) >> 16;
        msg[c+6] = (xl & 0x000000000000FF00) >> 8;
        msg[c+7] = (xl & 0x00000000000000FF);
        msg[c+8] = (xr & 0xFF00000000000000) >> 56;
        msg[c+9] = (xr & 0x00FF000000000000) >> 48;
        msg[c+10] = (xr & 0x0000FF0000000000) >> 40;
        msg[c+11] = (xr & 0x000000FF00000000) >> 32;
        msg[c+12] = (xr & 0x00000000FF000000) >> 24;
        msg[c+13] = (xr & 0x0000000000FF0000) >> 16;
        msg[c+14] = (xr & 0x000000000000FF00) >> 8;
        msg[c+15] = (xr & 0x00000000000000FF);
        c += 16;
    }
}

int zanderfishU_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    struct zanderU_state state;
    int count = 0;
    uint64_t xl;
    uint64_t xr;
    unsigned char crosskey[256];
    int blocks = msglen / zUblocklen;
    int c = 0;
    int i;
    zUgen_subkeys(&state, key, keylen, iv, ivlen, zrounds);
    zUgen_sbox(&state, key, keylen, &crosskey);
    zUgen_sboxB(&state, key, keylen, &crosskey);
    for (i = 0; i < blocks; i++) {
        xl = ((uint64_t)msg[c] << 56) + ((uint64_t)msg[c+1] << 48) + ((uint64_t)msg[c+2] << 40) + ((uint64_t)msg[c+3] << 32) + ((uint64_t)msg[c+4] << 24) + ((uint64_t)msg[c+5] << 16) + ((uint64_t)msg[c+6] << 8) + (uint64_t)msg[c+7];
        xr = ((uint64_t)msg[c+8] << 56) + ((uint64_t)msg[c+9] << 48) + ((uint64_t)msg[c+10] << 40) + ((uint64_t)msg[c+11] << 32) + ((uint64_t)msg[c+12] << 24) + ((uint64_t)msg[c+13] << 16) + ((uint64_t)msg[c+14] << 8) + (uint64_t)msg[c+15];
        
	state.next[0] = xl;
	state.next[1] = xr;

        zUblock_decrypt(&state, &xl, &xr);
        
	xl = xl ^ state.last[0];
	xr = xr ^ state.last[1];
	state.last[0] = state.next[0];
	state.last[1] = state.next[1];
        
        msg[c] = (xl & 0xFF00000000000000) >> 56;
        msg[c+1] = (xl & 0x00FF000000000000) >> 48;
        msg[c+2] = (xl & 0x0000FF0000000000) >> 40;
        msg[c+3] = (xl & 0x000000FF00000000) >> 32;
        msg[c+4] = (xl & 0x00000000FF000000) >> 24;
        msg[c+5] = (xl & 0x0000000000FF0000) >> 16;
        msg[c+6] = (xl & 0x000000000000FF00) >> 8;
        msg[c+7] = (xl & 0x00000000000000FF);
        msg[c+8] = (xr & 0xFF00000000000000) >> 56;
        msg[c+9] = (xr & 0x00FF000000000000) >> 48;
        msg[c+10] = (xr & 0x0000FF0000000000) >> 40;
        msg[c+11] = (xr & 0x000000FF00000000) >> 32;
        msg[c+12] = (xr & 0x00000000FF000000) >> 24;
        msg[c+13] = (xr & 0x0000000000FF0000) >> 16;
        msg[c+14] = (xr & 0x000000000000FF00) >> 8;
        msg[c+15] = (xr & 0x00000000000000FF);
        c += 16;

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
