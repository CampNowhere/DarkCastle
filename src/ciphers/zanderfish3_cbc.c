#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int z3blocklen = 32;
int z3rounds = 80;

int t0 = 0x57bf953b78f054bc;
int t1 = 0x0a78a94e98868e69;
int t2 = 0xf40f3f55f937505f;
int t3 = 0x886d00acc1792c76;


struct zander3_state {
    uint64_t K[80][4];
    uint64_t D[4];
    uint64_t last[4];
    uint64_t next[4];
};

struct z3ksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t zander3_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zander3_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void *zander3_F(struct z3ksa_state *state) {
    int r;
    for (r = 0; r < 12; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = zander3_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = zander3_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = zander3_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = zander3_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = zander3_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];
    }
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void z3gen_subkeys(struct zander3_state * state, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int z3rounds) {
    struct z3ksa_state kstate;
    int c = 0;
    int i;
    int s;
    memset(state->K, 0, 80*(4*sizeof(uint64_t)));
    memset(&kstate.r, 0, 16*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));
    memset(state->last, 0, 4*sizeof(uint64_t));
    memset(state->next, 0, 4*sizeof(uint64_t));

    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] = ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    c = 0;
    for (i = 0; i < (ivlen / 8); i++) {
        state->last[i] = 0;
        state->last[i] = ((uint64_t)iv[c] << 56) + ((uint64_t)iv[c+1] << 48) + ((uint64_t)iv[c+2] << 40) + ((uint64_t)iv[c+3] << 32) + ((uint64_t)iv[c+4] << 24) + ((uint64_t)iv[c+5] << 16) + ((uint64_t)iv[c+6] << 8) + (uint64_t)iv[c+7];
	c += 8;
    }
    for (i = 0; i < z3rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_F(&kstate);
            state->K[i][s] = 0;
	    state->K[i][s] = kstate.o;
        }
    }
    for (s = 0; s < 4; s++) {
        zander3_F(&kstate);
        state->D[s] = 0;
        state->D[s] = kstate.o;
    }
}

uint64_t z3block_encrypt(struct zander3_state * state, uint64_t *xl, uint64_t *xr, uint64_t *xp, uint64_t *xq) {
    int i;
    uint64_t Xr, Xl, Xp, Xq;

    Xl = *xl;
    Xr = *xr;
    Xp = *xp;
    Xq = *xq;

    for (i = 0; i < z3rounds; i++) {
        Xr = Xr + state->K[i][0] + t0;
        Xl = Xl + state->K[i][1] + t1;
        Xp = Xp + state->K[i][2] + t2;
        Xq = Xq + state->K[i][3] + t3;

        Xr += Xl;
        Xl = zander3_rotl(Xl, 9);
        Xl = Xl ^ Xp;
        Xp += Xq;
        Xq = zander3_rotl(Xq, 13);
        Xq = Xq ^ Xr;
        Xq += Xp;
        Xp = zander3_rotl(Xp, 7);
        Xp = Xp ^ Xl;
        Xp += Xr;
        Xr = zander3_rotl(Xr, 3);
        Xr = Xr ^ Xq;

        Xr += Xp;
        Xl += Xq;
        Xp += Xr;
        Xq += Xl;
        
        

    }
    *xl = Xl + state->D[3];
    *xr = Xr + state->D[2];
    *xp = Xp + state->D[1]; 
    *xq = Xq + state->D[0];

}

uint64_t z3block_decrypt(struct zander3_state * state, uint64_t *xl, uint64_t *xr, uint64_t *xp, uint64_t *xq) {
    int i;
    uint64_t Xr, Xl, Xp, Xq;
    
    Xl = *xl;
    Xr = *xr;
    Xp = *xp;
    Xq = *xq;
    Xl -= state->D[3];
    Xr -= state->D[2];
    Xp -= state->D[1];
    Xq -= state->D[0];

    for (i = (z3rounds - 1); i != -1; i--) {
        Xq -= Xl;
        Xp -= Xr;
        Xl -= Xq;
        Xr -= Xp;

        Xr = Xr ^ Xq;
        Xr = zander3_rotr(Xr, 3);
        Xp -= Xr;
        Xp = Xp ^ Xl;
        Xp = zander3_rotr(Xp, 7);
        Xq -= Xp;
        Xq = Xq ^ Xr;
        Xq = zander3_rotr(Xq, 13);
        Xp -= Xq;
        Xl = Xl ^ Xp;
        Xl = zander3_rotr(Xl, 9);
        Xr -= Xl;

        Xq -= state->K[i][3] + t3;
        Xp -= state->K[i][2] + t2;
        Xl -= state->K[i][1] + t1;
        Xr -=  state->K[i][0] + t0;

    }
    *xl = Xl;
    *xr = Xr;
    *xp = Xp;
    *xq = Xq;
    
}

void zanderfish3_cbc_encrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen, int extrabytes) {
    struct zander3_state state;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocks = msglen / z3blocklen;
    int c = 0;
    int i;
    z3gen_subkeys(&state, key, keylen, iv, ivlen, z3rounds);
    for (i = 0; i < blocks; i++) {
	if (i == (blocks - 1)) {
            for (int p = 0; p < extrabytes; p++) {
                msg[(msglen-1)-p] = (unsigned char *)extrabytes;
	    }
	}
	 
        xl = ((uint64_t)msg[c] << 56) + ((uint64_t)msg[c+1] << 48) + ((uint64_t)msg[c+2] << 40) + ((uint64_t)msg[c+3] << 32) + ((uint64_t)msg[c+4] << 24) + ((uint64_t)msg[c+5] << 16) + ((uint64_t)msg[c+6] << 8) + (uint64_t)msg[c+7];
        xr = ((uint64_t)msg[c+8] << 56) + ((uint64_t)msg[c+9] << 48) + ((uint64_t)msg[c+10] << 40) + ((uint64_t)msg[c+11] << 32) + ((uint64_t)msg[c+12] << 24) + ((uint64_t)msg[c+13] << 16) + ((uint64_t)msg[c+14] << 8) + (uint64_t)msg[c+15];
        xp = ((uint64_t)msg[c+16] << 56) + ((uint64_t)msg[c+17] << 48) + ((uint64_t)msg[c+18] << 40) + ((uint64_t)msg[c+19] << 32) + ((uint64_t)msg[c+20] << 24) + ((uint64_t)msg[c+21] << 16) + ((uint64_t)msg[c+22] << 8) + (uint64_t)msg[c+23];
        xq = ((uint64_t)msg[c+24] << 56) + ((uint64_t)msg[c+25] << 48) + ((uint64_t)msg[c+26] << 40) + ((uint64_t)msg[c+27] << 32) + ((uint64_t)msg[c+28] << 24) + ((uint64_t)msg[c+29] << 16) + ((uint64_t)msg[c+30] << 8) + (uint64_t)msg[c+31];
       
	xl = xl ^ state.last[0];
	xr = xr ^ state.last[1];
	xp = xp ^ state.last[2];
	xq = xq ^ state.last[3];

        z3block_encrypt(&state, &xl, &xr, &xp, &xq);

	state.last[0] = xl;
	state.last[1] = xr;
	state.last[2] = xp;
	state.last[3] = xq;
        
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
        msg[c+16] = (xp & 0xFF00000000000000) >> 56;
        msg[c+17] = (xp & 0x00FF000000000000) >> 48;
        msg[c+18] = (xp & 0x0000FF0000000000) >> 40;
        msg[c+19] = (xp & 0x000000FF00000000) >> 32;
        msg[c+20] = (xp & 0x00000000FF000000) >> 24;
        msg[c+21] = (xp & 0x0000000000FF0000) >> 16;
        msg[c+22] = (xp & 0x000000000000FF00) >> 8;
        msg[c+23] = (xp & 0x00000000000000FF);
        msg[c+24] = (xq & 0xFF00000000000000) >> 56;
        msg[c+25] = (xq & 0x00FF000000000000) >> 48;
        msg[c+26] = (xq & 0x0000FF0000000000) >> 40;
        msg[c+27] = (xq & 0x000000FF00000000) >> 32;
        msg[c+28] = (xq & 0x00000000FF000000) >> 24;
        msg[c+29] = (xq & 0x0000000000FF0000) >> 16;
        msg[c+30] = (xq & 0x000000000000FF00) >> 8;
        msg[c+31] = (xq & 0x00000000000000FF);
        c += 32;
    }
}

int zanderfish3_cbc_decrypt(unsigned char * msg, int msglen, unsigned char * key, int keylen, unsigned char * iv, int ivlen) {
    struct zander3_state state;
    int count = 0;
    uint64_t xl;
    uint64_t xr;
    uint64_t xp;
    uint64_t xq;
    int blocks = msglen / z3blocklen;
    int c = 0;
    int i;
    z3gen_subkeys(&state, key, keylen, iv, ivlen, z3rounds);
    for (i = 0; i < blocks; i++) {
        xl = ((uint64_t)msg[c] << 56) + ((uint64_t)msg[c+1] << 48) + ((uint64_t)msg[c+2] << 40) + ((uint64_t)msg[c+3] << 32) + ((uint64_t)msg[c+4] << 24) + ((uint64_t)msg[c+5] << 16) + ((uint64_t)msg[c+6] << 8) + (uint64_t)msg[c+7];
        xr = ((uint64_t)msg[c+8] << 56) + ((uint64_t)msg[c+9] << 48) + ((uint64_t)msg[c+10] << 40) + ((uint64_t)msg[c+11] << 32) + ((uint64_t)msg[c+12] << 24) + ((uint64_t)msg[c+13] << 16) + ((uint64_t)msg[c+14] << 8) + (uint64_t)msg[c+15];
        xp = ((uint64_t)msg[c+16] << 56) + ((uint64_t)msg[c+17] << 48) + ((uint64_t)msg[c+18] << 40) + ((uint64_t)msg[c+19] << 32) + ((uint64_t)msg[c+20] << 24) + ((uint64_t)msg[c+21] << 16) + ((uint64_t)msg[c+22] << 8) + (uint64_t)msg[c+23];
        xq = ((uint64_t)msg[c+24] << 56) + ((uint64_t)msg[c+25] << 48) + ((uint64_t)msg[c+26] << 40) + ((uint64_t)msg[c+27] << 32) + ((uint64_t)msg[c+28] << 24) + ((uint64_t)msg[c+29] << 16) + ((uint64_t)msg[c+30] << 8) + (uint64_t)msg[c+31];
        
	state.next[0] = xl;
	state.next[1] = xr;
	state.next[2] = xp;
	state.next[3] = xq;

        z3block_decrypt(&state, &xl, &xr, &xp, &xq);
        
	xl = xl ^ state.last[0];
	xr = xr ^ state.last[1];
	xp = xp ^ state.last[2];
	xq = xq ^ state.last[3];
	state.last[0] = state.next[0];
	state.last[1] = state.next[1];
	state.last[2] = state.next[2];
	state.last[3] = state.next[3];
        
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
        msg[c+16] = (xp & 0xFF00000000000000) >> 56;
        msg[c+17] = (xp & 0x00FF000000000000) >> 48;
        msg[c+18] = (xp & 0x0000FF0000000000) >> 40;
        msg[c+19] = (xp & 0x000000FF00000000) >> 32;
        msg[c+20] = (xp & 0x00000000FF000000) >> 24;
        msg[c+21] = (xp & 0x0000000000FF0000) >> 16;
        msg[c+22] = (xp & 0x000000000000FF00) >> 8;
        msg[c+23] = (xp & 0x00000000000000FF);
        msg[c+24] = (xq & 0xFF00000000000000) >> 56;
        msg[c+25] = (xq & 0x00FF000000000000) >> 48;
        msg[c+26] = (xq & 0x0000FF0000000000) >> 40;
        msg[c+27] = (xq & 0x000000FF00000000) >> 32;
        msg[c+28] = (xq & 0x00000000FF000000) >> 24;
        msg[c+29] = (xq & 0x0000000000FF0000) >> 16;
        msg[c+30] = (xq & 0x000000000000FF00) >> 8;
        msg[c+31] = (xq & 0x00000000000000FF);
        c += 32;

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

