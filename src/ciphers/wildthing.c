#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct wildthing_state {
    uint64_t lfsr[5];
};

uint64_t wt_rotateleft64(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t wregister1(uint64_t r) {
    return ((r << 11) ^ (r << 12) ^ (r >> 6) ^ (r >> 3));
}

uint64_t wregister2(uint64_t r) {
    return ((r << 9) ^ (r << 13) ^ (r >> 5) ^ (r >> 1));
}

uint64_t wregister3(uint64_t r) {
    return((r << 1) ^ (r << 2) ^ (r >> 3) ^ (r >> 1));
}

uint64_t wregister4(uint64_t r) {
    return((r << 14) ^ (r << 16) ^ (r >> 7) ^ (r >> 2));
}

uint64_t wt_sumup(struct wildthing_state *state) {
    return (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3]);
}

uint64_t rotateall(struct wildthing_state *state) {
    wt_rotateleft64(state->lfsr[0], 2);
    wt_rotateleft64(state->lfsr[1], 7);
    wt_rotateleft64(state->lfsr[2], 9);
    wt_rotateleft64(state->lfsr[3], 12);
    wt_rotateleft64(state->lfsr[4], 5);
}


uint64_t wt_getregister_output(struct wildthing_state *state) {
    return (state->lfsr[0] ^ state->lfsr[1] ^ state->lfsr[2] ^ state->lfsr[3] ^ state->lfsr[4]);
}

void wildthing_ksa(struct wildthing_state *state, unsigned char * key, unsigned char * iv) {
    uint64_t IV[2];
    int i;
    int m = 0;
    int inc = 8;
    for (i = 0; i < 4; i++) {
        state->lfsr[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }
 
    state->lfsr[4] = state->lfsr[0];
    for (i = 1; i < 4; i++) {
        state->lfsr[4] = state->lfsr[4] + state->lfsr[i];
    }

    IV[0] = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    IV[1] = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];

    state->lfsr[2] ^= IV[0];
    state->lfsr[3] ^= IV[1];
    
    uint64_t temp = 0x00000001;
    temp = (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + temp);
    for (int i = 0; i < 4; i++) {
        temp = (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + temp);
        state->lfsr[i] = temp;
    }
    for (i = 1; i < 4; i++) {
        state->lfsr[4] = state->lfsr[4] + state->lfsr[i];
    }
    rotateall(state);
}

unsigned char * wildthing_crypt(unsigned char * msg, unsigned char * key, unsigned char * iv, int msglen) {
    struct wildthing_state state;
    uint8_t k[8];
    uint64_t lfsr_out;
    int v = 8;
    int blocks = msglen / 8;
    int msglen_extra = msglen % 8;
    int extra = 0;
    int c = 0;
    if (msglen_extra != 0) {
        extra = 1; }
    wildthing_ksa(&state, key, iv);
    for (int i = 0; i < (blocks + extra); i++) {
        state.lfsr[0] = wregister1(state.lfsr[0]);
        state.lfsr[1] = wregister2(state.lfsr[1]);
        state.lfsr[2] = wregister3(state.lfsr[2]);
        state.lfsr[3] = wregister4(state.lfsr[3]);
        state.lfsr[4] = state.lfsr[4] + wt_sumup(&state);
        rotateall(&state);
        lfsr_out = wt_getregister_output(&state);
        k[0] = (lfsr_out & 0x00000000000000FF);
        k[1] = (lfsr_out & 0x000000000000FF00) >> 8;
        k[2] = (lfsr_out & 0x0000000000FF0000) >> 16;
        k[3] = (lfsr_out & 0x00000000FF000000) >> 24;
        k[4] = (lfsr_out & 0x000000FF00000000) >> 32;
        k[5] = (lfsr_out & 0x0000FF0000000000) >> 40;
        k[6] = (lfsr_out & 0x00FF000000000000) >> 48;
        k[7] = (lfsr_out & 0xFF00000000000000) >> 56;
        if (i == (blocks) && (msglen_extra != 0)) {
            v = msglen_extra; }
        for (int x = 0; x < v; x++) {
            msg[c] = msg[c] ^ k[x];
            c += 1;
       	}
    }
}
