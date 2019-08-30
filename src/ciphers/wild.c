#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct wild_state {
    uint32_t lfsr[4];
    uint32_t r[4];
    uint32_t j;
};

uint32_t uregister1(uint32_t r) {
    return ((r << 4) ^ (r << 3) ^ (r >> 4) ^ (r >> 3));
}

uint32_t uregister2(uint32_t r) {
    return ((r << 3) ^ (r << 2) ^ (r >> 4) ^ (r >> 1));
}

uint32_t uregister3(uint32_t r) {
    return((r << 1) ^ (r << 2) ^ (r >> 3) ^ (r >> 1));
}

uint32_t uregister4(uint32_t r) {
    return((r << 2) ^ (r << 5) ^ (r >> 4) ^ (r >> 2));
}

uint32_t getregister_output(struct wild_state *state) {
    return (state->lfsr[0] ^ state->lfsr[1] ^ state->lfsr[2] ^ state->lfsr[3] ^ state->j ^ state->r[0] ^ state->r[1] ^ state->r[2] ^ state->r[3]);
}

uint32_t w_sumup(struct wild_state *state) {
    return ((state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + state->r[0] + state->r[1] + state->r[2] + state->r[3]) & 0xFFFFFFFF);
}

void wild_ksa(struct wild_state *state, unsigned char * key, unsigned char * iv) {
    uint32_t IV[2];
    state->lfsr[0] = (key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3];
    state->lfsr[1] = (key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7];
    state->lfsr[2] = (key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11];
    state->lfsr[3] = (key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15];

    IV[0] = (iv[0] << 24) + (iv[1] << 16) + (iv[2] << 8) + iv[3];
    IV[1] = (iv[4] << 24) + (iv[5] << 16) + (iv[6] << 8) + iv[7];

    state->lfsr[2] ^= IV[0];
    state->lfsr[3] ^= IV[1];

    for (int i = 0; i < 4; i++) {
        state->r[i] = 0;
        state->r[i] = state->r[i] ^ state->lfsr[i];
    }
    
    uint32_t temp = 0x00000001;
    temp = (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + temp) & 0xFFFFFFFF;
    for (int r = 0; r < 128; r++) {
        for (int i = 0; i < 4; i++) {
            temp = (state->lfsr[0] + state->lfsr[1] + state->lfsr[2] + state->lfsr[3] + temp) & 0xFFFFFFFF;
            state->lfsr[i] = temp;
        }
    }

    state->j = 0;
    for (int i = 0; i < 4; i++) {
        state->j = (state->j + state->lfsr[i]) & 0xFFFFFFFF;
    }
}

unsigned char * wild_crypt(unsigned char * msg, unsigned char * key, unsigned char * iv, int msglen) {
    struct wild_state state;
    uint8_t k[4];
    uint32_t lfsr_out;
    int v = 4;
    int blocks = msglen / 4;
    int msglen_extra = msglen % 4;
    int extra = 0;
    int c = 0;
    if (msglen_extra != 0) {
        extra = 1; }
    wild_ksa(&state, key, iv);
    for (int i = 0; i < (blocks + extra); i++) {
        state.lfsr[0] = uregister1(state.lfsr[0]) ^ state.r[3];
        state.lfsr[1] = uregister2(state.lfsr[1]) ^ state.r[2];
        state.lfsr[2] = uregister3(state.lfsr[2]) ^ state.r[1];
        state.lfsr[3] = uregister4(state.lfsr[3]) ^ state.lfsr[3];
        state.r[3] = uregister1(state.r[3]) ^ state.lfsr[0];
        state.r[2] = uregister2(state.r[2]) ^ state.lfsr[1];
        state.r[0] = uregister3(state.r[0]) ^ state.lfsr[2];
        state.r[1] = uregister4(state.r[1]) ^ state.r[0];
        state.j = (state.j + w_sumup(&state)) & 0xFFFFFFFF;
        lfsr_out = getregister_output(&state);
        k[0] = (lfsr_out & 0x000000FF);
        k[1] = (lfsr_out & 0x0000FF00) >> 8;
        k[2] = (lfsr_out & 0x00FF0000) >> 16;
        k[3] = (lfsr_out & 0xFF000000) >> 24;
        if (i == (blocks) && (msglen_extra != 0)) {
            v = msglen_extra; }
        for (int x = 0; x < v; x++) {
            msg[c] = msg[c] ^ k[x];
            c += 1;
       	}
    }
}
