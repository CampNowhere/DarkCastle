#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void * key_wrap_1024_encrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * K) {
    wrzeszcz_random(keyprime, key_length);
    memcpy(K, keyprime, key_length);
    amagus_crypt(K, key, keylen, key, key_length);
    for (int i = 0; i < key_length; i++) {
        K[i] = K[i] ^ key[i];
    }
}

void * key_wrap_1024_decrypt(unsigned char * keyprime, int key_length, unsigned char * key) {
    for (int i = 0; i < key_length; i++) {
        keyprime[i] = keyprime[i] ^ key[i];
    }
    amagus_crypt(keyprime, key, keylen, key, key_length);
}

void * key_wrap_512_encrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * K) {
    wrzeszcz_random(keyprime, key_length);
    memcpy(K, keyprime, key_length);
    amagus_crypt(K, key, keylen, key, key_length);
    for (int i = 0; i < key_length; i++) {
        K[i] = K[i] ^ key[i];
    }
}

void * key_wrap_512_decrypt(unsigned char * keyprime, int key_length, unsigned char * key) {
    for (int i = 0; i < key_length; i++) {
        keyprime[i] = keyprime[i] ^ key[i];
    }
    amagus_crypt(keyprime, key, keylen, key, key_length);
}

void * key_wrap_256_encrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * K) {
    wrzeszcz_random(keyprime, key_length);
    memcpy(K, keyprime, key_length);
    uvajda_crypt(K, key, key, key_length);
    for (int i = 0; i < key_length; i++) {
        K[i] = K[i] ^ key[i];
    }
}

void * key_wrap_256_decrypt(unsigned char * keyprime, int key_length, unsigned char * key) {
    for (int i = 0; i < key_length; i++) {
        keyprime[i] = keyprime[i] ^ key[i];
    }
    uvajda_crypt(keyprime, key, key, key_length);
}

void * key_wrap_128_encrypt(unsigned char * keyprime, int key_length, unsigned char * key, unsigned char * K) {
    wrzeszcz_random(keyprime, key_length);
    memcpy(K, keyprime, key_length);
    wild_crypt(K, key, key, key_length);
    for (int i = 0; i < key_length; i++) {
        K[i] = K[i] ^ key[i];
    }
}

void * key_wrap_128_decrypt(unsigned char * keyprime, int key_length, unsigned char * key) {
    for (int i = 0; i < key_length; i++) {
        keyprime[i] = keyprime[i] ^ key[i];
    }
    wild_crypt(keyprime, key, key, key_length);
}
