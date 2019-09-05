#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ciphers/dyefamily.c"
#include "ciphers/darkcipher.c"
#include "ciphers/ganja.c"
#include "ciphers/zanderfish_cbc.c"
#include "ciphers/zanderfish_ofb.c"
#include "ciphers/zanderfish2_cbc.c"
#include "ciphers/zanderfishC_cbc.c"
#include "ciphers/wild.c"
#include "ciphers/wildthing.c"
#include "ciphers/purple.c"
#include "ciphers/uvajda.c"
#include "ciphers/spock_cbc.c"
#include "ciphers/specjal_cbc.c"
#include "ciphers/amagus.c"
#include "kdf/manja.c"
#include "hmac/ghmac.c"
#include "crypto_funcs.c"

void dark_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    dark_crypt(msg, keyprime, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void dark_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        dark_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zandercbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    int extrabytes = 8 - (fsize % 8);
    if (extrabytes != 0) {
        fsize += extrabytes;
    }
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, (fsize-extrabytes), infile);
    zanderfish_cbc_encrypt(msg, fsize, keyprime, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zandercbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length), infile);
        fclose(infile);
        int pad = zanderfish_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length),keyprime, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zanderofb_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, (fsize), infile);
    zanderfish_ofb_encrypt(msg, fsize, key, key_length, iv, iv_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zanderofb_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length), infile);
        fclose(infile);
        zanderfish_ofb_encrypt(msg, (fsize - mac_length - iv_length - key_length),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void bluedye_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    bluedye_crypt(msg, key, nonce, fsize, key_length, nonce_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void bluedye_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        bluedye_crypt(msg, key, nonce, (fsize - mac_length - nonce_length - key_length), key_length, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void wrzeszcz_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    wrzeszcz_crypt(msg, keyprime, nonce, fsize, key_length, nonce_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void wrzeszcz_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        wrzeszcz_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length), key_length, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
 }

void wild_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    wild_crypt(msg, key, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void wild_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        wild_crypt(msg, key, nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void ganja_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    ganja_crypt(msg, keyprime, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void ganja_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        ganja_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void purple_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    purple_crypt(msg, key, nonce, fsize, key_length, nonce_length);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void purple_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    int x;
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        purple_crypt(msg, key, nonce, (fsize - mac_length - nonce_length - key_length), key_length, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void uvajda_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    uvajda_crypt(msg, keyprime, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void uvajda_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length), infile);
        fclose(infile);
        uvajda_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void wildthing_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    wildthing_crypt(msg, keyprime, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void wildthing_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    unsigned char *keyprime[key_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);

        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length - key_length), infile);
        fclose(infile);
        wildthing_crypt(msg, keyprime, nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void spockcbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    int extrabytes = 16 - (fsize % 16);
    FILE *infile, *outfile;
    unsigned char *msg;
    int modfsize = (fsize + extrabytes);
    msg = (unsigned char *) malloc(modfsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_128_encrypt(keyprime, key_length, key, K);
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    spock_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, (fsize + extrabytes), outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void spockcbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_128_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - iv_length), infile);
        fclose(infile);
        int pad = spock_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void amagus_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    amagus_crypt(msg, keyprime, key_length, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void amagus_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length), infile);
        fclose(infile);
        amagus_crypt(msg, keyprime, key_length,  nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void amagus512_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_512_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    amagus_crypt(msg, keyprime, key_length, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void amagus512_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_512_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length), infile);
        fclose(infile);
        amagus_crypt(msg, keyprime, key_length,  nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void amagus1024_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_1024_encrypt(keyprime, key_length, key, K);
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    amagus_crypt(msg, keyprime, key_length, nonce, fsize);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void amagus1024_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length-key_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_1024_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - nonce_length-key_length), infile);
        fclose(infile);
        amagus_crypt(msg, keyprime, key_length,  nonce, (fsize - mac_length - nonce_length - key_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length - key_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void specjalcbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    int extrabytes = 32 - (fsize % 32);
    FILE *infile, *outfile;
    unsigned char *msg;
    int modfsize = (fsize + extrabytes);
    msg = (unsigned char *) malloc(modfsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_128_encrypt(keyprime, key_length, key, K);
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, fsize, infile);
    specjal_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, (fsize + extrabytes), outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void specjalcbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_128_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - iv_length), infile);
        fclose(infile);
        int pad = specjal_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zander2cbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    int extrabytes = 16 - (fsize % 16);
    if (extrabytes != 0) {
        fsize += extrabytes;
    }
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, (fsize-extrabytes), infile);
    zanderfish2_cbc_encrypt(msg, fsize, keyprime, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zander2cbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length), infile);
        fclose(infile);
        int pad = zanderfish2_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length),keyprime, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zanderCcbc_encrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    unsigned char *keyprime[key_length];
    unsigned char *K[key_length];
    int extrabytes = 16 - (fsize % 16);
    if (extrabytes != 0) {
        fsize += extrabytes;
    }
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    key_wrap_256_encrypt(keyprime, key_length, key, K);
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fwrite(K, 1, key_length, outfile);
    fread(msg, 1, (fsize-extrabytes), infile);
    zanderfishC_cbc_encrypt(msg, fsize, keyprime, key_length, iv, iv_length, extrabytes);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    fclose(infile);
    free(msg);

    outfile = fopen(outfile_name, "rb");
    fseek(outfile, 0, SEEK_END);
    fsize = ftell(outfile);
    fseek(outfile, 0, SEEK_SET);
    msg = (unsigned char *) malloc(fsize);
    fread(msg, 1, fsize, outfile);
    fclose(outfile);
    outfile = fopen(outfile_name, "wb");
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    ganja_hmac(msg, fsize, &mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zanderCcbc_decrypt(char *infile_name, long long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char mac[mac_length];
    unsigned char mac_key[key_length];
    unsigned char key[key_length];
    unsigned char *keyprime[key_length];
    unsigned char *msg;
    unsigned char mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    manja_kdf(password, strlen(password), key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    manja_kdf(key, key_length, mac_key, key_length, kdf_salt, strlen(kdf_salt), kdf_iterations);
    fread(&mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), &mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length-key_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(keyprime, 1, key_length, infile);
        key_wrap_256_decrypt(keyprime, key_length, key);
        fread(msg, 1, (fsize - mac_length - iv_length - key_length), infile);
        fclose(infile);
        int pad = zanderfishC_cbc_decrypt(msg, (fsize - mac_length - iv_length - key_length),keyprime, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length - key_length - pad), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
