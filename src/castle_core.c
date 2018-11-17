#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dyefamily.c"
#include "darkcipher.c"
#include "dark64.c"
#include "ganja.c"
#include "zanderfish_cbc.c"

void dark_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    dark_crypt(msg, key, nonce, fsize);
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
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void dark_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        dark_crypt(msg, key, nonce, (fsize - mac_length - nonce_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void zandercbc_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char iv[iv_length];
    wrzeszcz_random(&iv, iv_length);
    fwrite(iv, 1, iv_length, outfile);
    fread(msg, 1, fsize, infile);
    zanderfish_cbc_encrypt(msg, fsize, key, key_length, iv, iv_length);
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
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void zandercbc_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int iv_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-iv_length);
        unsigned char *iv[iv_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(iv, 1, iv_length, infile);
        fread(msg, 1, (fsize - mac_length - iv_length), infile);
        fclose(infile);
        zanderfish_cbc_decrypt(msg, (fsize - mac_length - iv_length),key, key_length, iv, iv_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - iv_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void dark64_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    dark64_crypt(msg, key, nonce, fsize);
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
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void dark64_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        dark64_crypt(msg, key, nonce, (fsize - mac_length - nonce_length));
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void bluedye_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
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
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void bluedye_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        bluedye_crypt(msg, key, nonce, (fsize - mac_length - nonce_length), key_length, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}

void wrzeszcz_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
    FILE *infile, *outfile;
    unsigned char *msg;
    msg = (unsigned char *) malloc(fsize);
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    infile = fopen(infile_name, "rb");
    outfile = fopen(outfile_name, "wb");
    unsigned char nonce[nonce_length];
    wrzeszcz_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    wrzeszcz_crypt(msg, key, nonce, fsize, key_length, nonce_length);
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
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    ganja_hmac(msg, fsize, mac, mac_key, key_length, kdf_salt);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void wrzeszcz_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
    FILE *infile, *outfile;
    unsigned char *mac[mac_length];
    unsigned char *mac_key[key_length];
    unsigned char *key[key_length];
    unsigned char *msg;
    unsigned char *mac_verify[mac_length];
    infile = fopen(infile_name, "rb");
    msg = (unsigned char *) malloc(fsize-mac_length);
    ganja_kdf(password, strlen(password), key, kdf_iterations, key_length, kdf_salt);
    ganja_kdf(key, key_length, mac_key, kdf_iterations, key_length, kdf_salt);
    fread(mac, 1, mac_length, infile);
    fread(msg, 1, (fsize-mac_length), infile);
    ganja_hmac(msg, (fsize-mac_length), mac_verify, mac_key, key_length, kdf_salt);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        wrzeszcz_crypt(msg, key, nonce, (fsize - mac_length - nonce_length), key_length, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered with.\n");
    }
}
