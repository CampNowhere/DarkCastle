#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dyefamily.c"
#include "darkcipher.c"
#include "h4a.c"
#include "ganja.c"

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
    reddye_random(&nonce, nonce_length);
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
        printf("Error: Message has been tampered.\n");
    }
}

void reddye_encrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) { 
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
    reddye_random(&nonce, nonce_length);
    fwrite(nonce, 1, nonce_length, outfile);
    fread(msg, 1, fsize, infile);
    reddye_crypt(msg, key, nonce, fsize, key_length, nonce_length);
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
    h4a_mac(msg, fsize, mac, mac_key, key_length);
    fwrite(mac, 1, mac_length, outfile);
    fwrite(msg, 1, fsize, outfile);
    fclose(outfile);
    free(msg);
}

void reddye_decrypt(char *infile_name, long fsize, char *outfile_name, int key_length, int nonce_length, int mac_length, int kdf_iterations, unsigned char * kdf_salt, unsigned char *password) {
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
    h4a_mac(msg, (fsize-mac_length), mac_verify, mac_key, key_length);
    free(msg);
    if (memcmp(mac, mac_verify, mac_length) == 0) {
        msg = (unsigned char *) malloc(fsize-mac_length-nonce_length);
        unsigned char *nonce[nonce_length];
        fseek(infile, mac_length, SEEK_SET);
        fread(nonce, 1, nonce_length, infile);
        fread(msg, 1, (fsize - mac_length - nonce_length), infile);
        fclose(infile);
        reddye_crypt(msg, key, nonce, (fsize - mac_length - nonce_length), key_length, nonce_length);
        outfile = fopen(outfile_name, "wb");
        fwrite(msg, 1, (fsize - mac_length - nonce_length), outfile);
        fclose(outfile);
        free(msg);
    }
    else {
        printf("Error: Message has been tampered.\n");
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
    reddye_random(&nonce, nonce_length);
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
        printf("Error: Message has been tampered.\n");
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
    reddye_random(&nonce, nonce_length);
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
        printf("Error: Message has been tampered.\n");
    }
}
