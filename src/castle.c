#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "castle_core.c"

void usage() {
    printf("DarkCastle v0.1 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\nDark      256 bit\nWrzeszcz  256 bit\nRedDye    128 bit\nBlueDye   256 bit\n\n");
    printf("Usage: dark <algorithm> <-e/-d> <input file> <output file> <password>\n\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "CastleCipherSui";
    int kdf_iterations = 10000;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int reddye_nonce_length = 8;
    int bluedye_nonce_length = 8;
    int dark_nonce_length = 16;
    int wrzeszcz_nonce_length = 8;

    int reddye_key_length = 16;
    int bluedye_key_length = 32;
    int dark_key_length = 32;
    int wrzeszcz_key_length = 32;

    int dark_mac_length = 32;
    int bluedye_mac_length = 32;
    int reddye_mac_length = 16;
    int wrzeszcz_mac_length = 32;

    if (argc != 6) {
        usage();
        exit(1);
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    unsigned char *password = argv[5];
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);

    if (strcmp(algorithm, "dark") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark_encrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "reddye") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            reddye_encrypt(infile_name, fsize, outfile_name, reddye_key_length, reddye_nonce_length, reddye_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            reddye_decrypt(infile_name, fsize, outfile_name, reddye_key_length, reddye_nonce_length, reddye_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "bluedye") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            bluedye_encrypt(infile_name, fsize, outfile_name, bluedye_key_length, bluedye_nonce_length, bluedye_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            bluedye_decrypt(infile_name, fsize, outfile_name, bluedye_key_length, bluedye_nonce_length, bluedye_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "wrzeszcz") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            wrzeszcz_encrypt(infile_name, fsize, outfile_name, wrzeszcz_key_length, wrzeszcz_nonce_length, wrzeszcz_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            wrzeszcz_decrypt(infile_name, fsize, outfile_name, wrzeszcz_key_length, wrzeszcz_nonce_length, wrzeszcz_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
}
