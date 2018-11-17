#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "castle_core.c"

void usage() {
    printf("DarkCastle v0.1.1 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\nzanderfish 256 bit\ndark       256 bit\ndark64     256 bit\nwrzeszcz   256 bit\nbluedye    256 bit\n\n");
    printf("Usage: castle <algorithm> <-e/-d> <input file> <output file> <password>\n\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "CastleCipherSui";
    int kdf_iterations = 10000;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish_nonce_length = 16;
    int bluedye_nonce_length = 8;
    int dark_nonce_length = 16;
    int dark64_nonce_length = 16;
    int wrzeszcz_nonce_length = 8;

    int zanderfish_key_length = 16;
    int bluedye_key_length = 32;
    int dark_key_length = 32;
    int dark64_key_length = 32;
    int wrzeszcz_key_length = 32;

    int dark_mac_length = 32;
    int dark64_mac_length = 32;
    int bluedye_mac_length = 32;
    int zanderfish_mac_length = 16;
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

    if (strcmp(algorithm, "dark64") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark64_encrypt(infile_name, fsize, outfile_name, dark64_key_length, dark64_nonce_length, dark64_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark64_decrypt(infile_name, fsize, outfile_name, dark64_key_length, dark64_nonce_length, dark64_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "dark") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            dark_encrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            dark_decrypt(infile_name, fsize, outfile_name, dark_key_length, dark_nonce_length, dark_mac_length, kdf_iterations, kdf_salt, password);
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
    else if (strcmp(algorithm, "zanderfish") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zandercbc_encrypt(infile_name, fsize, outfile_name, zanderfish_key_length, zanderfish_nonce_length, zanderfish_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zandercbc_decrypt(infile_name, fsize, outfile_name, zanderfish_key_length, zanderfish_nonce_length, zanderfish_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
}
