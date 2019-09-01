#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "castle_core.c"

void usage() {
    printf("DarkCastle v0.3.1 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\n\nzanderfish-ofb 256 bit\nzanderfish-cbc 256 bit\ndark           256 bit\nwrzeszcz       256 bit\nbluedye        256 bit\nwild           128 bit\nganja          256 bit\npurple         256 bit\nuvajda         256 bit\nwildthing      256 bit\nspock-cbc      128 bit\namagus         256 bit\n\n");
    printf("Usage: castle <algorithm> <-e/-d> <input file> <output file> <password>\n\n");
}

int main(int argc, char *argv[]) {
    unsigned char kdf_salt[] = "CastleCipherSui";
    int kdf_iterations = 10000;
    int max_password_len = 256;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish_nonce_length = 8;
    int bluedye_nonce_length = 8;
    int dark_nonce_length = 16;
    int wrzeszcz_nonce_length = 8;
    int wild_nonce_length = 8;
    int wildthing_nonce_length = 16;
    int ganja_nonce_length = 16;
    int purple_nonce_length = 16;
    int uvajda_nonce_length = 16;
    int spock_nonce_length = 16;
    int amagus_nonce_length = 16;

    int zanderfish_key_length = 32;
    int bluedye_key_length = 32;
    int dark_key_length = 32;
    int wrzeszcz_key_length = 32;
    int wild_key_length = 16;
    int wildthing_key_length = 32;
    int ganja_key_length = 32;
    int purple_key_length = 32;
    int uvajda_key_length = 32;
    int spock_key_length = 16;
    int amagus_key_length = 32;

    int dark_mac_length = 32;
    int bluedye_mac_length = 32;
    int zanderfish_mac_length = 32;
    int wrzeszcz_mac_length = 32;
    int wild_mac_length = 32;
    int wildthing_mac_length = 32;
    int ganja_mac_length = 32;
    int purple_mac_length = 32;
    int uvajda_mac_length = 32;
    int spock_mac_length = 32;
    int amagus_mac_length = 32;

    if (argc != 6) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    unsigned char *password = argv[5];
    if (strlen(password) > max_password_len) {
        printf("Max password limit %d bytes has been exceeded.\n", max_password_len);
        exit(1);
    }
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
    else if (strcmp(algorithm, "zanderfish-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zandercbc_encrypt(infile_name, fsize, outfile_name, zanderfish_key_length, zanderfish_nonce_length, zanderfish_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zandercbc_decrypt(infile_name, fsize, outfile_name, zanderfish_key_length, zanderfish_nonce_length, zanderfish_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "zanderfish-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zanderofb_encrypt(infile_name, fsize, outfile_name, zanderfish_key_length, zanderfish_nonce_length, zanderfish_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zanderofb_decrypt(infile_name, fsize, outfile_name, zanderfish_key_length, zanderfish_nonce_length, zanderfish_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "wild") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            wild_encrypt(infile_name, fsize, outfile_name, wild_key_length, wild_nonce_length, wild_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            wild_decrypt(infile_name, fsize, outfile_name, wild_key_length, wild_nonce_length, wild_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "ganja") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            ganja_encrypt(infile_name, fsize, outfile_name, ganja_key_length, ganja_nonce_length, ganja_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            ganja_decrypt(infile_name, fsize, outfile_name, ganja_key_length, ganja_nonce_length, ganja_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "purple") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            purple_encrypt(infile_name, fsize, outfile_name, purple_key_length, purple_nonce_length, purple_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            purple_decrypt(infile_name, fsize, outfile_name, purple_key_length, purple_nonce_length, purple_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "uvajda") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            uvajda_encrypt(infile_name, fsize, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            uvajda_decrypt(infile_name, fsize, outfile_name, uvajda_key_length, uvajda_nonce_length, uvajda_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "wildthing") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            wildthing_encrypt(infile_name, fsize, outfile_name, wildthing_key_length, wildthing_nonce_length, wildthing_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            wildthing_decrypt(infile_name, fsize, outfile_name, wildthing_key_length, wildthing_nonce_length, wildthing_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "spock-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            spockcbc_encrypt(infile_name, fsize, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            spockcbc_decrypt(infile_name, fsize, outfile_name, spock_key_length, spock_nonce_length, spock_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    else if (strcmp(algorithm, "amagus") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            amagus_encrypt(infile_name, fsize, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            amagus_decrypt(infile_name, fsize, outfile_name, amagus_key_length, amagus_nonce_length, amagus_mac_length, kdf_iterations, kdf_salt, password);
        }
    }
    return 0;
}
