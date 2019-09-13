# IMPORTANT MESSAGE FROM CampNowhere

This is a respository full of terrible crypto code. It is only here for educational purposes, to illustrate the myriad of reasons that you should never try to roll your own crypto. Everything below the line is the original author's README and other than this message this code has not been altered from the point at which it was forked. 

In this repository you will find:

1. Bad C code
    * Tons of constants stored as ints instead of preprocessor macro values
    * Cipher state stored in global variables
    * Reading the entire file into memory before performing an operation on it
    * Incredibly long if/else blocks
    * Lots of unnecessary repetition
    * Poorly structured loops that could easily enter an infinite state
    * Poor coupling - the implementations of the block ciphers themselves take pointers to contiguous blocks of memory
    * Bizarre practices like reading one byte at a time from /dev/urandom to generate a password (This is actually in this code's sister repository, DarkPass)
2. Cryptographic algorithms that are a jumble of bad C code, with no formal description, that don't even pass a smell test for being secure
3. Unprovable statements
    * "This leaves no room for clues regarding the state."
    * "In order to calculate the round after it or before it, all 512 bits of the state is needed."
    * "Best attack vector is brute force."
    
---

# DarkCastle

*** Warning the ciphers contained in this program are still undergoing cryptanalysis

*** Warning: this product is for non-production use.  If you want production level crypto, use OpenSSL or libsodium

DarkCastle is an authenticated file encryption program aiming to provide a large collection of community ciphers.  This program is intended for educational use until full cryptanalysis can be completed.

Please note these are one-shot encryption functions and will encrypt what you can fit into memory.

DarkCastle is accepting ciphers.  Email pvial00@gmail.com or open a github issue to submit/integrate a cipher, hash function, KDF or authentication method.

Complimenting DarkCastle is DarkPass, a password generator designed to give secure passwords compatible with DarkCastle.

https://github.com/pvial00/DarkPass

*** Tested on MacOS, FreeBSD, Linux, Solaris, OpenBSD, NetBSD


# Algorithms and authenticators

Recommended ciphers are Amagus/ZanderFish2/Dark/Spock as they have been vetted more than the others

Fastest cipher is WildThing

Uvajda 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Uvajda

Amagus 256/512/1024 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Amagus

WildThing 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/WildThing

Dark 256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/DarkCipher

Zanderfish2 256 bit authenticated with Ganja 256 bit - 128 bit IV length

https://github.com/pvial00/Zanderfish2

Zanderfish3 256 bit authenticated with Ganja 256 bit - 256 bit IV length

https://github.com/pvial00/Zanderfish3

ZanderfishU 1024 bit authenticated with Ganja 256 bit - 128 bit IV length

https://github.com/pvial00/ZanderfishU

Wild 128 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/WildLFSR

Spock-CBC 128/256 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Spock

Specjal-CBC 256/512/1024 bit authenticated with Ganja 256 bit - 128 bit nonce length

https://github.com/pvial00/Specjal
