/*
 * CSE451 Computer & Network Security - Assignment 1: DES (ECB mode)
 *
 * Team members:
 *   Name                            ID
 *   Youssef Ahmed Mohammed Refaat   2200405
 *   Mohammed Hamada Hassan          2200820
 *   Amr Ashraf Hussien              2201048
 *   Mohammed Walid                  2200243
 *   Ahmed Mahmoud Elmorsy           2200725
 *
 * Build : gcc -O3 2200405.c -o 2200405
 * Usage : 2200405 e key plaintext  ciphertext
 *         2200405 d key ciphertext plaintext
 *
 * Message files: raw binary bytes only. Each 8 bytes forms one DES block.
 * Key file: 8 raw bytes, OR exactly 16 hexadecimal digits (whitespace allowed).
 * No padding is performed; input sizes must be divisible by 8 bytes.
 * Data is streamed in 64 KiB chunks, so large files do not require large RAM.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

/* --- DES Tables --- */

static const unsigned char IP[64] = {
58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7
};

static const unsigned char FP[64] = {
40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25
};

/* Expansion table. Not used directly at run time (the expansion is done with
   rotations in feistel()) but kept as the reference definition. */
static const unsigned char E[48] = {
32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
 8, 9,10,11,12,13, 12,13,14,15,16,17,
16,17,18,19,20,21, 20,21,22,23,24,25,
24,25,26,27,28,29, 28,29,30,31,32, 1
};

static const unsigned char P[32] = {
16, 7,20,21,29,12,28,17,
 1,15,23,26, 5,18,31,10,
 2, 8,24,14,32,27, 3, 9,
19,13,30, 6,22,11, 4,25
};

static const unsigned char PC1[56] = {
57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4
};

static const unsigned char PC2[48] = {
14,17,11,24, 1, 5,  3,28,15, 6,21,10,
23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
41,52,31,37,47,55, 30,40,51,45,33,48,
44,49,39,56,34,53, 46,42,50,36,29,32
};

static const unsigned char SHIFTS[16] = {
1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

static const unsigned char SBOX[8][64] = {
    {
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    },
    {
    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    },
    {
    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    },
    {
    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    },
    {
    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    },
    {
    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    },
    {
    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    },
    {
    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    }
};

/* --- Pre-computed tables (built once at start-up) --- */
static uint64_t IPT[8][256];   /* initial permutation, one lookup per input byte */
static uint64_t FPT[8][256];   /* final permutation,   one lookup per input byte */
static uint32_t SP[8][64];     /* S-box output already passed through P          */
static uint64_t SUBKEY[16];    /* the 16 round keys (48 bits each)               */

/* Generic bit permutation: bit numbering follows the DES standard
   (bit 1 = most significant bit of an 'inbits'-wide value). */
static uint64_t permute(uint64_t x, const unsigned char *tbl, int n, int inbits)
{
    uint64_t y = 0;
    for (int i = 0; i < n; i++)
        y = (y << 1) | ((x >> (inbits - tbl[i])) & 1ULL);
    return y;
}

static void init_tables(void)
{
    /* The E table documents the DES expansion, implemented as rotations below. */
    (void)E[0];
    for (int b = 0; b < 8; b++) {
        for (int v = 0; v < 256; v++) {
            uint64_t x = (uint64_t)v << (56 - 8 * b);
            IPT[b][v] = permute(x, IP, 64, 64);
            FPT[b][v] = permute(x, FP, 64, 64);
        }
    }
    for (int i = 0; i < 8; i++) {
        for (int v = 0; v < 64; v++) {
            int row = ((v & 0x20) >> 4) | (v & 1);
            int col = (v >> 1) & 0x0F;
            uint64_t s = (uint64_t)SBOX[i][row * 16 + col] << (28 - 4 * i);
            SP[i][v] = (uint32_t)permute(s << 32, P, 32, 64);
        }
    }
}

/* Key schedule: PC-1, rotate C/D, PC-2 -> 16 sub-keys (computed once). */
static void key_schedule(uint64_t key)
{
    const uint32_t M = 0x0FFFFFFF;
    uint64_t k56 = permute(key, PC1, 56, 64);
    uint32_t C = (uint32_t)(k56 >> 28) & M;
    uint32_t D = (uint32_t)k56 & M;
    for (int r = 0; r < 16; r++) {
        int s = SHIFTS[r];
        C = ((C << s) | (C >> (28 - s))) & M;
        D = ((D << s) | (D >> (28 - s))) & M;
        uint64_t cd = ((uint64_t)C << 28) | D;
        SUBKEY[r] = permute(cd << 8, PC2, 48, 64);
    }
}

static uint64_t apply8(uint64_t t[8][256], uint64_t x)
{
    return t[0][x >> 56] ^ t[1][(x >> 48) & 0xFF] ^ t[2][(x >> 40) & 0xFF] ^
           t[3][(x >> 32) & 0xFF] ^ t[4][(x >> 24) & 0xFF] ^ t[5][(x >> 16) & 0xFF] ^
           t[6][(x >> 8) & 0xFF]  ^ t[7][x & 0xFF];
}

/* f-function: expansion E, XOR with sub-key, S-boxes + P (via SP tables). */
static uint32_t feistel(uint32_t R, uint64_t k)
{
    uint32_t a = (R >> 1) | (R << 31);   /* ROTR 1: groups 0..6 of E(R) */
    uint32_t b = (R << 1) | (R >> 31);   /* ROTL 1: group 7 of E(R)     */
    return SP[0][((a >> 26) & 0x3F) ^ ((k >> 42) & 0x3F)] |
           SP[1][((a >> 22) & 0x3F) ^ ((k >> 36) & 0x3F)] |
           SP[2][((a >> 18) & 0x3F) ^ ((k >> 30) & 0x3F)] |
           SP[3][((a >> 14) & 0x3F) ^ ((k >> 24) & 0x3F)] |
           SP[4][((a >> 10) & 0x3F) ^ ((k >> 18) & 0x3F)] |
           SP[5][((a >>  6) & 0x3F) ^ ((k >> 12) & 0x3F)] |
           SP[6][((a >>  2) & 0x3F) ^ ((k >>  6) & 0x3F)] |
           SP[7][( b        & 0x3F) ^ ( k        & 0x3F)];
}

/* One 64-bit block. Decryption = same network with the sub-keys reversed. */
static uint64_t des_block(uint64_t in, int decrypt)
{
    uint64_t ip = apply8(IPT, in);
    uint32_t L = (uint32_t)(ip >> 32), R = (uint32_t)ip;
    for (int r = 0; r < 16; r++) {
        uint32_t t = R;
        R = L ^ feistel(R, SUBKEY[decrypt ? 15 - r : r]);
        L = t;
    }
    return apply8(FPT, ((uint64_t)R << 32) | L);   /* swap halves, then FP */
}


/* --- Binary input/output and key handling --- */

/* Match either 8 raw key bytes, or 16 hex digits with optional whitespace.
   Plaintext and ciphertext files are NEVER auto-detected as hex. */
static int read_key(const char *path, uint64_t *key_out)
{
    unsigned char raw[128];
    unsigned char kbytes[8];
    size_t n, i;
    unsigned int digits = 0;
    int high = -1;
    FILE *fp = fopen(path, "rb");

    if (!fp) { perror("open key"); return 0; }
    n = fread(raw, 1, sizeof raw, fp);
    if (ferror(fp)) {
        perror("read key");
        fclose(fp);
        return 0;
    }
    {
        int close_failed = (fclose(fp) != 0);
        if (n == sizeof raw || close_failed) {
            fprintf(stderr, "Invalid or unreadable key file: expected 8 raw bytes or 16 hex digits.\n");
            return 0;
        }
    }

    if (n == 8) {
        for (i = 0; i < 8; ++i) kbytes[i] = raw[i];
    } else {
        /* Text-hex mode applies to keys only, never message data. */
        memset(kbytes, 0, sizeof kbytes);
        for (i = 0; i < n; ++i) {
            int ch = raw[i];
            int v;
            if (isspace((unsigned char)ch)) continue;
            if (ch >= '0' && ch <= '9') v = ch - '0';
            else if (ch >= 'a' && ch <= 'f') v = 10 + ch - 'a';
            else if (ch >= 'A' && ch <= 'F') v = 10 + ch - 'A';
            else { fprintf(stderr, "Invalid hexadecimal key character.\n"); return 0; }
            if (digits >= 16) { fprintf(stderr, "Key has more than 16 hex digits.\n"); return 0; }
            if (high < 0) high = v;
            else {
                kbytes[digits / 2] = (unsigned char)((high << 4) | v);
                high = -1;
            }
            ++digits;
        }
        if (digits != 16) {
            fprintf(stderr, "Key must be exactly 8 raw bytes or 16 hex digits.\n");
            return 0;
        }
    }

    *key_out = 0;
    for (i = 0; i < 8; ++i) *key_out = (*key_out << 8) | kbytes[i];
    return 1;
}

static uint64_t load64(const unsigned char *p)
{
    uint64_t x = 0;
    int i;
    for (i = 0; i < 8; ++i) x = (x << 8) | p[i];
    return x;
}

static void store64(unsigned char *p, uint64_t x)
{
    int i;
    for (i = 7; i >= 0; --i) {
        p[i] = (unsigned char)(x & 255U);
        x >>= 8;
    }
}

int main(int argc, char **argv)
{
    uint64_t key;
    int decrypt;
    FILE *in = NULL, *out = NULL;
    /* Multiple of DES block size for efficient streaming. */
    unsigned char buffer[64 * 1024];
    size_t n, i;
    int ok = 1;

    if (argc != 5 || strlen(argv[1]) != 1 ||
        (argv[1][0] != 'e' && argv[1][0] != 'd')) {
        fprintf(stderr,
            "Usage:\n  %s e keyfile plaintextfile ciphertextfile\n"
            "  %s d keyfile ciphertextfile plaintextfile\n",
            argv[0], argv[0]);
        return 1;
    }
    decrypt = (argv[1][0] == 'd');

    if (strcmp(argv[3], argv[4]) == 0 || strcmp(argv[2], argv[4]) == 0) {
        fprintf(stderr, "Output filename must differ from input and key filenames.\n");
        return 1;
    }
    if (!read_key(argv[2], &key)) return 1;

    in = fopen(argv[3], "rb");
    if (!in) { perror("open input"); return 1; }

    /* Reject non-8-byte-aligned input before creating an output file.
       Assignment input files are normal seekable files. */
    if (fseek(in, 0, SEEK_END) != 0) {
        perror("seek input"); fclose(in); return 1;
    }
    {
        long bytes = ftell(in);
        if (bytes < 0) {
            perror("size input"); fclose(in); return 1;
        }
        if ((bytes % 8) != 0) {
            fprintf(stderr, "Input size must be a multiple of 8 bytes (no padding).\n");
            fclose(in); return 1;
        }
    }
    if (fseek(in, 0, SEEK_SET) != 0) {
        perror("rewind input"); fclose(in); return 1;
    }

    out = fopen(argv[4], "wb");
    if (!out) { perror("open output"); fclose(in); return 1; }

    init_tables();
    key_schedule(key);

    while ((n = fread(buffer, 1, sizeof buffer, in)) != 0) {
        if ((n % 8) != 0) { /* Catches modifications during processing. */
            fprintf(stderr, "Unexpected partial DES block in input file.\n");
            ok = 0; break;
        }
        for (i = 0; i < n; i += 8)
            store64(buffer + i, des_block(load64(buffer + i), decrypt));

        if (fwrite(buffer, 1, n, out) != n) {
            perror("write output"); ok = 0; break;
        }
    }
    if (ferror(in)) { perror("read input"); ok = 0; }
    if (fclose(in) != 0) { perror("close input"); ok = 0; }
    if (fclose(out) != 0) { perror("close output"); ok = 0; }

    if (!ok) {
        remove(argv[4]); /* Do not leave an incomplete ciphertext or plaintext. */
        return 1;
    }
    return 0;
}
