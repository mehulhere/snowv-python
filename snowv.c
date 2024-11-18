// SNOW-V 32-bit Reference Implementation (Windows-Compatible High-Resolution Timing)
#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // For memcpy
#include <stdio.h>   // For printf
#include <math.h>    // For sqrt

#ifdef _WIN32
#include <windows.h> // For QueryPerformanceCounter, QueryPerformanceFrequency
#else
#include <time.h>    // For clock_gettime, struct timespec
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

u8 SBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,
    0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,
    0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,
    0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,
    0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,
    0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,
    0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,
    0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,
    0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,
    0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,
    0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,
    0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,
    0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,
    0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,
    0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,
    0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

u8 Sigma[16] = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};

#define MAKEU32(a, b) (((u32)(a) << 16) | ((u32)(b)))
#define MAKEU16(a, b) (((u16)(a) << 8) | ((u16)(b)))

struct SnowV32 {
    u16 A[16], B[16];     // LFSR
    u32 R1[4], R2[4], R3[4]; // FSM
    u32 AesKey1[4];
    u32 AesKey2[4];
};

// Function prototypes
void aes_enc_round(struct SnowV32* ctx, u32* result, u32* state, u32* roundKey);
u16 mul_x(u16 v, u16 c);
u16 mul_x_inv(u16 v, u16 d);
void permute_sigma(u32* state);
void fsm_update(struct SnowV32* ctx);
void lfsr_update(struct SnowV32* ctx);
void keystream(struct SnowV32* ctx, u8* z);
void keyiv_setup(struct SnowV32* ctx, u8* key, u8* iv, int is_aead_mode);

void aes_enc_round(struct SnowV32* ctx, u32* result, u32* state, u32* roundKey) {
    #define ROTL32(word32, offset) ((word32 << offset) | (word32 >> (32 - offset)))
    #define SB(index, offset) (((u32)(sb[(index) % 16])) << (offset * 8))
    #define MKSTEP(j) \
        w = SB(j * 4 + 0, 3) | SB(j * 4 + 5, 0) | SB(j * 4 + 10, 1) | SB(j * 4 + 15, 2); \
        t = ROTL32(w, 16) ^ ((w << 1) & 0xfefefefeUL) ^ (((w >> 7) & 0x01010101UL) * 0x1b); \
        result[j] = roundKey[j] ^ w ^ t ^ ROTL32(t, 8)

    u32 w, t;
    u8 sb[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            sb[i * 4 + j] = SBox[(state[i] >> (j * 8)) & 0xff];
    MKSTEP(0);
    MKSTEP(1);
    MKSTEP(2);
    MKSTEP(3);
    #undef ROTL32
    #undef SB
    #undef MKSTEP
}

u16 mul_x(u16 v, u16 c) {
    if (v & 0x8000)
        return (v << 1) ^ c;
    else
        return (v << 1);
}

u16 mul_x_inv(u16 v, u16 d) {
    if (v & 0x0001)
        return (v >> 1) ^ d;
    else
        return (v >> 1);
}

void permute_sigma(u32* state) {
    u8 tmp[16];
    for (int i = 0; i < 16; i++)
        tmp[i] = (u8)(state[Sigma[i] >> 2] >> ((Sigma[i] & 3) << 3));
    for (int i = 0; i < 4; i++)
        state[i] = MAKEU32(MAKEU16(tmp[4 * i + 3], tmp[4 * i + 2]),
                           MAKEU16(tmp[4 * i + 1], tmp[4 * i + 0]));
}

void fsm_update(struct SnowV32* ctx) {
    u32 R1temp[4];
    memcpy(R1temp, ctx->R1, sizeof(ctx->R1));
    for (int i = 0; i < 4; i++) {
        u32 T2 = MAKEU32(ctx->A[2 * i + 1], ctx->A[2 * i]);
        ctx->R1[i] = (T2 ^ ctx->R3[i]) + ctx->R2[i];
    }
    permute_sigma(ctx->R1);
    aes_enc_round(ctx, ctx->R3, ctx->R2, ctx->AesKey2);
    aes_enc_round(ctx, ctx->R2, R1temp, ctx->AesKey1);
}

void lfsr_update(struct SnowV32* ctx) {
    for (int i = 0; i < 8; i++) {
        u16 u = mul_x(ctx->A[0], 0x990F) ^ ctx->A[1] ^ mul_x_inv(ctx->A[8], 0xCC87) ^ ctx->B[0];
        u16 v = mul_x(ctx->B[0], 0xC963) ^ ctx->B[3] ^ mul_x_inv(ctx->B[8], 0xE4B1) ^ ctx->A[0];
        for (int j = 0; j < 15; j++) {
            ctx->A[j] = ctx->A[j + 1];
            ctx->B[j] = ctx->B[j + 1];
        }
        ctx->A[15] = u;
        ctx->B[15] = v;
    }
}

void keystream(struct SnowV32* ctx, u8* z) {
    for (int i = 0; i < 4; i++) {
        u32 T1 = MAKEU32(ctx->B[2 * i + 9], ctx->B[2 * i + 8]);
        u32 v = (T1 + ctx->R1[i]) ^ ctx->R2[i];
        z[i * 4 + 0] = (v >> 0) & 0xff;
        z[i * 4 + 1] = (v >> 8) & 0xff;
        z[i * 4 + 2] = (v >> 16) & 0xff;
        z[i * 4 + 3] = (v >> 24) & 0xff;
    }
    fsm_update(ctx);
    lfsr_update(ctx);
}

void keyiv_setup(struct SnowV32* ctx, u8* key, u8* iv, int is_aead_mode) {
    for (int i = 0; i < 8; i++) {
        ctx->A[i] = MAKEU16(iv[2 * i + 1], iv[2 * i]);
        ctx->A[i + 8] = MAKEU16(key[2 * i + 1], key[2 * i]);
        ctx->B[i] = 0x0000;
        ctx->B[i + 8] = MAKEU16(key[2 * i + 17], key[2 * i + 16]);
    }
    if (is_aead_mode == 1) {
        ctx->B[0] = 0x6C41;
        ctx->B[1] = 0x7865;
        ctx->B[2] = 0x6B45;
        ctx->B[3] = 0x2064;
        ctx->B[4] = 0x694A;
        ctx->B[5] = 0x676E;
        ctx->B[6] = 0x6854;
        ctx->B[7] = 0x6D6F;
    }
    for (int i = 0; i < 4; i++)
        ctx->R1[i] = ctx->R2[i] = ctx->R3[i] = 0x00000000;

    // Initialize AesKey1 and AesKey2
    for (int i = 0; i < 4; i++) {
        ctx->AesKey1[i] = MAKEU32(MAKEU16(key[4 * i + 3], key[4 * i + 2]),
                                 MAKEU16(key[4 * i + 1], key[4 * i + 0]));
        ctx->AesKey2[i] = MAKEU32(MAKEU16(key[4 * i + 19], key[4 * i + 18]),
                                 MAKEU16(key[4 * i + 17], key[4 * i + 16]));
    }

    for (int i = 0; i < 16; i++) {
        u8 z[16];
        keystream(ctx, z);
        for (int j = 0; j < 8; j++)
            ctx->A[j + 8] ^= MAKEU16(z[2 * j + 1], z[2 * j]);
        if (i == 14)
            for (int j = 0; j < 4; j++)
                ctx->R1[j] ^= MAKEU32(MAKEU16(key[4 * j + 3], key[4 * j + 2]),
                                     MAKEU16(key[4 * j + 1], key[4 * j + 0]));
        if (i == 15)
            for (int j = 0; j < 4; j++)
                ctx->R1[j] ^= MAKEU32(MAKEU16(key[4 * j + 19], key[4 * j + 18]),
                                     MAKEU16(key[4 * j + 17], key[4 * j + 16]));
    }
}

void measure_encryption_time(size_t data_size_bits) {
    size_t data_size_bytes = data_size_bits / 8;
    u8 key[32] = {0};
    u8 iv[16] = {0};
    struct SnowV32 cipher;
    u8* plaintext = (u8*)malloc(data_size_bytes);
    u8* ciphertext = (u8*)malloc(data_size_bytes);
    u8 keystream_block[16]; // Fixed size since keystream produces 16 bytes at a time

    if (!plaintext || !ciphertext) {
        printf("Memory allocation failed\n");
        free(plaintext);
        free(ciphertext);
        return;
    }

    // Initialize plaintext with some data (e.g., all zeros)
    memset(plaintext, 0, data_size_bytes);

    // Variables for timing
    const int num_trials = 1000;
    double times[num_trials];
    double total_time = 0.0;
    double min_time = 1e9;
    double max_time = 0.0;

    #ifdef _WIN32
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    #endif

    for (int trial = 0; trial < num_trials; trial++) {
        keyiv_setup(&cipher, key, iv, 0); // is_aead_mode = 0

        #ifdef _WIN32
        LARGE_INTEGER start_time, end_time;
        QueryPerformanceCounter(&start_time);
        #else
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
        #endif

        size_t bytes_encrypted = 0;
        while (bytes_encrypted < data_size_bytes) {
            size_t bytes_to_encrypt = data_size_bytes - bytes_encrypted;
            if (bytes_to_encrypt > 16)
                bytes_to_encrypt = 16;

            keystream(&cipher, keystream_block);

            // XOR plaintext with keystream to produce ciphertext
            for (size_t i = 0; i < bytes_to_encrypt; i++) {
                ciphertext[bytes_encrypted + i] = plaintext[bytes_encrypted + i] ^ keystream_block[i];
            }

            bytes_encrypted += bytes_to_encrypt;
        }

        #ifdef _WIN32
        QueryPerformanceCounter(&end_time);
        double time_taken = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / frequency.QuadPart;
        #else
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double time_taken = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
        time_taken += (end_time.tv_nsec - start_time.tv_nsec) / 1e6;
        #endif

        times[trial] = time_taken;
        total_time += time_taken;
        if (time_taken < min_time)
            min_time = time_taken;
        if (time_taken > max_time)
            max_time = time_taken;
    }

    double average_time = total_time / num_trials;

    // Calculate standard deviation
    double sum_squared_diff = 0.0;
    for (int i = 0; i < num_trials; i++) {
        double diff = times[i] - average_time;
        sum_squared_diff += diff * diff;
    }
    double std_dev = sqrt(sum_squared_diff / num_trials);

    printf("Encryption Time Statistics for %zu-bit data:\n", data_size_bits);
    printf("Average Encryption Time: %.3f us\n", average_time * 1000);
    printf("Minimum Encryption Time: %.3f us\n", min_time *  1000);
    printf("Maximum Encryption Time: %.3f us\n", max_time *  1000);
    printf("Standard Deviation: %.3f us\n\n", std_dev * 1000);

    free(plaintext);
    free(ciphertext);
}

int main() {
    // Measure encryption time for different data sizes
    measure_encryption_time(256);    // 256 bits
    measure_encryption_time(1024);   // 1024 bits
    measure_encryption_time(4096);   // 4096 bits

    return 0;
}
