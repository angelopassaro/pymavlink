#pragma once

#ifndef _LIGHT_CRYPTO_H
#define _LIGHT_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include "common.h"
#include "utils.h"

/***************************************************************************
 *                              CHACHA20                                   *
 * *************************************************************************/
static inline void u32t8le(uint32_t v, uint8_t p[4])
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t p[4])
{
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

static inline uint32_t rotl32(uint32_t x, int n)
{
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d)
{
    x[a] += x[b];
    x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = rotl32(x[b] ^ x[c], 7);
}

static void chacha20_serialize(uint32_t in[16], uint8_t output[64])
{
    int i;
    for (i = 0; i < 16; i++)
    {
        u32t8le(in[i], output + (i << 2));
    }
}

static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds)
{
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2)
    {
        chacha20_quarterround(x, 0, 4, 8, 12);
        chacha20_quarterround(x, 1, 5, 9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7, 8, 13);
        chacha20_quarterround(x, 3, 4, 9, 14);
    }

    for (i = 0; i < 16; i++)
    {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

// https://tools.ietf.org/html/rfc7539#section-2.3
static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12])
{
    int i;

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++)
    {
        s[4 + i] = u8t32le(key + i * 4);
    }

    s[12] = counter;

    for (i = 0; i < 3; i++)
    {
        s[13 + i] = u8t32le(nonce + i * 4);
    }
}

MAVLINK_HELPER void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t *in, uint8_t *out, int inlen)
{
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);

    for (i = 0; i < inlen; i += 64)
    {
        chacha20_block(s, block, 20);
        s[12]++;

        for (j = i; j < i + 64; j++)
        {
            if (j >= inlen)
            {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}

/***************************************************************************
 *                              RABBIT                                     *
 ***************************************************************************/
// Structure to store the instance data (internal state)
typedef struct
{
    uint32_t x[8];
    uint32_t c[8];
    uint32_t carry;
} t_instance;

typedef struct
{
    /* 
   * Put here all state variable needed during the encryption process.
   */
    t_instance master;
    t_instance work;
} t_instances;

inline uint32_t _rotl(uint32_t x, int rot) { return (x << rot) | (x >> (32 - rot)); }

// Square a 32-bit number to obtain the 64-bit result and return
// the upper 32 bit XOR the lower 32 bit
inline uint32_t g_func(uint32_t x)
{
    // Construct high and low argument for squaring
    uint32_t a = x & 0xFFFF;
    uint32_t b = x >> 16;
    // Calculate high and low result of squaring
    uint32_t h = ((((a * a) >> 17) + (a * b)) >> 15) + b * b;
    uint32_t l = x * x;
    // Return high XOR low;
    return h ^ l;
}

// Calculate the next internal state
inline void next_state(t_instance *p_instance)
{
    // Temporary data
    uint32_t g[8], c_old[8], i;

    // Save old counter values
    for (i = 0; i < 8; i++)
        c_old[i] = p_instance->c[i];

    // Calculate new counter values
    p_instance->c[0] += 0x4D34D34D + p_instance->carry;
    p_instance->c[1] += 0xD34D34D3 + (p_instance->c[0] < c_old[0]);
    p_instance->c[2] += 0x34D34D34 + (p_instance->c[1] < c_old[1]);
    p_instance->c[3] += 0x4D34D34D + (p_instance->c[2] < c_old[2]);
    p_instance->c[4] += 0xD34D34D3 + (p_instance->c[3] < c_old[3]);
    p_instance->c[5] += 0x34D34D34 + (p_instance->c[4] < c_old[4]);
    p_instance->c[6] += 0x4D34D34D + (p_instance->c[5] < c_old[5]);
    p_instance->c[7] += 0xD34D34D3 + (p_instance->c[6] < c_old[6]);
    p_instance->carry = (p_instance->c[7] < c_old[7]);

    // Calculate the g-functions
    for (i = 0; i < 8; i++)
        g[i] = g_func(p_instance->x[i] + p_instance->c[i]);

    // Calculate new state values
    p_instance->x[0] = g[0] + _rotl(g[7], 16) + _rotl(g[6], 16);
    p_instance->x[1] = g[1] + _rotl(g[0], 8) + g[7];
    p_instance->x[2] = g[2] + _rotl(g[1], 16) + _rotl(g[0], 16);
    p_instance->x[3] = g[3] + _rotl(g[2], 8) + g[1];
    p_instance->x[4] = g[4] + _rotl(g[3], 16) + _rotl(g[2], 16);
    p_instance->x[5] = g[5] + _rotl(g[4], 8) + g[3];
    p_instance->x[6] = g[6] + _rotl(g[5], 16) + _rotl(g[4], 16);
    p_instance->x[7] = g[7] + _rotl(g[6], 8) + g[5];
}

// key_setup
inline void key_setup(t_instances *instances, const uint8_t *p_key)
{
    // Temporary data
    uint32_t k0, k1, k2, k3, i;
    //Generate four subkeys
    k0 = *(uint32_t *)(p_key + 0);
    k1 = *(uint32_t *)(p_key + 4);
    k2 = *(uint32_t *)(p_key + 8);
    k3 = *(uint32_t *)(p_key + 12);

    // Generate initial state variables
    instances->master.x[0] = k0;
    instances->master.x[2] = k1;
    instances->master.x[4] = k2;
    instances->master.x[6] = k3;
    instances->master.x[1] = (k3 << 16) | (k2 >> 16);
    instances->master.x[3] = (k0 << 16) | (k3 >> 16);
    instances->master.x[5] = (k1 << 16) | (k0 >> 16);
    instances->master.x[7] = (k2 << 16) | (k1 >> 16);

    // Generate initial counter values
    instances->master.c[0] = _rotl(k2, 16);
    instances->master.c[2] = _rotl(k3, 16);
    instances->master.c[4] = _rotl(k0, 16);
    instances->master.c[6] = _rotl(k1, 16);
    instances->master.c[1] = (k0 & 0xFFFF0000) | (k1 & 0xFFFF);
    instances->master.c[3] = (k1 & 0xFFFF0000) | (k2 & 0xFFFF);
    instances->master.c[5] = (k2 & 0xFFFF0000) | (k3 & 0xFFFF);
    instances->master.c[7] = (k3 & 0xFFFF0000) | (k0 & 0xFFFF);

    // Reset carry flag
    instances->master.carry = 0;

    // Iterate the system four times
    for (i = 0; i < 4; i++)
        next_state(&(instances->master));

    // Modify the counters
    for (i = 0; i < 8; i++)
        instances->master.c[(i + 4) & 0x7] ^= instances->master.x[i];

    for (i = 0; i < 8; i++)
    {
        instances->work.x[i] = instances->master.x[i];
        instances->work.c[i] = instances->master.c[i];
    }

    instances->work.carry = instances->master.carry;
}

/* IV setup */
inline void iv_setup(t_instances *instances, const uint8_t *iv)
{
    /* Temporary variables */
    uint8_t i0, i1, i2, i3, i;

    /* Generate four subvectors */
    i0 = *(uint32_t *)(iv + 0);
    i2 = *(uint32_t *)(iv + 4);
    i1 = (i0 >> 16) | (i2 & 0xFFFF0000);
    i3 = (i2 << 16) | (i0 & 0x0000FFFF);

    /* Modify counter values */
    instances->work.c[0] = instances->master.c[0] ^ i0;
    instances->work.c[1] = instances->master.c[1] ^ i1;
    instances->work.c[2] = instances->master.c[2] ^ i2;
    instances->work.c[3] = instances->master.c[3] ^ i3;
    instances->work.c[4] = instances->master.c[4] ^ i0;
    instances->work.c[5] = instances->master.c[5] ^ i1;
    instances->work.c[6] = instances->master.c[6] ^ i2;
    instances->work.c[7] = instances->master.c[7] ^ i3;

    /* Copy state variables */
    for (i = 0; i < 8; i++)
        instances->work.x[i] = instances->master.x[i];
    instances->work.carry = instances->master.carry;

    /* Iterate the system four times */
    for (i = 0; i < 4; i++)
        next_state(&(instances->work));
}

// Encrypt or decrypt a block of data
inline void _cipher_rabbit(t_instance *p_instance, const uint8_t *p_src, uint8_t *p_dest, size_t data_size)
{
    uint32_t i;
    for (i = 0; i < data_size; i += 16)
    {

        // Iterate the system
        next_state(p_instance);

        // Encrypt 16 uint8_ts of data
        *(uint32_t *)(p_dest + 0) = *(uint32_t *)(p_src + 0) ^ p_instance->x[0] ^ (p_instance->x[5] >> 16) ^ (p_instance->x[3] << 16);
        *(uint32_t *)(p_dest + 4) = *(uint32_t *)(p_src + 4) ^ p_instance->x[2] ^ (p_instance->x[7] >> 16) ^ (p_instance->x[5] << 16);
        *(uint32_t *)(p_dest + 8) = *(uint32_t *)(p_src + 8) ^ p_instance->x[4] ^ (p_instance->x[1] >> 16) ^ (p_instance->x[7] << 16);
        *(uint32_t *)(p_dest + 12) = *(uint32_t *)(p_src + 12) ^ p_instance->x[6] ^ (p_instance->x[3] >> 16) ^ (p_instance->x[1] << 16);

        // Increment pointers to source and destination data
        p_src += 16;
        p_dest += 16;
    }
}

MAVLINK_HELPER void rabbit(const uint8_t *iv, const uint8_t *p_key, const uint8_t *p_src, uint8_t *p_dest, size_t data_size)
{
    t_instances instances;

    key_setup((t_instances *)&instances, (uint8_t *)p_key);
    iv_setup((t_instances *)&instances, iv);
    _cipher_rabbit((t_instance *)&instances.work, (uint8_t *)p_src, (uint8_t *)p_dest, data_size);
}

/***************************************************************************
 *                              TRIVIUM                                    *
 ***************************************************************************/
static inline void rotate(uint64_t *state, uint64_t *t1, uint64_t *t2, uint64_t *t3)
{
    /* rotate register C */
    state[5] = state[4];
    state[4] = *t2;

    /* rotate register B */
    state[3] = state[2];
    state[2] = *t1;

    /* rotate register A */
    state[1] = state[0];
    state[0] = *t3;
}

static inline void update(uint64_t *state, uint64_t *t1, uint64_t *t2, uint64_t *t3, uint64_t *stream)
{
    uint64_t x1, x2, x3;

    x1 = (state[0] << 2) ^ (state[1] >> 62);
    x2 = (state[0] << 29) ^ (state[1] >> 35);

    *t1 = x1 ^ x2;

    x1 = (state[2] << 5) ^ (state[3] >> 59);
    x2 = (state[2] << 20) ^ (state[3] >> 44);

    *t2 = x1 ^ x2;

    x1 = (state[4] << 2) ^ (state[5] >> 62);
    x2 = (state[4] << 47) ^ (state[5] >> 17);

    *t3 = x1 ^ x2;

    *stream ^= *t1 ^ *t2 ^ *t3;

    x1 = (state[0] << 27) ^ (state[1] >> 37);
    x2 = (state[0] << 28) ^ (state[1] >> 36);
    x3 = (state[2] << 14) ^ (state[3] >> 50);

    *t1 ^= (x1 & x2) ^ x3;

    x1 = (state[2] << 18) ^ (state[3] >> 46);
    x2 = (state[2] << 19) ^ (state[3] >> 45);
    x3 = (state[4] << 23) ^ (state[5] >> 41);

    *t2 ^= (x1 & x2) ^ x3;

    x1 = (state[4] << 45) ^ (state[5] >> 19);
    x2 = (state[4] << 46) ^ (state[5] >> 18);
    x3 = (state[0] << 5) ^ (state[1] >> 59);

    *t3 ^= (x1 & x2) ^ x3;
}

MAVLINK_HELPER void setup(uint8_t *state, uint8_t *key, uint8_t *iv)
{
    uint64_t t1, t2, t3;
    uint64_t s;

    uint64_t *State = (uint64_t *)state;

    /* Initialize register A */
    state[0] = key[2];
    state[1] = key[3];
    state[2] = key[4];
    state[3] = key[5];
    state[4] = key[6];
    state[5] = key[7];
    state[6] = key[8];
    state[7] = key[9];

    state[8] = 0x00;
    state[9] = 0x00;
    state[10] = 0x00;
    state[11] = 0x00;
    state[12] = 0x00;
    state[13] = 0x00;
    state[14] = key[0];
    state[15] = key[1];

    /* Initialize register B */
    state[16] = iv[2];
    state[17] = iv[3];
    state[18] = iv[4];
    state[19] = iv[5];
    state[20] = iv[6];
    state[21] = iv[7];
    state[22] = iv[8];
    state[23] = iv[9];

    state[24] = 0x00;
    state[25] = 0x00;
    state[26] = 0x00;
    state[27] = 0x00;
    state[28] = 0x00;
    state[29] = 0x00;
    state[30] = iv[0];
    state[31] = iv[1];

    /* Initialize register C */
    state[32] = 0x00;
    state[33] = 0x00;
    state[34] = 0x00;
    state[35] = 0x00;
    state[36] = 0x00;
    state[37] = 0x00;
    state[38] = 0x00;
    state[39] = 0x00;

    state[40] = 0x00;
    state[41] = 0x00;
    state[42] = 0x0E;
    state[43] = 0x00;
    state[44] = 0x00;
    state[45] = 0x00;
    state[46] = 0x00;
    state[47] = 0x00;

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);

    update(State, &t1, &t2, &t3, &s);
    rotate(State, &t1, &t2, &t3);
}

inline void _cipher_trivium(uint8_t *state, uint8_t *stream, uint16_t length)
{
    uint16_t i;
    uint64_t t1, t2, t3;

    uint64_t *State = (uint64_t *)state;
    uint64_t *Stream = (uint64_t *)stream;

    for (i = 0; i < length / 8; i++)
    {
        update(State, &t1, &t2, &t3, &Stream[i]);
        rotate(State, &t1, &t2, &t3);
    }
}

MAVLINK_HELPER void trivium(uint8_t *key, uint8_t *iv, uint8_t *stream, uint8_t length)
{

    //state
    uint8_t state[48];

    //setup state
    setup((uint8_t *)state, (uint8_t *)key, (uint8_t *)iv);
    _cipher_trivium((uint8_t *)state, (uint8_t *)stream, length);
}

/***************************************************************************
 *                              SIMON6496                                  *
 ***************************************************************************/
void inline SimonKey6496Schedule(uint32_t K[], uint32_t rk[])
{
    uint32_t i, c = 0xfffffffc;
    uint64_t z = 0x7369f885192c0ef5LL;
    rk[0] = K[0];
    rk[1] = K[1];
    rk[2] = K[2];
    for (i = 3; i < 42; i++)
    {
        rk[i] = c ^ (z & 1) ^ rk[i - 3] ^ ROTR32(rk[i - 1], 3) ^ ROTR32(rk[i - 1], 4);
        z >>= 1;
    }
}

void inline Simon6496Encrypt(uint32_t Pt[], uint32_t Ct[], uint32_t rk[])
{
    uint32_t i;
    Ct[1] = Pt[1];
    Ct[0] = Pt[0];
    for (i = 0; i < 42;)
        R32x2(Ct[1], Ct[0], rk[i++], rk[i++]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Simon6496(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{
    const int BLOCK_SIZE = 8;
    const int KEY_LEN = 12;
    const int KEY = 3;
    const int KEY_ROUND = 42;

    uint32_t K[KEY];
    uint32_t rk[KEY_ROUND];

    BytesToWords32(key, K, KEY_LEN);
    SimonKey6496Schedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t Pt[2];
    uint32_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
            Simon6496Encrypt(Pt, Ct, rk);
            Words32ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
    Simon6496Encrypt(Pt, Ct, rk);
    Words32ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}

/***************************************************************************
 *                              SIMON64128                                 *
 ***************************************************************************/

void inline Simon64128KeySchedule(uint32_t K[], uint32_t rk[])
{
    uint32_t i, c = 0xfffffffc;
    uint64_t z = 0xfc2ce51207a635dbLL;
    rk[0] = K[0];
    rk[1] = K[1];
    rk[2] = K[2];
    rk[3] = K[3];
    for (i = 4; i < 44; i++)
    {
        rk[i] = c ^ (z & 1) ^ rk[i - 4] ^ ROTR32(rk[i - 1], 3) ^ rk[i - 3] ^ ROTR32(rk[i - 1], 4) ^ ROTR32(rk[i - 3], 1);
        z >>= 1;
    }
}

void inline Simon64128Encrypt(uint32_t Pt[], uint32_t Ct[], uint32_t rk[])
{
    uint32_t i;
    Ct[1] = Pt[1];
    Ct[0] = Pt[0];
    for (i = 0; i < 44;)
        R32x2(Ct[1], Ct[0], rk[i++], rk[i++]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Simon64128(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 8;
    const int KEY_LEN = 16;
    const int KEY = 4;
    const int KEY_ROUND = 44;

    uint32_t K[KEY];
    uint32_t rk[KEY_ROUND];

    BytesToWords32(key, K, KEY_LEN);
    Simon64128KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t Pt[2];
    uint32_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
            Simon64128Encrypt(Pt, Ct, rk);
            Words32ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
    Simon64128Encrypt(Pt, Ct, rk);
    Words32ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}

/***************************************************************************
 *                              SIMON128128                                *
 ***************************************************************************/
void inline Simon128128KeySchedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, B = K[1], A = K[0];
    uint64_t c = 0xfffffffffffffffcLL, z = 0x7369f885192c0ef5LL;
    for (i = 0; i < 64;)
    {
        rk[i++] = A;
        A ^= c ^ (z & 1) ^ ROTR64(B, 3) ^ ROTR64(B, 4);
        z >>= 1;
        rk[i++] = B;
        B ^= c ^ (z & 1) ^ ROTR64(A, 3) ^ ROTR64(A, 4);
        z >>= 1;
    }
    rk[64] = A;
    A ^= c ^ 1 ^ ROTR64(B, 3) ^ ROTR64(B, 4);
    rk[65] = B;
    B ^= c ^ 0 ^ ROTR64(A, 3) ^ ROTR64(A, 4);
    rk[66] = A;
    rk[67] = B;
}

void inline Simon128128Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
{
    uint64_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 68; i += 2)
        R64x2(Ct[1], Ct[0], rk[i], rk[i + 1]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Simon128128(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 16;
    const int KEY_LEN = 16;
    const int KEY = 2;
    const int KEY_ROUND = 68;

    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    Simon128128KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t Pt[2];
    uint64_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
            Simon128128Encrypt(Pt, Ct, rk);
            Words64ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
    Simon128128Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
/***************************************************************************
 *                              SIMON128192                                *
 ***************************************************************************/
void inline SimonKey128192Schedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, C = K[2], B = K[1], A = K[0];
    uint64_t c = 0xfffffffffffffffcLL, z = 0xfc2ce51207a635dbLL;
    for (i = 0; i < 63;)
    {
        rk[i++] = A;
        A ^= c ^ (z & 1) ^ ROTR64(C, 3) ^ ROTR64(C, 4);
        z >>= 1;
        rk[i++] = B;
        B ^= c ^ (z & 1) ^ ROTR64(A, 3) ^ ROTR64(A, 4);
        z >>= 1;
        rk[i++] = C;
        C ^= c ^ (z & 1) ^ ROTR64(B, 3) ^ ROTR64(B, 4);
        z >>= 1;
    }
    rk[63] = A;
    A ^= c ^ 1 ^ ROTR64(C, 3) ^ ROTR64(C, 4);
    rk[64] = B;
    B ^= c ^ 0 ^ ROTR64(A, 3) ^ ROTR64(A, 4);
    rk[65] = C;
    C ^= c ^ 1 ^ ROTR64(B, 3) ^ ROTR64(B, 4);
    rk[66] = A;
    rk[67] = B;
    rk[68] = C;
}
void inline Simon128192Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
{
    uint64_t i, t;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 68; i += 2)
        R64x2(Ct[1], Ct[0], rk[i], rk[i + 1]);
    t = Ct[1];
    Ct[1] = Ct[0] ^ f64(Ct[1]) ^ rk[68];
    Ct[0] = t;
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Simon128192(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 16;
    const int KEY_LEN = 24;
    const int KEY = 3;
    const int KEY_ROUND = 69;

    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    SimonKey128192Schedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t Pt[2];
    uint64_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
            Simon128192Encrypt(Pt, Ct, rk);
            Words64ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
    Simon128192Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
/***************************************************************************
 *                              SIMON128256                                *
 ***************************************************************************/
void inline Simon128256KeySchedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, D = K[3], C = K[2], B = K[1], A = K[0];
    uint64_t c = 0xfffffffffffffffcLL, z = 0xfdc94c3a046d678bLL;
    for (i = 0; i < 64;)
    {
        rk[i++] = A;
        A ^= c ^ (z & 1) ^ ROTR64(D, 3) ^ ROTR64(D, 4) ^ B ^ ROTR64(B, 1);
        z >>= 1;
        rk[i++] = B;
        B ^= c ^ (z & 1) ^ ROTR64(A, 3) ^ ROTR64(A, 4) ^ C ^ ROTR64(C, 1);
        z >>= 1;
        rk[i++] = C;
        C ^= c ^ (z & 1) ^ ROTR64(B, 3) ^ ROTR64(B, 4) ^ D ^ ROTR64(D, 1);
        z >>= 1;
        rk[i++] = D;
        D ^= c ^ (z & 1) ^ ROTR64(C, 3) ^ ROTR64(C, 4) ^ A ^ ROTR64(A, 1);
        z >>= 1;
    }
    rk[64] = A;
    A ^= c ^ 0 ^ ROTR64(D, 3) ^ ROTR64(D, 4) ^ B ^ ROTR64(B, 1);
    rk[65] = B;
    B ^= c ^ 1 ^ ROTR64(A, 3) ^ ROTR64(A, 4) ^ C ^ ROTR64(C, 1);
    rk[66] = C;
    C ^= c ^ 0 ^ ROTR64(B, 3) ^ ROTR64(B, 4) ^ D ^ ROTR64(D, 1);
    rk[67] = D;
    D ^= c ^ 0 ^ ROTR64(C, 3) ^ ROTR64(C, 4) ^ A ^ ROTR64(A, 1);
    rk[68] = A;
    rk[69] = B;
    rk[70] = C;
    rk[71] = D;
}

void inline Simon128256Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
{
    uint64_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 72; i += 2)
        R64x2(Ct[1], Ct[0], rk[i], rk[i + 1]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Simon128256(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 16;
    const int KEY_LEN = 32;
    const int KEY = 4;
    const int KEY_ROUND = 72;

    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    Simon128256KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t Pt[2];
    uint64_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
            Simon128256Encrypt(Pt, Ct, rk);
            Words64ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
    Simon128256Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
/***************************************************************************
 *                              SPECK6496                                  *
 ***************************************************************************/
void inline Speck6496KeySchedule(uint32_t K[], uint32_t rk[])
{
    uint32_t i, C = K[2], B = K[1], A = K[0];
    for (i = 0; i < 26;)
    {
        rk[i] = A;
        ER32(B, A, i++);
        rk[i] = A;
        ER32(C, A, i++);
    }
}
void inline Speck6496Encrypt(uint32_t Pt[], uint32_t Ct[], uint32_t rk[])
{
    uint32_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 26;)
        ER32(Ct[1], Ct[0], rk[i++]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Speck6496(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 8;
    const int KEY_LEN = 12;
    const int KEY = 3;
    const int KEY_ROUND = 26;

    uint32_t K[KEY];
    uint32_t rk[KEY_ROUND];

    BytesToWords32(key, K, KEY_LEN);
    Speck6496KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t Pt[2];
    uint32_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            //STEP 2
            BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
            Speck6496Encrypt(Pt, Ct, rk);
            Words32ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);
            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
    Speck6496Encrypt(Pt, Ct, rk);
    Words32ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
/***************************************************************************
 *                              SPECK64128                                 *
 ***************************************************************************/
void inline Speck64128KeySchedule(uint32_t K[], uint32_t rk[])
{
    uint32_t i, D = K[3], C = K[2], B = K[1], A = K[0];
    for (i = 0; i < 27;)
    {
        rk[i] = A;
        ER32(B, A, i++);
        rk[i] = A;
        ER32(C, A, i++);
        rk[i] = A;
        ER32(D, A, i++);
    }
}

void inline Speck64128Encrypt(uint32_t Pt[], uint32_t Ct[], uint32_t rk[])
{
    uint32_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 27;)
        ER32(Ct[1], Ct[0], rk[i++]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Speck64128(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{
    int BLOCK_SIZE = 8;
    int KEY_LEN = 16;
    int KEY = 4;
    int KEY_ROUND = 27;

    uint32_t K[KEY];
    uint32_t rk[KEY_ROUND];

    BytesToWords32(key, K, KEY_LEN);
    Speck64128KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t Pt[2];
    uint32_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
            Speck64128Encrypt(Pt, Ct, rk);
            Words32ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords32(workingNonce, Pt, BLOCK_SIZE);
    Speck64128Encrypt(Pt, Ct, rk);
    Words32ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}

/***************************************************************************
 *                              SPECK128128                                *
 ***************************************************************************/
void inline Speck128128KeySchedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, B = K[1], A = K[0];
    for (i = 0; i < 31;)
    {
        rk[i] = A;
        ER64(B, A, i++);
    }
    rk[i] = A;
}
void inline Speck128128Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
{
    uint64_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 32;)
        ER64(Ct[1], Ct[0], rk[i++]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Speck128128(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 16;
    const int KEY_LEN = 16;
    const int KEY = 2;
    const int KEY_ROUND = 32;

    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    Speck128128KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t Pt[2];
    uint64_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
            Speck128128Encrypt(Pt, Ct, rk);
            Words64ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
    Speck128128Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
/***************************************************************************
 *                              SPECK128192                                *
 ***************************************************************************/
void inline Speck128192KeySchedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, C = K[2], B = K[1], A = K[0];
    for (i = 0; i < 32;)
    {
        rk[i] = A;
        ER64(B, A, i++);
        rk[i] = A;
        ER64(C, A, i++);
    }
    rk[i] = A;
}
void inline Speck128192Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
{
    uint64_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 33;)
        ER64(Ct[1], Ct[0], rk[i++]);
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Speck128192(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{
    const int BLOCK_SIZE = 16;
    const int KEY_LEN = 24;
    const int KEY = 3;
    const int KEY_ROUND = 33;

    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    Speck128192KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t Pt[2];
    uint64_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
            Speck128192Encrypt(Pt, Ct, rk);
            Words64ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
    Speck128192Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
/***************************************************************************
 *                              SPECK128256                                *
 ***************************************************************************/
void inline Speck128256KeySchedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, D = K[3], C = K[2], B = K[1], A = K[0];
    for (i = 0; i < 33;)
    {
        rk[i] = A;
        ER64(B, A, i++);
        rk[i] = A;
        ER64(C, A, i++);
        rk[i] = A;
        ER64(D, A, i++);
    }
    rk[i] = A;
}

void inline Speck128256Encrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
{
    uint64_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 34;)
    {
        ER64(Ct[1], Ct[0], rk[i++]);
    }
}

/**
 * For every block:
 * 1. Concat/xor/add nonce  with counter (random nonce)
 * 2. Encrypt nonce
 * 3. XOR between encrypted nonce and plain
 * 4. Increment counter
 */
MAVLINK_HELPER void Speck128256(uint8_t *nonce, uint8_t *key, uint8_t *plaintext, int length)
{

    const int BLOCK_SIZE = 16;
    const int KEY_LEN = 32;
    const int KEY = 4;
    const int KEY_ROUND = 34;

    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    Speck128256KeySchedule(K, rk);

    int block = 0;
    int last_block;
    uint8_t counter[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint64_t Pt[2];
    uint64_t Ct[2];
    uint8_t workingNonce[BLOCK_SIZE];
    uint8_t ct[BLOCK_SIZE];

    last_block = length - BLOCK_SIZE;

    if (length > BLOCK_SIZE)
    {
        for (block = 0; block < last_block; block += BLOCK_SIZE)
        {
            //STEP 1
            memcpy(workingNonce, nonce, BLOCK_SIZE);
            xored(counter, workingNonce, BLOCK_SIZE);

            BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
            Speck128256Encrypt(Pt, Ct, rk);
            Words64ToBytes(Ct, ct, 2);

            //STEP3
            xored(ct, &plaintext[block], BLOCK_SIZE);

            //STEP 4
            uint8_t count[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            byteAdd(counter, BLOCK_SIZE, count);
        }
    }

    /*******************************last block**********************************/

    //STEP 1
    memcpy(workingNonce, nonce, BLOCK_SIZE);
    xored(counter, workingNonce, BLOCK_SIZE);

    //STEP 2

    BytesToWords64(workingNonce, Pt, BLOCK_SIZE);
    Speck128256Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}

#endif
