#pragma once

#ifndef _SIMON_128192_H
#define _SIMON_128192_H

#define BLOCK_SIZE 16
#define IV_LEN 16
#define KEY_LEN 24
#define KEY 3
#define KEY_ROUND 69

#include "common.h"
#include "utils.h"

void inline SimonKeySchedule(uint64_t K[], uint64_t rk[])
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
void inline SimonEncrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
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
    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    SimonKeySchedule(K, rk);

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
            SimonEncrypt(Pt, Ct, rk);
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
    SimonEncrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
#endif
