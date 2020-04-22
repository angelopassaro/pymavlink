#pragma once

#ifndef _SIMON_128256_H
#define _SIMON_128256_H

#define BLOCK_SIZE 16
#define IV_LEN 16
#define KEY_LEN 32
#define KEY 4
#define KEY_ROUND 72

#include "common.h"
#include "utils.h"

void inline SimonKeySchedule(uint64_t K[], uint64_t rk[])
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

void inline SimonEncrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
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
