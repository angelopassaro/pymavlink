#pragma once

#ifndef _SPECK_128128_H
#define _SPECK_128128_H

#define BLOCK_SIZE 16
#define IV_LEN 16
#define KEY_LEN 16
#define KEY 2
#define KEY_ROUND 32

#include "common.h"
#include "utils.h"

void inline SpeckKeySchedule(uint64_t K[], uint64_t rk[])
{
    uint64_t i, B = K[1], A = K[0];
    for (i = 0; i < 31;)
    {
        rk[i] = A;
        ER64(B, A, i++);
    }
    rk[i] = A;
}
void inline SpeckEncrypt(uint64_t Pt[], uint64_t Ct[], uint64_t rk[])
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
    uint64_t K[KEY];
    uint64_t rk[KEY_ROUND];

    BytesToWords64(key, K, KEY_LEN);
    SpeckKeySchedule(K, rk);

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
            SpeckEncrypt(Pt, Ct, rk);
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
    SpeckEncrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ct, 2);

    //STEP3
    xored(ct, &plaintext[block], length - block);
}
#endif
