/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#ifndef _TRIVIUM_H
#define _TRIVIUM_H

#ifdef MAVLINK_USE_CXX_NAMESPACE
namespace mavlink
{
#endif

#ifndef MAVLINK_HELPER
#define MAVLINK_HELPER
#endif

#include <stdint.h>
#include <stdio.h>

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

inline void _cipher(uint8_t *state, uint8_t *stream, uint16_t length)
{
    uint16_t  i;
    uint64_t t1, t2, t3;

    uint64_t *State = (uint64_t *)state;
    uint64_t *Stream = (uint64_t *)stream;

    for (i = 0; i < length / 8; i++)
    {
        update(State, &t1, &t2, &t3, &Stream[i]);
        rotate(State, &t1, &t2, &t3);
    }
}

MAVLINK_HELPER void trivium(uint8_t *key, uint8_t *iv, uint8_t *stream, uint8_t length){

    //state
	uint8_t state[48];

    //setup state
    setup((uint8_t *)state,(uint8_t *)key, (uint8_t *)iv);
    _cipher((uint8_t *)state, (uint8_t *)stream, length);

}



#ifdef MAVLINK_USE_CXX_NAMESPACE
} // namespace mavlink
#endif
#endif
