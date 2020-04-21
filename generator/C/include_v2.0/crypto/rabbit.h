/*
* Implementation Ref: "Rabbit: A New High-Performance Stream Cipher"
* iv_setup from ECRYPT
*/
#pragma once

#ifndef _RABBIT_H
#define _RABBIT_H

#ifdef MAVLINK_USE_CXX_NAMESPACE
namespace mavlink
{
#endif

#ifndef MAVLINK_HELPER
#define MAVLINK_HELPER
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

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
    p_instance->c[0] += 0x4D34D34D +  p_instance->carry;
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
inline void _cipher(t_instance *p_instance, const uint8_t *p_src, uint8_t *p_dest, size_t data_size)
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

MAVLINK_HELPER void rabbit(const uint8_t *iv, const uint8_t *p_key, const uint8_t *p_src, uint8_t *p_dest, size_t data_size ){
    t_instances instances;

    key_setup((t_instances *)&instances, (uint8_t *)p_key);
    iv_setup((t_instances *)&instances, iv);
    _cipher((t_instance *)&instances.work, (uint8_t *)p_src, (uint8_t *)p_dest, data_size);


}
#ifdef MAVLINK_USE_CXX_NAMESPACE
} // namespace mavlink
#endif
#endif
