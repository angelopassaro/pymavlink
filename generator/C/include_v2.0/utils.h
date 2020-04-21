#pragma once

#ifndef _UTILS_H
#define _UTILS_H

#include "common.h"
#include <stdint.h>

/**
* Convert  give words in bytes
* words is a multiple of block size in words
* bytes is a multiple of block size in bytes

*  @param words  the input word
*  @param bytes  the output bytes
*  @param numwords  the lenght of word
*/
MAVLINK_HELPER void Words32ToBytes(uint32_t words[], uint8_t bytes[], int numwords)
{
    int i, j = 0;
    for (i = 0; i < numwords; i++)
    {
        bytes[j] = (uint8_t)words[i];
        bytes[j + 1] = (uint8_t)(words[i] >> 8);
        bytes[j + 2] = (uint8_t)(words[i] >> 16);
        bytes[j + 3] = (uint8_t)(words[i] >> 24);
        j += 4;
    }
}

/**
* Convert  give the bytes in words
* words is a multiple of block size in words
* bytes is a multiple of block size in bytes

*  @param bytes  the input bytes
*  @param word  the output word
*  @param numbytes  the lenght of bytes
*/
MAVLINK_HELPER void BytesToWords32(uint8_t bytes[], uint32_t words[], int numbytes)
{
    int i, j = 0;
    for (i = 0; i < numbytes / 4; i++)
    {
        words[i] = (uint32_t)bytes[j] | ((uint32_t)bytes[j + 1] << 8) | ((uint32_t)bytes[j + 2] << 16) | ((uint32_t)bytes[j + 3] << 24);
        j += 4;
    }
}

/**
* Convert  give words in bytes
* words is a multiple of block size in words
* bytes is a multiple of block size in bytes
*  @param bytes  the input bytes
*  @param word  the output word
*  @param numbytes  the lenght of bytes
*/
MAVLINK_HELPER void Words64ToBytes(uint64_t words[], uint8_t bytes[], int numwords)
{
    int i, j = 0;
    for (i = 0; i < numwords; i++)
    {
        bytes[j] = (uint8_t)words[i];
        bytes[j + 1] = (uint8_t)(words[i] >> 8);
        bytes[j + 2] = (uint8_t)(words[i] >> 16);
        bytes[j + 3] = (uint8_t)(words[i] >> 24);
        bytes[j + 4] = (uint8_t)(words[i] >> 32);
        bytes[j + 5] = (uint8_t)(words[i] >> 40);
        bytes[j + 6] = (uint8_t)(words[i] >> 48);
        bytes[j + 7] = (uint8_t)(words[i] >> 56);
        j += 8;
    }
}

/**
* Convert  give the bytes in words
* words is a multiple of block size in words
* bytes is a multiple of block size in bytes
*
*  @param bytes  the input bytes
*  @param words  the output words
*  @param numbytes  the lenght of bytes
*/
MAVLINK_HELPER void BytesToWords64(uint8_t bytes[], uint64_t words[], int numbytes)
{
    int i, j = 0;
    for (i = 0; i < numbytes / 8; i++)
    {
        words[i] = (uint64_t)bytes[j] | ((uint64_t)bytes[j + 1] << 8) | ((uint64_t)bytes[j + 2] << 16) |
                   ((uint64_t)bytes[j + 3] << 24) | ((uint64_t)bytes[j + 4] << 32) | ((uint64_t)bytes[j + 5] << 40) |
                   ((uint64_t)bytes[j + 6] << 48) | ((uint64_t)bytes[j + 7] << 56);
        j += 8;
    }
}
/*
* Support function for ctr mode
*/
MAVLINK_HELPER void byteAdd(uint8_t *dst, int dstLength, uint8_t *count)
{
    int carry = 0;

    for (int i = 0; i < dstLength; i++)
    {
        uint8_t odst = dst[i];
        uint8_t osrc = i < dstLength ? count[i] : (uint8_t)0;

        int ndst = (uint8_t)(odst + osrc + carry);
        dst[i] = ndst;
        carry = ndst < odst ? 1 : 0;
    }
}

MAVLINK_HELPER void xored(uint8_t *in, uint8_t *out, int length)
{
    for (int i = 0; i < length; i++)
    {
        out[i] ^= in[i];
    }
}

MAVLINK_HELPER void hex_print(uint8_t *pv, uint16_t s, uint16_t len)
{
    uint8_t *p = pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        unsigned int i;
        for (i = s; i < len; ++i)
            printf("%02x ", p[i]);
    }
    printf("\n\n");
}
#endif
