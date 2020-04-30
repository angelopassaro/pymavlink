#pragma once

#ifndef _FOURQ_RANDOM_H
#define _FOURQ_RANDOM_H
/***********************************************************************************

* FourQlib: a high-performance crypto library based on the elliptic curve FourQ

*

*    Copyright (c) Microsoft Corporation. All rights reserved.

*

* Abstract: pseudo-random function

************************************************************************************/
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

static int lock = -1;

static __inline void delay(unsigned int count)

{

    while (count--)
    {
    }
}

MAVLINK_HELPER int random_bytes(unsigned char *random_array, unsigned int nbytes)

{ // Generation of "nbytes" of random values

    int r, n = nbytes, count = 0;

    if (lock == -1)
    {

        do
        {

            lock = open("/dev/urandom", O_RDONLY);

            if (lock == -1)
            {

                delay(0xFFFFF);
            }

        } while (lock == -1);
    }

    while (n > 0)
    {

        do
        {

            r = read(lock, random_array + count, n);

            if (r == -1)
            {

                delay(0xFFFF);
            }

        } while (r == -1);

        count += r;

        n -= r;
    }

    return true;
}
#endif