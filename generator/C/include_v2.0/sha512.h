#ifndef _FOUR_SHA_512
#define _FOUR_SHA_512

typedef unsigned long long uint64;

static inline uint64 load_bigendian(const unsigned char *x)

{

    return (uint64)(x[7]) | (((uint64)(x[6])) << 8) | (((uint64)(x[5])) << 16) | (((uint64)(x[4])) << 24) | (((uint64)(x[3])) << 32) | (((uint64)(x[2])) << 40) | (((uint64)(x[1])) << 48) | (((uint64)(x[0])) << 56);
}

MAVLINK_HELPER void store_bigendian(unsigned char *x, uint64 u)

{

    x[7] = (unsigned char)u;
    u >>= 8;

    x[6] = (unsigned char)u;
    u >>= 8;

    x[5] = (unsigned char)u;
    u >>= 8;

    x[4] = (unsigned char)u;
    u >>= 8;

    x[3] = (unsigned char)u;
    u >>= 8;

    x[2] = (unsigned char)u;
    u >>= 8;

    x[1] = (unsigned char)u;
    u >>= 8;

    x[0] = (unsigned char)u;
}

#define SHR(x, c) ((x) >> (c))

#define ROTR512(x, c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch512(x, y, z) ((x & y) ^ (~x & z))

#define Maj512(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

#define Sigma0512(x) (ROTR512(x, 28) ^ ROTR512(x, 34) ^ ROTR512(x, 39))

#define Sigma1512(x) (ROTR512(x, 14) ^ ROTR512(x, 18) ^ ROTR512(x, 41))

#define sigma0512(x) (ROTR512(x, 1) ^ ROTR512(x, 8) ^ SHR(x, 7))

#define sigma1512(x) (ROTR512(x, 19) ^ ROTR512(x, 61) ^ SHR(x, 6))

#define M512(w0, w14, w9, w1) w0 = sigma1512(w14) + w9 + sigma0512(w1) + w0;

#define EXPAND             \
    M512(w0, w14, w9, w1)  \
    M512(w1, w15, w10, w2) \
    M512(w2, w0, w11, w3)  \
    M512(w3, w1, w12, w4)  \
    M512(w4, w2, w13, w5)  \
    M512(w5, w3, w14, w6)  \
    M512(w6, w4, w15, w7)  \
    M512(w7, w5, w0, w8)   \
    M512(w8, w6, w1, w9)   \
    M512(w9, w7, w2, w10)  \
    M512(w10, w8, w3, w11) M512(w11, w9, w4, w12) M512(w12, w10, w5, w13) M512(w13, w11, w6, w14) M512(w14, w12, w7, w15) M512(w15, w13, w8, w0)
#define F512(w, k)                                  \
    T1 = h + Sigma1512(e) + Ch512(e, f, g) + k + w; \
    T2 = Sigma0512(a) + Maj512(a, b, c);            \
    h = g;                                          \
    g = f;                                          \
    f = e;                                          \
    e = d + T1;                                     \
    d = c;                                          \
    c = b;                                          \
    b = a;                                          \
    a = T1 + T2;

MAVLINK_HELPER int crypto_hashblocks_sha512(unsigned char *statebytes, const unsigned char *in, unsigned long long inlen)

{

    uint64 state[8];

    uint64 a;

    uint64 b;

    uint64 c;

    uint64 d;

    uint64 e;

    uint64 f;

    uint64 g;

    uint64 h;

    uint64 T1;

    uint64 T2;

    a = load_bigendian(statebytes + 0);
    state[0] = a;

    b = load_bigendian(statebytes + 8);
    state[1] = b;

    c = load_bigendian(statebytes + 16);
    state[2] = c;

    d = load_bigendian(statebytes + 24);
    state[3] = d;

    e = load_bigendian(statebytes + 32);
    state[4] = e;

    f = load_bigendian(statebytes + 40);
    state[5] = f;

    g = load_bigendian(statebytes + 48);
    state[6] = g;

    h = load_bigendian(statebytes + 56);
    state[7] = h;

    while (inlen >= 128)
    {

        uint64 w0 = load_bigendian(in + 0);

        uint64 w1 = load_bigendian(in + 8);

        uint64 w2 = load_bigendian(in + 16);

        uint64 w3 = load_bigendian(in + 24);

        uint64 w4 = load_bigendian(in + 32);

        uint64 w5 = load_bigendian(in + 40);

        uint64 w6 = load_bigendian(in + 48);

        uint64 w7 = load_bigendian(in + 56);

        uint64 w8 = load_bigendian(in + 64);

        uint64 w9 = load_bigendian(in + 72);

        uint64 w10 = load_bigendian(in + 80);

        uint64 w11 = load_bigendian(in + 88);

        uint64 w12 = load_bigendian(in + 96);

        uint64 w13 = load_bigendian(in + 104);

        uint64 w14 = load_bigendian(in + 112);

        uint64 w15 = load_bigendian(in + 120);

        F512(w0, 0x428a2f98d728ae22ULL)

        F512(w1, 0x7137449123ef65cdULL)

        F512(w2, 0xb5c0fbcfec4d3b2fULL)

        F512(w3, 0xe9b5dba58189dbbcULL)

        F512(w4, 0x3956c25bf348b538ULL)

        F512(w5, 0x59f111f1b605d019ULL)

        F512(w6, 0x923f82a4af194f9bULL)

        F512(w7, 0xab1c5ed5da6d8118ULL)

        F512(w8, 0xd807aa98a3030242ULL)

        F512(w9, 0x12835b0145706fbeULL)

        F512(w10, 0x243185be4ee4b28cULL)

        F512(w11, 0x550c7dc3d5ffb4e2ULL)

        F512(w12, 0x72be5d74f27b896fULL)

        F512(w13, 0x80deb1fe3b1696b1ULL)

        F512(w14, 0x9bdc06a725c71235ULL)

        F512(w15, 0xc19bf174cf692694ULL)

        EXPAND

        F512(w0, 0xe49b69c19ef14ad2ULL)

        F512(w1, 0xefbe4786384f25e3ULL)

        F512(w2, 0x0fc19dc68b8cd5b5ULL)

        F512(w3, 0x240ca1cc77ac9c65ULL)

        F512(w4, 0x2de92c6f592b0275ULL)

        F512(w5, 0x4a7484aa6ea6e483ULL)

        F512(w6, 0x5cb0a9dcbd41fbd4ULL)

        F512(w7, 0x76f988da831153b5ULL)

        F512(w8, 0x983e5152ee66dfabULL)

        F512(w9, 0xa831c66d2db43210ULL)

        F512(w10, 0xb00327c898fb213fULL)

        F512(w11, 0xbf597fc7beef0ee4ULL)

        F512(w12, 0xc6e00bf33da88fc2ULL)

        F512(w13, 0xd5a79147930aa725ULL)

        F512(w14, 0x06ca6351e003826fULL)

        F512(w15, 0x142929670a0e6e70ULL)

        EXPAND

        F512(w0, 0x27b70a8546d22ffcULL)

        F512(w1, 0x2e1b21385c26c926ULL)

        F512(w2, 0x4d2c6dfc5ac42aedULL)

        F512(w3, 0x53380d139d95b3dfULL)

        F512(w4, 0x650a73548baf63deULL)

        F512(w5, 0x766a0abb3c77b2a8ULL)

        F512(w6, 0x81c2c92e47edaee6ULL)

        F512(w7, 0x92722c851482353bULL)

        F512(w8, 0xa2bfe8a14cf10364ULL)

        F512(w9, 0xa81a664bbc423001ULL)

        F512(w10, 0xc24b8b70d0f89791ULL)

        F512(w11, 0xc76c51a30654be30ULL)

        F512(w12, 0xd192e819d6ef5218ULL)

        F512(w13, 0xd69906245565a910ULL)

        F512(w14, 0xf40e35855771202aULL)

        F512(w15, 0x106aa07032bbd1b8ULL)

        EXPAND

        F512(w0, 0x19a4c116b8d2d0c8ULL)

        F512(w1, 0x1e376c085141ab53ULL)

        F512(w2, 0x2748774cdf8eeb99ULL)

        F512(w3, 0x34b0bcb5e19b48a8ULL)

        F512(w4, 0x391c0cb3c5c95a63ULL)

        F512(w5, 0x4ed8aa4ae3418acbULL)

        F512(w6, 0x5b9cca4f7763e373ULL)

        F512(w7, 0x682e6ff3d6b2b8a3ULL)

        F512(w8, 0x748f82ee5defb2fcULL)

        F512(w9, 0x78a5636f43172f60ULL)

        F512(w10, 0x84c87814a1f0ab72ULL)

        F512(w11, 0x8cc702081a6439ecULL)

        F512(w12, 0x90befffa23631e28ULL)

        F512(w13, 0xa4506cebde82bde9ULL)

        F512(w14, 0xbef9a3f7b2c67915ULL)

        F512(w15, 0xc67178f2e372532bULL)

        EXPAND

        F512(w0, 0xca273eceea26619cULL)

        F512(w1, 0xd186b8c721c0c207ULL)

        F512(w2, 0xeada7dd6cde0eb1eULL)

        F512(w3, 0xf57d4f7fee6ed178ULL)

        F512(w4, 0x06f067aa72176fbaULL)

        F512(w5, 0x0a637dc5a2c898a6ULL)

        F512(w6, 0x113f9804bef90daeULL)

        F512(w7, 0x1b710b35131c471bULL)

        F512(w8, 0x28db77f523047d84ULL)

        F512(w9, 0x32caab7b40c72493ULL)

        F512(w10, 0x3c9ebe0a15c9bebcULL)

        F512(w11, 0x431d67c49c100d4cULL)

        F512(w12, 0x4cc5d4becb3e42b6ULL)

        F512(w13, 0x597f299cfc657e2aULL)

        F512(w14, 0x5fcb6fab3ad6faecULL)

        F512(w15, 0x6c44198c4a475817ULL)

        a += state[0];

        b += state[1];

        c += state[2];

        d += state[3];

        e += state[4];

        f += state[5];

        g += state[6];

        h += state[7];

        state[0] = a;

        state[1] = b;

        state[2] = c;

        state[3] = d;

        state[4] = e;

        state[5] = f;

        state[6] = g;

        state[7] = h;

        in += 128;

        inlen -= 128;
    }

    store_bigendian(statebytes + 0, state[0]);

    store_bigendian(statebytes + 8, state[1]);

    store_bigendian(statebytes + 16, state[2]);

    store_bigendian(statebytes + 24, state[3]);

    store_bigendian(statebytes + 32, state[4]);

    store_bigendian(statebytes + 40, state[5]);

    store_bigendian(statebytes + 48, state[6]);

    store_bigendian(statebytes + 56, state[7]);

    return (int)inlen;
}

static const unsigned char iv[64] = {

    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,

    0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,

    0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b,

    0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,

    0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1,

    0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,

    0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,

    0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79

};

typedef unsigned long long uint64;

MAVLINK_HELPER int crypto_sha512(const unsigned char *in, unsigned long long inlen, unsigned char *out)

{

    unsigned char h[64];

    unsigned char padded[256];

    int i;

    unsigned long long bytes = inlen;

    for (i = 0; i < 64; ++i)
        h[i] = iv[i];

    crypto_hashblocks_sha512(h, in, inlen);

    in += inlen;

    inlen &= 127;

    in -= inlen;

    for (i = 0; i < inlen; ++i)
        padded[i] = in[i];

    padded[inlen] = 0x80;

    if (inlen < 112)
    {

        for (i = (int)inlen + 1; i < 119; ++i)
            padded[i] = 0;

        padded[119] = (unsigned char)(bytes >> 61);

        padded[120] = (unsigned char)(bytes >> 53);

        padded[121] = (unsigned char)(bytes >> 45);

        padded[122] = (unsigned char)(bytes >> 37);

        padded[123] = (unsigned char)(bytes >> 29);

        padded[124] = (unsigned char)(bytes >> 21);

        padded[125] = (unsigned char)(bytes >> 13);

        padded[126] = (unsigned char)(bytes >> 5);

        padded[127] = (unsigned char)(bytes << 3);

        crypto_hashblocks_sha512(h, padded, 128);
    }
    else
    {

        for (i = (int)inlen + 1; i < 247; ++i)
            padded[i] = 0;

        padded[247] = (unsigned char)(bytes >> 61);

        padded[248] = (unsigned char)(bytes >> 53);

        padded[249] = (unsigned char)(bytes >> 45);

        padded[250] = (unsigned char)(bytes >> 37);

        padded[251] = (unsigned char)(bytes >> 29);

        padded[252] = (unsigned char)(bytes >> 21);

        padded[253] = (unsigned char)(bytes >> 13);

        padded[254] = (unsigned char)(bytes >> 5);

        padded[255] = (unsigned char)(bytes << 3);

        crypto_hashblocks_sha512(h, padded, 256);
    }

    for (i = 0; i < 64; ++i)
        out[i] = h[i];

    return 0;
}

#endif
