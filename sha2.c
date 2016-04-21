//
//  SHA2 Code Borrowed from Breadwallet. Copyright included below:
//
//  Created by Aaron Voisine on 8/16/15.
//  Copyright (c) 2015 breadwallet LLC.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#include <stdint.h>
#include <ntsid.h>
#include <string.h>
#include "sha2.h"

#if defined(__cplusplus)
extern "C"
{
#endif

// bitwise right rotation
#define ror32(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

// basic sha2 functions
#define ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// basic sha256 functions
#define s0(x) (ror32((x), 2) ^ ror32((x), 13) ^ ror32((x), 22))
#define s1(x) (ror32((x), 6) ^ ror32((x), 11) ^ ror32((x), 25))
#define s2(x) (ror32((x), 7) ^ ror32((x), 18) ^ ((x) >> 3))
#define s3(x) (ror32((x), 17) ^ ror32((x), 19) ^ ((x) >> 10))

static void _BRSHA256Compress(uint32_t *r, uint32_t *x)
{
    static const uint32_t k[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    size_t i;
    uint32_t a = r[0], b = r[1], c = r[2], d = r[3], e = r[4], f = r[5], g = r[6], h = r[7], t1, t2, w[64];

    for (i = 0; i < 16; i++) w[i] = be32(x[i]);
    for (; i < 64; i++) w[i] = s3(w[i - 2]) + w[i - 7] + s2(w[i - 15]) + w[i - 16];

    for (i = 0; i < 64; i++) {
        t1 = h + s1(e) + ch(e, f, g) + k[i] + w[i];
        t2 = s0(a) + maj(a, b, c);
        h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }

    r[0] += a, r[1] += b, r[2] += c, r[3] += d, r[4] += e, r[5] += f, r[6] += g, r[7] += h;
    a = b = c = d = e = f = g = h = t1 = t2 = 0;
    memset(w, 0, sizeof(w));
}

void BRSHA224(void *md28, const void *data, size_t len) {
    size_t i;
    uint32_t x[16], buf[] = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511,
                             0x64f98fa7, 0xbefa4fa4}; // initial buffer values

    for (i = 0; i < len; i += 64) { // process data in 64 byte blocks
        memcpy(x, (const uint8_t *)data + i, (i + 64 < len) ? 64 : len - i);
        if (i + 64 > len) break;
        _BRSHA256Compress(buf, x);
    }

    memset((uint8_t *)x + (len - i), 0, 64 - (len - i)); // clear remainder of x
    ((uint8_t *)x)[len - i] = 0x80; // append padding
    if (len - i >= 56) _BRSHA256Compress(buf, x), memset(x, 0, 64); // length goes to next block
    *(uint64_t *)&x[14] = be64((uint64_t)len*8); // append length in bits
    _BRSHA256Compress(buf, x); // finalize
    for (i = 0; i < 7; i++) ((uint32_t *)md28)[i] = be32(buf[i]); // write to md
    memset(x, 0, sizeof(x));
    memset(buf, 0, sizeof(buf));
}

void BRSHA256(void *md32, const void *data, size_t len)
{
    size_t i;
    uint32_t x[16], buf[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }; // initial buffer values
    
    for (i = 0; i < len; i += 64) { // process data in 64 byte blocks
        memcpy(x, (const uint8_t *)data + i, (i + 64 < len) ? 64 : len - i);
        if (i + 64 > len) break;
        _BRSHA256Compress(buf, x);
    }
    
    memset((uint8_t *)x + (len - i), 0, 64 - (len - i)); // clear remainder of x
    ((uint8_t *)x)[len - i] = 0x80; // append padding
    if (len - i >= 56) _BRSHA256Compress(buf, x), memset(x, 0, 64); // length goes to next block
    *(uint64_t *)&x[14] = be64((uint64_t)len*8); // append length in bits
    _BRSHA256Compress(buf, x); // finalize
    for (i = 0; i < 8; i++) ((uint32_t *)md32)[i] = be32(buf[i]); // write to md
    memset(x, 0, sizeof(x));
    memset(buf, 0, sizeof(buf));
}
#if defined(__cplusplus)
}
#endif