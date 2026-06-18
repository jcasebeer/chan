// md5.h - single-header MD5 (RFC 1321), public domain.
//
// One-shot API:
//   unsigned char digest[16];
//   md5_buf(data, len, digest);          // raw 16-byte digest
//   char hex[33];
//   md5_hex(data, len, hex);             // lowercase hex string (NUL-terminated)
//
// Implementation follows the reference algorithm; verified against the standard
// test vectors (e.g. "" => d41d8cd98f00b204e9800998ecf8427e, "abc" => 900150...).
#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Per-round left-rotate amounts.
static const uint32_t MD5_S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// Constants: floor(abs(sin(i + 1)) * 2^32).
static const uint32_t MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static inline uint32_t md5_rotl(uint32_t x, uint32_t c) {
  return (x << c) | (x >> (32 - c));
}

// Process one 64-byte block at `p` into the running state a0..d0.
static inline void md5_block(const unsigned char *p, uint32_t *a0, uint32_t *b0,
                             uint32_t *c0, uint32_t *d0) {
  uint32_t M[16];
  for (int i = 0; i < 16; i++) {
    M[i] = (uint32_t) p[i * 4] | ((uint32_t) p[i * 4 + 1] << 8) |
           ((uint32_t) p[i * 4 + 2] << 16) | ((uint32_t) p[i * 4 + 3] << 24);
  }
  uint32_t A = *a0, B = *b0, C = *c0, D = *d0;
  for (int i = 0; i < 64; i++) {
    uint32_t F;
    int g;
    if (i < 16) {
      F = (B & C) | (~B & D);
      g = i;
    } else if (i < 32) {
      F = (D & B) | (~D & C);
      g = (5 * i + 1) & 15;
    } else if (i < 48) {
      F = B ^ C ^ D;
      g = (3 * i + 5) & 15;
    } else {
      F = C ^ (B | ~D);
      g = (7 * i) & 15;
    }
    F = F + A + MD5_K[i] + M[g];
    A = D;
    D = C;
    C = B;
    B = B + md5_rotl(F, MD5_S[i]);
  }
  *a0 += A;
  *b0 += B;
  *c0 += C;
  *d0 += D;
}

// Compute the MD5 digest of `data`/`len` into the 16-byte `out`.
static inline void md5_buf(const void *data, size_t len, unsigned char out[16]) {
  uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const unsigned char *msg = (const unsigned char *) data;

  // Process all complete 64-byte blocks directly from the input.
  size_t full = len & ~(size_t) 63;
  for (size_t off = 0; off < full; off += 64)
    md5_block(msg + off, &a0, &b0, &c0, &d0);

  // Final block(s): remaining bytes + 0x80 padding + 64-bit bit length.
  unsigned char tail[128];
  size_t rem = len - full;
  memcpy(tail, msg + full, rem);
  tail[rem] = 0x80;
  size_t padlen = (rem + 1 <= 56) ? 64 : 128;  // room for 8-byte length
  memset(tail + rem + 1, 0, padlen - rem - 1 - 8);
  uint64_t bits = (uint64_t) len * 8;
  for (int i = 0; i < 8; i++) tail[padlen - 8 + i] = (unsigned char) (bits >> (8 * i));
  for (size_t off = 0; off < padlen; off += 64)
    md5_block(tail + off, &a0, &b0, &c0, &d0);

  uint32_t v[4] = {a0, b0, c0, d0};
  for (int i = 0; i < 4; i++) {
    out[i * 4] = (unsigned char) v[i];
    out[i * 4 + 1] = (unsigned char) (v[i] >> 8);
    out[i * 4 + 2] = (unsigned char) (v[i] >> 16);
    out[i * 4 + 3] = (unsigned char) (v[i] >> 24);
  }
}

// Compute the MD5 of `data`/`len` as a 32-char lowercase hex string (+NUL).
static inline void md5_hex(const void *data, size_t len, char out[33]) {
  unsigned char d[16];
  md5_buf(data, len, d);
  static const char *hx = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    out[i * 2] = hx[d[i] >> 4];
    out[i * 2 + 1] = hx[d[i] & 15];
  }
  out[32] = '\0';
}

#endif  // MD5_H
