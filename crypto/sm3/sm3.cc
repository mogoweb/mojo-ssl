// Copyright 2024 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/sm3.h>

#include <string.h>

#include "../internal.h"


// SM3 initial values (GM/T 0004-2012)
static const uint32_t kIV[8] = {
    0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
    0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL,
};

#define ROTATE(x, n) bssl::CRYPTO_rotl_u32(x, n)

#define P0(x) ((x) ^ ROTATE((x), 9) ^ ROTATE((x), 17))
#define P1(x) ((x) ^ ROTATE((x), 15) ^ ROTATE((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))

#define FF1(x, y, z) (((x) & (y)) | ((x | y) & (z)))
#define GG1(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))

#define EXPAND(W0, W7, W13, W3, W10) \
    (P1((W0) ^ (W7) ^ ROTATE((W13), 15)) ^ ROTATE((W3), 7) ^ (W10))

#define RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF, GG) \
    do { \
      uint32_t A12 = ROTATE(A, 12); \
      uint32_t SS1 = ROTATE(A12 + E + TJ, 7); \
      uint32_t SS2 = SS1 ^ A12; \
      uint32_t TT1 = FF(A, B, C) + D + SS2 + (Wj); \
      uint32_t TT2 = GG(E, F, G) + H + SS1 + (Wi); \
      B = ROTATE(B, 9); \
      D = TT1; \
      F = ROTATE(F, 19); \
      H = P0(TT2); \
    } while (0)

#define R1(A, B, C, D, E, F, G, H, TJ, Wi, Wj) \
    RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF0, GG0)

#define R2(A, B, C, D, E, F, G, H, TJ, Wi, Wj) \
    RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF1, GG1)

// Load 32-bit big-endian word
static inline uint32_t load_u32_be(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

// Store 32-bit big-endian word
static inline void store_u32_be(uint8_t *p, uint32_t x) {
  p[0] = static_cast<uint8_t>(x >> 24);
  p[1] = static_cast<uint8_t>(x >> 16);
  p[2] = static_cast<uint8_t>(x >> 8);
  p[3] = static_cast<uint8_t>(x);
}

// SM3 compression function - matches Tongsuo implementation exactly
static void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
  uint32_t A, B, C, D, E, F, G, H;
  uint32_t W00, W01, W02, W03, W04, W05, W06, W07;
  uint32_t W08, W09, W10, W11, W12, W13, W14, W15;

  A = state[0];
  B = state[1];
  C = state[2];
  D = state[3];
  E = state[4];
  F = state[5];
  G = state[6];
  H = state[7];

  // Load message words (big-endian)
  const uint8_t *data = block;
  W00 = load_u32_be(data); data += 4;
  W01 = load_u32_be(data); data += 4;
  W02 = load_u32_be(data); data += 4;
  W03 = load_u32_be(data); data += 4;
  W04 = load_u32_be(data); data += 4;
  W05 = load_u32_be(data); data += 4;
  W06 = load_u32_be(data); data += 4;
  W07 = load_u32_be(data); data += 4;
  W08 = load_u32_be(data); data += 4;
  W09 = load_u32_be(data); data += 4;
  W10 = load_u32_be(data); data += 4;
  W11 = load_u32_be(data); data += 4;
  W12 = load_u32_be(data); data += 4;
  W13 = load_u32_be(data); data += 4;
  W14 = load_u32_be(data); data += 4;
  W15 = load_u32_be(data);

  // 16 rounds with FF0/GG0
  R1(A, B, C, D, E, F, G, H, 0x79CC4519, W00, W00 ^ W04);
  W00 = EXPAND(W00, W07, W13, W03, W10);
  R1(D, A, B, C, H, E, F, G, 0xF3988A32, W01, W01 ^ W05);
  W01 = EXPAND(W01, W08, W14, W04, W11);
  R1(C, D, A, B, G, H, E, F, 0xE7311465, W02, W02 ^ W06);
  W02 = EXPAND(W02, W09, W15, W05, W12);
  R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W03, W03 ^ W07);
  W03 = EXPAND(W03, W10, W00, W06, W13);
  R1(A, B, C, D, E, F, G, H, 0x9CC45197, W04, W04 ^ W08);
  W04 = EXPAND(W04, W11, W01, W07, W14);
  R1(D, A, B, C, H, E, F, G, 0x3988A32F, W05, W05 ^ W09);
  W05 = EXPAND(W05, W12, W02, W08, W15);
  R1(C, D, A, B, G, H, E, F, 0x7311465E, W06, W06 ^ W10);
  W06 = EXPAND(W06, W13, W03, W09, W00);
  R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W07, W07 ^ W11);
  W07 = EXPAND(W07, W14, W04, W10, W01);
  R1(A, B, C, D, E, F, G, H, 0xCC451979, W08, W08 ^ W12);
  W08 = EXPAND(W08, W15, W05, W11, W02);
  R1(D, A, B, C, H, E, F, G, 0x988A32F3, W09, W09 ^ W13);
  W09 = EXPAND(W09, W00, W06, W12, W03);
  R1(C, D, A, B, G, H, E, F, 0x311465E7, W10, W10 ^ W14);
  W10 = EXPAND(W10, W01, W07, W13, W04);
  R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W11, W11 ^ W15);
  W11 = EXPAND(W11, W02, W08, W14, W05);
  R1(A, B, C, D, E, F, G, H, 0xC451979C, W12, W12 ^ W00);
  W12 = EXPAND(W12, W03, W09, W15, W06);
  R1(D, A, B, C, H, E, F, G, 0x88A32F39, W13, W13 ^ W01);
  W13 = EXPAND(W13, W04, W10, W00, W07);
  R1(C, D, A, B, G, H, E, F, 0x11465E73, W14, W14 ^ W02);
  W14 = EXPAND(W14, W05, W11, W01, W08);
  R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W15, W15 ^ W03);
  W15 = EXPAND(W15, W06, W12, W02, W09);

  // 48 rounds with FF1/GG1
  R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
  W00 = EXPAND(W00, W07, W13, W03, W10);
  R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
  W01 = EXPAND(W01, W08, W14, W04, W11);
  R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
  W02 = EXPAND(W02, W09, W15, W05, W12);
  R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
  W03 = EXPAND(W03, W10, W00, W06, W13);
  R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
  W04 = EXPAND(W04, W11, W01, W07, W14);
  R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
  W05 = EXPAND(W05, W12, W02, W08, W15);
  R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
  W06 = EXPAND(W06, W13, W03, W09, W00);
  R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
  W07 = EXPAND(W07, W14, W04, W10, W01);
  R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
  W08 = EXPAND(W08, W15, W05, W11, W02);
  R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
  W09 = EXPAND(W09, W00, W06, W12, W03);
  R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
  W10 = EXPAND(W10, W01, W07, W13, W04);
  R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
  W11 = EXPAND(W11, W02, W08, W14, W05);
  R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
  W12 = EXPAND(W12, W03, W09, W15, W06);
  R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
  W13 = EXPAND(W13, W04, W10, W00, W07);
  R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
  W14 = EXPAND(W14, W05, W11, W01, W08);
  R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);
  W15 = EXPAND(W15, W06, W12, W02, W09);
  R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W00, W00 ^ W04);
  W00 = EXPAND(W00, W07, W13, W03, W10);
  R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W01, W01 ^ W05);
  W01 = EXPAND(W01, W08, W14, W04, W11);
  R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W02, W02 ^ W06);
  W02 = EXPAND(W02, W09, W15, W05, W12);
  R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W03, W03 ^ W07);
  W03 = EXPAND(W03, W10, W00, W06, W13);
  R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W04, W04 ^ W08);
  W04 = EXPAND(W04, W11, W01, W07, W14);
  R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W05, W05 ^ W09);
  W05 = EXPAND(W05, W12, W02, W08, W15);
  R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W06, W06 ^ W10);
  W06 = EXPAND(W06, W13, W03, W09, W00);
  R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W07, W07 ^ W11);
  W07 = EXPAND(W07, W14, W04, W10, W01);
  R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W08, W08 ^ W12);
  W08 = EXPAND(W08, W15, W05, W11, W02);
  R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W09, W09 ^ W13);
  W09 = EXPAND(W09, W00, W06, W12, W03);
  R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W10, W10 ^ W14);
  W10 = EXPAND(W10, W01, W07, W13, W04);
  R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W11, W11 ^ W15);
  W11 = EXPAND(W11, W02, W08, W14, W05);
  R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W12, W12 ^ W00);
  W12 = EXPAND(W12, W03, W09, W15, W06);
  R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W13, W13 ^ W01);
  W13 = EXPAND(W13, W04, W10, W00, W07);
  R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W14, W14 ^ W02);
  W14 = EXPAND(W14, W05, W11, W01, W08);
  R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W15, W15 ^ W03);
  W15 = EXPAND(W15, W06, W12, W02, W09);
  R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
  W00 = EXPAND(W00, W07, W13, W03, W10);
  R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
  W01 = EXPAND(W01, W08, W14, W04, W11);
  R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
  W02 = EXPAND(W02, W09, W15, W05, W12);
  R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
  W03 = EXPAND(W03, W10, W00, W06, W13);
  R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
  R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
  R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
  R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
  R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
  R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
  R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
  R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
  R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
  R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
  R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
  R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);

  // Update state
  state[0] ^= A;
  state[1] ^= B;
  state[2] ^= C;
  state[3] ^= D;
  state[4] ^= E;
  state[5] ^= F;
  state[6] ^= G;
  state[7] ^= H;
}

int SM3_Init(SM3_CTX *ctx) {
  bssl::OPENSSL_memset(ctx, 0, sizeof(*ctx));
  for (int i = 0; i < 8; i++) {
    ctx->h[i] = kIV[i];
  }
  return 1;
}

int SM3_Update(SM3_CTX *ctx, const void *data, size_t len) {
  if (len == 0) {
    return 1;
  }

  const uint8_t *in = static_cast<const uint8_t *>(data);
  size_t todo;

  if (ctx->num != 0) {
    todo = SM3_CBLOCK - ctx->num;
    if (todo > len) {
      todo = len;
    }
    bssl::OPENSSL_memcpy(&ctx->data[ctx->num], in, todo);
    ctx->num += todo;
    in += todo;
    len -= todo;

    if (ctx->num == SM3_CBLOCK) {
      sm3_compress(ctx->h, ctx->data);
      ctx->num = 0;

      uint64_t bits = SM3_CBLOCK * 8;
      ctx->Nh += (bits >> 32) + ((ctx->Nl + (bits & 0xffffffff)) < ctx->Nl);
      ctx->Nl += bits & 0xffffffff;
    }
  }

  while (len >= SM3_CBLOCK) {
    sm3_compress(ctx->h, in);
    in += SM3_CBLOCK;
    len -= SM3_CBLOCK;

    uint64_t bits = SM3_CBLOCK * 8;
    ctx->Nh += (bits >> 32) + ((ctx->Nl + (bits & 0xffffffff)) < ctx->Nl);
    ctx->Nl += bits & 0xffffffff;
  }

  if (len > 0) {
    bssl::OPENSSL_memcpy(ctx->data, in, len);
    ctx->num = len;
  }

  return 1;
}

int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *ctx) {
  uint32_t low = ctx->Nl;
  uint32_t high = ctx->Nh;

  uint64_t bits = ctx->num * 8;
  high += (bits >> 32) + ((low + (bits & 0xffffffff)) < low);
  low += bits & 0xffffffff;

  size_t pad = (ctx->num < 56) ? (56 - ctx->num) : (120 - ctx->num);

  uint8_t padding[128] = {0x80};

  SM3_Update(ctx, padding, pad);

  uint8_t length[8];
  store_u32_be(length, high);
  store_u32_be(length + 4, low);
  SM3_Update(ctx, length, 8);

  for (int i = 0; i < 8; i++) {
    store_u32_be(out + 4 * i, ctx->h[i]);
  }

  return 1;
}

void SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  SM3_CTX ctx;
  SM3_Init(&ctx);
  SM3_Update(&ctx, data, len);
  SM3_Final(out, &ctx);
}
