/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/sm3.h>

#define DATA_ORDER_IS_BIG_ENDIAN

#define HASH_LONG               SM3_WORD
#define HASH_CTX                SM3_CTX
#define HASH_CBLOCK             SM3_CBLOCK
#define HASH_UPDATE             SM3_Update
#define HASH_TRANSFORM          SM3_Transform
#define HASH_FINAL              SM3_Final
#define HASH_MAKE_STRING(c, s)              \
      do {                                  \
        unsigned long ll;                   \
        ll=(c)->A; (void)HOST_l2c(ll, (s)); \
        ll=(c)->B; (void)HOST_l2c(ll, (s)); \
        ll=(c)->C; (void)HOST_l2c(ll, (s)); \
        ll=(c)->D; (void)HOST_l2c(ll, (s)); \
        ll=(c)->E; (void)HOST_l2c(ll, (s)); \
        ll=(c)->F; (void)HOST_l2c(ll, (s)); \
        ll=(c)->G; (void)HOST_l2c(ll, (s)); \
        ll=(c)->H; (void)HOST_l2c(ll, (s)); \
      } while (0)

#if defined(OPENSSL_SM3_ASM)
# if defined(__aarch64__)
#  include "crypto/arm_arch.h"
#  define HWSM3_CAPABLE (OPENSSL_armcap_P & ARMV8_SM3)
void ossl_hwsm3_block_data_order(SM3_CTX *c, const void *p, size_t num);
# endif
#endif

#if defined(HWSM3_CAPABLE)
# define HASH_BLOCK_DATA_ORDER (HWSM3_CAPABLE ? ossl_hwsm3_block_data_order \
                                              : ossl_sm3_block_data_order)
#else
# define HASH_BLOCK_DATA_ORDER   ossl_sm3_block_data_order
#endif

void ossl_sm3_block_data_order(SM3_CTX *c, const void *p, size_t num);

#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

#if defined(DATA_ORDER_IS_BIG_ENDIAN)

# define HOST_c2l(c,l)  (l =(((unsigned long)(*((c)++)))<<24),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))    )           )
# define HOST_l2c(l,c)  (*((c)++)=(unsigned char)(((l)>>24)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)    )&0xff),      \
                         l)

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

# define HOST_c2l(c,l)  (l =(((unsigned long)(*((c)++)))    ),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<<24)           )
# define HOST_l2c(l,c)  (*((c)++)=(unsigned char)(((l)    )&0xff),      \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff),      \
                         l)

#endif

/*
 * Time for some action :-)
 */

int HASH_UPDATE(HASH_CTX *c, const void *data_, size_t len)
{
  const unsigned char *data = data_;
  unsigned char *p;
  HASH_LONG l;
  size_t n;

  if (len == 0)
    return 1;

  l = (c->Nl + (((HASH_LONG) len) << 3)) & 0xffffffffUL;
  if (l < c->Nl)              /* overflow */
    c->Nh++;
  c->Nh += (HASH_LONG) (len >> 29); /* might cause compiler warning on
                                      * 16-bit */
  c->Nl = l;

  n = c->num;
  if (n != 0) {
    p = (unsigned char *)c->data;

    if (len >= HASH_CBLOCK || len + n >= HASH_CBLOCK) {
      memcpy(p + n, data, HASH_CBLOCK - n);
      HASH_BLOCK_DATA_ORDER(c, p, 1);
      n = HASH_CBLOCK - n;
      data += n;
      len -= n;
      c->num = 0;
      /*
        * We use memset rather than OPENSSL_cleanse() here deliberately.
        * Using OPENSSL_cleanse() here could be a performance issue. It
        * will get properly cleansed on finalisation so this isn't a
        * security problem.
        */
      memset(p, 0, HASH_CBLOCK); /* keep it zeroed */
    } else {
      memcpy(p + n, data, len);
      c->num += (unsigned int)len;
      return 1;
    }
  }

  n = len / HASH_CBLOCK;
  if (n > 0) {
    HASH_BLOCK_DATA_ORDER(c, data, n);
    n *= HASH_CBLOCK;
    data += n;
    len -= n;
  }

  if (len != 0) {
    p = (unsigned char *)c->data;
    c->num = (unsigned int)len;
    memcpy(p, data, len);
  }
  return 1;
}

void HASH_TRANSFORM(HASH_CTX *c, const unsigned char *data)
{
  HASH_BLOCK_DATA_ORDER(c, data, 1);
}

int HASH_FINAL(unsigned char *md, HASH_CTX *c)
{
  unsigned char *p = (unsigned char *)c->data;
  size_t n = c->num;

  p[n] = 0x80;                /* there is always room for one */
  n++;

  if (n > (HASH_CBLOCK - 8)) {
    memset(p + n, 0, HASH_CBLOCK - n);
    n = 0;
    HASH_BLOCK_DATA_ORDER(c, p, 1);
  }
  memset(p + n, 0, HASH_CBLOCK - 8 - n);

  p += HASH_CBLOCK - 8;
#if   defined(DATA_ORDER_IS_BIG_ENDIAN)
  (void)HOST_l2c(c->Nh, p);
  (void)HOST_l2c(c->Nl, p);
#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)
  (void)HOST_l2c(c->Nl, p);
  (void)HOST_l2c(c->Nh, p);
#endif
  p -= HASH_CBLOCK;
  HASH_BLOCK_DATA_ORDER(c, p, 1);
  c->num = 0;
  OPENSSL_cleanse(p, HASH_CBLOCK);

#ifndef HASH_MAKE_STRING
# error "HASH_MAKE_STRING must be defined!"
#else
  HASH_MAKE_STRING(c, md);
#endif

  return 1;
}

#ifndef MD32_REG_T
# if defined(__alpha) || defined(__mips)
#  define MD32_REG_T long
/*
 * This comment was originally written for MD5, which is why it
 * discusses A-D. But it basically applies to all 32-bit digests,
 * which is why it was moved to common header file.
 *
 * In case you wonder why A-D are declared as long and not
 * as MD5_LONG. Doing so results in slight performance
 * boost on LP64 architectures. The catch is we don't
 * really care if 32 MSBs of a 64-bit register get polluted
 * with eventual overflows as we *save* only 32 LSBs in
 * *either* case. Now declaring 'em long excuses the compiler
 * from keeping 32 MSBs zeroed resulting in 13% performance
 * improvement under SPARC Solaris7/64 and 5% under AlphaLinux.
 * Well, to be honest it should say that this *prevents*
 * performance degradation.
 */
# else
/*
 * Above is not absolute and there are LP64 compilers that
 * generate better code if MD32_REG_T is defined int. The above
 * pre-processor condition reflects the circumstances under which
 * the conclusion was made and is subject to further extension.
 */
#  define MD32_REG_T int
# endif
#endif

#define P0(X) (X ^ ROTATE(X, 9) ^ ROTATE(X, 17))
#define P1(X) (X ^ ROTATE(X, 15) ^ ROTATE(X, 23))

#define FF0(X,Y,Z) (X ^ Y ^ Z)
#define GG0(X,Y,Z) (X ^ Y ^ Z)

#define FF1(X,Y,Z) ((X & Y) | ((X | Y) & Z))
#define GG1(X,Y,Z) ((Z ^ (X & (Y ^ Z))))

#define EXPAND(W0,W7,W13,W3,W10) \
   (P1(W0 ^ W7 ^ ROTATE(W13, 15)) ^ ROTATE(W3, 7) ^ W10)

#define RND(A, B, C, D, E, F, G, H, TJ, Wi, Wj, FF, GG)           \
     do {                                                         \
       const SM3_WORD A12 = ROTATE(A, 12);                        \
       const SM3_WORD A12_SM = A12 + E + TJ;                      \
       const SM3_WORD SS1 = ROTATE(A12_SM, 7);                    \
       const SM3_WORD TT1 = FF(A, B, C) + D + (SS1 ^ A12) + (Wj); \
       const SM3_WORD TT2 = GG(E, F, G) + H + SS1 + Wi;           \
       B = ROTATE(B, 9);                                          \
       D = TT1;                                                   \
       F = ROTATE(F, 19);                                         \
       H = P0(TT2);                                               \
     } while(0)

#define R1(A,B,C,D,E,F,G,H,TJ,Wi,Wj) \
   RND(A,B,C,D,E,F,G,H,TJ,Wi,Wj,FF0,GG0)

#define R2(A,B,C,D,E,F,G,H,TJ,Wi,Wj) \
   RND(A,B,C,D,E,F,G,H,TJ,Wi,Wj,FF1,GG1)

#define SM3_A 0x7380166fUL
#define SM3_B 0x4914b2b9UL
#define SM3_C 0x172442d7UL
#define SM3_D 0xda8a0600UL
#define SM3_E 0xa96f30bcUL
#define SM3_F 0x163138aaUL
#define SM3_G 0xe38dee4dUL
#define SM3_H 0xb0fb0e4eUL
