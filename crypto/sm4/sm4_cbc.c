#include <openssl/sm4.h>

#include "../fipsmodule/modes/internal.h"
#include "internal.h"


void SM4_cbc_encrypt_ex(const uint8_t *in, uint8_t *out, size_t length, const SM4_KEY *key, uint8_t *ivec, const int enc)
{
  if (enc)
    CRYPTO_sm4_cbc128_encrypt(in,
                              out,
                              length,
                              key,
                              ivec,
                              (sm4_block128_f) ossl_sm4_encrypt);
else
    CRYPTO_sm4_cbc128_decrypt(in,
                              out,
                              length,
                              key,
                              ivec,
                              (sm4_block128_f) ossl_sm4_decrypt);
}
