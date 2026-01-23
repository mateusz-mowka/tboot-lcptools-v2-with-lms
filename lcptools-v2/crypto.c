#include "crypto_interface.h"
#include "crypto.h"
#include "../include/hash.h"
#include <stdio.h>

crypto_status
crypto_hash_buffer (
  const unsigned char  *buf,
  size_t               size,
  unsigned char        *hash,
  uint16_t             hash_alg
  )
{
  return crypto_hash_buffer_internal (buf, size, hash, hash_alg);
}

crypto_status
crypto_read_rsa_pubkey (
  const char     *file,
  unsigned char  **key,
  size_t         *keysize
  )
{
  if (NULL == file) {
    printf ("crypto_read_rsa_pubkey called with filename == NULL");
    return crypto_nullptr_error;
  }

  if (NULL == keysize) {
    printf ("crypto_read_rsa_pubkey called with *keysize == NULL");
    return crypto_nullptr_error;
  }

  return crypto_read_rsa_pubkey_internal (file, key, keysize);
}

crypto_status
crypto_read_ecdsa_pubkey (
  const char  *file,
  uint8_t     **qx,
  uint8_t     **qy,
  size_t      *key_size_bytes
  )
{
  return crypto_read_ecdsa_pubkey_internal (file, qx, qy, key_size_bytes);
}

crypto_status
crypto_rsa_sign (
  crypto_sized_buffer  *sig_block,
  crypto_sized_buffer  *digest,
  uint16_t             sig_alg,
  uint16_t             hash_alg,
  const char           *privkey_file
  )
{
  return crypto_rsa_sign_internal (sig_block, digest, sig_alg, hash_alg, privkey_file);
}

bool
crypto_verify_rsa_signature (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey,
  crypto_sized_buffer  *signature,
  uint16_t             hashAlg,
  uint16_t             sig_alg,
  uint16_t             list_ver
  )
{
  return crypto_verify_rsa_signature_internal (data, pubkey, signature, hashAlg, sig_alg, list_ver);
}

bool
crypto_verify_ec_signature (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey_x,
  crypto_sized_buffer  *pubkey_y,
  crypto_sized_buffer  *sig_r,
  crypto_sized_buffer  *sig_s,
  uint16_t             sigalg,
  uint16_t             hashalg
  )
{
  return crypto_verify_ec_signature_internal (data, pubkey_x, pubkey_y, sig_r, sig_s, sigalg, hashalg);
}

bool
crypto_ec_sign_data (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *r,
  crypto_sized_buffer  *s,
  uint16_t             sigalg,
  uint16_t             hashalg,
  const char           *privkey_file
  )
{
  return crypto_ec_sign_data_internal (data, r, s, sigalg, hashalg, privkey_file);
}
