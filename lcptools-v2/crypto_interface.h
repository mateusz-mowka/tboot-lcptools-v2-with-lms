#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "crypto.h"

crypto_status
crypto_hash_buffer_internal (
  const unsigned char  *buf,
  size_t               size,
  unsigned char        *hash,
  uint16_t             hash_alg
  );

crypto_status
crypto_read_rsa_pubkey_internal (
  const char     *file,
  unsigned char  **key,
  size_t         *keysize
  );

crypto_status
crypto_read_ecdsa_pubkey_internal (
  const char  *file,
  uint8_t     **qx,
  uint8_t     **qy,
  size_t      *key_size_bytes
  );

crypto_status
crypto_rsa_sign_internal (
  crypto_sized_buffer  *sig_block,
  crypto_sized_buffer  *digest,
  uint16_t             sig_alg,
  uint16_t             hash_alg,
  const char           *privkey_file
  );

bool
crypto_verify_rsa_signature_internal (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey,
  crypto_sized_buffer  *signature,
  uint16_t             hashAlg,
  uint16_t             sig_alg,
  uint16_t             list_ver
  );

bool
crypto_verify_ec_signature_internal (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey_x,
  crypto_sized_buffer  *pubkey_y,
  crypto_sized_buffer  *sig_r,
  crypto_sized_buffer  *sig_s,
  uint16_t             sigalg,
  uint16_t             hashalg
  );

bool
crypto_ec_sign_data_internal (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *r,
  crypto_sized_buffer  *s,
  uint16_t             sigalg,
  uint16_t             hashalg,
  const char           *privkey_file
  );
