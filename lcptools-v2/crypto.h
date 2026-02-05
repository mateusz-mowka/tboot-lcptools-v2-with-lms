#pragma once

#include "../include/lcp3.h"

#define CRYPTO_SHA1_LENGTH    20
#define CRYPTO_SHA256_LENGTH  32
#define CRYPTO_SM3_LENGTH     32
#define CRYPTO_SHA384_LENGTH  48
#define CRYPTO_SHA512_LENGTH  64

typedef enum {
  crypto_ok,
  crypto_general_fail,
  crypto_unknown_hashalg,
  crypto_unknown_signalg,
  crypto_nullptr_error,
  crypto_invalid_size,
  crypto_memory_alloc_fail,
  crypto_file_io_error,
  crypto_invalid_key,
  crypto_buffer_too_small,
  crypto_crypto_operation_fail
} crypto_status;

typedef struct {
  size_t           size;
  unsigned char    data[];
} crypto_sized_buffer;

crypto_status
crypto_hash_buffer (
  const unsigned char  *buf,
  size_t               size,
  unsigned char        *hash,
  uint16_t             hash_alg
  );

crypto_status
crypto_read_rsa_pubkey (
  const char     *file,
  unsigned char  **key,
  size_t         *keysize
  );

crypto_status
crypto_read_ecdsa_pubkey (
  const char  *file,
  uint8_t     **qx,
  uint8_t     **qy,
  size_t      *key_size_bytes
  );

crypto_status
crypto_rsa_sign (
  crypto_sized_buffer  *sig_block,
  crypto_sized_buffer  *digest,
  uint16_t             sig_alg,
  uint16_t             hash_alg,
  const char           *privkey_file
  );

bool
crypto_verify_rsa_signature (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey,
  crypto_sized_buffer  *signature,
  uint16_t             hashAlg,
  uint16_t             sig_alg,
  uint16_t             list_ver
  );

bool
crypto_verify_ec_signature (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey_x,
  crypto_sized_buffer  *pubkey_y,
  crypto_sized_buffer  *sig_r,
  crypto_sized_buffer  *sig_s,
  uint16_t             sigalg,
  uint16_t             hashalg
  );

bool
crypto_ec_sign_data (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *r,
  crypto_sized_buffer  *s,
  uint16_t             sigalg,
  uint16_t             hashalg,
  const char           *privkey_file
  );
