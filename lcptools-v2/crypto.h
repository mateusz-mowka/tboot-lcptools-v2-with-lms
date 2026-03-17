#pragma once

#define CRYPTO_SHA1_LENGTH    20
#define CRYPTO_SHA256_LENGTH  32
#define CRYPTO_SM3_LENGTH     32
#define CRYPTO_SHA384_LENGTH  48
#define CRYPTO_SHA512_LENGTH  64
#define MAX_RSA_KEY_SIZE         0x180
#define MIN_RSA_KEY_SIZE         0x100
#define MAX_ECC_KEY_SIZE         0x30
#define MIN_ECC_KEY_SIZE         0x20

#ifndef __packed
#define __packed   __attribute__ ((packed))
#endif

typedef struct __packed {
    uint8_t  Version;
    uint16_t KeySize; //IN BITS - 2048 or 3072!
    uint32_t Exponent;
    uint8_t  Modulus[MAX_RSA_KEY_SIZE];
} rsa_public_key;

typedef struct __packed {
    uint8_t  Version;
    uint16_t KeySize; //IN BITS - 2048 or 3072!
    uint16_t HashAlg;
    uint8_t  Signature[MAX_RSA_KEY_SIZE];
} rsa_signature;

typedef struct __packed {
    uint8_t  Version;
    uint16_t KeySize; //IN BITS - 256 or 384!
    uint8_t  QxQy[2*MAX_ECC_KEY_SIZE];
} ecc_public_key;

typedef struct __packed {
    uint8_t Version;
    uint16_t KeySize; //IN BITS - 256 or 384!
    uint16_t HashAlg;
    uint8_t  sigRsigS[2*MAX_ECC_KEY_SIZE];
} ecc_signature;

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
  crypto_crypto_operation_fail,
  crypto_not_supported
} crypto_status;

typedef struct {
  size_t           size;
  unsigned char   *data;
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

bool
crypto_lms_verify_signature (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len
  );

crypto_status
crypto_lms_sign_data (
  const unsigned char  *msg,
  size_t               msg_len,
  unsigned char        *signature,
  size_t               *sig_len,
  const char           *privkey_file,
  const unsigned char  *aux_data,
  size_t               aux_len
  );

bool
crypto_mldsa_verify_signature (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len
  );

crypto_status
crypto_mldsa_sign_data (
  const unsigned char  *msg,
  size_t               msg_len,
  unsigned char        *signature,
  size_t               *sig_len,
  const char           *privkey_file
  );

bool
crypto_read_mldsa_pubkey (
  const char     *file,
  unsigned char  *pubkey,
  size_t         pubkey_size
  );
