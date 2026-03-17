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
  if ((NULL == buf) || (NULL == hash)) {
    fprintf (stderr, "crypto_hash_buffer called with NULL parameter\n");
    return crypto_nullptr_error;
  }

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
    fprintf (stderr, "crypto_read_rsa_pubkey called with filename == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == keysize) {
    fprintf (stderr, "crypto_read_rsa_pubkey called with *keysize == NULL\n");
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
  if ((NULL == file) || (NULL == qx) || (NULL == qy) || (NULL == key_size_bytes)) {
    fprintf (stderr, "crypto_read_ecdsa_pubkey called with NULL parameter\n");
    return crypto_nullptr_error;
  }

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
  if ((NULL == sig_block) || (NULL == digest) || (NULL == privkey_file)) {
    fprintf (stderr, "crypto_rsa_sign called with NULL parameter\n");
    return crypto_nullptr_error;
  }

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
  if ((NULL == data) || (NULL == pubkey) || (NULL == signature)) {
    fprintf (stderr, "crypto_verify_rsa_signature called with NULL parameter\n");
    return false;
  }

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
  if ((NULL == data) || (NULL == pubkey_x) || (NULL == pubkey_y) ||
      (NULL == sig_r) || (NULL == sig_s)) {
    fprintf (stderr, "crypto_verify_ec_signature called with NULL parameter\n");
    return false;
  }

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
  if ((NULL == data) || (NULL == r) || (NULL == s) || (NULL == privkey_file)) {
    fprintf (stderr, "crypto_ec_sign_data called with NULL parameter\n");
    return false;
  }

  return crypto_ec_sign_data_internal (data, r, s, sigalg, hashalg, privkey_file);
}

bool
crypto_lms_verify_signature (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len
  )
{
  if ((NULL == msg) || (NULL == signature) || (NULL == public_key)) {
    fprintf (stderr, "crypto_lms_verify_signature called with NULL parameter\n");
    return false;
  }

  return crypto_lms_verify_signature_internal (msg, msg_len, signature, sig_len, public_key, pubkey_len);
}

crypto_status
crypto_lms_sign_data (
  const unsigned char  *msg,
  size_t               msg_len,
  unsigned char        *signature,
  size_t               *sig_len,
  const char           *privkey_file,
  const unsigned char  *aux_data,
  size_t               aux_len
  )
{
  if ((NULL == msg) || (NULL == signature) || (NULL == sig_len) || (NULL == privkey_file)) {
    fprintf (stderr, "crypto_lms_sign_data called with NULL parameter\n");
    return crypto_nullptr_error;
  }

  return crypto_lms_sign_data_internal (msg, msg_len, signature, sig_len, privkey_file, aux_data, aux_len);
}

bool
crypto_mldsa_verify_signature (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len
  )
{
  if ((NULL == msg) || (NULL == signature) || (NULL == public_key)) {
    fprintf (stderr, "crypto_mldsa_verify_signature called with NULL parameter\n");
    return false;
  }

  return crypto_mldsa_verify_signature_internal (msg, msg_len, signature, sig_len, public_key, pubkey_len);
}

crypto_status
crypto_mldsa_sign_data (
  const unsigned char  *msg,
  size_t               msg_len,
  unsigned char        *signature,
  size_t               *sig_len,
  const char           *privkey_file
  )
{
  if ((NULL == msg) || (NULL == signature) || (NULL == sig_len) || (NULL == privkey_file)) {
    fprintf (stderr, "crypto_mldsa_sign_data called with NULL parameter\n");
    return crypto_nullptr_error;
  }

  return crypto_mldsa_sign_data_internal (msg, msg_len, signature, sig_len, privkey_file);
}

bool
crypto_read_mldsa_pubkey (
  const char     *file,
  unsigned char  *pubkey,
  size_t         pubkey_size
  )
{
  if ((NULL == file) || (NULL == pubkey)) {
    fprintf (stderr, "crypto_read_mldsa_pubkey called with NULL parameter\n");
    return false;
  }

  return crypto_read_mldsa_pubkey_internal (file, pubkey, pubkey_size);
}
