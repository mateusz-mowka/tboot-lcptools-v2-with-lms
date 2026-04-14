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
  if (NULL == hash) {
    fprintf (stderr, "crypto_hash_buffer called with NULL hash parameter\n");
    return crypto_nullptr_error;
  }

  if ((NULL == buf) && (size != 0)) {
    fprintf (stderr, "crypto_hash_buffer called with NULL buf and non-zero size\n");
    return crypto_nullptr_error;
  }

  /* size == 0 is valid: produces the hash of an empty message */
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
  if (NULL == file) {
    fprintf (stderr, "crypto_read_ecdsa_pubkey called with file == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == qx) {
    fprintf (stderr, "crypto_read_ecdsa_pubkey called with qx == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == qy) {
    fprintf (stderr, "crypto_read_ecdsa_pubkey called with qy == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == key_size_bytes) {
    fprintf (stderr, "crypto_read_ecdsa_pubkey called with key_size_bytes == NULL\n");
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
  if (NULL == sig_block) {
    fprintf (stderr, "crypto_rsa_sign called with sig_block == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == digest) {
    fprintf (stderr, "crypto_rsa_sign called with digest == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == privkey_file) {
    fprintf (stderr, "crypto_rsa_sign called with privkey_file == NULL\n");
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
  if (NULL == data) {
    fprintf (stderr, "crypto_verify_rsa_signature called with data == NULL\n");
    return false;
  }

  if (NULL == pubkey) {
    fprintf (stderr, "crypto_verify_rsa_signature called with pubkey == NULL\n");
    return false;
  }

  if (NULL == signature) {
    fprintf (stderr, "crypto_verify_rsa_signature called with signature == NULL\n");
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
  if (NULL == data) {
    fprintf (stderr, "crypto_verify_ec_signature called with data == NULL\n");
    return false;
  }

  if (NULL == pubkey_x) {
    fprintf (stderr, "crypto_verify_ec_signature called with pubkey_x == NULL\n");
    return false;
  }

  if (NULL == pubkey_y) {
    fprintf (stderr, "crypto_verify_ec_signature called with pubkey_y == NULL\n");
    return false;
  }

  if (NULL == sig_r) {
    fprintf (stderr, "crypto_verify_ec_signature called with sig_r == NULL\n");
    return false;
  }

  if (NULL == sig_s) {
    fprintf (stderr, "crypto_verify_ec_signature called with sig_s == NULL\n");
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
  if (NULL == data) {
    fprintf (stderr, "crypto_ec_sign_data called with data == NULL\n");
    return false;
  }

  if (NULL == r) {
    fprintf (stderr, "crypto_ec_sign_data called with r == NULL\n");
    return false;
  }

  if (NULL == s) {
    fprintf (stderr, "crypto_ec_sign_data called with s == NULL\n");
    return false;
  }

  if (NULL == privkey_file) {
    fprintf (stderr, "crypto_ec_sign_data called with privkey_file == NULL\n");
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
  if (NULL == msg) {
    fprintf (stderr, "crypto_lms_verify_signature called with msg == NULL\n");
    return false;
  }

  if (NULL == signature) {
    fprintf (stderr, "crypto_lms_verify_signature called with signature == NULL\n");
    return false;
  }

  if (NULL == public_key) {
    fprintf (stderr, "crypto_lms_verify_signature called with public_key == NULL\n");
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
  if (NULL == msg) {
    fprintf (stderr, "crypto_lms_sign_data called with msg == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == signature) {
    fprintf (stderr, "crypto_lms_sign_data called with signature == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == sig_len) {
    fprintf (stderr, "crypto_lms_sign_data called with sig_len == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == privkey_file) {
    fprintf (stderr, "crypto_lms_sign_data called with privkey_file == NULL\n");
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
  if (NULL == msg) {
    fprintf (stderr, "crypto_mldsa_verify_signature called with msg == NULL\n");
    return false;
  }

  if (NULL == signature) {
    fprintf (stderr, "crypto_mldsa_verify_signature called with signature == NULL\n");
    return false;
  }

  if (NULL == public_key) {
    fprintf (stderr, "crypto_mldsa_verify_signature called with public_key == NULL\n");
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
  if (NULL == msg) {
    fprintf (stderr, "crypto_mldsa_sign_data called with msg == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == signature) {
    fprintf (stderr, "crypto_mldsa_sign_data called with signature == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == sig_len) {
    fprintf (stderr, "crypto_mldsa_sign_data called with sig_len == NULL\n");
    return crypto_nullptr_error;
  }

  if (NULL == privkey_file) {
    fprintf (stderr, "crypto_mldsa_sign_data called with privkey_file == NULL\n");
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
  if (NULL == file) {
    fprintf (stderr, "crypto_read_mldsa_pubkey called with file == NULL\n");
    return false;
  }

  if (NULL == pubkey) {
    fprintf (stderr, "crypto_read_mldsa_pubkey called with pubkey == NULL\n");
    return false;
  }

  return crypto_read_mldsa_pubkey_internal (file, pubkey, pubkey_size);
}
