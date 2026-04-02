#ifndef USE_IPPC

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/decoder.h>
#include <openssl/core.h>
#include <openssl/param_build.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include "../include/hash.h"
#include "../include/lcp3.h"
#include "crypto_interface.h"
#include "safe_lib.h"
#include "lcputils.h"
#define LOG      printf
#define ERROR    printf
#define DISPLAY  printf
#define print_hex(prefix, data, n)  dump_hex(prefix, data, n, 16)

#define MAJOR_VER(v)  ((v) >> 8)
#define MINOR_VER(v)  ((v) & 0xff)
extern bool  verbose;

crypto_status
crypto_hash_buffer_internal (
  const unsigned char  *buf,
  size_t               size,
  unsigned char        *hash,
  uint16_t             hash_alg
  )
{
  if ( hash == NULL ) {
    return crypto_operation_fail;
  }

  EVP_MD_CTX    *ctx = EVP_MD_CTX_create ();
  const EVP_MD  *md;

  if (ctx == NULL) {
    return crypto_operation_fail;
  }

  switch (hash_alg) {
    case TB_HALG_SHA1_LG:
    case TB_HALG_SHA1:
      md = EVP_sha1 ();
      break;
    case TB_HALG_SHA256:
      md = EVP_sha256 ();
      break;
    case TB_HALG_SHA384:
      md = EVP_sha384 ();
      break;
    case TB_HALG_SHA512:
      md = EVP_sha512 ();
      break;
    case TB_HALG_SM3:
      md = EVP_sm3 ();
      break;
    default:
      EVP_MD_CTX_destroy (ctx);
      return crypto_unknown_hashalg;
  }

  EVP_DigestInit (ctx, md);
  EVP_DigestUpdate (ctx, buf, size);
  EVP_DigestFinal (ctx, hash, NULL);
  EVP_MD_CTX_destroy (ctx);
  return crypto_ok;
}

crypto_status
crypto_read_rsa_pubkey_internal (
  const char     *file,
  unsigned char  **key,
  size_t         *keysize
  )
{
  FILE    *fp      = NULL;
  BIGNUM  *modulus = NULL;

  EVP_PKEY  *pubkey = NULL;

  *key = NULL;

  printf ("read_rsa_pubkey_file_2_1\n");
  fp = fopen (file, "rb");
  if ( fp == NULL ) {
    printf (
            "Error: failed to open .pem file %s: %s\n",
            file,
            strerror (errno)
            );
    goto ERROR;
  }

  OSSL_DECODER_CTX  *dctx;
  dctx = OSSL_DECODER_CTX_new_for_pkey (&pubkey, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
  if ( dctx == NULL ) {
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_DECODER_from_fp (dctx, fp)) {
    OSSL_DECODER_CTX_free (dctx);
    goto OPENSSL_ERROR;
  }

  OSSL_DECODER_CTX_free (dctx);
  if ( pubkey == NULL ) {
    goto OPENSSL_ERROR;
  }

  // Close the file, won't need it anymore
  fclose (fp);
  fp = NULL;

  *keysize = (size_t)EVP_PKEY_get_size (pubkey);
  if ((*keysize != MIN_RSA_KEY_SIZE) && (*keysize != MAX_RSA_KEY_SIZE)) {
    printf ("Error: public key size %ld is not supported\n", *keysize);
    goto ERROR;
  }

  EVP_PKEY_get_bn_param (pubkey, "n", &modulus);
  if (modulus == NULL) {
    goto OPENSSL_ERROR;
  }

  // Allocate for the key
  *key = malloc (*keysize);
  if (*key == NULL) {
    printf ("Error: failed to allocate memory for public key.\n");
    goto ERROR;
  }

  // Save mod into key array
  size_t  result = 0;
  result = BN_bn2bin (modulus, *key);
  if ((result <= 0) || (result != *keysize)) {
    goto OPENSSL_ERROR;
  }

  // SUCCESS:
  EVP_PKEY_free(pubkey);
  BN_free(modulus);  /* owned copy from EVP_PKEY_get_bn_param */
  return crypto_ok;
OPENSSL_ERROR:
  printf ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  goto ERROR;
ERROR:
  if (fp != NULL) {
    fclose (fp);
  }

  if (*key != NULL) {
    free (*key);
  }

  if (modulus != NULL) {
    BN_free(modulus);  /* owned copy from EVP_PKEY_get_bn_param */
  }

  if (pubkey != NULL) {
  EVP_PKEY_free(pubkey);
  }

  return crypto_operation_fail;
}

crypto_status
crypto_read_ecdsa_pubkey_internal (
  const char  *file,
  uint8_t     **qx,
  uint8_t     **qy,
  size_t      *key_size_bytes
  )
{
  FILE    *fp = NULL;
  BIGNUM  *x  = NULL;
  BIGNUM  *y  = NULL;

  EVP_PKEY  *pubkey = NULL;

  *qx = NULL;
  *qy = NULL;

  LOG ("read ecdsa pubkey file for list signature.\n");
  fp = fopen (file, "rb");
  if ( fp == NULL) {
    ERROR ("ERROR: cannot open file.\n");
    goto ERROR;
  }

  OSSL_DECODER_CTX  *dctx;
  dctx = OSSL_DECODER_CTX_new_for_pkey (&pubkey, "PEM", NULL, "EC", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
  if ( dctx == NULL ) {
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_DECODER_from_fp (dctx, fp)) {
    OSSL_DECODER_CTX_free (dctx);
    goto OPENSSL_ERROR;
  }

  OSSL_DECODER_CTX_free (dctx);

  if ( pubkey == NULL ) {
    goto OPENSSL_ERROR;
  }

  fclose (fp);
  fp = NULL;

  EVP_PKEY_get_bn_param (pubkey, "qx", &x);
  EVP_PKEY_get_bn_param (pubkey, "qy", &y);
  if ((x == NULL) || (y == NULL)) {
    goto OPENSSL_ERROR;
  }

  /* Use the larger coordinate size to determine field width.  BN_num_bytes
     returns the minimum byte count, so a coordinate with a leading zero byte
     will report one fewer than the field size.  Taking the max ensures we
     use the correct field width (32 for P-256, 48 for P-384). */
  {
    int x_bytes = BN_num_bytes (x);
    int y_bytes = BN_num_bytes (y);
    *key_size_bytes = (x_bytes > y_bytes) ? (size_t)x_bytes : (size_t)y_bytes;
  }

  if ((*key_size_bytes != MIN_ECC_KEY_SIZE) && (*key_size_bytes != MAX_ECC_KEY_SIZE)) {
    ERROR (
           "ERROR: keySize 0x%X is not 0x%X or 0x%X.\n",
           (unsigned int)(*key_size_bytes),
           MIN_ECC_KEY_SIZE,
           MAX_ECC_KEY_SIZE
           );
    goto ERROR;
  }

  // BE arrays for data from openssl
  *qx = malloc (sizeof (lcp_ecc_signature_t) + (2*(*key_size_bytes)));
  if (*qx == NULL) {
    ERROR ("Failed to allocate memory for public key.\n");
    goto ERROR;
  }

  *qy = malloc (sizeof (lcp_ecc_signature_t) + (2*(*key_size_bytes)));
  if (*qy == NULL) {
    ERROR ("Failed to allocate memory for public key.\n");
    goto ERROR;
  }

  /* BN_bn2binpad writes exactly key_size_bytes, zero-padding coordinates
     that have fewer significant bytes than the field width. */
  if (!BN_bn2binpad (x, *qx, (int)(*key_size_bytes))) {
    goto OPENSSL_ERROR;
  }

  if (!BN_bn2binpad (y, *qy, (int)(*key_size_bytes))) {
    goto OPENSSL_ERROR;
  }

  // Flip BE to LE
  buffer_reverse_byte_order ((uint8_t *)*qx, (*key_size_bytes));
  buffer_reverse_byte_order ((uint8_t *)*qy, (*key_size_bytes));

  EVP_PKEY_free (pubkey);
  BN_free (x);
  BN_free (y);
  return crypto_ok;

  // Errors:
OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
ERROR:
  // Free all allocated mem
  if (fp != NULL) {
    fclose (fp);
  }

  if (*qx != NULL) {
    free (*qx);
  }

  if (*qy != NULL) {
    free (*qy);
  }

  if (pubkey != NULL) {
    EVP_PKEY_free (pubkey);
  }

  if (x != NULL) {
    BN_free (x);
  }

  if (y != NULL) {
    BN_free (y);
  }

  return crypto_operation_fail;
}

static EVP_PKEY_CTX *
rsa_get_sig_ctx (
  const char  *key_path,
  uint16_t    key_size_bytes
  )
{
  FILE          *fp       = NULL;
  EVP_PKEY      *evp_priv = NULL;
  EVP_PKEY_CTX  *context  = NULL; // This will be returned

  printf ("[rsa_get_sig_ctx]\n");
  fp = fopen (key_path, "r");
  if (fp == NULL) {
    goto ERROR;
  }

  evp_priv = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  if (evp_priv == NULL) {
    goto OPENSSL_ERROR;
  }

  fclose (fp);
  fp = NULL;

  if (EVP_PKEY_size (evp_priv) != key_size_bytes) {
    ERROR ("ERROR: key size incorrect\n");
    goto ERROR;
  }

  context = EVP_PKEY_CTX_new (evp_priv, NULL);
  if (context == NULL) {
    goto OPENSSL_ERROR;
  }

  EVP_PKEY_free (evp_priv);
  return context;

OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
ERROR:
  if (fp != NULL) {
    fclose (fp);
  }

  if (evp_priv != NULL) {
    EVP_PKEY_free (evp_priv);
  }

  if (context != NULL) {
    EVP_PKEY_CTX_free (context);
  }

  return NULL;
}

static bool
rsa_ssa_pss_sign (
  crypto_sized_buffer  *signature_block,
  crypto_sized_buffer  *data_to_sign,
  uint16_t             sig_alg,
  uint16_t             hash_alg,
  EVP_PKEY_CTX         *private_key_context
  )

/*
    This function: signs data using rsa private key context

    In: pointer to a correctly sized buffer to hold signature block, raw data
    to sign (will be hashed internally), hash alg used to hash data,
    Openssl private key context

    Out: true on success, false on failure. Also signature_block gets signature block data

*/
{
  printf ("[rsa_ssa_pss_sign]\n");
  int           result; // For openssl return codes
  size_t        siglen; // Holds length of signature returned by openssl must be 256 or 384
  const EVP_MD  *evp_hash_alg;
  uint8_t       hash_buf[SHA512_DIGEST_SIZE];
  size_t        digest_len;

  if ((signature_block == NULL) || (data_to_sign == NULL) || (private_key_context == NULL)) {
    printf ("Error: one or more data buffers is not defined.\n");
    return false;
  }

  /* Hash the raw data internally — callers now pass raw list data
   * instead of a pre-computed digest, for cross-backend compatibility. */
  digest_len = get_hash_size (hash_alg);
  if (digest_len == 0) {
    printf ("ERROR: unsupported hash algorithm 0x%04X\n", hash_alg);
    return false;
  }

  if (!hash_buffer (data_to_sign->data, data_to_sign->size,
                    (tb_hash_t *)hash_buf, hash_alg)) {
    printf ("ERROR: failed to hash data for RSA signing\n");
    return false;
  }

  // Init sig
  result = EVP_PKEY_sign_init (private_key_context);
  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

  switch (sig_alg) {
    case TPM_ALG_RSASSA:
      result = EVP_PKEY_CTX_set_rsa_padding (private_key_context, RSA_PKCS1_PADDING);
      break;
    case TPM_ALG_RSAPSS:
      result = EVP_PKEY_CTX_set_rsa_padding (private_key_context, RSA_PKCS1_PSS_PADDING);
      break;
    default:
      printf ("ERROR: unsupported signature algorithm.\n");
      return false;
  }

  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

  if (sig_alg == TPM_ALG_RSAPSS) {
    result = EVP_PKEY_CTX_set_rsa_pss_saltlen (private_key_context, -1);
    if (result <= 0) {
      goto OPENSSL_ERROR;
    }
  }

  switch (hash_alg) {
    case TB_HALG_SHA1_LG:
    case TB_HALG_SHA1:
      evp_hash_alg = EVP_sha1 ();
      break;
    case TB_HALG_SHA256:
      evp_hash_alg = EVP_sha256 ();
      break;
    case TB_HALG_SHA384:
      evp_hash_alg = EVP_sha384 ();
      break;
    default:
      printf ("Unsupported hash alg.\n");
      return false;
  }

  // Set signature md parameter
  result = EVP_PKEY_CTX_set_signature_md (private_key_context, evp_hash_alg);
  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

  // Calculate signature size (dry run)
  result = EVP_PKEY_sign (
                          private_key_context,
                          NULL,
                          &siglen,
                          hash_buf,
                          digest_len
                          );
  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

  if (siglen != signature_block->size) {
    printf ("ERROR: signature size incorrect.\n");
    return false;
  }

  // Do the signing
  result = EVP_PKEY_sign (
                          private_key_context,
                          signature_block->data,
                          &siglen,
                          hash_buf,
                          digest_len
                          );
  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

  // All good, function end
  OPENSSL_cleanse (hash_buf, sizeof (hash_buf));
  return true;

  // Error handling
OPENSSL_ERROR:
  printf ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  OPENSSL_cleanse (hash_buf, sizeof (hash_buf));
  return false;
}

crypto_status
crypto_rsa_sign_internal (
  crypto_sized_buffer  *sig_block,
  crypto_sized_buffer  *digest,
  uint16_t             sig_alg,
  uint16_t             hash_alg,
  const char           *privkey_file
  )
{
  EVP_PKEY_CTX  *context = NULL;   // Context for openssl functions
  bool sign_status = false;
  // Create context using key
  context = rsa_get_sig_ctx (privkey_file, sig_block->size);
  if ( context == NULL) {
    printf ("ERROR: failed to initialize EVP context.\n");
    return crypto_operation_fail;
  }

  // Sign
  sign_status = rsa_ssa_pss_sign (sig_block, digest, sig_alg, hash_alg, context);

  EVP_PKEY_CTX_free (context);

  return (sign_status == true ? crypto_ok : crypto_operation_fail);
}

static uint16_t
pkcs_get_hashalg (
  const unsigned char  *data
  )

/*
From:
http://mpqs.free.fr/h11300-pkcs-1v2-2-rsa-cryptography-standard-wp_EMC_Corporation_Public-Key_Cryptography_Standards_(PKCS).pdf#page=40
   EM=00∥01∥FF∥…∥FF∥00∥T - PKCS1.5 padding starts with 00 01 || 0xFF for padding ||
   00 || T - this is the DER encoded hash identifier and hash message
   T - SHA-1:       30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 ∥ H
   T - SHA-256:     30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 ∥ H
   T - SHA-384:     30 41 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 ∥ H
   T - SHA-512:     30 51 30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 ∥ H

   E.g.
   SHA-256
   30 31 - sequence 0x31 bytes
      30 0D - sequence 0x0D bytes
         06 09 - OID (object ID) - 9 bytes
            60 86 48 01 65 03 04 02 01 - OID: SHA-256: FIPS180-3
         05 00 - parameters and size
      04 20 - octet of strings size 0x20 bytes
         H  - hash of a secret message
*/
{
  uint8_t  der_oid = DER_TAG_OID;
  size_t   oid_size;

  if (data == NULL) {
    return TPM_ALG_NULL;
  }

  data += 2;   // Skip 00 01

  // Skip 0xFFs padding and 00 after it
  size_t max_skip = 256;
  size_t skip_count = 0;

  while (*data == 0xFF && skip_count < max_skip) {
    data++;
    skip_count++;
  }
  
  // After 0xFFs, expect a 0x00 delimiter
  if (*data != 0x00) {
    return TPM_ALG_NULL;
  }
  data++; // Move past 0x00

  // Then move to der_oid
  data += 4; // Already advanced one for 0x00 above
  if (*data != der_oid) {
    return TPM_ALG_NULL;
  }

  data += 1;
  // Read oid size:
  oid_size = *data;
  if (oid_size == 0x05) {
    return TPM_ALG_SHA1;     // Only Sha1 has this size
  }

  // Move to the last byte to see what alg is used
  data += oid_size;
  switch (*data) {
    case 0x01:
      return TPM_ALG_SHA256;
    case 0x02:
      return TPM_ALG_SHA384;
    case 0x03:
      return TPM_ALG_SHA512;
    default:
      return TPM_ALG_NULL;
  }
}

bool
crypto_verify_rsa_signature_internal (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey,
  crypto_sized_buffer  *signature,
  uint16_t             hashAlg,
  uint16_t             sig_alg,
  uint16_t             list_ver
  )
{
  int            status;
  EVP_PKEY_CTX   *evp_context   = NULL;
  EVP_PKEY       *evp_key       = NULL;
  BIGNUM         *modulus       = NULL;
  BIGNUM         *exponent      = NULL;
  tb_hash_t      *digest        = NULL;
  unsigned char  exp_arr[]      = { 0x01, 0x00, 0x01 };
  unsigned char  *decrypted_sig = NULL;

  size_t           dcpt_sig_len;
  OSSL_PARAM_BLD  *params_build = NULL;
  OSSL_PARAM      *params       = NULL;

  LOG ("[verify_rsa_signature]\n");
  if ((data == NULL) || (pubkey == NULL) || (signature == NULL)) {
    ERROR ("Error: list data, pubkey or signature buffer not defined.\n");
    return false;
  }

  modulus  = BN_bin2bn (pubkey->data, pubkey->size, NULL);
  exponent = BN_bin2bn (exp_arr, 3, NULL);
  if ((modulus == NULL) || (exponent == NULL)) {
    ERROR ("Error: failed to convert modulus and/or exponent.\n");
    goto OPENSSL_ERROR;
  }

  evp_context = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
  if ( evp_context == NULL) {
    ERROR ("Error: failed to initialize CTX from name.\n");
    goto OPENSSL_ERROR;
  }

  params_build = OSSL_PARAM_BLD_new ();
  if ( params_build == NULL ) {
    ERROR ("Error: failed to set up parameter builder.\n");
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_PARAM_BLD_push_BN (params_build, "n", modulus)) {
    ERROR ("Error: failed to push modulus into param build.\n");
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_PARAM_BLD_push_BN (params_build, "e", exponent)) {
    ERROR ("Error: failed to push exponent into param build.\n");
    goto OPENSSL_ERROR;
  }

  params = OSSL_PARAM_BLD_to_param (params_build);
  if ( params == NULL ) {
    ERROR ("Error: failed to construct parameters from builder.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_fromdata_init (evp_context) <= 0 ) {
    ERROR ("Error: failed to initialize key creation.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_fromdata (evp_context, &evp_key, EVP_PKEY_PUBLIC_KEY, params) <= 0 ) {
    ERROR ("Error: failed to create key.\n");
    goto OPENSSL_ERROR;
  }

  OSSL_PARAM_free (params);
  params = NULL;
  OSSL_PARAM_BLD_free (params_build);
  params_build = NULL;
  EVP_PKEY_CTX_free (evp_context);
  evp_context = NULL;

  if (MAJOR_VER (list_ver) != MAJOR_VER (LCP_TPM20_POLICY_LIST2_1_VERSION_300)) {

    evp_context = EVP_PKEY_CTX_new (evp_key, NULL);
    if ( evp_context == NULL ) {
      ERROR ("Error: failed to instatiate CTX.\n");
      goto OPENSSL_ERROR;
    }

    if ( EVP_PKEY_encrypt_init (evp_context) <= 0 ) {
      ERROR ("Error: failed to initialize signature decryption.\n");
      goto OPENSSL_ERROR;
    }

    if ( EVP_PKEY_CTX_set_rsa_padding (evp_context, RSA_NO_PADDING) <= 0 ) {
      ERROR ("Error: failed to set RSA padding.\n");
      goto OPENSSL_ERROR;
    }

    if ( EVP_PKEY_encrypt (evp_context, NULL, &dcpt_sig_len, signature->data, pubkey->size) <= 0 ) {
      ERROR ("Error: failed to retrieve decrypted signature length.\n");
      goto OPENSSL_ERROR;
    }

    decrypted_sig = OPENSSL_malloc (dcpt_sig_len);
    if ( decrypted_sig == NULL ) {
      ERROR ("Error: failed to allocate memory for decrypted signature.\n");
      status = 0;
      goto EXIT;
    }

    if ( EVP_PKEY_encrypt (evp_context, decrypted_sig, &dcpt_sig_len, signature->data, pubkey->size) <= 0 ) {
      ERROR ("Error: failed to decrypt signature.\n");
      goto OPENSSL_ERROR;
    }

    if ( verbose ) {
      LOG ("Decrypted signature: \n");
      print_hex ("", decrypted_sig, dcpt_sig_len);
    }

    EVP_PKEY_CTX_free (evp_context);
    evp_context = NULL;
    // In older lists we need to get hashAlg from signature data.
    hashAlg = pkcs_get_hashalg ((const unsigned char *)decrypted_sig);
    OPENSSL_free ((void *)decrypted_sig);
    decrypted_sig = NULL;
  }

  evp_context = EVP_PKEY_CTX_new (evp_key, NULL);
  if ( evp_context == NULL ) {
    ERROR ("Error: failed to initialize CTX from pkey.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_verify_init (evp_context) <= 0) {
    ERROR ("Error: failed to initialize verification.");
    goto OPENSSL_ERROR;
  }

  if ( sig_alg == TPM_ALG_RSAPSS) {
    status = EVP_PKEY_CTX_set_rsa_padding (evp_context, RSA_PKCS1_PSS_PADDING);
  } else if ((sig_alg == TPM_ALG_RSASSA) || (sig_alg == LCP_POLSALG_RSA_PKCS_15)) {
    status = EVP_PKEY_CTX_set_rsa_padding (evp_context, RSA_PKCS1_PADDING);
  } else {
    ERROR ("Error: unsupported signature algorithm.\n");
    status = 0;
    goto EXIT;
  }

  if ( status <= 0) {
    ERROR ("Error: failed to set rsa padding.\n");
    goto OPENSSL_ERROR;
  }

  if ( hashAlg == TPM_ALG_SHA1 ) {
    status = EVP_PKEY_CTX_set_signature_md (evp_context, EVP_sha1 ());
  } else if ( hashAlg == TPM_ALG_SHA256 ) {
    status = EVP_PKEY_CTX_set_signature_md (evp_context, EVP_sha256 ());
  } else if ( hashAlg == TPM_ALG_SHA384 ) {
    status = EVP_PKEY_CTX_set_signature_md (evp_context, EVP_sha384 ());
  } else {
    ERROR ("Error: Unknown hash alg.\n");
    status = 0;
    goto EXIT;
  }

  if ( status <= 0 ) {
    ERROR ("Error: failed to set signature message digest.\n");
    goto OPENSSL_ERROR;
  }

  digest = malloc (sizeof (tb_hash_t));
  if (digest == NULL) {
    ERROR ("Error: failed to allocate digest");
    status = 0;
    goto EXIT;
  }

  if ( !hash_buffer ((const unsigned char *)data->data, data->size, digest, hashAlg)) {
    ERROR ("Error: failed to hash list contents.\n");
    status = 0;
    goto EXIT;
  }

  status = EVP_PKEY_verify (evp_context, signature->data, signature->size, (const unsigned char *)digest, get_hash_size (hashAlg));
  if (status < 0) {
    /* Error occurred */
    goto OPENSSL_ERROR;
  } else {
    /* EVP_PKEY_verify returns 1=valid, 0=invalid; both fall through to EXIT */
    goto EXIT;
  }

OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  status = 0;
EXIT:
  if (params_build != NULL) {
    OSSL_PARAM_BLD_free (params_build);
  }

  if (params != NULL) {
    OSSL_PARAM_free (params);
  }

  if (evp_context != NULL) {
    EVP_PKEY_CTX_free (evp_context);
  }

  if (evp_key != NULL) {
    EVP_PKEY_free (evp_key);
  }

  if (modulus != NULL) {
    BN_free (modulus);
  }

  if (exponent != NULL) {
    BN_free (exponent);
  }

  if (digest != NULL) {
    free (digest);
  }

  if (decrypted_sig != NULL) {
    OPENSSL_free ((void *)decrypted_sig);
  }

  return status ? true : false;
}

static unsigned char *
der_encode_sig_comps (
  crypto_sized_buffer  *sig_r,
  crypto_sized_buffer  *sig_s,
  int                  *length
  )
{
  // Buffers for signature (will be passed to EVP_Verify):
  unsigned char  *der_encoded_sig = NULL;
  unsigned char  *helper_ptr      = NULL; // Will be adjusted by openssl api - orig value + sigsize
  ECDSA_SIG      *sig             = NULL;
  BIGNUM         *r;
  BIGNUM         *s;
  int            encoded_size = 0;

  LOG ("[der_encode_sig_comps]\n");
  r = BN_bin2bn (sig_r->data, sig_r->size, NULL);
  s = BN_bin2bn (sig_s->data, sig_s->size, NULL);
  if ((r == NULL) || (s == NULL)) {
    ERROR ("Error: failed to allocate signature componenst.\n");
    goto EXIT;
  }

  sig = ECDSA_SIG_new ();
  if (sig == NULL) {
    ERROR ("Error: failed to allocate signature structure.\n");
    goto EXIT;
  }

  if (!ECDSA_SIG_set0 (sig, r, s)) {
    ERROR ("Error: failed to set signature components.\n");
    goto EXIT;
  }

  encoded_size = i2d_ECDSA_SIG (sig, NULL);
  if (!encoded_size) {
    ERROR ("Error: failed to calculate the size of encoded buffer.\n");
    goto EXIT;
  }

  helper_ptr      = OPENSSL_malloc (encoded_size);
  if (helper_ptr == NULL) {
    ERROR ("Error: failed to allocate memory for encoded signature.\n");
    goto EXIT;
  }
  der_encoded_sig = helper_ptr;
  *length         = encoded_size;
  // i2d_ECDSA_SIG changes value of the pointer passed, that's why we first assigned
  // it to der_encoded_sig, which will hold the encoded_sig.
  if (!i2d_ECDSA_SIG (sig, &helper_ptr)) {
    ERROR ("Error: failed to encode signature.\n");
    OPENSSL_free (der_encoded_sig);
    der_encoded_sig = NULL;
    goto EXIT;
  }

EXIT:
  if (sig != NULL) {
    ECDSA_SIG_free (sig);
    // SIG_free also frees r and s
    r = NULL;
    s = NULL;
  }

  if (r != NULL) {
    BN_free (r);
  }

  if (s != NULL) {
    BN_free (s);
  }

  return der_encoded_sig;
}

bool
crypto_verify_ec_signature_internal (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *pubkey_x,
  crypto_sized_buffer  *pubkey_y,
  crypto_sized_buffer  *sig_r,
  crypto_sized_buffer  *sig_s,
  uint16_t             sigalg,
  uint16_t             hashalg
  )
{
  int                  result;
  BIGNUM               *x       = NULL;
  BIGNUM               *y       = NULL;
  EVP_PKEY             *evp_key = NULL;
  const EVP_MD         *mdtype;
  const unsigned char  *der_encoded_sig = NULL;
  int                  encoded_len;
  int                  curveId = 0;
  EVP_MD_CTX           *mctx   = NULL;
  EVP_PKEY_CTX         *pctx   = NULL;

  const EC_GROUP   *ec_group     = NULL;
  EC_POINT         *ec_point     = NULL;
  unsigned char    *point_buffer = NULL;
  size_t           pt_buf_len;
  BN_CTX           *bctx         = NULL;
  const char       *curveName    = NULL;
  EVP_PKEY_CTX     *fromdata_ctx   = NULL;
  OSSL_PARAM_BLD   *ec_params_build = NULL;
  OSSL_PARAM       *ec_params       = NULL;

  LOG ("[verify_ec_signature]\n");
  if ((data == NULL) || (pubkey_x == NULL) || (pubkey_y == NULL) || (sig_r == NULL) || (sig_s == NULL)) {
    ERROR ("Error: one or more buffers are not defined.\n");
    return false;
  }

  if ( hashalg == TPM_ALG_SM3_256 ) {
    curveId = NID_sm2;
    mdtype  = EVP_sm3 ();
    curveName = SN_sm2;
  } else if ( hashalg == TPM_ALG_SHA256 ) {
    curveId = NID_X9_62_prime256v1;
    mdtype  = EVP_sha256 ();
    curveName = SN_X9_62_prime256v1;
  } else if ( hashalg == TPM_ALG_SHA384 ) {
    curveId = NID_secp384r1;
    mdtype  = EVP_sha384 ();
    curveName = SN_secp384r1;
  } else {
    ERROR ("Error: unsupported hashalg.\n");
    result = 0;
    goto EXIT;
  }

  ec_group = EC_GROUP_new_by_curve_name (curveId);
  if ( ec_group == NULL ) {
    ERROR ("Error: failed to create new EC group.\n");
    goto OPENSSL_ERROR;
  }

  x = BN_bin2bn (pubkey_x->data, pubkey_x->size, NULL);
  y = BN_bin2bn (pubkey_y->data, pubkey_y->size, NULL);
  if ((x == NULL) || (y == NULL)) {
    ERROR ("Error: Failed to convert binary pubkey to BIGNUM x and/or y.\n");
    goto OPENSSL_ERROR;
  }

  ec_point = EC_POINT_new (ec_group);
  if ( ec_point == NULL ) {
    ERROR ("Error: failed to create new EC point.\n");
    goto OPENSSL_ERROR;
  }

  bctx = BN_CTX_new ();
  if ( bctx == NULL ) {
    ERROR ("Error: Failed to create BIGNUM context.\n");
    goto OPENSSL_ERROR;
  }

  if ( EC_POINT_set_affine_coordinates (ec_group, ec_point, x, y, bctx) <= 0 ) {
    ERROR ("Error: failed to set affine coordinates.\n");
    goto OPENSSL_ERROR;
  }

  BN_CTX_free (bctx);
  bctx = NULL;
  bctx = BN_CTX_new ();
  if ( bctx == NULL ) {
    ERROR ("Error: Failed to create BIGNUM context.\n");
    goto OPENSSL_ERROR;
  }

  pt_buf_len   = EC_POINT_point2oct (ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL, 0, bctx);
  if ( pt_buf_len == 0 ) {
    ERROR ("Error: failed to calculate point buffer length.\n");
    goto OPENSSL_ERROR;
  }
  point_buffer = OPENSSL_malloc (pt_buf_len);
  if ( point_buffer == NULL ) {
    ERROR ("Error: failed to allocate point buffer.\n");
    goto OPENSSL_ERROR;
  }

  if ( EC_POINT_point2oct (ec_group, ec_point, POINT_CONVERSION_COMPRESSED, point_buffer, pt_buf_len, bctx) <= 0 ) {
    ERROR ("Error: failed to convert EC point into octal string.\n");
    goto OPENSSL_ERROR;
  }

  fromdata_ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if ( fromdata_ctx == NULL ) {
    ERROR ("Error: failed to initialize key creation CTX.\n");
    goto OPENSSL_ERROR;
  }

  ec_params_build = OSSL_PARAM_BLD_new ();
  if ( ec_params_build == NULL ) {
    ERROR ("Error: failed to set up parameter builder.\n");
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_PARAM_BLD_push_utf8_string (ec_params_build, "group", curveName, 0)) {
    ERROR ("Error: failed to push group into param build.\n");
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_PARAM_BLD_push_octet_string (ec_params_build, "pub", point_buffer, pt_buf_len)) {
    ERROR ("Error: failed to push pubkey into param build.\n");
    goto OPENSSL_ERROR;
  }

  ec_params = OSSL_PARAM_BLD_to_param (ec_params_build);
  if ( ec_params == NULL ) {
    ERROR ("Error: failed to construct params from build.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_fromdata_init (fromdata_ctx) <= 0 ) {
    ERROR ("ERROR: failed to initialize key creation from data.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_fromdata (fromdata_ctx, &evp_key, EVP_PKEY_PUBLIC_KEY, ec_params) <= 0) {
    ERROR ("Error: failed to create EC_KEY.\n");
    result = 0;
    goto EXIT;
  }

  OSSL_PARAM_BLD_free (ec_params_build);
  ec_params_build = NULL;
  OSSL_PARAM_free (ec_params);
  ec_params = NULL;
  EVP_PKEY_CTX_free (fromdata_ctx);
  fromdata_ctx = NULL;
  BN_CTX_free (bctx);
  bctx = NULL;

  mctx = EVP_MD_CTX_new ();
  if (mctx == NULL) {
    ERROR ("Error: failed to generate message digest context.\n");
    result = 0;
    goto EXIT;
  }

  pctx = EVP_PKEY_CTX_new (evp_key, NULL);
  if (pctx == NULL) {
    ERROR ("Error: failed to generate key context.\n");
    result = 0;
    goto EXIT;
  }

  if (sigalg == TPM_ALG_SM2) {
    if ( EVP_PKEY_CTX_set1_id (pctx, SM2_ID, SM2_ID_LEN) <= 0 ) {
      ERROR ("Error: failed to set sm2 id.\n");
      goto OPENSSL_ERROR;
    }
  }

  EVP_MD_CTX_set_pkey_ctx (mctx, pctx);
  der_encoded_sig = der_encode_sig_comps (sig_r, sig_s, &encoded_len);
  if (der_encoded_sig == NULL) {
    ERROR ("Error: failed to DER encode signature components.\n");
    result = 0;
    goto EXIT;
  }

  if ( EVP_DigestVerifyInit (mctx, NULL, mdtype, NULL, evp_key) <= 0 ) {
    ERROR ("Error: error while verifying (init).\n");
    goto OPENSSL_ERROR;
  }

  if ( verbose ) {
    LOG ("Data that was signed:\n");
    print_hex ("    ", data->data, data->size);
  }

  if ( EVP_DigestVerifyUpdate (mctx, data->data, data->size) <= 0) {
    ERROR ("Error: error while verifying (update).\n");
    goto OPENSSL_ERROR;
  }

  result = EVP_DigestVerifyFinal (mctx, der_encoded_sig, encoded_len);
  if (result < 0) {
    ERROR ("Error: error while verifying (final)\tError code = %d.\n", result);
    goto OPENSSL_ERROR;
  }

  goto EXIT;
OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  result = 0;
EXIT:
  // cleanup:
  if (ec_point != NULL) {
    EC_POINT_free (ec_point);
  }

  if (point_buffer != NULL) {
    OPENSSL_free (point_buffer);  /* allocated with OPENSSL_malloc */
  }

  if (ec_params_build != NULL) {
    OSSL_PARAM_BLD_free (ec_params_build);
  }

  if (ec_params != NULL) {
    OSSL_PARAM_free (ec_params);
  }

  if (fromdata_ctx != NULL) {
    EVP_PKEY_CTX_free (fromdata_ctx);
  }

  if (bctx != NULL) {
    BN_CTX_free (bctx);
  }

  if (ec_group != NULL) {
    EC_GROUP_free ((EC_GROUP *)ec_group);
  }

  if (evp_key != NULL) {
    EVP_PKEY_free (evp_key);
  }

  if (x != NULL) {
    BN_free (x);
  }

  if (y != NULL) {
    BN_free (y);
  }

  if (der_encoded_sig != NULL) {
    OPENSSL_free ((void *)der_encoded_sig);  /* allocated by OPENSSL_malloc */
  }

  if (mctx != NULL) {
    EVP_MD_CTX_free (mctx);
  }

  if (pctx != NULL) {
    EVP_PKEY_CTX_free (pctx);
  }

  return result ? true : false;
}

bool
crypto_ec_sign_data_internal (
  crypto_sized_buffer  *data,
  crypto_sized_buffer  *r,
  crypto_sized_buffer  *s,
  uint16_t             sigalg,
  uint16_t             hashalg,
  const char           *privkey_file
  )
{
  int                  result;
  size_t               sig_length;
  EVP_PKEY             *evp_key         = NULL;
  EVP_MD_CTX           *mctx            = NULL;
  EVP_PKEY_CTX         *pctx            = NULL;
  FILE                 *fp              = NULL;
  ECDSA_SIG            *ecdsa_sig       = NULL;
  const BIGNUM         *sig_r           = NULL; // Is freed when ECDSA_SIG is freed
  const BIGNUM         *sig_s           = NULL; // Is freed when ECDSA_SIG is freed
  const unsigned char  *signature_block = NULL;
  const unsigned char  *signature_block_orig = NULL; /* to track OPENSSL_malloc'd ptr */

  LOG ("[ec_sign_data]\n");
  if ((data == NULL) || (r == NULL) || (s == NULL)) {
    ERROR ("Error: one or more data buffers not defined.\n");
    return false;
  }

  mctx = EVP_MD_CTX_new ();
  if (mctx == NULL) {
    ERROR ("Error: failed to allocate message digest context.\n");
    goto OPENSSL_ERROR;
  }

  fp = fopen (privkey_file, "rb");
  if ( fp == NULL ) {
    ERROR ("Error: failed to open file %s: %s\n", privkey_file, strerror (errno));
    result = 0;
    goto EXIT;
  }

  OSSL_DECODER_CTX  *dctx;
  dctx = OSSL_DECODER_CTX_new_for_pkey (&evp_key, "PEM", NULL, "EC", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
  if ( dctx == NULL ) {
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_DECODER_from_fp (dctx, fp)) {
    OSSL_DECODER_CTX_free (dctx);
    goto OPENSSL_ERROR;
  }

  OSSL_DECODER_CTX_free (dctx);
  fclose (fp);
  fp = NULL;

  pctx = EVP_PKEY_CTX_new (evp_key, NULL);
  if (pctx == NULL) {
    ERROR ("Error: failed to allocate pkey context.\n");
    goto OPENSSL_ERROR;
  }

  if (sigalg == TPM_ALG_SM2) {
    result = EVP_PKEY_CTX_set1_id (pctx, SM2_ID, SM2_ID_LEN);
    if (result <= 0) {
      ERROR ("Error: failed to allocate SM2 id.\n");
      goto OPENSSL_ERROR;
    }
  }

  EVP_MD_CTX_set_pkey_ctx (mctx, pctx);
  switch (hashalg) {
    case TPM_ALG_SM3_256:
      result = EVP_DigestSignInit (mctx, &pctx, EVP_sm3 (), NULL, evp_key);
      break;
    case TPM_ALG_SHA256:
      result = EVP_DigestSignInit (mctx, &pctx, EVP_sha256 (), NULL, evp_key);
      break;
    case TPM_ALG_SHA384:
      result = EVP_DigestSignInit (mctx, &pctx, EVP_sha384 (), NULL, evp_key);
      break;
    default:
      ERROR ("Error: unsupported hashalg.\n");
      result = 0;
      goto EXIT;
  }

  if (result <= 0) {
    ERROR ("Error: failed to initialize signature.\n");
    goto OPENSSL_ERROR;
  }

  result = EVP_DigestSignUpdate (mctx, data->data, data->size);
  if (result <= 0) {
    ERROR ("Error: failed to update signature.\n");
    goto OPENSSL_ERROR;
  }

  // Dry run, calculate length:
  result = EVP_DigestSignFinal (mctx, NULL, &sig_length);
  if (result <= 0 ) {
    ERROR ("Error: failed to compute signature length.\n");
    goto OPENSSL_ERROR;
  }

  signature_block = OPENSSL_malloc (sig_length);
  if (signature_block == NULL) {
    ERROR ("Error: failed to allocate signature block.\n");
    goto OPENSSL_ERROR;
  }

  signature_block_orig = signature_block;

  result = EVP_DigestSignFinal (mctx, (unsigned char *)signature_block, &sig_length);
  if (result <= 0) {
    ERROR ("Error: failed to compute signature length.\n");
    goto OPENSSL_ERROR;
  }

  // signature_block is DER encoded, we decode it:
  ecdsa_sig = d2i_ECDSA_SIG (NULL, &signature_block, sig_length);
  if (ecdsa_sig == NULL) {
    ERROR ("Error: failed to decode signature.\n");
    goto OPENSSL_ERROR;
  }

  sig_r = ECDSA_SIG_get0_r (ecdsa_sig);
  sig_s = ECDSA_SIG_get0_s (ecdsa_sig);
  if ((sig_r == NULL) || (sig_s == NULL)) {
    ERROR ("Error: failed to extract signature components.\n");
    goto OPENSSL_ERROR;
  }

  /* Use BN_bn2binpad to zero-pad signature components to the full
     field width.  BN_bn2bin would silently write fewer bytes when a
     component has a leading zero, corrupting the output. */
  if (!BN_bn2binpad (sig_r, r->data, (int)r->size) ||
      !BN_bn2binpad (sig_s, s->data, (int)s->size)) {
    ERROR ("Error: failed to serialize signature components.\n");
    goto OPENSSL_ERROR;
  }

  goto EXIT;
OPENSSL_ERROR:
  DISPLAY ("Error.\n");
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  result = 0;
EXIT:
  if (evp_key != NULL) {
    EVP_PKEY_free (evp_key);
  }

  if (mctx != NULL) {
    EVP_MD_CTX_free (mctx);
  }

  if (pctx != NULL) {
    EVP_PKEY_CTX_free (pctx);
  }

  if (fp != NULL) {
    fclose (fp);
  }

  if (ecdsa_sig != NULL) {
    ECDSA_SIG_free (ecdsa_sig);
  }

  if (signature_block_orig != NULL) {
    OPENSSL_free ((void *)signature_block_orig);
  }

  return result ? true : false;
}

/*
 * LMS is not supported via the OpenSSL backend.
 * LMS/HSS requires the IPPC backend (USE_IPPC=1).
 */

bool
crypto_lms_verify_signature_internal (
  const unsigned char  *msg       __attribute__ ((unused)),
  size_t               msg_len    __attribute__ ((unused)),
  const unsigned char  *signature __attribute__ ((unused)),
  size_t               sig_len    __attribute__ ((unused)),
  const unsigned char  *public_key __attribute__ ((unused)),
  size_t               pubkey_len __attribute__ ((unused))
  )
{
  ERROR ("ERROR: LMS signature verification is not supported via the OpenSSL backend.\n");
  ERROR ("       Build with USE_IPPC=1 to enable LMS support.\n");
  return false;
}

crypto_status
crypto_lms_sign_data_internal (
  const unsigned char  *msg          __attribute__ ((unused)),
  size_t               msg_len       __attribute__ ((unused)),
  unsigned char        *signature    __attribute__ ((unused)),
  size_t               *sig_len      __attribute__ ((unused)),
  const char           *privkey_file __attribute__ ((unused)),
  const unsigned char  *aux_data     __attribute__ ((unused)),
  size_t               aux_len       __attribute__ ((unused))
  )
{
  ERROR ("ERROR: LMS signature generation is not supported via the OpenSSL backend.\n");
  ERROR ("       Build with USE_IPPC=1 to enable LMS support.\n");
  return crypto_not_supported;
}

/*
 * ML-DSA-87 implementation using OpenSSL >= 3.6 EVP API (FIPS 204).
 *
 * ML-DSA-87 parameters (security level 5):
 *   Public key:  2592 bytes
 *   Private key: 4896 bytes
 *   Signature:   4627 bytes
 *
 * Keys are stored as PEM or DER files (PKCS#8 / SubjectPublicKeyInfo),
 * generated via: openssl genpkey -algorithm ML-DSA-87
 * ML-DSA is a "pure" signature scheme: no separate hash step — the EVP
 * DigestSign/DigestVerify one-shot API is used with md=NULL.
 */

#define MLDSA87_PUBKEY_SIZE     2592
#define MLDSA87_PRIVKEY_SIZE    4896
#define MLDSA87_SIGNATURE_SIZE  4627

/*
 * Read an ML-DSA-87 public key from a PEM or DER file and extract the
 * raw 2592-byte public key into the caller-supplied buffer.
 */
bool
crypto_read_mldsa_pubkey_internal (
  const char     *file,
  unsigned char  *pubkey,
  size_t         pubkey_size
  )
{
  EVP_PKEY       *pkey   = NULL;
  FILE           *fp     = NULL;
  bool           result  = false;
  size_t         raw_len = pubkey_size;

  LOG ("[read_mldsa_pubkey]\n");

  if (pubkey_size < MLDSA87_PUBKEY_SIZE) {
    ERROR ("ERROR: ML-DSA pubkey buffer too small: need %d, have %zu\n",
           MLDSA87_PUBKEY_SIZE, pubkey_size);
    return false;
  }

  fp = fopen (file, "rb");
  if (fp == NULL) {
    ERROR ("ERROR: Cannot open ML-DSA public key file: %s\n", file);
    return false;
  }

  /* Try PEM first (-----BEGIN PUBLIC KEY-----) */
  pkey = PEM_read_PUBKEY (fp, NULL, NULL, NULL);
  if (pkey == NULL) {
    /* PEM failed — try DER (SubjectPublicKeyInfo) */
    rewind (fp);
    pkey = d2i_PUBKEY_fp (fp, NULL);
  }

  fclose (fp);

  if (pkey == NULL) {
    /* PEM and DER both failed — try raw binary (exactly 2592 bytes) */
    fp = fopen (file, "rb");
    if (fp != NULL) {
      fseek (fp, 0, SEEK_END);
      long fsize = ftell (fp);
      if (fsize == MLDSA87_PUBKEY_SIZE) {
        fseek (fp, 0, SEEK_SET);
        if (fread (pubkey, 1, MLDSA87_PUBKEY_SIZE, fp) == MLDSA87_PUBKEY_SIZE) {
          fclose (fp);
          return true;
        }
      }
      fclose (fp);
    }
    ERROR ("ERROR: Failed to read ML-DSA-87 public key (not PEM, DER, or raw): %s\n", file);
    goto OPENSSL_ERROR;
  }

  /* Verify algorithm */
  if (!EVP_PKEY_is_a (pkey, "ML-DSA-87")) {
    ERROR ("ERROR: Public key is not ML-DSA-87\n");
    goto EXIT;
  }

  /* Extract raw public key bytes */
  if (EVP_PKEY_get_raw_public_key (pkey, pubkey, &raw_len) <= 0) {
    ERROR ("ERROR: Failed to extract raw ML-DSA-87 public key\n");
    goto OPENSSL_ERROR;
  }

  if (raw_len != MLDSA87_PUBKEY_SIZE) {
    ERROR ("ERROR: Unexpected ML-DSA-87 public key size: %zu\n", raw_len);
    goto EXIT;
  }

  result = true;
  goto EXIT;

OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
EXIT:
  if (pkey != NULL) {
    EVP_PKEY_free (pkey);
  }

  return result;
}

crypto_status
crypto_mldsa_sign_data_internal (
  const unsigned char  *msg,
  size_t               msg_len,
  unsigned char        *signature,
  size_t               *sig_len,
  const char           *privkey_file
  )
{
  EVP_PKEY       *pkey      = NULL;
  EVP_MD_CTX     *mctx      = NULL;
  FILE           *fp        = NULL;
  crypto_status  result     = crypto_operation_fail;

  LOG ("[mldsa_sign_data]\n");

  /* Check output buffer size */
  if (*sig_len < MLDSA87_SIGNATURE_SIZE) {
    ERROR ("ERROR: ML-DSA signature buffer too small: need %d, have %zu\n",
           MLDSA87_SIGNATURE_SIZE, *sig_len);
    return crypto_buffer_too_small;
  }

  /* Read private key from PEM or DER file */
  fp = fopen (privkey_file, "rb");
  if (fp == NULL) {
    ERROR ("ERROR: Cannot open ML-DSA private key file: %s\n", privkey_file);
    return crypto_file_io_error;
  }

  /* Try PEM first (-----BEGIN PRIVATE KEY-----) */
  pkey = PEM_read_PrivateKey (fp, NULL, NULL, NULL);
  if (pkey == NULL) {
    /* PEM failed — try DER (PKCS#8) */
    rewind (fp);
    pkey = d2i_PrivateKey_fp (fp, NULL);
  }

  fclose (fp);
  fp = NULL;

  if (pkey == NULL) {
    /* PEM and DER both failed — try raw binary (exactly 4896 bytes) */
    fp = fopen (privkey_file, "rb");
    if (fp != NULL) {
      fseek (fp, 0, SEEK_END);
      long fsize = ftell (fp);
      if (fsize == MLDSA87_PRIVKEY_SIZE) {
        unsigned char raw_priv[MLDSA87_PRIVKEY_SIZE];
        fseek (fp, 0, SEEK_SET);
        if (fread (raw_priv, 1, MLDSA87_PRIVKEY_SIZE, fp) == MLDSA87_PRIVKEY_SIZE) {
          fclose (fp);
          fp = NULL;
          pkey = EVP_PKEY_new_raw_private_key_ex (NULL, "ML-DSA-87", NULL,
                                                   raw_priv, MLDSA87_PRIVKEY_SIZE);
        } else {
          fclose (fp);
          fp = NULL;
        }
      } else {
        fclose (fp);
        fp = NULL;
      }
    }
    if (pkey == NULL) {
      ERROR ("ERROR: Failed to read ML-DSA-87 private key (not PEM, DER, or raw): %s\n",
             privkey_file);
      goto OPENSSL_ERROR;
    }
  }

  /* Verify algorithm */
  if (!EVP_PKEY_is_a (pkey, "ML-DSA-87")) {
    ERROR ("ERROR: Private key is not ML-DSA-87\n");
    goto EXIT;
  }

  /* One-shot DigestSign (ML-DSA has no separate hash step, md=NULL) */
  mctx = EVP_MD_CTX_new ();
  if (mctx == NULL) {
    ERROR ("ERROR: Failed to allocate EVP_MD_CTX\n");
    goto EXIT;
  }

  if (EVP_DigestSignInit_ex (mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
    ERROR ("ERROR: EVP_DigestSignInit_ex failed for ML-DSA-87\n");
    goto OPENSSL_ERROR;
  }

  size_t out_len = *sig_len;
  if (EVP_DigestSign (mctx, signature, &out_len, msg, msg_len) <= 0) {
    ERROR ("ERROR: EVP_DigestSign failed for ML-DSA-87\n");
    goto OPENSSL_ERROR;
  }

  *sig_len = out_len;

  if (verbose) {
    LOG ("ML-DSA-87 signature generation succeeded, signature length: %zu\n", *sig_len);
  }

  result = crypto_ok;
  goto EXIT;

OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
EXIT:
  if (mctx != NULL) {
    EVP_MD_CTX_free (mctx);
  }

  if (pkey != NULL) {
    EVP_PKEY_free (pkey);
  }

  return result;
}

bool
crypto_mldsa_verify_signature_internal (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len
  )
{
  EVP_PKEY    *pkey   = NULL;
  EVP_MD_CTX  *mctx   = NULL;
  bool        result  = false;
  int         verify_result;

  LOG ("[mldsa_verify_signature]\n");

  (void)sig_len;    /* ML-DSA-87 signature has a fixed size */
  (void)pubkey_len; /* ML-DSA-87 pubkey has a fixed size */

  /* Create EVP_PKEY from raw public key bytes */
  pkey = EVP_PKEY_new_raw_public_key_ex (NULL, "ML-DSA-87", NULL, public_key, pubkey_len);
  if (pkey == NULL) {
    ERROR ("ERROR: Failed to import ML-DSA-87 public key\n");
    goto OPENSSL_ERROR;
  }

  /* One-shot DigestVerify (ML-DSA has no separate hash step, md=NULL) */
  mctx = EVP_MD_CTX_new ();
  if (mctx == NULL) {
    ERROR ("ERROR: Failed to allocate EVP_MD_CTX\n");
    goto EXIT;
  }

  if (EVP_DigestVerifyInit_ex (mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
    ERROR ("ERROR: EVP_DigestVerifyInit_ex failed for ML-DSA-87\n");
    goto OPENSSL_ERROR;
  }

  verify_result = EVP_DigestVerify (mctx, signature, sig_len, msg, msg_len);
  if (verify_result < 0) {
    ERROR ("ERROR: EVP_DigestVerify error for ML-DSA-87\n");
    goto OPENSSL_ERROR;
  }

  if (verify_result != 1) {
    ERROR ("ERROR: ML-DSA-87 signature verification failed (invalid signature)\n");
    goto EXIT;
  }

  if (verbose) {
    LOG ("ML-DSA-87 signature verification succeeded\n");
  }

  result = true;
  goto EXIT;

OPENSSL_ERROR:
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
EXIT:
  if (mctx != NULL) {
    EVP_MD_CTX_free (mctx);
  }

  if (pkey != NULL) {
    EVP_PKEY_free (pkey);
  }

  return result;
}

#endif /* !USE_IPPC */
