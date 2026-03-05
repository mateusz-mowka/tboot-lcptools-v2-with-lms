#ifndef USE_IPPC

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  #include <openssl/decoder.h>
  #include <openssl/core.h>
  #include <openssl/param_build.h>
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include "../include/hash.h"
#include "../include/lcp3.h"
#include "crypto_interface.h"
#include "safe_lib.h"
#include "hash-sigs/hss.h"
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
    return crypto_general_fail;
  }

  EVP_MD_CTX    *ctx = EVP_MD_CTX_create ();
  const EVP_MD  *md;

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
      return crypto_unknown_hashalg;
      break;
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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY  *pubkey = NULL;
 #else
  RSA  *pubkey = NULL;
 #endif

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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  OSSL_DECODER_CTX  *dctx;
  dctx = OSSL_DECODER_CTX_new_for_pkey (&pubkey, "PEM", NULL, "RSA", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
  if ( dctx == NULL ) {
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_DECODER_from_fp (dctx, fp)) {
    goto OPENSSL_ERROR;
  }

  OSSL_DECODER_CTX_free (dctx);
 #else
  pubkey = PEM_read_RSA_PUBKEY (fp, NULL, NULL, NULL);
 #endif
  if ( pubkey == NULL ) {
    goto OPENSSL_ERROR;
  }

  // Close the file, won't need it anymore
  fclose (fp);
  fp = NULL;

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  *keysize = (size_t)EVP_PKEY_get_size (pubkey);
 #else
  *keysize = RSA_size (pubkey);
 #endif
  if ((*keysize != 256) && (*keysize != 384)) {
    printf ("Error: public key size %ld is not supported\n", *keysize);
    goto ERROR;
  }

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY_get_bn_param (pubkey, "n", &modulus);
 #elif OPENSSL_VERSION_NUMBER >= 0x10100000L
  RSA_get0_key (pubkey, (const BIGNUM **)&modulus, NULL, NULL);
 #else
  modulus = pubkey->n;
 #endif
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY_free(pubkey);
#else
  RSA_free(pubkey);
#endif
  BN_free(modulus);
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
    BN_free(modulus);
  }

  if (pubkey != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_PKEY_free(pubkey);
#else
  RSA_free(pubkey);
#endif
  }

  return crypto_general_fail;
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

 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  const EC_KEY    *pubkey   = NULL;
  const EC_POINT  *pubpoint = NULL;
  const EC_GROUP  *pubgroup = NULL;
  BN_CTX          *ctx      = NULL;
 #else
  EVP_PKEY  *pubkey;
 #endif

  LOG ("read ecdsa pubkey file for list signature.\n");
  fp = fopen (file, "rb");
  if ( fp == NULL) {
    ERROR ("ERROR: cannot open file.\n");
    goto ERROR;
  }

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  OSSL_DECODER_CTX  *dctx;
  dctx = OSSL_DECODER_CTX_new_for_pkey (&pubkey, "PEM", NULL, "EC", OSSL_KEYMGMT_SELECT_PUBLIC_KEY, NULL, NULL);
  if ( dctx == NULL ) {
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_DECODER_from_fp (dctx, fp)) {
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

 #else
  pubkey = PEM_read_EC_PUBKEY (fp, NULL, NULL, NULL);
  if ( pubkey == NULL ) {
    goto OPENSSL_ERROR;
  }

  fclose (fp);
  fp = NULL;

  pubpoint = EC_KEY_get0_public_key (pubkey);
  if ( pubpoint == NULL ) {
    goto OPENSSL_ERROR;
  }

  pubgroup = EC_KEY_get0_group (pubkey);
  if ( pubgroup == NULL ) {
    goto OPENSSL_ERROR;
  }

  x   = BN_new ();
  y   = BN_new ();
  ctx = BN_CTX_new ();
  if ((x == NULL) || (y == NULL) || (ctx == NULL)) {
    goto OPENSSL_ERROR;
  }

  result = EC_POINT_get_affine_coordinates_GFp (pubgroup, pubpoint, x, y, ctx);
  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

 #endif
  *key_size_bytes = BN_num_bytes (x);
  if (BN_num_bytes (x) != BN_num_bytes (y)) {
    ERROR ("ERROR: key coordinates are not the same length.");
    goto ERROR;
  }

  if ((((*key_size_bytes)*8) != 256) && (((*key_size_bytes)*8) != 384)) {
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

  if (!BN_bn2bin (x, *qx)) {
    goto OPENSSL_ERROR;
  }

  if (!BN_bn2bin (y, *qy)) {
    goto OPENSSL_ERROR;
  }

  // Flip BE to LE
  buffer_reverse_byte_order ((uint8_t *)*qx, (*key_size_bytes));
  buffer_reverse_byte_order ((uint8_t *)*qy, (*key_size_bytes));

  OPENSSL_free ((void *)pubkey);
  OPENSSL_free ((void *)x);
  OPENSSL_free ((void *)y);
 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  OPENSSL_free ((void *)pubpoint);
  OPENSSL_free ((void *)pubgroup);
  OPENSSL_free ((void *)ctx);
 #endif
  return crypto_ok;

  // Errors:
OPENSSL_ERROR:
  ERR_load_crypto_strings ();
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  ERR_free_strings ();
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
    OPENSSL_free ((void *)pubkey);
  }

  if (x != NULL) {
    OPENSSL_free ((void *)x);
  }

  if (y != NULL) {
    OPENSSL_free ((void *)y);
  }

 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  if (pubpoint != NULL) {
    OPENSSL_free ((void *)pubpoint);
  }

  if (pubgroup != NULL) {
    OPENSSL_free ((void *)pubgroup);
  }

  if (ctx != NULL) {
    OPENSSL_free ((void *)ctx);
  }

 #endif
  return crypto_general_fail;
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

  OPENSSL_free (evp_priv);
  return context;

OPENSSL_ERROR:
  ERR_load_crypto_strings ();
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  ERR_free_strings ();
ERROR:
  if (fp != NULL) {
    fclose (fp);
  }

  if (evp_priv != NULL) {
    OPENSSL_free (evp_priv);
  }

  if (context != NULL) {
    OPENSSL_free (context);
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

    In: pointer to a correctly sized buffer to hold signature block, digest of
    lcp list data, hash alg used to hash data, Openssl private key context

    Out: true on success, false on failure. Also signature_block gets signature block data

*/
{
  printf ("[rsa_ssa_pss_sign]\n");
  int           result; // For openssl return codes
  size_t        siglen; // Holds length of signature returned by openssl must be 256 or 384
  const EVP_MD  *evp_hash_alg;

  if ((signature_block == NULL) || (data_to_sign == NULL) || (private_key_context == NULL)) {
    printf ("Error: one or more data buffers is not defined.\n");
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
      break;
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
                          data_to_sign->data,
                          get_hash_size (hash_alg)
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
                          data_to_sign->data,
                          get_hash_size (hash_alg)
                          );
  if (result <= 0) {
    goto OPENSSL_ERROR;
  }

  // All good, function end
  return true;

  // Error handling
OPENSSL_ERROR:
  ERR_load_crypto_strings ();
  printf ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  ERR_free_strings ();
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
    return crypto_general_fail;
  }

  // Sign
  sign_status = rsa_ssa_pss_sign (sig_block, digest, sig_alg, hash_alg, context);

  EVP_PKEY_CTX_free (context);

  return (sign_status == true ? crypto_ok : crypto_general_fail);
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
  uint8_t  der_oid = 0x06;
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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  size_t  dcpt_sig_len;
 #else
  RSA  *rsa_pubkey = NULL;
 #endif

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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  evp_context = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
  if ( evp_context == NULL) {
    ERROR ("Error: failed to initialize CTX from name.\n");
    goto OPENSSL_ERROR;
  }

  OSSL_PARAM_BLD  *params_build = OSSL_PARAM_BLD_new ();
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

  if ( !OSSL_PARAM_BLD_push_BN (params_build, "d", NULL)) {
    ERROR ("Error: failed to push NULL into param build.\n");
    goto OPENSSL_ERROR;
  }

  OSSL_PARAM  *params = OSSL_PARAM_BLD_to_param (params_build);
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
  OSSL_PARAM_BLD_free (params_build);
  EVP_PKEY_CTX_free (evp_context);
  evp_context = NULL;
 #else
  rsa_pubkey = RSA_new ();
  if ( rsa_pubkey == NULL ) {
    ERROR ("Error: failed to allocate key\n");
    status = 0;
    goto EXIT;
  }

 #if OPENSSL_VERSION_NUMBER >= 0x10100000L
  RSA_set0_key (rsa_pubkey, modulus, exponent, NULL);
 #else
  rsa_pubkey->n = modulus;
  rsa_pubkey->e = exponent;
  rsa_pubkey->d = rsa_pubkey->p = rsa_pubkey->q = NULL;
 #endif
 #endif

  if (MAJOR_VER (list_ver) != MAJOR_VER (LCP_TPM20_POLICY_LIST2_1_VERSION_300)) {
 #if OPENSSL_VERSION_NUMBER >= 0x30000000L

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
 #else
    decrypted_sig = OPENSSL_malloc (pubkey->size);
    status        = RSA_public_decrypt (pubkey->size, signature->data, decrypted_sig, rsa_pubkey, RSA_NO_PADDING);
    if (status <= 0) {
      ERROR ("Error: failed to decrypt signature.\n");
      goto OPENSSL_ERROR;
    }

    if ( verbose ) {
      LOG ("Decrypted signature: \n");
      print_hex ("", decrypted_sig, pubkey->size);
    }

 #endif
    // In older lists we need to get hashAlg from signature data.
    hashAlg = pkcs_get_hashalg ((const unsigned char *)decrypted_sig);
    OPENSSL_free ((void *)decrypted_sig);
  }

 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  evp_key = EVP_PKEY_new ();
  if ( evp_key == NULL) {
    goto OPENSSL_ERROR;
  }

  status = EVP_PKEY_set1_RSA (evp_key, rsa_pubkey);
  if (status <= 0) {
    goto OPENSSL_ERROR;
  }

 #endif

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

  status = EVP_PKEY_verify (evp_context, signature->data, pubkey->size, (const unsigned char *)digest, get_hash_size (hashAlg));
  if (status < 0) {
    // Error occurred
    goto OPENSSL_ERROR;
  } else {
    // EVP_PKEY_verify executed successfully
    goto EXIT;
  }

OPENSSL_ERROR:
  ERR_load_crypto_strings ();
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  ERR_free_strings ();
  status = 0;
EXIT:
 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  if (rsa_pubkey != NULL) {
    OPENSSL_free ((void *)rsa_pubkey);
  }

 #endif
  if (evp_context != NULL) {
    OPENSSL_free ((void *)evp_context);
  }

  if (evp_key != NULL) {
    OPENSSL_free ((void *)evp_key);
  }

  if (modulus != NULL) {
    OPENSSL_free ((void *)modulus);
  }

  if (exponent != NULL) {
    OPENSSL_free ((void *)exponent);
  }

  if (digest != NULL) {
    free (digest);
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
  der_encoded_sig = helper_ptr;
  *length         = encoded_size;
  // i2d_ECDSA_SIG changes value of the pointer passed, that's why we first assigned
  // it to der_encoded_sig, which will hold the encoded_sig.
  if (!i2d_ECDSA_SIG (sig, &helper_ptr)) {
    ERROR ("Error: failed to encode signature.\n");
    return NULL;
  }

EXIT:
  if (sig != NULL) {
    ECDSA_SIG_free (sig);
    // SIG_free also frees r and s
    r = NULL;
    s = NULL;
  }

  if (r != NULL) {
    OPENSSL_free ((void *)r);
  }

  if (s != NULL) {
    OPENSSL_free ((void *)s);
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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  const EC_GROUP  *ec_group     = NULL;
  EC_POINT        *ec_point     = NULL;
  unsigned char   *point_buffer = NULL;
  size_t          pt_buf_len;
  BN_CTX          *bctx      = NULL;
  const char      *curveName = NULL;
 #else
  EC_KEY    *ec_key   = NULL;
  EC_GROUP  *ec_group = NULL;
 #endif

  LOG ("[verify_ec_signature]\n");
  if ((data == NULL) || (pubkey_x == NULL) || (pubkey_y == NULL) || (sig_r == NULL) || (sig_s == NULL)) {
    ERROR ("Error: one or more buffers are not defined.\n");
    return false;
  }

  if ( hashalg == TPM_ALG_SM3_256 ) {
    curveId = NID_sm2;
    mdtype  = EVP_sm3 ();
 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    curveName = SN_sm2;
 #endif
  } else if ( hashalg == TPM_ALG_SHA256 ) {
    curveId = NID_secp256k1;
    mdtype  = EVP_sha256 ();
 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    curveName = SN_secp256k1;
 #endif
  } else if ( hashalg == TPM_ALG_SHA384 ) {
    curveId = NID_secp384r1;
    mdtype  = EVP_sha384 ();
 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
    curveName = SN_secp384r1;
 #endif
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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
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

  pt_buf_len   = EC_POINT_point2oct (ec_group, ec_point, POINT_CONVERSION_COMPRESSED, NULL, 0, bctx);
  point_buffer = OPENSSL_malloc (pt_buf_len);
  if ( point_buffer == NULL ) {
    ERROR ("Error: failed to allocate point buffer.\n");
    goto OPENSSL_ERROR;
  }

  if ( EC_POINT_point2oct (ec_group, ec_point, POINT_CONVERSION_COMPRESSED, point_buffer, pt_buf_len, bctx) <= 0 ) {
    ERROR ("Error: failed to convert EC point into octal string.\n");
    goto OPENSSL_ERROR;
  }

  EVP_PKEY_CTX  *ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if ( ctx == NULL ) {
    ERROR ("Error: failed to initialize key creation CTX.\n");
    goto OPENSSL_ERROR;
  }

  OSSL_PARAM_BLD  *params_build = OSSL_PARAM_BLD_new ();
  if ( params_build == NULL ) {
    ERROR ("Error: failed to set up parameter builder.\n");
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_PARAM_BLD_push_utf8_string (params_build, "group", curveName, 0)) {
    ERROR ("Error: failed to push group into param build.\n");
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_PARAM_BLD_push_octet_string (params_build, "pub", point_buffer, pt_buf_len)) {
    ERROR ("Error: failed to push pubkey into param build.\n");
    goto OPENSSL_ERROR;
  }

  OSSL_PARAM  *params = OSSL_PARAM_BLD_to_param (params_build);
  if ( params == NULL ) {
    ERROR ("Error: failed to construct params from build.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_fromdata_init (ctx) <= 0 ) {
    ERROR ("ERROR: failed to initialize key creation from data.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_fromdata (ctx, &evp_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    ERROR ("Error: failed to create EC_KEY.\n");
    result = 0;
    goto EXIT;
  }

  OSSL_PARAM_BLD_free (params_build);
  OSSL_PARAM_free (params);
  EVP_PKEY_CTX_free (ctx);
  BN_CTX_free (bctx);
 #else
  ec_key = EC_KEY_new ();
  if (ec_key == NULL) {
    ERROR ("Error: failed to generate EC_KEY.\n");
    result = 0;
    goto EXIT;
  }

  evp_key = EVP_PKEY_new ();
  if (evp_key == NULL) {
    ERROR ("Error: failed to generate EC_KEY.\n");
    result = 0;
    goto EXIT;
  }

  if ( EC_KEY_set_group (ec_key, ec_group) <= 0) {
    ERROR ("Failed to set EC Key group.\n");
    goto OPENSSL_ERROR;
  }

  if ( EC_KEY_set_public_key_affine_coordinates (ec_key, x, y) <= 0) {
    ERROR ("Failed to set key coordinates.\n");
    goto OPENSSL_ERROR;
  }

  if ( EVP_PKEY_assign_EC_KEY (evp_key, ec_key) <= 0) {
    ERROR ("Error: failed to assign EC KEY to EVP structure.\n");
    goto OPENSSL_ERROR;
  }

  if (sigalg == TPM_ALG_SM2) {
    if ( EVP_PKEY_set_alias_type (evp_key, EVP_PKEY_SM2) <= 0 ) {
      ERROR ("Error: failed to set EVP KEY alias to SM2.\n");
      goto OPENSSL_ERROR;
    }
  }

 #endif

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
  ERR_load_crypto_strings ();
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  ERR_free_strings ();
  result = 0;
EXIT:
  // cleanup:
 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (ec_point != NULL) {
    OPENSSL_free ((void *)ec_point);
  }

  if (point_buffer != NULL) {
    OPENSSL_free ((void *)point_buffer);
  }

 #else
  if (ec_key != NULL) {
    OPENSSL_free ((void *)ec_key);
  }

 #endif
  if (ec_group != NULL) {
    OPENSSL_free ((void *)ec_group);
  }

  if (evp_key != NULL) {
    OPENSSL_free ((void *)evp_key);
  }

  if (x != NULL) {
    OPENSSL_free ((void *)x);
  }

  if (y != NULL) {
    OPENSSL_free ((void *)y);
  }

  if (der_encoded_sig != NULL) {
    OPENSSL_free ((void *)der_encoded_sig);
  }

  if (mctx != NULL) {
    OPENSSL_free (mctx);
  }

  if (pctx != NULL) {
    OPENSSL_free (pctx);
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

 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  EC_KEY  *ec_key = NULL;
 #endif

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

 #if OPENSSL_VERSION_NUMBER >= 0x30000000L
  OSSL_DECODER_CTX  *dctx;
  dctx = OSSL_DECODER_CTX_new_for_pkey (&evp_key, "PEM", NULL, "EC", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, NULL, NULL);
  if ( dctx == NULL ) {
    goto OPENSSL_ERROR;
  }

  if ( !OSSL_DECODER_from_fp (dctx, fp)) {
    goto OPENSSL_ERROR;
  }

  OSSL_DECODER_CTX_free (dctx);
 #else
  ec_key = PEM_read_ECPrivateKey (fp, NULL, NULL, NULL);
  if (ec_key == NULL) {
    ERROR ("Error: failed to allocate EC key.\n");
    goto OPENSSL_ERROR;
  }

  evp_key = EVP_PKEY_new ();
  if (evp_key == NULL) {
    ERROR ("Error: failed to allocate EVP key.\n");
    goto OPENSSL_ERROR;
  }

  result = EVP_PKEY_assign_EC_KEY (evp_key, ec_key);
  if (result <= 0) {
    ERROR ("Error: failed to assign EC key to EVP structure.\n");
    goto OPENSSL_ERROR;
  }

  if (sigalg == TPM_ALG_SM2) {
    result = EVP_PKEY_set_alias_type (evp_key, EVP_PKEY_SM2);
    if (result <= 0) {
      ERROR ("Error: failed to assign SM2 alias to EVP key.\n");
      goto OPENSSL_ERROR;
    }
  }

 #endif
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
      return false;
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

  BN_bn2bin (sig_r, r->data);
  BN_bn2bin (sig_s, s->data);

  goto EXIT;
OPENSSL_ERROR:
  DISPLAY ("Error.\n");
  ERR_load_crypto_strings ();
  ERROR ("OpenSSL error: %s\n", ERR_error_string (ERR_get_error (), NULL));
  ERR_free_strings ();
  result = 0;
EXIT:
 #if OPENSSL_VERSION_NUMBER < 0x30000000L
  if (ec_key != NULL) {
    OPENSSL_free ((void *)ec_key);
  }

 #endif
  if (evp_key != NULL) {
    OPENSSL_free ((void *)evp_key);
  }

  if (mctx != NULL) {
    OPENSSL_free ((void *)mctx);
  }

  if (pctx != NULL) {
    OPENSSL_free ((void *)pctx);
  }

  if (fp != NULL) {
    fclose (fp);
  }

  if (ecdsa_sig != NULL) {
    ECDSA_SIG_free (ecdsa_sig);
  }

  return result ? true : false;
}

bool
crypto_lms_verify_signature_internal (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len __attribute__ ((unused))
  )
{
  if ((NULL == msg) || (NULL == signature) || (NULL == public_key)) {
    ERROR ("LMS verify: NULL parameter\n");
    return false;
  }

  /* Note: public_key already has LEVELS prefix (4 bytes 0x01000000 BE)
   * and signature already has NSPK prefix (4 bytes 0x00000000)
   * added by the caller (pollist2_1.c) */

  /* Verify signature using hash-sigs library */
  bool  result = hss_validate_signature (
                                         public_key,
                                         msg,
                                         msg_len,
                                         signature,
                                         sig_len,
                                         NULL /* info parameter */
                                         );

  if (!result) {
    ERROR ("LMS signature verification failed\n");
    return false;
  }

  if (verbose) {
    LOG ("LMS signature verification succeeded\n");
  }

  return true;
}

/*
 * Callback for hss_load_private_key to read private key file
 */
static bool
read_private_key (
  unsigned char  *buffer,
  size_t         len_buffer,
  void           *context
  )
{
  const char  *filename = (const char *)context;
  FILE        *fp       = fopen (filename, "rb");

  if (NULL == fp) {
    ERROR ("Failed to open private key file: %s\n", filename);
    return false;
  }

  size_t  bytes_read = fread (buffer, 1, len_buffer, fp);
  fclose (fp);

  if (bytes_read != len_buffer) {
    ERROR ("Failed to read %zu bytes from private key file (got %zu)\n", len_buffer, bytes_read);
    return false;
  }

  return true;
}

/*
 * Callback for hss_generate_signature to update private key file
 */
static bool
update_private_key (
  unsigned char  *buffer,
  size_t         len_buffer,
  void           *context
  )
{
  const char  *filename = (const char *)context;

  /* Try to open for update (read/write without truncating) */
  FILE  *fp = fopen (filename, "r+");

  if (NULL == fp) {
    /* If r+ fails, fall back to creating new file */
    ERROR ("Cannot open private key for update with r+ mode: %s\n", filename);
    fp = fopen (filename, "wb");
    if (NULL == fp) {
      ERROR ("Cannot open private key for update with wb mode: %s\n", filename);
      return false;
    }
  }

  /* Write the entire buffer as one item (matching original implementation) */
  size_t  written = fwrite (buffer, len_buffer, 1, fp);

  if (written != 1) {
    ERROR ("Cannot write to private key for update: %s\n", filename);
    fclose (fp);
    return false;
  }

  if (fclose (fp) != 0) {
    ERROR ("Cannot close the private key after update: %s\n", filename);
    return false;
  }

  if (verbose) {
    LOG ("LMS private key successfully updated.\n");
  }

  return true;
}

/*
 * LMS signature generation using hash-sigs library
 */
crypto_status
crypto_lms_sign_data_internal (
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
    ERROR ("LMS sign: NULL parameter\n");
    return crypto_nullptr_error;
  }

  struct hss_working_key  *working_key   = NULL;
  unsigned char           *aux_data_copy = NULL;
  size_t                  aux_data_len   = aux_len;

  /* Load auxiliary data if provided */
  if ((aux_data != NULL) && (aux_len > 0)) {
    aux_data_copy = malloc (aux_len);
    if (NULL == aux_data_copy) {
      ERROR ("Failed to allocate memory for aux data\n");
      return crypto_memory_alloc_fail;
    }

    memcpy (aux_data_copy, aux_data, aux_len);
  }

  /* Load private key into working key structure */
  working_key = hss_load_private_key (
                                      read_private_key,
                                      (void *)privkey_file,
                                      0, /* memory_target: 0 = minimize memory */
                                      aux_data_copy,
                                      aux_data_len,
                                      NULL /* info parameter */
                                      );

  if (aux_data_copy != NULL) {
    free (aux_data_copy);
  }

  if (NULL == working_key) {
    ERROR ("Failed to load LMS private key from %s\n", privkey_file);
    return crypto_invalid_key;
  }

  /* Query signature length */
  size_t  sig_buffer_len = hss_get_signature_len_from_working_key (working_key);
  if (sig_buffer_len == 0) {
    ERROR ("Failed to get signature length\n");
    hss_free_working_key (working_key);
    return crypto_crypto_operation_fail;
  }

  /* Check if provided buffer is large enough
   * Note: hss_generate_signature already includes NSPK prefix (levels-1 field) */
  if (*sig_len < sig_buffer_len) {
    ERROR ("Signature buffer too small: need %zu, have %zu\n", sig_buffer_len, *sig_len);
    hss_free_working_key (working_key);
    return crypto_buffer_too_small;
  }

  /* Generate signature directly into output buffer
   * The signature already includes the NSPK prefix (levels-1 = 0x00000000) */
  bool  result = hss_generate_signature (
                                         working_key,
                                         update_private_key,
                                         (void *)privkey_file,
                                         msg,
                                         msg_len,
                                         signature,
                                         sig_buffer_len,
                                         NULL /* info parameter */
                                         );

  if (!result) {
    ERROR ("LMS signature generation failed\n");
    hss_free_working_key (working_key);
    return crypto_crypto_operation_fail;
  }

  *sig_len = sig_buffer_len;

  hss_free_working_key (working_key);

  if (verbose) {
    LOG ("LMS signature generation succeeded, signature length: %zu\n", *sig_len);
  }

  return crypto_ok;
}

/*
 * ML-DSA stubs for OpenSSL backend.
 * OpenSSL does not support ML-DSA (FIPS 204). These stubs emit a compile-time
 * info message and return failure at runtime.
 */
#pragma message("ML-DSA is not supported with OpenSSL backend")

bool
crypto_mldsa_keygen_internal (
  const char  *pubkey_file,
  const char  *privkey_file
  )
{
  (void)pubkey_file;
  (void)privkey_file;
  printf ("ERROR: ML-DSA key generation is not supported with OpenSSL backend\n");
  return false;
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
  (void)msg;
  (void)msg_len;
  (void)signature;
  (void)sig_len;
  (void)privkey_file;
  printf ("ERROR: ML-DSA signing is not supported with OpenSSL backend\n");
  return crypto_general_fail;
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
  (void)msg;
  (void)msg_len;
  (void)signature;
  (void)sig_len;
  (void)public_key;
  (void)pubkey_len;
  printf ("ERROR: ML-DSA verification is not supported with OpenSSL backend\n");
  return false;
}

#endif /* !USE_IPPC */
