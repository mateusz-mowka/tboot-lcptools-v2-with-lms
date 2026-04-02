#ifndef LCPT_CRYPTO_H
#define LCPT_CRYPTO_H

/*
 * tboot is a freestanding 32-bit pre-kernel module built with -nostdinc.
 * It supplies its own type definitions via types.h (guarded by __TYPES_H__).
 * Only pull in the standard headers when building userspace tools.
 */
#ifndef __TYPES_H__
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#endif

#define CRYPTO_SHA1_LENGTH    20
#define CRYPTO_SHA256_LENGTH  32
#define CRYPTO_SM3_LENGTH     32
#define CRYPTO_SHA384_LENGTH  48
#define CRYPTO_SHA512_LENGTH  64
#define MAX_RSA_KEY_SIZE         0x180
#define MIN_RSA_KEY_SIZE         0x100
#define MAX_ECC_KEY_SIZE         0x30
#define MIN_ECC_KEY_SIZE         0x20

/* LMS/LMOTS component sizes (LMS_SHA256_M24_H20 / LMOTS_SHA256_N24_W4) */
#define LMOTS_SIGNATURE_N_SIZE   24   /* SHA-256/192 digest size */
#define LMOTS_SIGNATURE_P_SIZE   51   /* Number of n-byte elements in LMOTS signature */
#define LMOTS_SIGNATURE_BLOCK_SIZE (LMOTS_SIGNATURE_N_SIZE * LMOTS_SIGNATURE_P_SIZE)

#define LMS_SIGNATURE_H_HEIGHT   20   /* Height of the LMS tree */
#define LMS_SIGNATURE_M_SIZE     24   /* Bytes in each LMS tree node (SHA-256/192) */
#define LMS_SIGNATURE_BLOCK_SIZE (LMS_SIGNATURE_H_HEIGHT * LMS_SIGNATURE_M_SIZE)

#define LMS_MAX_PUBKEY_SIZE      48

/* Maximum LMS signature size (4-byte NSPK prefix + signature block) */
/* = 4 + 4 + (4 + N + P*N) + 4 + (H * M)                           */
#define LMS_MAX_SIGNATURE_SIZE ( \
    sizeof(uint32_t) /* NSPK prefix */ + \
    sizeof(uint32_t) /* Q */ + \
    sizeof(uint32_t) + LMOTS_SIGNATURE_N_SIZE + LMOTS_SIGNATURE_BLOCK_SIZE /* lmots_signature */ + \
    sizeof(uint32_t) /* LmsType */ + \
    LMS_SIGNATURE_BLOCK_SIZE /* Path */ \
    )

/* ML-DSA-87 sizes (NIST FIPS 204, security level 5) */
#define MLDSA87_PUBKEY_SIZE      2592
#define MLDSA87_PRIVKEY_SIZE     4896
#define MLDSA87_SIGNATURE_SIZE   4627

/* ML-DSA-87 public key sub-field sizes (FIPS 204 Table 1) */
#define MLDSA87_RHO_SIZE           32   /* Seed used to generate matrix A */
#define MLDSA87_T1_SIZE          2560   /* High-order bits of polynomial vector t */

/* ML-DSA-87 signature sub-field sizes (FIPS 204 Algorithm 3) */
#define MLDSA87_COMMIT_HASH_SIZE   64   /* Commitment hash (c_tilde) */
#define MLDSA87_RESP_VECTOR_SIZE 4480   /* Response vector of l polynomials (z) */
#define MLDSA87_HINT_VECTOR_SIZE   83   /* Hint vector (h) */

/* ASN.1 DER tag constants */
#define DER_TAG_SEQUENCE         0x30
#define DER_TAG_BIT_STRING       0x03
#define DER_TAG_OCTET_STRING     0x04
#define DER_TAG_OID              0x06

/* EC uncompressed point indicator (not a DER tag, but same byte value as OCTET STRING) */
#define EC_POINT_UNCOMPRESSED    0x04

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
  crypto_operation_fail,
  crypto_unknown_hashalg,
  crypto_unknown_signalg,
  crypto_nullptr_error,
  crypto_invalid_size,
  crypto_memory_alloc_fail,
  crypto_file_io_error,
  crypto_invalid_key,
  crypto_buffer_too_small,
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

#endif /* LCPT_CRYPTO_H */
