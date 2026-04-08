#ifdef USE_IPPC

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ippc/cryptography-primitives/include/ippcp.h"
#include "ippc/cryptography-primitives/include/ippcpdefs.h"
#include "../include/hash.h"
#include "../include/lcp3.h"
#include "crypto_interface.h"
#include "safe_lib.h"
#include "lcputils.h"
#include "crypto_ippc_defines.h"
#include "crypto_ippc_lms.h"

static const IppsHashMethod *
get_ipp_hash_method (
  uint16_t  hash_alg_id
  )
{
  const IppsHashMethod  *method = NULL;

  switch (hash_alg_id) {
    case TB_HALG_SHA256:
      method = ippsHashMethod_SHA256 ();
      break;
    case TB_HALG_SHA384:
      method = ippsHashMethod_SHA384 ();
      break;
    case TB_HALG_SHA512:
      method = ippsHashMethod_SHA512 ();
      break;
    case TB_HALG_SM3:
      method = ippsHashMethod_SM3 ();
      break;
    default:
      printf ("ERROR: Unsupported hash Algorithm: 0x%04X!\n", hash_alg_id);
  }

  return method;
}

crypto_status
crypto_hash_buffer_internal (
  const unsigned char  *buf,
  size_t               size,
  unsigned char        *hash,
  uint16_t             hash_alg
  )
{
  IppStatus             status  = ippStsNoOperation;
  int                   ctx_size = 0;
  IppsHashState_rmf     *p_ctx   = NULL;
  const IppsHashMethod  *method  = NULL;

  /* Validate input parameters */
  if ((buf == NULL) || (hash == NULL)) {
    printf ("ERROR: NULL pointer passed to crypto_hash_buffer_internal\n");
    return crypto_nullptr_error;
  }

  method = get_ipp_hash_method (hash_alg);
  if (method == NULL) {
    return crypto_unknown_hashalg;
  }

  /* Get required context size */
  status = ippsHashGetSize_rmf (&ctx_size);
  if (status != ippStsNoErr) {
    printf ("Error getting hash context size: %s\n", ippcpGetStatusString (status));
    return crypto_operation_fail;
  }

  /* Allocate context */
  p_ctx = (IppsHashState_rmf *)malloc (ctx_size);
  if (p_ctx == NULL) {
    printf ("ERROR: Memory allocation failed for hash context\n");
    return crypto_memory_alloc_fail;
  }

  /* Initialize context */
  status = ippsHashInit_rmf (p_ctx, method);
  if (status != ippStsNoErr) {
    printf ("ERROR: Hash initialization failed: %s\n", ippcpGetStatusString (status));
    free (p_ctx);
    return crypto_operation_fail;
  }

  /* Update with message data (skip when size is 0 — hashing empty input is valid) */
  if (size > 0) {
    status = ippsHashUpdate_rmf (buf, size, p_ctx);
    if (status != ippStsNoErr) {
      printf ("ERROR: Hash update failed: %s\n", ippcpGetStatusString (status));
      free (p_ctx);
      return crypto_operation_fail;
    }
  }

  /* Finalize and get digest */
  status = ippsHashFinal_rmf (hash, p_ctx);
  if (status != ippStsNoErr) {
    printf ("ERROR: Hash finalization failed: %s\n", ippcpGetStatusString (status));
    free (p_ctx);
    return crypto_operation_fail;
  }

  free (p_ctx);
  return crypto_ok;
}

/* Simple base64 decode function */
uint16_t
base64_decode (
  const uint8_t  *src,
  uint32_t       src_len,
  uint8_t        *dst,
  uint32_t       dst_max_len
  )
{
  static const uint8_t  d[] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 0,  0,  0,  63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
    0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  0,
    0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0,  0,  0,  0,  0
  };

  uint32_t  i = 0, j = 0;
  uint8_t   c[4];

  while (i < src_len) {
    /* Skip whitespace and newlines */
    if ((src[i] == ' ') || (src[i] == '\r') || (src[i] == '\n') || (src[i] == '\t')) {
      i++;
      continue;
    }

    if (src[i] == '=') {
      break;
    }

    /* Collect 4 base64 chars */
    int  k;
    for (k = 0; k < 4 && i < src_len; k++) {
      while (i < src_len && (src[i] == ' ' || src[i] == '\r' || src[i] == '\n' || src[i] == '\t')) {
        i++;
      }

      if ((i >= src_len) || (src[i] == '=')) {
        break;
      }

      if (src[i] > 127) {
        printf ("ERROR: base64_decode: invalid byte 0x%02X at offset %u\n", src[i], i);
        return 0;
      }

      c[k] = d[src[i++]];
    }

    if (k >= 2) {
      if (j >= dst_max_len) {
        printf ("ERROR: base64_decode output buffer overflow\n");
        return 0;
      }

      dst[j++] = (c[0] << 2) | (c[1] >> 4);
    }

    if (k >= 3) {
      if (j >= dst_max_len) {
        printf ("ERROR: base64_decode output buffer overflow\n");
        return 0;
      }

      dst[j++] = (c[1] << 4) | (c[2] >> 2);
    }

    if (k >= 4) {
      if (j >= dst_max_len) {
        printf ("ERROR: base64_decode output buffer overflow\n");
        return 0;
      }

      dst[j++] = (c[2] << 6) | c[3];
    }
  }

  return j;
}

/* Helper function to parse DER length field */
static int
der_parse_length (
  const uint8_t  *data,
  size_t         *offset,
  size_t         max_size,
  size_t         *length
  )
{
  if (*offset >= max_size) {
    return -1;
  }

  uint8_t  first_byte = data[*offset];
  (*offset)++;

  if ((first_byte & 0x80) == 0) {
    /* Short form: length is in the first byte */
    *length = first_byte;
    return 0;
  }

  /* Long form: first byte (minus high bit) tells us how many bytes encode the length */
  int  num_length_bytes = first_byte & 0x7F;
  if ((num_length_bytes == 0) || (num_length_bytes > 4) || (*offset + num_length_bytes > max_size)) {
    /* num_length_bytes == 0 means indefinite length (0x80), which is invalid in DER */
    return -1;
  }

  *length = 0;
  for (int i = 0; i < num_length_bytes; i++) {
    *length = (*length << 8) | data[*offset];
    (*offset)++;
  }

  return 0;
}

/* Helper function to parse DER INTEGER and extract its value */
static int
der_parse_integer (
  const uint8_t  *data,
  size_t         *offset,
  size_t         max_size,
  uint8_t        **value,
  size_t         *value_len
  )
{
  if (*offset >= max_size) {
    return -1;
  }

  /* Check tag (should be 0x02 for INTEGER) */
  if (data[*offset] != 0x02) {
    printf ("ERROR: Expected INTEGER tag (0x02), got 0x%02X\n", data[*offset]);
    return -1;
  }

  (*offset)++;

  /* Parse length */
  size_t  len;
  if (der_parse_length (data, offset, max_size, &len) != 0) {
    printf ("ERROR: Failed to parse INTEGER length\n");
    return -1;
  }

  if (*offset + len > max_size) {
    printf ("ERROR: INTEGER value extends beyond buffer\n");
    return -1;
  }

  /* Skip leading zero byte if present (used for positive numbers with high bit set) */
  if ((len > 0) && (data[*offset] == 0x00)) {
    (*offset)++;
    len--;
  }

  *value     = (uint8_t *)&data[*offset];
  *value_len = len;
  *offset   += len;

  return 0;
}

/* Helper structure to hold parsed RSA key components */
typedef struct {
  crypto_sized_buffer n;
  crypto_sized_buffer p;
  crypto_sized_buffer q;
  crypto_sized_buffer dp;
  crypto_sized_buffer dq;
  crypto_sized_buffer qinv;
} rsa_private_key_params;

/* Parse RSA private key from DER format (PKCS#1) */
static int
parse_rsa_private_key_der (
  const uint8_t           *der_buf,
  size_t                  der_size,
  rsa_private_key_params  *params
  )
{
  size_t   offset = 0;
  uint8_t  *temp_value;
  size_t   temp_len;

  /* Parse outer SEQUENCE */
  if (der_buf[offset] != DER_TAG_SEQUENCE) {
    printf ("ERROR: Expected SEQUENCE tag (0x30)\n");
    return -1;
  }

  offset++;

  size_t  seq_len;
  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    printf ("ERROR: Failed to parse SEQUENCE length\n");
    return -1;
  }

  /* Parse version (INTEGER) - should be 0 for two-prime RSA */
  if (der_parse_integer (der_buf, &offset, der_size, &temp_value, &temp_len) != 0) {
    printf ("ERROR: Failed to parse version\n");
    return -1;
  }

  /* Parse modulus (n) - save it to get key size */
  uint8_t *n_ptr = NULL;
  size_t n_len = 0;
  if (der_parse_integer (der_buf, &offset, der_size, &n_ptr, &n_len) != 0) {
    printf ("ERROR: Failed to parse modulus\n");
    return -1;
  }
  params->n.data = n_ptr;
  params->n.size = n_len;

  /* Skip publicExponent (e) */
  if (der_parse_integer (der_buf, &offset, der_size, &temp_value, &temp_len) != 0) {
    printf ("ERROR: Failed to parse publicExponent\n");
    return -1;
  }

  /* Skip privateExponent (d) */
  if (der_parse_integer (der_buf, &offset, der_size, &temp_value, &temp_len) != 0) {
    printf ("ERROR: Failed to parse privateExponent\n");
    return -1;
  }

  /* Parse prime1 (p) */
  uint8_t *p_ptr = NULL;
  size_t p_len = 0;
  if (der_parse_integer (der_buf, &offset, der_size, &p_ptr, &p_len) != 0) {
    printf ("ERROR: Failed to parse prime1 (p)\n");
    return -1;
  }
  params->p.data = p_ptr;
  params->p.size = p_len;

  /* Parse prime2 (q) */
  uint8_t *q_ptr = NULL;
  size_t q_len = 0;
  if (der_parse_integer (der_buf, &offset, der_size, &q_ptr, &q_len) != 0) {
    printf ("ERROR: Failed to parse prime2 (q)\n");
    return -1;
  }
  params->q.data = q_ptr;
  params->q.size = q_len;

  /* Parse exponent1 (dP) */
  uint8_t *dp_ptr = NULL;
  size_t dp_len = 0;
  if (der_parse_integer (der_buf, &offset, der_size, &dp_ptr, &dp_len) != 0) {
    printf ("ERROR: Failed to parse exponent1 (dP)\n");
    return -1;
  }
  params->dp.data = dp_ptr;
  params->dp.size = dp_len;

  /* Parse exponent2 (dQ) */
  uint8_t *dq_ptr = NULL;
  size_t dq_len = 0;
  if (der_parse_integer (der_buf, &offset, der_size, &dq_ptr, &dq_len) != 0) {
    printf ("ERROR: Failed to parse exponent2 (dQ)\n");
    return -1;
  }
  params->dq.data = dq_ptr;
  params->dq.size = dq_len;

  /* Parse coefficient (qInv) */
  uint8_t *qinv_ptr = NULL;
  size_t qinv_len = 0;
  if (der_parse_integer (der_buf, &offset, der_size, &qinv_ptr, &qinv_len) != 0) {
    printf ("ERROR: Failed to parse coefficient (qInv)\n");
    return -1;
  }
  params->qinv.data = qinv_ptr;
  params->qinv.size = qinv_len;

  return 0;
}

/* Parse RSA public key from DER format (PKCS#1 - RSAPublicKey) */
static int
parse_rsa_public_key_pkcs1 (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        **modulus,
  size_t         *modulus_len
  )
{
  size_t   offset  = 0;
  size_t   seq_len = 0;
  uint8_t  *temp_value;
  size_t   temp_len;

  /* Parse outer SEQUENCE */
  if (der_buf[offset] != DER_TAG_SEQUENCE) {
    printf ("ERROR: Expected SEQUENCE tag (0x30) at offset %zu\n", offset);
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    printf ("ERROR: Failed to parse SEQUENCE length\n");
    return -1;
  }

  /* Parse modulus (n) - this returns a pointer into der_buf */
  if (der_parse_integer (der_buf, &offset, der_size, modulus, modulus_len) != 0) {
    printf ("ERROR: Failed to parse modulus\n");
    return -1;
  }

  /* Parse publicExponent (e) - we don't need it but validate it exists */
  if (der_parse_integer (der_buf, &offset, der_size, &temp_value, &temp_len) != 0) {
    printf ("ERROR: Failed to parse publicExponent\n");
    return -1;
  }

  return 0;
}

/* Parse RSA public key from DER format (SubjectPublicKeyInfo - generic PUBLIC KEY) */
static int
parse_rsa_public_key_spki (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        **modulus,
  size_t         *modulus_len
  )
{
  size_t  offset = 0;
  size_t  seq_len;

  /* rsaEncryption OID: 1.2.840.113549.1.1.1 */
  static const uint8_t  rsa_oid[] = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
  };

  /* Parse outer SEQUENCE (SubjectPublicKeyInfo) */
  if (der_buf[offset] != DER_TAG_SEQUENCE) {
    printf ("ERROR: Expected SEQUENCE tag (0x30)\n");
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    printf ("ERROR: Failed to parse outer SEQUENCE length\n");
    return -1;
  }

  /* Parse algorithm identifier SEQUENCE */
  if (der_buf[offset] != DER_TAG_SEQUENCE) {
    printf ("ERROR: Expected algorithm SEQUENCE tag (0x30)\n");
    return -1;
  }

  offset++;

  size_t  alg_seq_len;
  if (der_parse_length (der_buf, &offset, der_size, &alg_seq_len) != 0) {
    printf ("ERROR: Failed to parse algorithm SEQUENCE length\n");
    return -1;
  }

  /* Validate the AlgorithmIdentifier contains rsaEncryption OID */
  size_t  alg_seq_end = offset + alg_seq_len;
  if ((alg_seq_len < sizeof (rsa_oid)) || (alg_seq_end > der_size)) {
    printf ("ERROR: Algorithm identifier too short or extends beyond buffer\n");
    return -1;
  }

  if (memcmp (&der_buf[offset], rsa_oid, sizeof (rsa_oid)) != 0) {
    printf ("ERROR: AlgorithmIdentifier OID is not rsaEncryption\n");
    return -1;
  }

  /* Skip past the full AlgorithmIdentifier SEQUENCE content (OID + optional NULL) */
  offset = alg_seq_end;

  /* Parse BIT STRING containing the public key */
  if (offset >= der_size || der_buf[offset] != DER_TAG_BIT_STRING) {
    printf ("ERROR: Expected BIT STRING tag (0x03)\n");
    return -1;
  }

  offset++;

  size_t  bitstring_len;
  if (der_parse_length (der_buf, &offset, der_size, &bitstring_len) != 0) {
    printf ("ERROR: Failed to parse BIT STRING length\n");
    return -1;
  }

  /* Validate and skip the unused bits byte (must be 0 for byte-aligned keys) */
  if ((offset >= der_size) || (bitstring_len == 0)) {
    printf ("ERROR: Unexpected end of data in BIT STRING\n");
    return -1;
  }

  if (der_buf[offset] != 0x00) {
    printf ("ERROR: BIT STRING unused bits byte is non-zero (0x%02X), malformed key\n", der_buf[offset]);
    return -1;
  }

  offset++;
  bitstring_len--;

  /* Now we have the RSAPublicKey structure (PKCS#1) inside the BIT STRING */
  if (offset + bitstring_len > der_size) {
    printf ("ERROR: BIT STRING extends beyond buffer\n");
    return -1;
  }

  /* Parse the inner RSAPublicKey structure */
  return parse_rsa_public_key_pkcs1 (der_buf + offset, bitstring_len, modulus, modulus_len);
}

/* Extract RSA public key modulus and copy to buffer */
static int
extract_rsa_public_key_to_buffer (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        pem_type,
  uint8_t        *key_buf,
  uint16_t       max_size,
  uint16_t       *key_size
  )
{
  uint8_t  *modulus     = NULL;
  size_t   modulus_len  = 0;
  int      result;

  if (pem_type == PEMTYPE_RSA_PUBLIC) {
    /* PKCS#1 format */
    result = parse_rsa_public_key_pkcs1 (der_buf, der_size, &modulus, &modulus_len);
  } else if (pem_type == PEMTYPE__PUBLIC) {
    /* SubjectPublicKeyInfo format */
    result = parse_rsa_public_key_spki (der_buf, der_size, &modulus, &modulus_len);
  } else {
    return -1;
  }

  if (result != 0) {
    return -1;
  }

  /* Validate key size */
  if ((modulus_len != RSA_KEY_MIN_BYTES) && (modulus_len != RSA_KEY_MAX_BYTES)) {
    printf ("ERROR: Unsupported RSA key size: %zu bytes\n", modulus_len);
    return -1;
  }

  if (modulus_len > max_size) {
    printf ("ERROR: Key buffer too small (%d bytes) for key size (%zu bytes)\n", max_size, modulus_len);
    return -1;
  }

  /* Copy modulus to output buffer, then flip BE to LE
     (match EC key reader and LCP policy list format) */
  memcpy (key_buf, modulus, modulus_len);
  buffer_reverse_byte_order (key_buf, modulus_len);
  *key_size = modulus_len;

  return 0;
}

/* Parse EC public key from SubjectPublicKeyInfo DER format (BEGIN PUBLIC KEY with EC OID) */
static int
parse_ec_public_key_spki (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        *key_buf,
  uint16_t       key_buf_size,
  uint16_t       *key_size
  )
{
  size_t  offset = 0;
  size_t  seq_len, alg_seq_len, bitstring_len;
  size_t  alg_seq_end;
  size_t  coord_size;

  /* id-ecPublicKey OID: 1.2.840.10045.2.1 */
  static const uint8_t  ec_oid[] = {
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
  };

  /* Parse outer SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    return -1;
  }

  /* Parse algorithm identifier SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &alg_seq_len) != 0) {
    return -1;
  }

  alg_seq_end = offset + alg_seq_len;

  /* Check for id-ecPublicKey OID */
  if ((alg_seq_len < sizeof (ec_oid)) || (alg_seq_end > der_size)) {
    return -1;
  }

  if (memcmp (&der_buf[offset], ec_oid, sizeof (ec_oid)) != 0) {
    return -1;
  }

  /* Skip past the full AlgorithmIdentifier SEQUENCE content (EC OID + curve OID) */
  offset = alg_seq_end;

  /* Parse BIT STRING containing the public key point */
  if (offset >= der_size || der_buf[offset] != DER_TAG_BIT_STRING) {
    printf ("ERROR: Expected BIT STRING tag for EC public key\n");
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &bitstring_len) != 0) {
    return -1;
  }

  /* Skip unused bits byte (must be 0) */
  if (offset >= der_size || der_buf[offset] != 0x00) {
    return -1;
  }

  offset++;
  bitstring_len--;

  /* Check for uncompressed point marker (0x04) */
  if (offset >= der_size || der_buf[offset] != EC_POINT_UNCOMPRESSED) {
    printf ("ERROR: Only uncompressed EC points are supported\n");
    return -1;
  }

  offset++;
  bitstring_len--;

  /* Remaining bytes are qx || qy */
  if ((bitstring_len == 0) || (bitstring_len % 2 != 0)) {
    printf ("ERROR: Invalid EC point data length\n");
    return -1;
  }

  coord_size = bitstring_len / 2;

  if ((coord_size != ECC_KEY_LEN_MIN_BYTES) && (coord_size != ECC_KEY_LEN_MAX_BYTES)) {
    printf ("ERROR: Unsupported EC coordinate size: %zu\n", coord_size);
    return -1;
  }

  if (key_buf_size < bitstring_len) {
    printf ("ERROR: Key buffer too small for EC public key\n");
    return -1;
  }

  /* Copy qx || qy to key_buf */
  memcpy (key_buf, &der_buf[offset], bitstring_len);

  /*
   * DER/ASN.1 encodes integers in big-endian order, so coordinates parsed
   * from PEM/DER files are always BE.  Reverse each coordinate to LE to
   * match the binary key format expected by IPPC and LCP policy structures.
   * Binary key files bypass this parser and are already stored in LE.
   */
  buffer_reverse_byte_order (key_buf, coord_size);
  buffer_reverse_byte_order (key_buf + coord_size, coord_size);

  *key_size = (uint16_t)coord_size;

  return 0;
}

/* Parse EC private key from SEC1 DER format (BEGIN EC PRIVATE KEY) */
static int
parse_ec_private_key_sec1 (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        *key_buf,
  uint16_t       key_buf_size,
  uint16_t       *key_size
  )
{
  size_t  offset = 0;
  size_t  seq_len, int_len, octet_len;

  /* Parse outer SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    return -1;
  }

  /* Parse version INTEGER (must be 1) */
  if (offset >= der_size || der_buf[offset] != 0x02) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &int_len) != 0) {
    return -1;
  }

  if ((int_len != 1) || (offset >= der_size) || (der_buf[offset] != 0x01)) {
    printf ("ERROR: EC private key version must be 1\n");
    return -1;
  }

  offset++;

  /* Parse private key OCTET STRING */
  if (offset >= der_size || der_buf[offset] != DER_TAG_OCTET_STRING) {
    printf ("ERROR: Expected OCTET STRING for EC private key\n");
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &octet_len) != 0) {
    return -1;
  }

  if ((octet_len != ECC_KEY_LEN_MIN_BYTES) && (octet_len != ECC_KEY_LEN_MAX_BYTES)) {
    printf ("ERROR: Unsupported EC private key size: %zu\n", octet_len);
    return -1;
  }

  if (offset + octet_len > der_size) {
    printf ("ERROR: EC private key data extends beyond buffer\n");
    return -1;
  }

  if (key_buf_size < octet_len) {
    printf ("ERROR: Key buffer too small for EC private key\n");
    return -1;
  }

  /* Copy private key scalar to key_buf */
  memcpy (key_buf, &der_buf[offset], octet_len);

  /* Reverse to LE (match binary key format used by IPPC) */
  buffer_reverse_byte_order (key_buf, octet_len);

  *key_size = (uint16_t)octet_len;

  return 0;
}

/* DER key extraction with ASN.1 parsing */
static uint8_t
get_key_from_der (
  uint8_t   *der_buf,
  uint16_t  der_size,
  uint8_t   pem_type,
  uint16_t  *key_size
  )
{
  /* Handle RSA public keys */
  if (pem_type == PEMTYPE_RSA_PUBLIC) {
    /* PKCS#1 format: RSAPublicKey */
    uint8_t  *modulus;
    size_t   modulus_len;

    if (parse_rsa_public_key_pkcs1 (der_buf, der_size, &modulus, &modulus_len) != 0) {
      printf ("ERROR: Failed to parse RSA public key (PKCS#1)\n");
      return crypto_operation_fail;
    }

    *key_size = modulus_len;
    return crypto_ok;
  } else if (pem_type == PEMTYPE__PUBLIC) {
    /* SubjectPublicKeyInfo format: generic PUBLIC KEY */
    uint8_t  *modulus;
    size_t   modulus_len;

    if (parse_rsa_public_key_spki (der_buf, der_size, &modulus, &modulus_len) != 0) {
      printf ("ERROR: Failed to parse RSA public key (SubjectPublicKeyInfo)\n");
      return crypto_operation_fail;
    }

    *key_size = modulus_len;
    return crypto_ok;
  } else if ((pem_type == PEMTYPE_RSA_PRIVATE) || (pem_type == PEMTYPE__PRIVATE)) {
    /* RSA private key */
    /* Parse the DER structure - this extracts the CRT parameters but doesn't copy to key_buf
     * The actual key loading is done in rsa_load_private_key_from_file which stores
     * the DER buffer pointer for later use */
    rsa_private_key_params  params;
    if (parse_rsa_private_key_der (der_buf, der_size, &params) != 0) {
      printf ("ERROR: Failed to parse RSA private key DER structure\n");
      return crypto_operation_fail;
    }

    /* Return the modulus size as the key size for algorithm detection */
    *key_size = params.n.size;
    return crypto_ok;
  }

  printf ("WARNING: get_key_from_der does not support pem_type %d\n", pem_type);
  return crypto_operation_fail;
}

static uint8_t
get_der_from_pem (
  char      *pem_data_buf,
  uint16_t  pem_data_size,
  uint8_t   **p_der_buf,
  uint16_t  *p_der_size
  )
{
  /* This routine converts BASE64 encoded PEM key to DER sequence
   * it Allocates DER buffer which must be freed by caller
   */

  uint32_t  i;
  uint8_t   key_type;
  uint8_t   *p_pem_header;
  uint8_t   *p_b64_string;
  uint32_t  b64_length;

  *p_der_size = 0;

  /* Note: PEM files can contain CR and LF characters (0x0D and 0x0A) or just LF */
  /* Evaluate PEM header */
  p_pem_header = (uint8_t *)pem_data_buf;

  /* Header is terminated by '\n' (0x0A) character - replace with NULL */
  for (i = 0; i < pem_data_size; i++) {
    if (0x0a == *(pem_data_buf+i)) {
      break;
    }
  }

  if (i == pem_data_size) {
    /* not a PEM file - might be a binary file */
    return PEMTYPE_INVALID;
  }

  *(pem_data_buf+i) = 0;
  if (i > 0 && *(pem_data_buf+i-1) == 0x0D) {
    *(pem_data_buf + i - 1) = 0;
  }

  i++;

  if (strcmp ((char *)p_pem_header, "-----BEGIN EC PARAMETERS-----") == 0) {
    /* need to skip past to end of "-----END EC PARAMETERS-----") */
    for ( ; i < (uint32_t)(pem_data_size-10); i++) {
      if ('-' == *(pem_data_buf+i)) {
        /* Found EC Params trailer */
        break;
      }
    }

    for ( ; i < (uint32_t)(pem_data_size-10); i++) {
      if ('\n' == *(pem_data_buf+i)) {
        /* Found end of EC Params trailer */
        break;
      }
    }

    i++;
    p_pem_header = (uint8_t *)pem_data_buf + i;
    for ( ; i < (uint32_t)(pem_data_size-10); i++) {
      if (0x0a == *(pem_data_buf+i)) {
        *(pem_data_buf+i) = 0;
        if (*(pem_data_buf+i-1) == 0x0D) {
          *(pem_data_buf+i-1) = 0;
        }

        break;
      }
    }

    i++;
  }

  /* We are either at the first header or skipped past the EC Params section */
  if (strcmp ((char *)p_pem_header, "-----BEGIN EC PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE_EC_PUBLIC;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN EC PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE_EC_PRIVATE;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN RSA PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE_RSA_PUBLIC;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN RSA PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE_RSA_PRIVATE;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN LMS PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE_LMS_PUBLIC;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN LMS PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE_LMS_PRIVATE;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE__PUBLIC;
  } else if (strcmp ((char *)p_pem_header, "-----BEGIN PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE__PRIVATE;
  } else {
    printf ("ERROR: unsupported PEM header %s\n", p_pem_header);
    return PEMTYPE_UNKNOWN;
  }

  /* Set pointer to Base64 string */
  p_b64_string = (uint8_t *)pem_data_buf + i;

  /* Calculate B64 String Length = Trailer - B64String */
  /* Find Trailer */
  for ( ; i < (uint32_t)(pem_data_size-10); i++) {
    if ('-' == *(pem_data_buf+i)) {
      /* note that '-' does not appear in Base64 encoding */
      break;
    }
  }

  b64_length = (uint8_t *)pem_data_buf + i - p_b64_string;

  /* Allocate DER buffer (3 bytes for every 4 Base64 bytes) actual size will be less */
  uint32_t  der_buf_size = (3*b64_length)/4;
  *p_der_buf = (uint8_t *)malloc (der_buf_size);
  if (*p_der_buf == NULL) {
    printf ("ERROR: Failed to allocate DER buffer\n");
    return PEMTYPE_UNKNOWN;
  }

  /* Decode PEM Base64 to DER */
  *p_der_size = base64_decode (p_b64_string, b64_length, *p_der_buf, der_buf_size);
  if (*p_der_size == 0) {
    printf ("ERROR: Failed to decode PEM\n");
    free (*p_der_buf);
    *p_der_buf = NULL;
    return PEMTYPE_UNKNOWN;
  }

  return key_type;
}

static crypto_status
handle_pem_type_validation (
  uint8_t      pem_type,
  bool         is_private,
  const char   *filename,
  uint16_t     *alg_id
  )
{
  /* Set algorithm ID based on PEM type */
  if (alg_id != NULL) {
    switch (pem_type) {
      case PEMTYPE_EC_PRIVATE:
      case PEMTYPE_EC_PUBLIC:
        *alg_id = KEY_ALG_TYPE_ECC;
        break;
      case PEMTYPE_RSA_PRIVATE:
      case PEMTYPE_RSA_PUBLIC:
        *alg_id = KEY_ALG_TYPE_RSA;
        break;
      case PEMTYPE_LMS_PRIVATE:
      case PEMTYPE_LMS_PUBLIC:
        *alg_id = KEY_ALG_TYPE_LMS;
        break;
      case PEMTYPE__PUBLIC:
      case PEMTYPE__PRIVATE:
        /* Generic PEM types - algorithm will be refined by key size detection later */
        *alg_id = HASH_ALG_TYPE_NULL;
        break;
      default:
        *alg_id = HASH_ALG_TYPE_NULL;
        break;
    }
  }

  /* Validate that key type matches is_private parameter */
  switch (pem_type) {
    case PEMTYPE_RSA_PUBLIC:
    case PEMTYPE_EC_PUBLIC:
    case PEMTYPE_LMS_PUBLIC:
    case PEMTYPE__PUBLIC:
      if (is_private) {
        printf ("ERROR: Wrong key type (%s)\n", filename);
        return crypto_operation_fail;
      }
      break;
    case PEMTYPE_EC_PRIVATE:
    case PEMTYPE_RSA_PRIVATE:
    case PEMTYPE_LMS_PRIVATE:
    case PEMTYPE__PRIVATE:
      if (!is_private) {
        printf ("ERROR: Wrong key type (%s)\n", filename);
        return crypto_operation_fail;
      }
      break;
    case PEMTYPE_UNKNOWN:
    case PEMTYPE_INVALID:
      /* could be binary key */
      break;
    default:
      break;
  }

  return crypto_ok;
}

static crypto_status
handle_der_format_key (
  uint8_t      *p_der_buf,
  uint16_t     der_size,
  uint8_t      pem_type,
  uint8_t      *key_buf,
  uint16_t     *key_size,
  uint16_t     *alg_id
  )
{
  uint16_t       orig_key_buf_size = *key_size;
  crypto_status  status;

  /* Handle EC public key from SPKI format (BEGIN PUBLIC KEY with EC OID) */
  if (pem_type == PEMTYPE__PUBLIC) {
    if (parse_ec_public_key_spki (p_der_buf, der_size, key_buf, orig_key_buf_size, key_size) == 0) {
      if (alg_id != NULL) {
        *alg_id = KEY_ALG_TYPE_ECC;
      }
      return crypto_ok;
    }
    /* Not an EC key - fall through to RSA parsing */
  }

  /* Handle EC private key from SEC1 format (BEGIN EC PRIVATE KEY) */
  if (pem_type == PEMTYPE_EC_PRIVATE) {
    if (parse_ec_private_key_sec1 (p_der_buf, der_size, key_buf, orig_key_buf_size, key_size) == 0) {
      if (alg_id != NULL) {
        *alg_id = KEY_ALG_TYPE_ECC;
      }
      return crypto_ok;
    }
    return crypto_operation_fail;
  }

  /* Handle EC public key (BEGIN EC PUBLIC KEY - rare but supported) */
  if (pem_type == PEMTYPE_EC_PUBLIC) {
    /* EC PUBLIC KEY PEM is not standard SPKI, but try SPKI parsing anyway */
    if (parse_ec_public_key_spki (p_der_buf, der_size, key_buf, orig_key_buf_size, key_size) == 0) {
      if (alg_id != NULL) {
        *alg_id = KEY_ALG_TYPE_ECC;
      }
      return crypto_ok;
    }
    return crypto_operation_fail;
  }

  /* RSA key handling */
  status = get_key_from_der (p_der_buf, der_size, pem_type, key_size);

  if (alg_id != NULL) {
    if ((*key_size == RSA_KEY_MIN_BYTES) || (*key_size == RSA_KEY_MAX_BYTES)) {
      *alg_id = KEY_ALG_TYPE_RSA;
    } else if ((*key_size == ECC_KEY_LEN_MIN_BYTES) || (*key_size == ECC_KEY_LEN_MAX_BYTES)) {
      *alg_id = KEY_ALG_TYPE_ECC;
    } else {
      *alg_id = HASH_ALG_TYPE_NULL;
    }
  }

  if (status == crypto_ok) {
    /* For RSA public keys, extract the modulus to key_buf */
    if ((pem_type == PEMTYPE_RSA_PUBLIC) || (pem_type == PEMTYPE__PUBLIC)) {
      if (extract_rsa_public_key_to_buffer (p_der_buf, der_size, pem_type, key_buf, orig_key_buf_size, key_size) != 0) {
        printf ("ERROR: Failed to extract RSA public key modulus\n");
        return crypto_operation_fail;
      }
    }
    /* For RSA private keys, the DER parsing just validates and returns size */
    /* The actual key data will be used later during signing operations */
  }

  return status;
}

static crypto_status
handle_binary_ecc_private_key (
  uint8_t   *p_file_data_buf,
  size_t    file_data_size,
  uint8_t   *key_buf,
  uint16_t  *key_size,
  uint16_t  *alg_id
  )
{
  if (alg_id != NULL) {
    *alg_id = KEY_ALG_TYPE_ECC;
  }

  if (*key_size < file_data_size) {
    printf ("ERROR: Key too large %zu (max: %d)\n", file_data_size, *key_size);
    *key_size = 0;
    return crypto_operation_fail;
  }

  memcpy (key_buf, p_file_data_buf, file_data_size);
  /* Binary ECC private keys are stored in LE (TPM convention).
   * crypto_read_key returns ECC keys in LE — no reversal needed. */
  *key_size = file_data_size;
  return crypto_ok;
}

static crypto_status
handle_binary_ecc_public_key (
  uint8_t   *p_file_data_buf,
  size_t    file_data_size,
  uint8_t   *key_buf,
  uint16_t  *key_size,
  uint16_t  *alg_id
  )
{
  if (alg_id != NULL) {
    *alg_id = KEY_ALG_TYPE_ECC;
  }

  if (*key_size * 2 < file_data_size) {
    printf ("ERROR: Key too large %zu (max: %d)\n", file_data_size, *key_size);
    *key_size = 0;
    return crypto_operation_fail;
  }

  memcpy (key_buf, p_file_data_buf, file_data_size);
  /* Binary ECC public keys are stored as qx_LE || qy_LE (TPM convention).
   * crypto_read_key returns ECC keys in LE — no reversal needed. */
  *key_size = file_data_size/2;
  return crypto_ok;
}

static crypto_status
handle_binary_rsa_key (
  uint8_t   *p_file_data_buf,
  size_t    file_data_size,
  uint8_t   *key_buf,
  uint16_t  *key_size,
  uint16_t  *alg_id
  )
{
  if (alg_id != NULL) {
    *alg_id = KEY_ALG_TYPE_RSA;
  }

  memcpy (key_buf, p_file_data_buf, file_data_size);
  /* Flip to LE (match EC key reader and LCP policy list format) */
  buffer_reverse_byte_order (key_buf, file_data_size);
  *key_size = file_data_size;
  return crypto_ok;
}

static crypto_status
handle_binary_lms_public_key (
  uint8_t   *p_file_data_buf,
  size_t    file_data_size,
  uint8_t   *key_buf,
  uint16_t  *key_size,
  uint16_t  *alg_id
  )
{
  size_t actual_size = file_data_size;

  if (alg_id != NULL) {
    *alg_id = KEY_ALG_TYPE_LMS;
  }

  /* Handle optional 4-byte prefix */
  if (file_data_size == LMS_PUBLIC_KEY_MAX_BYTES + 4) {
    actual_size -= 4;
    memcpy (key_buf, p_file_data_buf + 4, actual_size);
  } else {
    memcpy (key_buf, p_file_data_buf, actual_size);
  }

  *key_size = actual_size;
  return crypto_ok;
}

static crypto_status
handle_binary_lms_private_key (
  uint8_t   *p_file_data_buf,
  size_t    file_data_size,
  uint8_t   *key_buf,
  uint16_t  *key_size,
  uint16_t  *alg_id
  )
{
  size_t actual_size = file_data_size;

  if (alg_id != NULL) {
    *alg_id = KEY_ALG_TYPE_LMS;
  }

  /* Handle optional 4-byte prefix */
  if (file_data_size == LMS_PRIVATE_KEY_MAX_BYTES + 4) {
    actual_size -= 4;
    memcpy (key_buf, p_file_data_buf + 4, actual_size);
  } else {
    memcpy (key_buf, p_file_data_buf, actual_size);
  }

  buffer_reverse_byte_order (key_buf, actual_size);
  *key_size = actual_size;
  return crypto_ok;
}

static crypto_status
handle_binary_format_key (
  uint8_t   *p_file_data_buf,
  size_t    file_data_size,
  bool      is_private,
  uint8_t   *key_buf,
  uint16_t  *key_size,
  uint16_t  *alg_id
  )
{
  /* Binary ECC private key */
  if (is_private && ((file_data_size == ECC_KEY_LEN_MIN_BYTES) || (file_data_size == ECC_KEY_LEN_MAX_BYTES))) {
    return handle_binary_ecc_private_key (p_file_data_buf, file_data_size, key_buf, key_size, alg_id);
  }
  
  /* Binary ECC public key */
  if (!is_private && ((file_data_size == (2*ECC_KEY_LEN_MIN_BYTES)) || (file_data_size == (2*ECC_KEY_LEN_MAX_BYTES)))) {
    return handle_binary_ecc_public_key (p_file_data_buf, file_data_size, key_buf, key_size, alg_id);
  }
  
  /* Binary RSA key */
  if ((file_data_size == RSA_KEY_MIN_BYTES) || (file_data_size == RSA_KEY_MAX_BYTES)) {
    return handle_binary_rsa_key (p_file_data_buf, file_data_size, key_buf, key_size, alg_id);
  }
  
  /* Binary LMS public key */
  if ((file_data_size == (LMS_PUBLIC_KEY_MAX_BYTES + 4)) ||
      (file_data_size == LMS_PUBLIC_KEY_MAX_BYTES)) {
    return handle_binary_lms_public_key (p_file_data_buf, file_data_size, key_buf, key_size, alg_id);
  }
  
  /* Binary LMS private key */
  if ((file_data_size == LMS_PRIVATE_KEY_MAX_BYTES) ||
      (file_data_size == LMS_PRIVATE_KEY_MAX_BYTES + 4)) {
    return handle_binary_lms_private_key (p_file_data_buf, file_data_size, key_buf, key_size, alg_id);
  }

  return crypto_operation_fail;
}

crypto_status
crypto_read_key (
  const char  *filename,
  bool        is_private,
  uint8_t     *key_buf,
  uint16_t    *key_size,
  uint16_t    *alg_id
  )
{
  /* Opens the specified file and extracts the desired key to specified location
   * Detects file type (PEM | DER | BINARY)
   */

  uint8_t        *p_file_data_buf;
  size_t         file_data_size;
  crypto_status  status;
  uint8_t        *p_der_buf;
  uint16_t       der_size = 0;
  uint8_t        pem_type = 0;

  /* Read the key file */
  p_file_data_buf = (uint8_t *)read_file (filename, &file_data_size, false);
  if (p_file_data_buf == NULL) {
    printf ("Error reading Key file\n");
    return crypto_operation_fail;
  }

  /* Check if file is PEM format and convert to DER if needed */
  if ((memcmp (p_file_data_buf, "-----BEG", 8) == 0) && (file_data_size > 0x80)) {
    /* PEM format - convert to DER */
    pem_type = get_der_from_pem ((char *)p_file_data_buf, file_data_size, &p_der_buf, &der_size);
    if (der_size == 0) {
      printf ("ERROR: Corrupted PEM file\n");
      free ((void *)p_file_data_buf);
      return crypto_operation_fail;
    }

    /* Validate PEM type and set algorithm ID */
    status = handle_pem_type_validation (pem_type, is_private, filename, alg_id);
    if (status != crypto_ok) {
      if (p_der_buf != p_file_data_buf) {
        free ((void *)p_der_buf);
      }
      free ((void *)p_file_data_buf);
      return status;
    }
  } else {
    /* Not PEM format - use raw file data */
    p_der_buf = p_file_data_buf;
    der_size  = file_data_size;
  }

  /* Try to handle as DER format */
  if ((der_size != 0) && (*p_der_buf == DER_TAG_SEQUENCE)) {
    status = handle_der_format_key (p_der_buf, der_size, pem_type, key_buf, key_size, alg_id);
    
    if (status == crypto_ok) {
      free ((void *)p_file_data_buf);
      if ((p_der_buf != p_file_data_buf) && (p_der_buf != NULL)) {
        free ((void *)p_der_buf);
      }
      return crypto_ok;
    }
  }

  /* Not DER format - clean up DER buffer if separate */
  if (p_der_buf != p_file_data_buf) {
    free ((void *)p_der_buf);
  }

  /* Try to handle as binary format */
  status = handle_binary_format_key (p_file_data_buf, file_data_size, is_private, key_buf, key_size, alg_id);
  
  if (status == crypto_ok) {
    free ((void *)p_file_data_buf);
    return crypto_ok;
  }

  /* No valid format found */
  printf ("ERROR: Invalid Key (%s)\n", filename);
  free ((void *)p_file_data_buf);
  return crypto_operation_fail;
}

crypto_status
crypto_read_rsa_pubkey_internal (
  const char     *file,
  unsigned char  **key,
  size_t         *keysize
  )
{
  uint8_t        temp_buf[RSA_KEY_MAX_BYTES];
  uint16_t       temp_size = RSA_KEY_MAX_BYTES;
  uint16_t       alg_id    = 0;
  crypto_status  status;

  if ((file == NULL) || (key == NULL) || (keysize == NULL)) {
    printf ("ERROR: NULL pointer passed to crypto_read_rsa_pubkey_internal\n");
    return crypto_nullptr_error;
  }

  /* Read the key using crypto_read_key */
  status = crypto_read_key (file, false, temp_buf, &temp_size, &alg_id);
  if (status != crypto_ok) {
    return status;
  }

  /* Verify it's an RSA key */
  if (alg_id != KEY_ALG_TYPE_RSA) {
    printf ("ERROR: Key is not an RSA key (alg_id: %d)\n", alg_id);
    return crypto_invalid_key;
  }

  /* Allocate buffer for the key */
  *key = (unsigned char *)malloc (temp_size);
  if (*key == NULL) {
    printf ("ERROR: Failed to allocate memory for RSA public key\n");
    return crypto_memory_alloc_fail;
  }

  /* Copy the key data */
  memcpy (*key, temp_buf, temp_size);
  *keysize = (size_t)temp_size;

  return crypto_ok;
}

crypto_status
crypto_read_ecdsa_pubkey_internal (
  const char  *file,
  uint8_t     **qx,
  uint8_t     **qy,
  size_t      *key_size_bytes
  )
{
  uint8_t        temp_buf[ECC_KEY_LEN_MAX_BYTES * 2];
  uint16_t       temp_size = ECC_KEY_LEN_MAX_BYTES * 2;
  uint16_t       alg_id    = 0;
  crypto_status  status;
  size_t         coord_size;

  if ((file == NULL) || (qx == NULL) || (qy == NULL) || (key_size_bytes == NULL)) {
    printf ("ERROR: NULL pointer passed to crypto_read_ecdsa_pubkey_internal\n");
    return crypto_nullptr_error;
  }

  /* Read the key using crypto_read_key */
  status = crypto_read_key (file, false, temp_buf, &temp_size, &alg_id);
  if (status != crypto_ok) {
    return status;
  }

  /* Verify it's an ECC key */
  if (alg_id != KEY_ALG_TYPE_ECC) {
    printf ("ERROR: Key is not an ECC key (alg_id: %d)\n", alg_id);
    return crypto_invalid_key;
  }

  /* ECC public key consists of qx and qy coordinates, each of size temp_size */
  coord_size = (size_t)temp_size;

  /* Allocate buffers for qx and qy */
  *qx = (uint8_t *)malloc (coord_size);
  if (*qx == NULL) {
    printf ("ERROR: Failed to allocate memory for ECC qx coordinate\n");
    return crypto_memory_alloc_fail;
  }

  *qy = (uint8_t *)malloc (coord_size);
  if (*qy == NULL) {
    printf ("ERROR: Failed to allocate memory for ECC qy coordinate\n");
    free (*qx);
    *qx = NULL;
    return crypto_memory_alloc_fail;
  }

  /* Copy the coordinate data (qx is first half, qy is second half) */
  memcpy (*qx, temp_buf, coord_size);
  memcpy (*qy, temp_buf + coord_size, coord_size);
  *key_size_bytes = coord_size;

  return crypto_ok;
}



/* Helper function to create BigNum from byte array */
static IppStatus
create_bignum_from_bytes (
  const uint8_t    *data,
  int              data_len,
  IppsBigNumState  **pp_bn
  )
{
  int        bn_size = 0;
  IppStatus  status;

  /* Get required size for BigNum */
  status = ippsBigNumGetSize (data_len, &bn_size);
  if (status != ippStsNoErr) {
    return status;
  }

  /* Allocate BigNum structure */
  *pp_bn = (IppsBigNumState *)malloc (bn_size);
  if (*pp_bn == NULL) {
    return ippStsMemAllocErr;
  }

  /* Initialize BigNum */
  status = ippsBigNumInit (data_len, *pp_bn);
  if (status != ippStsNoErr) {
    free (*pp_bn);
    *pp_bn = NULL;
    return status;
  }

  /* Set BigNum value from octet string */
  status = ippsSetOctString_BN (data, data_len, *pp_bn);
  if (status != ippStsNoErr) {
    free (*pp_bn);
    *pp_bn = NULL;
    return status;
  }

  return ippStsNoErr;
}

/* Helper function to create RSA private key context from file */
static IppsRSAPrivateKeyState *
rsa_load_private_key_from_file (
  const char  *privkey_file,
  int         *key_size_bits,
  int         *key_ctx_size_out
  )
{
  uint8_t                 *file_data = NULL;
  size_t                  file_size  = 0;
  uint8_t                 *der_buf   = NULL;
  uint16_t                der_size   = 0;
  uint8_t                 pem_type   = 0;
  rsa_private_key_params  params     = { 0 };
  IppStatus               ipp_status;
  IppsRSAPrivateKeyState  *priv_key = NULL;
  IppsBigNumState         *p_bn = NULL, *q_bn = NULL;
  IppsBigNumState         *dp_bn = NULL, *dq_bn = NULL, *qinv_bn = NULL;
  int                     key_ctx_size = 0;
  int                     factor_bits_p, factor_bits_q;

  /* Read the file */
  file_data = (uint8_t *)read_file (privkey_file, &file_size, false);
  if (file_data == NULL) {
    printf ("ERROR: Failed to read RSA private key file\n");
    return NULL;
  }

  /* Check if it's PEM and convert to DER if needed */
  if (memcmp (file_data, "-----BEG", 8) == 0) {
    /* PEM format - convert to DER */
    pem_type = get_der_from_pem ((char *)file_data, file_size, &der_buf, &der_size);
    free (file_data);
    file_data = NULL;

    if ((der_size == 0) || (der_buf == NULL)) {
      printf ("ERROR: Failed to convert PEM to DER\n");
      return NULL;
    }
  } else if (file_data[0] == DER_TAG_SEQUENCE) {
    /* Already DER format */
    der_buf  = file_data;
    der_size = file_size;
    pem_type = PEMTYPE_RSA_PRIVATE;
  } else {
    printf ("ERROR: Unrecognized key format (not PEM or DER)\n");
    free (file_data);
    return NULL;
  }

  /* Verify it's an RSA private key */
  if ((pem_type != PEMTYPE_RSA_PRIVATE) && (pem_type != PEMTYPE__PRIVATE)) {
    printf ("ERROR: Not an RSA private key\n");
    free (der_buf);
    return NULL;
  }

  /* Parse the DER structure to extract CRT parameters */
  if (parse_rsa_private_key_der (der_buf, der_size, &params) != 0) {
    printf ("ERROR: Failed to parse RSA private key\n");
    free (der_buf);
    return NULL;
  }

  /* Calculate key size from p and q */
  factor_bits_p  = params.p.size * 8;
  factor_bits_q  = params.q.size * 8;
  *key_size_bits = (factor_bits_p + factor_bits_q);

  /* Create BigNum structures from the parsed parameters */
  if (create_bignum_from_bytes (params.p.data, params.p.size, &p_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for p\n");
    goto cleanup;
  }
  if (create_bignum_from_bytes (params.q.data, params.q.size, &q_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for q\n");
    goto cleanup;
  }
  if (create_bignum_from_bytes (params.dp.data, params.dp.size, &dp_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for dP\n");
    goto cleanup;
  }
  if (create_bignum_from_bytes (params.dq.data, params.dq.size, &dq_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for dQ\n");
    goto cleanup;
  }
  if (create_bignum_from_bytes (params.qinv.data, params.qinv.size, &qinv_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for qInv\n");
    goto cleanup;
  }

  /* Get size for private key context */
  ipp_status = ippsRSA_GetSizePrivateKeyType2 (factor_bits_p, factor_bits_q, &key_ctx_size);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA private key size: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Allocate private key context */
  priv_key = (IppsRSAPrivateKeyState *)malloc (key_ctx_size);
  if (priv_key == NULL) {
    printf ("ERROR: Failed to allocate RSA private key context\n");
    goto cleanup;
  }

  /* Initialize private key */
  ipp_status = ippsRSA_InitPrivateKeyType2 (factor_bits_p, factor_bits_q, priv_key, key_ctx_size);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize RSA private key: %s\n", ippcpGetStatusString (ipp_status));
    free (priv_key);
    priv_key = NULL;
    goto cleanup;
  }

  /* Set private key parameters */
  ipp_status = ippsRSA_SetPrivateKeyType2 (p_bn, q_bn, dp_bn, dq_bn, qinv_bn, priv_key);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: Failed to set RSA private key parameters: %s\n", ippcpGetStatusString (ipp_status));
    free (priv_key);
    priv_key = NULL;
    goto cleanup;
  }

  if (key_ctx_size_out != NULL) {
    *key_ctx_size_out = key_ctx_size;
  }

cleanup:
  /* Free temporary resources — zero key material first */
  if (der_buf) {
    explicit_bzero (der_buf, der_size);
    free (der_buf);
  }

  /* Zero BigNum states holding private key factors before freeing.
   * We recompute the state size via ippsBigNumGetSize for each. */
  {
    int bn_sz = 0;
    if (p_bn) {
      if (ippsBigNumGetSize (params.p.size, &bn_sz) == ippStsNoErr)
        explicit_bzero (p_bn, bn_sz);
      free (p_bn);
    }

    if (q_bn) {
      if (ippsBigNumGetSize (params.q.size, &bn_sz) == ippStsNoErr)
        explicit_bzero (q_bn, bn_sz);
      free (q_bn);
    }

    if (dp_bn) {
      if (ippsBigNumGetSize (params.dp.size, &bn_sz) == ippStsNoErr)
        explicit_bzero (dp_bn, bn_sz);
      free (dp_bn);
    }

    if (dq_bn) {
      if (ippsBigNumGetSize (params.dq.size, &bn_sz) == ippStsNoErr)
        explicit_bzero (dq_bn, bn_sz);
      free (dq_bn);
    }

    if (qinv_bn) {
      if (ippsBigNumGetSize (params.qinv.size, &bn_sz) == ippStsNoErr)
        explicit_bzero (qinv_bn, bn_sz);
      free (qinv_bn);
    }
  }

  return priv_key;
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
  IppsRSAPrivateKeyState  *priv_key    = NULL;
  const IppsHashMethod    *hash_method = NULL;
  IppStatus               status;
  int                     key_size_bits    = 0;
  int                     priv_key_ctx_sz  = 0;
  int                     buffer_size      = 0;
  uint8_t                 *scratch_buffer  = NULL;

  if ((sig_block == NULL) || (digest == NULL) || (privkey_file == NULL)) {
    printf ("ERROR: crypto_rsa_sign_internal called with NULL pointer\n");
    return crypto_nullptr_error;
  }

  /* Load private key */
  priv_key = rsa_load_private_key_from_file (privkey_file, &key_size_bits, &priv_key_ctx_sz);
  if (priv_key == NULL) {
    printf ("ERROR: Failed to load RSA private key\n");
    return crypto_operation_fail;
  }

  crypto_status  result_code = crypto_operation_fail;

  /* Get hash method */
  hash_method = get_ipp_hash_method (hash_alg);
  if (hash_method == NULL) {
    printf ("ERROR: Unsupported hash algorithm\n");
    result_code = crypto_unknown_hashalg;
    goto rsa_sign_cleanup;
  }

  /* Get buffer size for signing operation */
  status = ippsRSA_GetBufferSizePrivateKey (&buffer_size, priv_key);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA buffer size: %s\n", ippcpGetStatusString (status));
    goto rsa_sign_cleanup;
  }

  /* Allocate scratch buffer */
  scratch_buffer = (uint8_t *)malloc (buffer_size);
  if (scratch_buffer == NULL) {
    printf ("ERROR: Failed to allocate scratch buffer\n");
    goto rsa_sign_cleanup;
  }

  /* Perform signing based on signature algorithm */
  if (sig_alg == TPM_ALG_RSASSA) {
    /* PKCS#1 v1.5 signing */
    status = ippsRSASign_PKCS1v15_rmf (
                                       digest->data,
                                       digest->size,
                                       sig_block->data,
                                       priv_key,
                                       NULL, /* No public key needed for signing */
                                       hash_method,
                                       scratch_buffer
                                       );
  } else if (sig_alg == TPM_ALG_RSAPSS) {
    /* PSS signing - requires salt */
    int      salt_len  = 0; /* Salt length, typically hash output length */
    uint8_t  *pss_salt = NULL;

    /* Determine salt length based on hash algorithm */
    switch (hash_alg) {
      case TB_HALG_SHA256:
        salt_len = 32;
        break;
      case TB_HALG_SHA384:
        salt_len = 48;
        break;
      case TB_HALG_SHA512:
        salt_len = 64;
        break;
      default:
        salt_len = 32;  /* Default to SHA256 length */
        break;
    }

    /* IPPC requires a non-NULL salt buffer — generate random bytes */
    pss_salt = (uint8_t *)malloc (salt_len);
    if (pss_salt == NULL) {
      printf ("ERROR: Failed to allocate PSS salt buffer\n");
      goto rsa_sign_cleanup;
    }

    {
      /* Use ippsTRNGenRDSEED_BN to generate random salt via a temporary BigNum */
      IppsBigNumState  *salt_bn   = NULL;
      int              salt_bn_sz = 0;

      if (ippsBigNumGetSize (salt_len, &salt_bn_sz) != ippStsNoErr) {
        free (pss_salt);
        goto rsa_sign_cleanup;
      }

      salt_bn = (IppsBigNumState *)malloc (salt_bn_sz);
      if (salt_bn == NULL) {
        free (pss_salt);
        goto rsa_sign_cleanup;
      }

      if (ippsBigNumInit (salt_len, salt_bn) != ippStsNoErr ||
          ippsTRNGenRDSEED_BN (salt_bn, salt_len * 8, NULL) != ippStsNoErr ||
          ippsGetOctString_BN (pss_salt, salt_len, salt_bn) != ippStsNoErr) {
        free (salt_bn);
        free (pss_salt);
        goto rsa_sign_cleanup;
      }

      free (salt_bn);
    }

    status = ippsRSASign_PSS_rmf (
                                  digest->data,
                                  digest->size,
                                  pss_salt,
                                  salt_len,
                                  sig_block->data,
                                  priv_key,
                                  NULL, /* No public key needed for signing */
                                  hash_method,
                                  scratch_buffer
                                  );
    free (pss_salt);
  } else {
    printf ("ERROR: Unsupported RSA signature algorithm: 0x%04X\n", sig_alg);
    goto rsa_sign_cleanup;
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: RSA signing failed with status: %s\n", ippcpGetStatusString (status));
    goto rsa_sign_cleanup;
  }

  result_code = crypto_ok;

rsa_sign_cleanup:
  if (priv_key) {
    explicit_bzero (priv_key, priv_key_ctx_sz);
  }
  free (priv_key);
  free (scratch_buffer);
  return result_code;
}

/* Helper function to extract hash algorithm from PKCS#1 padded signature
 * Used for backwards compatibility with old LCP list formats
 * Based on OpenSSL's pkcs_get_hashalg function */
static uint16_t
pkcs_get_hashalg (
  const unsigned char  *data
  )
{
  uint8_t  der_oid = DER_TAG_OID;
  size_t   oid_size;

  if (data == NULL) {
    return TPM_ALG_NULL;
  }

  data += 2;   /* Skip 00 01 */
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
  /* Read oid size */
  oid_size = *data;
  if (oid_size == 0x05) {
    return TPM_ALG_NULL;
  }

  /* Move to the last byte of the OID to determine hash algorithm.
   * SHA-2 OIDs end with 01 (SHA-256), 02 (SHA-384), 03 (SHA-512).
   * data currently points to the OID length byte; advance oid_size
   * to land on the last byte of the OID content. */
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
  IppsRSAPublicKeyState  *pub_key     = NULL;
  IppsBigNumState        *modulus_bn  = NULL;
  IppsBigNumState        *exp_bn      = NULL;
  const IppsHashMethod   *hash_method = NULL;
  IppStatus              status;
  int                    key_size_bits;
  int                    pub_exp_bits     = 32; /* Typical public exponent is 65537 (0x010001) */
  int                    pub_key_size     = 0;
  int                    buffer_size      = 0;
  uint8_t                *scratch_buffer  = NULL;
  int                    is_valid         = 0;
  bool                   result           = false;
  uint8_t                pub_exp[]        = { 0x01, 0x00, 0x01 }; /* 65537 in big-endian */

  if ((data == NULL) || (pubkey == NULL) || (signature == NULL)) {
    printf ("ERROR: crypto_verify_rsa_signature_internal called with NULL pointer\n");
    return false;
  }

  /* Backwards compatibility: For old list versions, extract hash algorithm from signature */
  if ((list_ver & 0xFF00) != (LCP_TPM20_POLICY_LIST2_1_VERSION_300 & 0xFF00)) {
    /* Old list format - need to decrypt signature to get hash algorithm */
    /* Note: IPPC's RSA operations work with BigNum, not raw bytes for encryption */
    /* For backwards compatibility, we'll need to use raw RSA operation */
    uint8_t  *decrypted_sig = (uint8_t *)malloc (pubkey->size);
    if (decrypted_sig != NULL) {
      /* Create temporary RSA structures for raw decryption */
      IppsRSAPublicKeyState  *temp_key     = NULL;
      IppsBigNumState        *temp_mod_bn  = NULL;
      IppsBigNumState        *temp_exp_bn  = NULL;
      IppsBigNumState        *sig_bn       = NULL;
      IppsBigNumState        *result_bn    = NULL;
      int                    temp_key_size = 0;
      int                    bn_size       = 0;

      /* Create BigNums */
      if ((create_bignum_from_bytes (pubkey->data, pubkey->size, &temp_mod_bn) == ippStsNoErr) &&
          (create_bignum_from_bytes (pub_exp, sizeof (pub_exp), &temp_exp_bn) == ippStsNoErr) &&
          (create_bignum_from_bytes (signature->data, signature->size, &sig_bn) == ippStsNoErr))
      {
        /* Create result BigNum */
        ippsBigNumGetSize (pubkey->size, &bn_size);
        result_bn = (IppsBigNumState *)malloc (bn_size);
        if (result_bn != NULL) {
          ippsBigNumInit (pubkey->size, result_bn);

          /* Create and initialize public key */
          if (ippsRSA_GetSizePublicKey (pubkey->size * 8, 32, &temp_key_size) == ippStsNoErr) {
            temp_key = (IppsRSAPublicKeyState *)malloc (temp_key_size);
            if (temp_key != NULL) {
              if ((ippsRSA_InitPublicKey (pubkey->size * 8, 32, temp_key, temp_key_size) == ippStsNoErr) &&
                  (ippsRSA_SetPublicKey (temp_mod_bn, temp_exp_bn, temp_key) == ippStsNoErr))
              {
                /* Allocate scratch buffer for RSA operation */
                int temp_buf_size = 0;
                uint8_t *temp_scratch = NULL;
                if (ippsRSA_GetBufferSizePublicKey (&temp_buf_size, temp_key) == ippStsNoErr) {
                  temp_scratch = (uint8_t *)malloc (temp_buf_size);
                }

                /* Perform encryption (which is sig^e mod n = original padded message) */
                IppStatus enc_st = ippsRSA_Encrypt (sig_bn, result_bn, temp_key, temp_scratch);
                if (enc_st == ippStsNoErr) {
                  /* Extract result to byte array */
                  if (ippsGetOctString_BN (decrypted_sig, pubkey->size, result_bn) == ippStsNoErr) {
                    /* Extract hash algorithm from decrypted signature */
                    hashAlg = pkcs_get_hashalg (decrypted_sig);
                    if (hashAlg != TPM_ALG_NULL) {
                      printf ("INFO: Extracted hash algorithm 0x%04X from signature (old list format)\n", hashAlg);
                    }
                  }
                }

                if (temp_scratch) {
                  free (temp_scratch);
                }
              }

              free (temp_key);
            }
          }

          free (result_bn);
        }
      }

      if (temp_mod_bn) {
        free (temp_mod_bn);
      }

      if (temp_exp_bn) {
        free (temp_exp_bn);
      }

      if (sig_bn) {
        free (sig_bn);
      }

      free (decrypted_sig);

      if (hashAlg == TPM_ALG_NULL) {
        printf ("ERROR: Failed to extract hash algorithm from signature\n");
        return false;
      }
    }
  }

  /* Get hash method for IPPC — the _rmf verify functions hash internally */
  hash_method = get_ipp_hash_method (hashAlg);
  if (hash_method == NULL) {
    printf ("ERROR: Failed to get hash method\n");
    return false;
  }

  /* Calculate key size in bits from modulus size */
  key_size_bits = pubkey->size * 8;

  /* Create BigNum for modulus (n) */
  if (create_bignum_from_bytes (pubkey->data, pubkey->size, &modulus_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for modulus\n");
    goto cleanup;
  }

  /* Create BigNum for public exponent (e = 65537) */
  if (create_bignum_from_bytes (pub_exp, sizeof (pub_exp), &exp_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for public exponent\n");
    goto cleanup;
  }

  /* Get size for public key context */
  status = ippsRSA_GetSizePublicKey (key_size_bits, pub_exp_bits, &pub_key_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA public key size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate public key context */
  pub_key = (IppsRSAPublicKeyState *)malloc (pub_key_size);
  if (pub_key == NULL) {
    printf ("ERROR: Failed to allocate RSA public key context\n");
    goto cleanup;
  }

  /* Initialize public key */
  status = ippsRSA_InitPublicKey (key_size_bits, pub_exp_bits, pub_key, pub_key_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize RSA public key: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Set public key parameters */
  status = ippsRSA_SetPublicKey (modulus_bn, exp_bn, pub_key);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to set RSA public key: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Get buffer size for verification */
  status = ippsRSA_GetBufferSizePublicKey (&buffer_size, pub_key);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA buffer size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate scratch buffer */
  scratch_buffer = (uint8_t *)malloc (buffer_size);
  if (scratch_buffer == NULL) {
    printf ("ERROR: Failed to allocate scratch buffer\n");
    goto cleanup;
  }

  /* Verify signature based on signature algorithm.
   *
   * IMPORTANT: ippsRSAVerify_*_rmf functions accept a MESSAGE and hash it
   * internally using the specified hash method.  We must pass the raw data
   * (not a pre-computed digest) so that only a single hash is performed,
   * matching the signing convention used by OpenSSL (EVP_PKEY_sign takes
   * a pre-hashed digest, i.e. single hash).
   *
   * Previously this code pre-hashed the data and then passed the digest,
   * causing IPPC to double-hash and producing signatures incompatible
   * with OpenSSL. */
  if (sig_alg == TPM_ALG_RSASSA) {
    /* PKCS#1 v1.5 verification */
    status = ippsRSAVerify_PKCS1v15_rmf (
                                         data->data,
                                         (int)data->size,
                                         signature->data,
                                         &is_valid,
                                         pub_key,
                                         hash_method,
                                         scratch_buffer
                                         );
  } else if (sig_alg == TPM_ALG_RSAPSS) {
    /* PSS verification */
    status = ippsRSAVerify_PSS_rmf (
                                    data->data,
                                    (int)data->size,
                                    signature->data,
                                    &is_valid,
                                    pub_key,
                                    hash_method,
                                    scratch_buffer
                                    );
  } else {
    printf ("ERROR: Unsupported RSA signature algorithm: 0x%04X\n", sig_alg);
    goto cleanup;
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: RSA verification failed with status: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  result = (is_valid == 1);

cleanup:
  if (scratch_buffer) {
    free (scratch_buffer);
  }

  if (pub_key) {
    free (pub_key);
  }

  if (modulus_bn) {
    free (modulus_bn);
  }

  if (exp_bn) {
    free (exp_bn);
  }

  return result;
}

/*
 * Resolve EC hash algorithm to digest size and validate the key size
 * against the expected curve for that algorithm.
 *
 * Returns true on success (digest_size is set).
 */
static bool
ec_get_digest_size (
  uint16_t  hashalg,
  size_t    key_size,
  size_t    *digest_size
  )
{
  switch (hashalg) {
    case TB_HALG_SHA1:
    case TB_HALG_SHA1_LG:
      *digest_size = SHA1_LENGTH;
      if ((key_size != ECC_KEY_LEN_MIN_BYTES) && (key_size != ECC_KEY_LEN_MAX_BYTES)) {
        printf ("ERROR: Unsupported EC key size: %zu bytes\n", key_size);
        return false;
      }

      break;
    case TB_HALG_SHA256:
      *digest_size = SHA256_LENGTH;
      if (key_size != ECC_KEY_LEN_MIN_BYTES) {
        printf ("ERROR: SHA-256 requires 32-byte EC key (P-256)\n");
        return false;
      }

      break;
    case TB_HALG_SHA384:
      *digest_size = SHA384_LENGTH;
      if (key_size != ECC_KEY_LEN_MAX_BYTES) {
        printf ("ERROR: SHA-384 requires 48-byte EC key (P-384)\n");
        return false;
      }

      break;
    case TB_HALG_SHA512:
      *digest_size = SHA512_LENGTH;
      if (key_size != ECC_KEY_LEN_MAX_BYTES) {
        printf ("ERROR: SHA-512 requires 48-byte EC key (P-384)\n");
        return false;
      }

      break;
    case TB_HALG_SM3:
      *digest_size = 32;  /* SM3 produces 256-bit hash */
      if (key_size != ECC_KEY_LEN_MIN_BYTES) {
        printf ("ERROR: SM2 requires 32-byte EC key\n");
        return false;
      }

      break;
    default:
      printf ("ERROR: Unsupported hash algorithm: 0x%04X\n", hashalg);
      return false;
  }

  return true;
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
  IppsGFpState         *gfp           = NULL;
  IppsGFpECState       *ec            = NULL;
  IppsGFpECPoint       *pub_point     = NULL;
  IppsBigNumState      *msg_digest_bn = NULL;
  IppsBigNumState      *sig_r_bn      = NULL;
  IppsBigNumState      *sig_s_bn      = NULL;
  IppsBigNumState      *pubkey_x_bn   = NULL;
  IppsBigNumState      *pubkey_y_bn   = NULL;
  IppStatus            status;
  uint8_t              digest[SHA512_LENGTH];
  size_t               digest_size;
  int                  gfp_size        = 0;
  int                  ec_size         = 0;
  int                  point_size      = 0;
  int                  scratch_size    = 0;
  uint8_t              *scratch_buffer = NULL;
  IppECResult          result          = ippECInvalidSignature;
  bool                 is_valid        = false;
  const IppsGFpMethod  *gfp_method     = NULL;

  if ((data == NULL) || (pubkey_x == NULL) || (pubkey_y == NULL) ||
      (sig_r == NULL) || (sig_s == NULL))
  {
    printf ("ERROR: crypto_verify_ec_signature_internal called with NULL pointer\n");
    return false;
  }

  /* Determine digest size and validate key size for this hash algorithm */
  if (!ec_get_digest_size (hashalg, pubkey_x->size, &digest_size)) {
    return false;
  }

  /* Hash the data */
  if (crypto_hash_buffer_internal (data->data, data->size, digest, hashalg) != crypto_ok) {
    printf ("ERROR: Failed to hash data for EC verification\n");
    return false;
  }

  /* Select GFp method based on curve */
  if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
    gfp_method = ippsGFpMethod_p256sm2 ();
  } else if (pubkey_x->size == ECC_KEY_LEN_MAX_BYTES) {
    gfp_method = ippsGFpMethod_p384r1 ();
  } else if (pubkey_x->size == ECC_KEY_LEN_MIN_BYTES) {
    gfp_method = ippsGFpMethod_p256r1 ();
  } else {
    printf ("ERROR: Unsupported EC key size: %zu bytes\n", pubkey_x->size);
    return false;
  }

  {
    /* Get size for GFp context */
    status = ippsGFpGetSize (pubkey_x->size * 8, &gfp_size);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to get GFp size: %s\n", ippcpGetStatusString (status));
      return false;
    }

    /* Allocate GFp context */
    gfp = (IppsGFpState *)malloc (gfp_size);
    if (gfp == NULL) {
      printf ("ERROR: Failed to allocate GFp context\n");
      return false;
    }

    /* Initialize GFp context */
    status = ippsGFpInitFixed (pubkey_x->size * 8, gfp_method, gfp);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to initialize GFp context: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }

    /* Get size for EC context */
    status = ippsGFpECGetSize (gfp, &ec_size);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to get EC size: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }

    /* Allocate EC context */
    ec = (IppsGFpECState *)malloc (ec_size);
    if (ec == NULL) {
      printf ("ERROR: Failed to allocate EC context\n");
      goto cleanup;
    }

    /* Initialize EC context with standard curve */
    if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
      status = ippsGFpECInitStdSM2 (gfp, ec);
    } else if (pubkey_x->size == ECC_KEY_LEN_MIN_BYTES) {
      status = ippsGFpECInitStd256r1 (gfp, ec);
    } else {
      status = ippsGFpECInitStd384r1 (gfp, ec);
    }

    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to initialize EC curve: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }
  }

  /* Create BigNum structures */
  if (create_bignum_from_bytes (digest, digest_size, &msg_digest_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for message digest\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (sig_r->data, sig_r->size, &sig_r_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for signature R\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (sig_s->data, sig_s->size, &sig_s_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for signature S\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (pubkey_x->data, pubkey_x->size, &pubkey_x_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for public key X\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (pubkey_y->data, pubkey_y->size, &pubkey_y_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for public key Y\n");
    goto cleanup;
  }

  /* Get size for EC point */
  status = ippsGFpECPointGetSize (ec, &point_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get EC point size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate EC point for public key */
  pub_point = (IppsGFpECPoint *)malloc (point_size);
  if (pub_point == NULL) {
    printf ("ERROR: Failed to allocate EC point\n");
    goto cleanup;
  }

  /* Initialize and set EC point with public key coordinates */
  status = ippsGFpECPointInit (NULL, NULL, pub_point, ec);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize EC point: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  status = ippsGFpECSetPointRegular (pubkey_x_bn, pubkey_y_bn, pub_point, ec);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to set EC point coordinates: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Get scratch buffer size — ECDSA verify uses 2 scalar multiplications */
  status = ippsGFpECScratchBufferSize (2, ec, &scratch_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get scratch buffer size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate scratch buffer */
  scratch_buffer = (uint8_t *)malloc (scratch_size);
  if (scratch_buffer == NULL) {
    printf ("ERROR: Failed to allocate scratch buffer\n");
    goto cleanup;
  }

  /* Verify ECDSA/SM2 signature */
  if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
    /* Use SM2 verification */
    status = ippsGFpECVerifySM2 (
                                 msg_digest_bn,
                                 pub_point,
                                 sig_r_bn,
                                 sig_s_bn,
                                 &result,
                                 ec,
                                 scratch_buffer
                                 );
  } else {
    /* Use standard ECDSA verification */
    status = ippsGFpECVerifyDSA (
                                 msg_digest_bn,
                                 pub_point,
                                 sig_r_bn,
                                 sig_s_bn,
                                 &result,
                                 ec,
                                 scratch_buffer
                                 );
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: EC signature verification failed with status: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  is_valid = (result == ippECValid);

cleanup:
  if (scratch_buffer) {
    free (scratch_buffer);
  }

  if (pub_point) {
    free (pub_point);
  }

  if (ec) {
    free (ec);
  }

  if (gfp) {
    free (gfp);
  }

  if (msg_digest_bn) {
    free (msg_digest_bn);
  }

  if (sig_r_bn) {
    free (sig_r_bn);
  }

  if (sig_s_bn) {
    free (sig_s_bn);
  }

  if (pubkey_x_bn) {
    free (pubkey_x_bn);
  }

  if (pubkey_y_bn) {
    free (pubkey_y_bn);
  }

  return is_valid;
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
  IppsGFpState         *gfp           = NULL;
  IppsGFpECState       *ec            = NULL;
  IppsGFpECPoint       *pub_point     = NULL;
  IppsBigNumState      *msg_digest_bn = NULL;
  IppsBigNumState      *priv_key_bn   = NULL;
  IppsBigNumState      *eph_key_bn    = NULL;
  IppsBigNumState      *sig_r_bn      = NULL;
  IppsBigNumState      *sig_s_bn      = NULL;
  IppStatus            status;
  uint8_t              digest[SHA512_LENGTH];
  size_t               digest_size;
  uint8_t              priv_key_buf[ECC_KEY_LEN_MAX_BYTES];
  uint16_t             priv_key_size   = ECC_KEY_LEN_MAX_BYTES;
  uint16_t             alg_id          = 0;
  int                  gfp_size        = 0;
  int                  ec_size         = 0;
  int                  point_size      = 0;
  int                  bn_size         = 0;
  int                  scratch_size    = 0;
  uint8_t              *scratch_buffer = NULL;
  crypto_status        read_status;
  bool                 result_ok   = false;
  uint8_t              *r_data     = NULL;
  uint8_t              *s_data     = NULL;
  const IppsGFpMethod  *gfp_method = NULL;

  if ((data == NULL) || (r == NULL) || (s == NULL) || (privkey_file == NULL)) {
    printf ("ERROR: crypto_ec_sign_data_internal called with NULL pointer\n");
    return false;
  }

  /* Read private key */
  read_status = crypto_read_key (privkey_file, true, priv_key_buf, &priv_key_size, &alg_id);
  if (read_status != crypto_ok) {
    printf ("ERROR: Failed to read EC private key\n");
    return false;
  }

  /* Verify it's an ECC key */
  if (alg_id != KEY_ALG_TYPE_ECC) {
    printf ("ERROR: Key is not an ECC key (alg_id: %d)\n", alg_id);
    return false;
  }

  /* Determine digest size and validate key size for this hash algorithm */
  if (!ec_get_digest_size (hashalg, (size_t)priv_key_size, &digest_size)) {
    return false;
  }

  /* Hash the data */
  if (crypto_hash_buffer_internal (data->data, data->size, digest, hashalg) != crypto_ok) {
    printf ("ERROR: Failed to hash data for EC signing\n");
    return false;
  }

  /* Select GFp method based on curve */
  if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
    gfp_method = ippsGFpMethod_p256sm2 ();
  } else if (priv_key_size == ECC_KEY_LEN_MAX_BYTES) {
    gfp_method = ippsGFpMethod_p384r1 ();
  } else if (priv_key_size == ECC_KEY_LEN_MIN_BYTES) {
    gfp_method = ippsGFpMethod_p256r1 ();
  } else {
    printf ("ERROR: Unsupported EC key size: %d bytes\n", priv_key_size);
    return false;
  }

  {
    /* Get size for GFp context */
    status = ippsGFpGetSize (priv_key_size * 8, &gfp_size);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to get GFp size: %s\n", ippcpGetStatusString (status));
      return false;
    }

    /* Allocate GFp context */
    gfp = (IppsGFpState *)malloc (gfp_size);
    if (gfp == NULL) {
      printf ("ERROR: Failed to allocate GFp context\n");
      return false;
    }

    /* Initialize GFp context */
    status = ippsGFpInitFixed (priv_key_size * 8, gfp_method, gfp);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to initialize GFp context: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }

    /* Get size for EC context */
    status = ippsGFpECGetSize (gfp, &ec_size);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to get EC size: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }

    /* Allocate EC context */
    ec = (IppsGFpECState *)malloc (ec_size);
    if (ec == NULL) {
      printf ("ERROR: Failed to allocate EC context\n");
      goto cleanup;
    }

    /* Initialize EC context with standard curve */
    if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
      status = ippsGFpECInitStdSM2 (gfp, ec);
    } else if (priv_key_size == ECC_KEY_LEN_MIN_BYTES) {
      status = ippsGFpECInitStd256r1 (gfp, ec);
    } else {
      status = ippsGFpECInitStd384r1 (gfp, ec);
    }

    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to initialize EC curve: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }
  }

  /* Create BigNum structures */
  if (create_bignum_from_bytes (digest, digest_size, &msg_digest_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for message digest\n");
    goto cleanup;
  }

  /* crypto_read_key returns EC private keys in little-endian byte order,
   * but ippsSetOctString_BN (used by create_bignum_from_bytes) expects
   * big-endian.  Reverse back to BE before creating the BigNum. */
  buffer_reverse_byte_order (priv_key_buf, priv_key_size);

  if (create_bignum_from_bytes (priv_key_buf, priv_key_size, &priv_key_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for private key\n");
    goto cleanup;
  }

  /* Allocate BigNum for signature components (r and s) */
  status = ippsBigNumGetSize (priv_key_size, &bn_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get BigNum size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  sig_r_bn = (IppsBigNumState *)malloc (bn_size);
  if (sig_r_bn == NULL) {
    printf ("ERROR: Failed to allocate BigNum for signature R\n");
    goto cleanup;
  }

  sig_s_bn = (IppsBigNumState *)malloc (bn_size);
  if (sig_s_bn == NULL) {
    printf ("ERROR: Failed to allocate BigNum for signature S\n");
    goto cleanup;
  }

  status = ippsBigNumInit (priv_key_size, sig_r_bn);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize BigNum for signature R: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  status = ippsBigNumInit (priv_key_size, sig_s_bn);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize BigNum for signature S: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Get size for EC point */
  status = ippsGFpECPointGetSize (ec, &point_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get EC point size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate EC point for public key */
  pub_point = (IppsGFpECPoint *)malloc (point_size);
  if (pub_point == NULL) {
    printf ("ERROR: Failed to allocate EC point\n");
    goto cleanup;
  }

  /* Initialize EC point */
  status = ippsGFpECPointInit (NULL, NULL, pub_point, ec);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize EC point: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Get scratch buffer size */
  status = ippsGFpECScratchBufferSize (2, ec, &scratch_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get scratch buffer size: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate scratch buffer */
  scratch_buffer = (uint8_t *)malloc (scratch_size);
  if (scratch_buffer == NULL) {
    printf ("ERROR: Failed to allocate scratch buffer\n");
    goto cleanup;
  }

  /* Derive public key from private key */
  status = ippsGFpECPublicKey (priv_key_bn, pub_point, ec, scratch_buffer);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to derive public key: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Generate ephemeral private key for ECDSA/SM2 signing.
   * IPPC requires a caller-provided random ephemeral key k in [1, n-1]
   * where n is the EC subgroup order. Uses hardware TRNG (RDSEED). */
  {
    int  eph_bn_size = 0;
    status = ippsBigNumGetSize (priv_key_size, &eph_bn_size);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to get BigNum size for ephemeral key: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }

    eph_key_bn = (IppsBigNumState *)malloc (eph_bn_size);
    if (eph_key_bn == NULL) {
      printf ("ERROR: Failed to allocate ephemeral key BigNum\n");
      goto cleanup;
    }

    status = ippsBigNumInit (priv_key_size, eph_key_bn);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to initialize ephemeral key BigNum: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }

    status = ippsTRNGenRDSEED_BN (eph_key_bn, priv_key_size * 8, NULL);
    if (status != ippStsNoErr) {
      printf ("ERROR: Failed to generate ephemeral key via RDSEED: %s\n", ippcpGetStatusString (status));
      goto cleanup;
    }
  }

  /* Sign the digest with ECDSA or SM2 */
  if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
    status = ippsGFpECSignSM2 (msg_digest_bn, priv_key_bn, eph_key_bn, sig_r_bn, sig_s_bn, ec, scratch_buffer);
  } else {
    status = ippsGFpECSignDSA (msg_digest_bn, priv_key_bn, eph_key_bn, sig_r_bn, sig_s_bn, ec, scratch_buffer);
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: EC signing failed with status: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Extract signature components to output buffers */
  r_data = (uint8_t *)malloc (priv_key_size);
  s_data = (uint8_t *)malloc (priv_key_size);
  if ((r_data == NULL) || (s_data == NULL)) {
    printf ("ERROR: Failed to allocate signature output buffers\n");
    goto cleanup;
  }

  /* Convert BigNum to octet string */
  status = ippsGetOctString_BN (r_data, priv_key_size, sig_r_bn);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to extract signature R: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  status = ippsGetOctString_BN (s_data, priv_key_size, sig_s_bn);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to extract signature S: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Copy to output buffers */
  if ((r->size < (size_t)priv_key_size) || (s->size < (size_t)priv_key_size)) {
    printf ("ERROR: Output buffers too small\n");
    goto cleanup;
  }

  memcpy (r->data, r_data, priv_key_size);
  memcpy (s->data, s_data, priv_key_size);
  r->size = priv_key_size;
  s->size = priv_key_size;

  result_ok = true;

cleanup:
  /* Zero private key material from stack */
  memset (priv_key_buf, 0, sizeof (priv_key_buf));

  if (r_data) {
    free (r_data);
  }

  if (s_data) {
    free (s_data);
  }

  if (scratch_buffer) {
    free (scratch_buffer);
  }

  if (pub_point) {
    free (pub_point);
  }

  if (ec) {
    free (ec);
  }

  if (gfp) {
    free (gfp);
  }

  if (msg_digest_bn) {
    free (msg_digest_bn);
  }

  if (priv_key_bn) {
    free (priv_key_bn);
  }

  if (eph_key_bn) {
    free (eph_key_bn);
  }

  if (sig_r_bn) {
    free (sig_r_bn);
  }

  if (sig_s_bn) {
    free (sig_s_bn);
  }

  return result_ok;
}

/* Validate LMS/LMOTS types in the signature and return the IPPC algo type.
 * Only LMS_SHA256_M24_H20 + LMOTS_SHA256_N24_W4 is supported. */
static IppStatus
validate_lms_sig_algo_type (
  const unsigned char  *signature,
  size_t               sig_len,
  IppsLMSAlgoType      *algo_type
  )
{
  if (sig_len < sizeof(lms_signature_block)) {
    printf ("ERROR: LMS signature too short: %zu (expected %zu)\n", sig_len, sizeof(lms_signature_block));
    return ippStsSizeErr;
  }

  /* Validate LMOTS type at offset sizeof(uint32_t) (after Q) */
  uint32_t  lmots_type;
  memcpy (&lmots_type, signature + sizeof(uint32_t), sizeof(lmots_type));
  lmots_type = ntohl (lmots_type);

  if (lmots_type != LMOTS_SHA256_N24_W4) {
    printf ("ERROR: Unsupported LMOTS type in signature: 0x%x (expected LMOTS_SHA256_N24_W4=0x%x)\n",
            lmots_type, LMOTS_SHA256_N24_W4);
    return ippStsNotSupportedModeErr;
  }

  /* Validate LMS type after Q + lmots_signature */
  uint32_t  lms_type;
  memcpy (&lms_type, signature + sizeof(uint32_t) + sizeof(lmots_signature), sizeof(lms_type));
  lms_type = ntohl (lms_type);

  if (lms_type != LMS_SHA256_M24_H20) {
    printf ("ERROR: Unsupported LMS type in signature: 0x%x (expected LMS_SHA256_M24_H20=0x%x)\n",
            lms_type, LMS_SHA256_M24_H20);
    return ippStsNotSupportedModeErr;
  }

  algo_type->lmsOIDAlgo   = LMS_SHA256_M24_H20;
  algo_type->lmotsOIDAlgo = LMOTS_SHA256_N24_W4;
  return ippStsNoErr;
}

bool
crypto_lms_verify_signature_internal (
  const unsigned char  *msg,
  size_t               msg_len,
  const unsigned char  *signature,
  size_t               sig_len,
  const unsigned char  *public_key,
  size_t               pubkey_len
  )
{
  const unsigned char    *actual_pubkey = NULL;
  const unsigned char    *actual_sig    = NULL;
  size_t                 actual_sig_len = 0;
  IppStatus              status         = ippStsNoErr;
  IppsLMSAlgoType        algo_type      = { 0 };
  IppsLMSPublicKeyState  *pubkey_state  = NULL;
  IppsLMSSignatureState  *sig_state     = NULL;
  Ipp8u                  *buffer        = NULL;
  Ipp32s                 pubkey_size    = 0;
  Ipp32s                 sig_size       = 0;
  Ipp32s                 buffer_size    = 0;
  int                    is_valid       = 0;
  bool                   result         = false;

  if ((NULL == msg) || (NULL == signature) || (NULL == public_key)) {
    printf ("ERROR: crypto_lms_verify_signature_internal called with NULL parameter\n");
    return false;
  }

  if (pubkey_len < sizeof(uint32_t) + sizeof(lms_xdr_key_data)) {
    printf ("ERROR: Public key buffer too short: %zu\n", pubkey_len);
    return false;
  }

  if (sig_len < sizeof(uint32_t) + sizeof(lms_signature_block)) {
    printf ("ERROR: Signature buffer too short: %zu\n", sig_len);
    return false;
  }

  /* Strip LEVELS / NSPK prefixes */
  actual_pubkey = public_key + sizeof(uint32_t);
  actual_sig    = signature + sizeof(uint32_t);
  actual_sig_len = sig_len - sizeof(uint32_t);

  /* Validate LMS/LMOTS types in signature and get IPPC algo type */
  status = validate_lms_sig_algo_type (actual_sig, actual_sig_len, &algo_type);
  if (status != ippStsNoErr) {
    goto cleanup;
  }

  /* Get required buffer sizes */
  status = ippsLMSPublicKeyStateGetSize (&pubkey_size, algo_type);
  if (status != ippStsNoErr) {
    printf ("ERROR: ippsLMSPublicKeyStateGetSize failed: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  status = ippsLMSSignatureStateGetSize (&sig_size, algo_type);
  if (status != ippStsNoErr) {
    printf ("ERROR: ippsLMSSignatureStateGetSize failed: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  status = ippsLMSVerifyBufferGetSize (&buffer_size, (Ipp32s)msg_len, algo_type);
  if (status != ippStsNoErr) {
    printf ("ERROR: ippsLMSVerifyBufferGetSize failed: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Allocate memory */
  pubkey_state = (IppsLMSPublicKeyState *)malloc (pubkey_size);
  if (NULL == pubkey_state) {
    printf ("ERROR: Failed to allocate LMS public key state\n");
    goto cleanup;
  }

  sig_state = (IppsLMSSignatureState *)malloc (sig_size);
  if (NULL == sig_state) {
    printf ("ERROR: Failed to allocate LMS signature state\n");
    goto cleanup;
  }

  buffer = (Ipp8u *)malloc (buffer_size);
  if (NULL == buffer) {
    printf ("ERROR: Failed to allocate LMS working buffer\n");
    goto cleanup;
  }

  /* Validate LMS and LMOTS types in public key (lms_xdr_key_data) */
  uint32_t  pubkey_lms_type;
  uint32_t  pubkey_lmots_type;
  memcpy (&pubkey_lms_type, actual_pubkey, sizeof(pubkey_lms_type));
  memcpy (&pubkey_lmots_type, actual_pubkey + sizeof(uint32_t), sizeof(pubkey_lmots_type));
  pubkey_lms_type = ntohl (pubkey_lms_type);
  pubkey_lmots_type = ntohl (pubkey_lmots_type);

  if (pubkey_lms_type != LMS_SHA256_M24_H20) {
    printf ("ERROR: Unsupported LMS type in public key: 0x%x (expected LMS_SHA256_M24_H20=0x%x)\n",
            pubkey_lms_type, LMS_SHA256_M24_H20);
    goto cleanup;
  }

  if (pubkey_lmots_type != LMOTS_SHA256_N24_W4) {
    printf ("ERROR: Unsupported LMOTS type in public key: 0x%x (expected LMOTS_SHA256_N24_W4=0x%x)\n",
            pubkey_lmots_type, LMOTS_SHA256_N24_W4);
    goto cleanup;
  }

  const Ipp8u  *pI = actual_pubkey + 2 * sizeof(uint32_t);       /* Skip LmsType + LmotsType */
  const Ipp8u  *pK = actual_pubkey + 2 * sizeof(uint32_t) + I_LEN; /* After LmsType + LmotsType + I */

  /* Initialize public key state */
  status = ippsLMSSetPublicKeyState (algo_type, pI, pK, pubkey_state);
  if (status != ippStsNoErr) {
    printf ("ERROR: ippsLMSSetPublicKeyState failed: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Parse signature components per lcp3.h (lms_signature_block):
   * lmots_signature = Type + Seed (LMOTS_SIGNATURE_N_SIZE) + Y (LMOTS_SIGNATURE_BLOCK_SIZE)
   * lms_signature_block = Q + lmots_signature + LmsType + Path (LMS_SIGNATURE_BLOCK_SIZE)
   * Size already validated by validate_lms_sig_algo_type(). */
  Ipp32u  q;
  memcpy (&q, actual_sig, sizeof(q));
  q = ntohl (q);  /* Convert from big-endian */

  const Ipp8u  *pC        = actual_sig + 2 * sizeof(uint32_t);                                        /* Skip Q + LMOTS Type */
  const Ipp8u  *pY        = actual_sig + 2 * sizeof(uint32_t) + SHA256_192_DIGEST_SIZE;                /* After Q + LMOTS Type + Seed */
  const Ipp8u  *pAuthPath = actual_sig + sizeof(uint32_t) + sizeof(lmots_signature) + sizeof(uint32_t); /* After Q + lmots_sig + LmsType */

  /* Initialize signature state */
  status = ippsLMSSetSignatureState (algo_type, q, pC, pY, pAuthPath, sig_state);
  if (status != ippStsNoErr) {
    printf ("ERROR: ippsLMSSetSignatureState failed: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  /* Verify the signature */
  status = ippsLMSVerify (msg, (Ipp32s)msg_len, sig_state, &is_valid, pubkey_state, buffer);
  if (status != ippStsNoErr) {
    printf ("ERROR: ippsLMSVerify failed: %s\n", ippcpGetStatusString (status));
    goto cleanup;
  }

  if (is_valid != 1) {
    printf ("ERROR: LMS signature verification failed (invalid signature)\n");
    goto cleanup;
  }

  if (verbose) {
    printf ("LMS signature verification succeeded\n");
  }

  result = true;

cleanup:
  if (pubkey_state) {
    free (pubkey_state);
  }

  if (sig_state) {
    free (sig_state);
  }

  if (buffer) {
    free (buffer);
  }

  return result;
}

/*
 * Custom RNG callback for ippsLMSKeyGen that feeds known seed and I values.
 * First call produces the secret seed, second call produces the I identifier.
 */
static IppStatus
lms_keygen_rng_callback (
  Ipp32u  *pRand,
  int     nBits,
  void    *pCtx
  )
{
  lms_keygen_rng_ctx  *ctx    = (lms_keygen_rng_ctx *)pCtx;
  int                 nBytes  = nBits / 8;

  if (ctx->call_count == 0) {
    /* First call: provide the secret seed */
    memcpy (pRand, ctx->seed, nBytes);
  } else if (ctx->call_count == 1) {
    /* Second call: provide the I identifier */
    memcpy (pRand, ctx->identifier, nBytes);
  } else {
    return ippStsErr;
  }

  ctx->call_count++;
  return ippStsNoErr;
}

/*
 * LMS signature generation using IPPC library.
 * Reads an LMS private key (LMS_SHA256_M24_H20 + LMOTS_SHA256_N24_W4),
 * reconstructs the IPPC key state, signs the message, and serializes the signature
 * in wire format with HSS NSPK prefix.
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
    printf ("LMS sign: NULL parameter\n");
    return crypto_nullptr_error;
  }

  IppStatus               ipp_status    = ippStsNoErr;
  crypto_status           result        = crypto_operation_fail;
  uint8_t                 *file_data    = NULL;
  size_t                  file_size     = 0;
  IppsLMSPrivateKeyState  *priv_key     = NULL;
  IppsLMSPublicKeyState   *pub_key      = NULL;
  IppsLMSSignatureState   *sig_state    = NULL;
  Ipp8u                   *keygen_buf   = NULL;
  Ipp8u                   *sign_buf     = NULL;
  Ipp32s                  priv_key_size = 0;
  Ipp32s                  pub_key_size  = 0;
  Ipp32s                  sig_size      = 0;
  Ipp32s                  keygen_buf_sz = 0;
  Ipp32s                  sign_buf_sz   = 0;
  uint32_t                leaf_q;
  Ipp32s                  extra_buf_sz  = 0;

  /* Fixed algorithm type: LMS_SHA256_M24_H20 + LMOTS_SHA256_N24_W4 */
  IppsLMSAlgoType  algo_type = {
    .lmsOIDAlgo   = LMS_SHA256_M24_H20,
    .lmotsOIDAlgo = LMOTS_SHA256_N24_W4
  };

  /* Read private key file */
  file_data = (uint8_t *)read_file (privkey_file, &file_size, false);
  if (NULL == file_data) {
    printf ("ERROR: Failed to read LMS private key file: %s\n", privkey_file);
    return crypto_file_io_error;
  }

  /* Validate exact file size */
  if (file_size != LMS_PRV_EXPECTED_SIZE) {
    printf ("ERROR: Invalid LMS private key file size: %zu (expected %d)\n",
            file_size, LMS_PRV_EXPECTED_SIZE);
    free (file_data);
    return crypto_operation_fail;
  }

  /* Validate compressed parameter sets match LMS_SHA256_M24_H20 + LMOTS_SHA256_N24_W4 */
  if (file_data[LMS_PRV_PARAMS_OFFSET] != LMS_PRV_COMPRESSED_LM) {
    printf ("ERROR: Unsupported LMS type in private key: 0x%02x (expected 0x%02x for LMS_SHA256_M24_H20)\n",
            file_data[LMS_PRV_PARAMS_OFFSET], LMS_PRV_COMPRESSED_LM);
    free (file_data);
    return crypto_operation_fail;
  }

  if (file_data[LMS_PRV_PARAMS_OFFSET + 1] != LMS_PRV_COMPRESSED_LMOTS) {
    printf ("ERROR: Unsupported LMOTS type in private key: 0x%02x (expected 0x%02x for LMOTS_SHA256_N24_W4)\n",
            file_data[LMS_PRV_PARAMS_OFFSET + 1], LMS_PRV_COMPRESSED_LMOTS);
    free (file_data);
    return crypto_operation_fail;
  }

  /* Extract sequence counter (leaf index) - big-endian uint64 in first 8 bytes */
  uint64_t  seq_counter = 0;
  for (int i = 0; i < LMS_PRV_COUNTER_SIZE; i++) {
    seq_counter = (seq_counter << 8) | file_data[LMS_PRV_COUNTER_OFFSET + i];
  }

  leaf_q = (uint32_t)seq_counter;

  /* Check if key is exhausted (2^20 = 1048576 leaves for H20) */
  if (seq_counter >= ((uint64_t)1 << LMS_SIGN_H)) {
    printf ("ERROR: LMS private key is exhausted (q=%lu, max=%lu)\n",
            (unsigned long)seq_counter, (unsigned long)((uint64_t)1 << LMS_SIGN_H));
    free (file_data);
    return crypto_operation_fail;
  }

  /* Pointers into file data for seed and I */
  const uint8_t  *seed  = file_data + LMS_PRV_SEED_OFFSET;
  const uint8_t  *I_val = file_data + LMS_PRV_SEED_OFFSET + LMS_SIGN_N;

  /* Check output buffer size */
  if (*sig_len < LMS_SIGN_TOTAL_SIZE) {
    printf ("ERROR: Signature buffer too small: need %zu, have %zu\n",
            (size_t)LMS_SIGN_TOTAL_SIZE, *sig_len);
    free (file_data);
    return crypto_buffer_too_small;
  }

  /* Determine extra buffer size for tree node caching.
   * The extra buffer stores Merkle tree nodes (each LMS_SIGN_N bytes) to speed up signing.
   * It must be a multiple of LMS_SIGN_N (24). Round down any provided aux_len. */
  if ((aux_data != NULL) && (aux_len >= LMS_SIGN_N)) {
    extra_buf_sz = (Ipp32s)((aux_len / LMS_SIGN_N) * LMS_SIGN_N);
  } else {
    extra_buf_sz = (Ipp32s)(LMS_SIGN_N * LMS_SIGN_H);
  }

  /* Get required IPPC state sizes */
  ipp_status = ippsLMSPrivateKeyStateGetSize (&priv_key_size, algo_type, extra_buf_sz);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSPrivateKeyStateGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  ipp_status = ippsLMSPublicKeyStateGetSize (&pub_key_size, algo_type);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSPublicKeyStateGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  ipp_status = ippsLMSSignatureStateGetSize (&sig_size, algo_type);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSSignatureStateGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  ipp_status = ippsLMSKeyGenBufferGetSize (&keygen_buf_sz, algo_type);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSKeyGenBufferGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  ipp_status = ippsLMSSignBufferGetSize (&sign_buf_sz, (Ipp32s)msg_len, algo_type);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSSignBufferGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Allocate IPPC states and working buffers */
  priv_key   = (IppsLMSPrivateKeyState *)malloc (priv_key_size);
  pub_key    = (IppsLMSPublicKeyState *)malloc (pub_key_size);
  sig_state  = (IppsLMSSignatureState *)malloc (sig_size);
  keygen_buf = (Ipp8u *)malloc (keygen_buf_sz);
  sign_buf   = (Ipp8u *)malloc (sign_buf_sz);

  if (!priv_key || !pub_key || !sig_state || !keygen_buf || !sign_buf) {
    printf ("ERROR: Failed to allocate LMS buffers\n");
    result = crypto_memory_alloc_fail;
    goto cleanup;
  }

  /* Initialize key pair states */
  ipp_status = ippsLMSInitKeyPair (algo_type, extra_buf_sz, priv_key, pub_key);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSInitKeyPair failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Reconstruct the key pair from the saved seed/I values using a custom RNG.
   * This feeds the known seed and I into ippsLMSKeyGen, reproducing the exact
   * key and computing the Merkle tree for the extra buffer cache. */
  lms_keygen_rng_ctx  rng_ctx = {
    .seed       = seed,
    .identifier = I_val,
    .call_count = 0
  };

  ipp_status = ippsLMSKeyGen (priv_key, pub_key, lms_keygen_rng_callback, &rng_ctx, keygen_buf);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSKeyGen failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* ippsLMSKeyGen sets q=0. Restore the correct leaf index from the private key file. */
  lms_privkey_mirror  *priv_mirror = (lms_privkey_mirror *)priv_key;

  /* Sanity check: validate mirror struct alignment by verifying the algorithm
   * fields match what we configured.  If these don't match, the IPPC internal
   * struct layout has changed and the mirror structs must be updated. */
  if (priv_mirror->lmsOIDAlgo != LMS_SHA256_M24_H20 ||
      priv_mirror->lmotsOIDAlgo != LMOTS_SHA256_N24_W4) {
    printf ("ERROR: LMS private key mirror struct mismatch: lmsOID=%d lmotsOID=%d "
            "(expected %d, %d)\n",
            priv_mirror->lmsOIDAlgo, priv_mirror->lmotsOIDAlgo,
            LMS_SHA256_M24_H20, LMOTS_SHA256_N24_W4);
    printf ("       IPPC internal layout may have changed — update mirror structs\n");
    goto cleanup;
  }

  priv_mirror->q = leaf_q;

  /* Initialize signature state */
  ipp_status = ippsLMSInitSignature (algo_type, sig_state);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSInitSignature failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Sign the message */
  ipp_status = ippsLMSSign (msg, (Ipp32s)msg_len, priv_key, sig_state, NULL, NULL, sign_buf);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsLMSSign failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Extract signature components via mirror struct and serialize into wire format */
  lms_sig_state_mirror  *sig_mirror = (lms_sig_state_mirror *)sig_state;

  /* Sanity check signature state mirror alignment via algorithm fields */
  if (sig_mirror->_lmsOIDAlgo != LMS_SHA256_M24_H20 ||
      sig_mirror->_lmotsSig._lmotsOIDAlgo != LMOTS_SHA256_N24_W4) {
    printf ("ERROR: LMS sig state mirror struct mismatch: lmsOID=%d lmotsOID=%d "
            "(expected %d, %d)\n",
            sig_mirror->_lmsOIDAlgo, sig_mirror->_lmotsSig._lmotsOIDAlgo,
            LMS_SHA256_M24_H20, LMOTS_SHA256_N24_W4);
    printf ("       IPPC internal layout may have changed — update mirror structs\n");
    goto cleanup;
  }

  unsigned char         *p_out      = signature;

  /* NSPK prefix: u32str(0) for single-level HSS tree */
  uint32_t  nspk = htonl (0);
  memcpy (p_out, &nspk, sizeof (uint32_t));
  p_out += sizeof (uint32_t);

  /* Q: leaf index (big-endian) */
  uint32_t  q_be = htonl (sig_mirror->_q);
  memcpy (p_out, &q_be, sizeof (uint32_t));
  p_out += sizeof (uint32_t);

  /* LMOTS type (big-endian) */
  uint32_t  lmots_type_be = htonl ((uint32_t)sig_mirror->_lmotsSig._lmotsOIDAlgo);
  memcpy (p_out, &lmots_type_be, sizeof (uint32_t));
  p_out += sizeof (uint32_t);

  /* C randomizer (24 bytes) */
  memcpy (p_out, sig_mirror->_lmotsSig.pC, LMS_SIGN_N);
  p_out += LMS_SIGN_N;

  /* Y array (24 * 51 = 1224 bytes) */
  memcpy (p_out, sig_mirror->_lmotsSig.pY, (size_t)LMS_SIGN_N * LMS_SIGN_P);
  p_out += (size_t)LMS_SIGN_N * LMS_SIGN_P;

  /* LMS type (big-endian) */
  uint32_t  lms_type_be = htonl ((uint32_t)sig_mirror->_lmsOIDAlgo);
  memcpy (p_out, &lms_type_be, sizeof (uint32_t));
  p_out += sizeof (uint32_t);

  /* Auth path (20 * 24 = 480 bytes) */
  memcpy (p_out, sig_mirror->_pAuthPath, (size_t)LMS_SIGN_H * LMS_SIGN_M);
  p_out += (size_t)LMS_SIGN_H * LMS_SIGN_M;

  *sig_len = LMS_SIGN_TOTAL_SIZE;

  /* Update the private key file: increment the sequence counter.
   * This MUST succeed — failure risks LMS one-time key reuse. */
  seq_counter = (uint64_t)leaf_q + 1;
  {
    FILE  *fp = fopen (privkey_file, "r+b");
    if (NULL == fp) {
      printf ("ERROR: Cannot open private key for counter update: %s\n", privkey_file);
      result = crypto_operation_fail;
      goto cleanup;
    }

    {
      uint8_t  counter_bytes[LMS_PRV_COUNTER_SIZE];
      uint64_t temp_counter = seq_counter;
      for (int i = LMS_PRV_COUNTER_SIZE - 1; i >= 0; i--) {
        counter_bytes[i] = (uint8_t)(temp_counter & 0xFF);
        temp_counter >>= 8;
      }

      if (fwrite (counter_bytes, LMS_PRV_COUNTER_SIZE, 1, fp) != 1) {
        printf ("ERROR: Failed to update LMS private key counter — risk of key reuse\n");
        fclose (fp);
        result = crypto_operation_fail;
        goto cleanup;
      }

      /* Ensure the counter update reaches persistent storage before returning
       * the signature.  LMS security depends on never reusing a leaf index. */
      if (fflush (fp) != 0 || fsync (fileno (fp)) != 0) {
        printf ("ERROR: Failed to flush LMS private key counter to disk — risk of key reuse\n");
        fclose (fp);
        result = crypto_operation_fail;
        goto cleanup;
      }

      fclose (fp);
    }
  }

  if (verbose) {
    printf ("LMS signature generation succeeded (IPPC), signature length: %zu\n", *sig_len);
  }

  result = crypto_ok;

cleanup:
  if (keygen_buf) {
    free (keygen_buf);
  }

  if (sign_buf) {
    free (sign_buf);
  }

  if (sig_state) {
    free (sig_state);
  }

  if (pub_key) {
    free (pub_key);
  }

  if (priv_key) {
    free (priv_key);
  }

  if (file_data) {
    explicit_bzero (file_data, file_size);
    free (file_data);
  }

  return result;
}

/* ========================================================================== */
/*                         ML-DSA-87 Implementation                           */
/* ========================================================================== */

/*
 * ML-DSA-87 parameters (NIST FIPS 204, security level 5):
 *   Public key:  2592 bytes
 *   Private key: 4896 bytes
 *   Signature:   4627 bytes
 *
 * Keys are stored as PEM or DER files (PKCS#8 / SubjectPublicKeyInfo),
 * generated via: openssl genpkey -algorithm ML-DSA-87
 */

/* ML-DSA-87 OID: 2.16.840.1.101.3.4.3.19 */
static const uint8_t  mldsa87_oid[] = {
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
};

/*
 * Extract raw 2592-byte public key from SubjectPublicKeyInfo (SPKI) DER.
 * Structure: SEQUENCE { SEQUENCE { OID ML-DSA-87 }, BIT STRING { raw pubkey } }
 */
static int
parse_mldsa_public_key_spki (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        *pubkey,
  size_t         pubkey_buf_size,
  size_t         *pubkey_len
  )
{
  size_t  offset = 0;
  size_t  seq_len, alg_seq_len, bitstring_len;
  size_t  alg_seq_end;

  /* Outer SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    return -1;
  }

  /* AlgorithmIdentifier SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &alg_seq_len) != 0) {
    return -1;
  }

  alg_seq_end = offset + alg_seq_len;

  /* Verify ML-DSA-87 OID */
  if ((alg_seq_len < sizeof (mldsa87_oid)) || (alg_seq_end > der_size)) {
    return -1;
  }

  if (memcmp (&der_buf[offset], mldsa87_oid, sizeof (mldsa87_oid)) != 0) {
    printf ("ERROR: Not an ML-DSA-87 public key\n");
    return -1;
  }

  offset = alg_seq_end;

  /* BIT STRING containing the raw public key */
  if (offset >= der_size || der_buf[offset] != DER_TAG_BIT_STRING) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &bitstring_len) != 0) {
    return -1;
  }

  /* Skip unused-bits byte (must be 0) */
  if (offset >= der_size || der_buf[offset] != 0x00) {
    return -1;
  }

  offset++;
  bitstring_len--;

  if (bitstring_len != MLDSA87_PUBKEY_SIZE) {
    printf ("ERROR: Unexpected ML-DSA-87 public key size: %zu (expected %d)\n",
            bitstring_len, MLDSA87_PUBKEY_SIZE);
    return -1;
  }

  if (pubkey_buf_size < bitstring_len || offset + bitstring_len > der_size) {
    return -1;
  }

  memcpy (pubkey, &der_buf[offset], bitstring_len);
  *pubkey_len = bitstring_len;

  return 0;
}

/*
 * Extract raw 4896-byte expanded private key from PKCS#8 DER.
 * Structure: SEQUENCE { INTEGER 0, SEQUENCE { OID }, OCTET STRING {
 *              SEQUENCE { OCTET STRING (seed 32B), OCTET STRING (expanded 4896B) } } }
 */
static int
parse_mldsa_private_key_pkcs8 (
  const uint8_t  *der_buf,
  size_t         der_size,
  uint8_t        *privkey,
  size_t         privkey_buf_size,
  size_t         *privkey_len
  )
{
  size_t  offset = 0;
  size_t  seq_len, int_len, alg_seq_len, alg_seq_end;
  size_t  octet_len, inner_end, seed_len, expanded_len;

  /* Outer SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &seq_len) != 0) {
    return -1;
  }

  /* Version INTEGER (must be 0) */
  if (offset >= der_size || der_buf[offset] != 0x02) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &int_len) != 0) {
    return -1;
  }

  if ((int_len != 1) || (offset >= der_size) || (der_buf[offset] != 0x00)) {
    printf ("ERROR: PKCS#8 version must be 0\n");
    return -1;
  }

  offset++;

  /* AlgorithmIdentifier SEQUENCE */
  if (offset >= der_size || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &alg_seq_len) != 0) {
    return -1;
  }

  alg_seq_end = offset + alg_seq_len;

  /* Verify ML-DSA-87 OID */
  if ((alg_seq_len < sizeof (mldsa87_oid)) || (alg_seq_end > der_size)) {
    return -1;
  }

  if (memcmp (&der_buf[offset], mldsa87_oid, sizeof (mldsa87_oid)) != 0) {
    printf ("ERROR: Not an ML-DSA-87 private key\n");
    return -1;
  }

  offset = alg_seq_end;

  /* Outer OCTET STRING wrapping the private key data */
  if (offset >= der_size || der_buf[offset] != DER_TAG_OCTET_STRING) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, der_size, &octet_len) != 0) {
    return -1;
  }

  inner_end = offset + octet_len;

  if (inner_end > der_size) {
    return -1;
  }

  /* Inner SEQUENCE: { OCTET STRING (seed), OCTET STRING (expanded key) } */
  if (offset >= inner_end || der_buf[offset] != DER_TAG_SEQUENCE) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, inner_end, &seq_len) != 0) {
    return -1;
  }

  /* First OCTET STRING: seed (skip it) */
  if (offset >= inner_end || der_buf[offset] != DER_TAG_OCTET_STRING) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, inner_end, &seed_len) != 0) {
    return -1;
  }

  offset += seed_len;

  /* Second OCTET STRING: expanded private key (what IPPC needs) */
  if (offset >= inner_end || der_buf[offset] != DER_TAG_OCTET_STRING) {
    return -1;
  }

  offset++;

  if (der_parse_length (der_buf, &offset, inner_end, &expanded_len) != 0) {
    return -1;
  }

  if (expanded_len != MLDSA87_PRIVKEY_SIZE) {
    printf ("ERROR: Unexpected ML-DSA-87 expanded private key size: %zu (expected %d)\n",
            expanded_len, MLDSA87_PRIVKEY_SIZE);
    return -1;
  }

  if (privkey_buf_size < expanded_len || offset + expanded_len > der_size) {
    return -1;
  }

  memcpy (privkey, &der_buf[offset], expanded_len);
  *privkey_len = expanded_len;

  return 0;
}

/*
 * Read an ML-DSA-87 public key from a PEM or DER file and extract
 * the raw 2592-byte public key into the caller-supplied buffer.
 */
bool
crypto_read_mldsa_pubkey_internal (
  const char     *file,
  unsigned char  *pubkey,
  size_t         pubkey_size
  )
{
  uint8_t   *file_data = NULL;
  size_t    file_size  = 0;
  uint8_t   *der_buf   = NULL;
  uint16_t  der_size   = 0;
  uint8_t   pem_type;
  size_t    raw_len    = 0;

  if (pubkey_size < MLDSA87_PUBKEY_SIZE) {
    printf ("ERROR: ML-DSA pubkey buffer too small: need %d, have %zu\n",
            MLDSA87_PUBKEY_SIZE, pubkey_size);
    return false;
  }

  file_data = (uint8_t *)read_file (file, &file_size, false);
  if (file_data == NULL) {
    return false;
  }

  /* Check if PEM and convert to DER if needed */
  if (memcmp (file_data, "-----BEG", 8) == 0) {
    pem_type = get_der_from_pem ((char *)file_data, file_size, &der_buf, &der_size);
    free (file_data);
    file_data = NULL;

    if ((der_size == 0) || (der_buf == NULL)) {
      printf ("ERROR: Failed to convert ML-DSA PEM to DER\n");
      return false;
    }

    if (pem_type != PEMTYPE__PUBLIC) {
      printf ("ERROR: Expected PUBLIC KEY PEM, got pem_type %d\n", pem_type);
      free (der_buf);
      return false;
    }
  } else if (file_data[0] == DER_TAG_SEQUENCE) {
    /* Already DER */
    der_buf  = file_data;
    der_size = (uint16_t)file_size;
  } else if (file_size == MLDSA87_PUBKEY_SIZE) {
    /* Raw binary public key */
    memcpy (pubkey, file_data, MLDSA87_PUBKEY_SIZE);
    free (file_data);
    return true;
  } else {
    printf ("ERROR: ML-DSA public key file is not PEM, DER, or raw (%zu bytes): %s\n",
            file_size, file);
    free (file_data);
    return false;
  }

  if (parse_mldsa_public_key_spki (der_buf, der_size, pubkey, pubkey_size, &raw_len) != 0) {
    printf ("ERROR: Failed to parse ML-DSA-87 public key from %s\n", file);
    free (der_buf);
    return false;
  }

  free (der_buf);
  return true;
}

/*
 * Read an ML-DSA-87 private key from a PEM or DER file and extract the
 * raw 4896-byte expanded private key into the caller-supplied buffer.
 */
static bool
read_mldsa_privkey_from_pem (
  const char     *file,
  uint8_t        *privkey,
  size_t         privkey_size,
  size_t         *privkey_len
  )
{
  uint8_t   *file_data = NULL;
  size_t    file_size  = 0;
  uint8_t   *der_buf   = NULL;
  uint16_t  der_size   = 0;
  uint8_t   pem_type;

  file_data = (uint8_t *)read_file (file, &file_size, false);
  if (file_data == NULL) {
    return false;
  }

  if (memcmp (file_data, "-----BEG", 8) == 0) {
    pem_type = get_der_from_pem ((char *)file_data, file_size, &der_buf, &der_size);
    free (file_data);
    file_data = NULL;

    if ((der_size == 0) || (der_buf == NULL)) {
      printf ("ERROR: Failed to convert ML-DSA private key PEM to DER\n");
      return false;
    }

    if (pem_type != PEMTYPE__PRIVATE) {
      printf ("ERROR: Expected PRIVATE KEY PEM, got pem_type %d\n", pem_type);
      free (der_buf);
      return false;
    }
  } else if (file_data[0] == DER_TAG_SEQUENCE) {
    der_buf  = file_data;
    der_size = (uint16_t)file_size;
  } else if (file_size == MLDSA87_PRIVKEY_SIZE) {
    /* Raw binary expanded private key */
    memcpy (privkey, file_data, MLDSA87_PRIVKEY_SIZE);
    *privkey_len = MLDSA87_PRIVKEY_SIZE;
    free (file_data);
    return true;
  } else {
    printf ("ERROR: ML-DSA private key file is not PEM, DER, or raw (%zu bytes): %s\n",
            file_size, file);
    free (file_data);
    return false;
  }

  if (parse_mldsa_private_key_pkcs8 (der_buf, der_size, privkey, privkey_size, privkey_len) != 0) {
    printf ("ERROR: Failed to parse ML-DSA-87 private key from %s\n", file);
    free (der_buf);
    return false;
  }

  free (der_buf);
  return true;
}

/*
 * ML-DSA-87 signature generation using IPPC library.
 * Reads a PEM or DER PKCS#8 private key file and signs the message.
 */
crypto_status
crypto_mldsa_sign_data_internal (
  const unsigned char  *msg,
  size_t               msg_len,
  unsigned char        *signature,
  size_t               *sig_len,
  const char           *privkey_file
  )
{
  IppStatus         ipp_status    = ippStsNoErr;
  crypto_status     result        = crypto_operation_fail;
  IppsMLDSAState    *state        = NULL;
  Ipp8u             *sign_buf     = NULL;
  Ipp8u             *prv_key      = NULL;
  Ipp32s            state_size    = 0;
  Ipp32s            sign_buf_sz   = 0;
  IppsMLDSAInfo     info;
  size_t            prv_len       = 0;

  /* Get key sizes */
  ipp_status = ippsMLDSA_GetInfo (&info, ML_DSA_87);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_GetInfo failed: %s\n", ippcpGetStatusString (ipp_status));
    return crypto_operation_fail;
  }

  /* Check output buffer size */
  if (*sig_len < (size_t)info.signatureSize) {
    printf ("ERROR: ML-DSA signature buffer too small: need %d, have %zu\n",
            info.signatureSize, *sig_len);
    return crypto_buffer_too_small;
  }

  /* Read private key from PEM or DER file */
  prv_key = (Ipp8u *)malloc (info.privateKeySize);
  if (NULL == prv_key) {
    printf ("ERROR: Failed to allocate ML-DSA private key buffer\n");
    return crypto_memory_alloc_fail;
  }

  if (!read_mldsa_privkey_from_pem (privkey_file, prv_key,
                                     (size_t)info.privateKeySize, &prv_len)) {
    printf ("ERROR: Failed to read ML-DSA-87 private key from %s\n", privkey_file);
    free (prv_key);
    return crypto_file_io_error;
  }

  /* Get IPPC state size */
  ipp_status = ippsMLDSA_GetSize (&state_size);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_GetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    free (prv_key);
    return crypto_operation_fail;
  }

  state = (IppsMLDSAState *)malloc (state_size);
  if (NULL == state) {
    printf ("ERROR: Failed to allocate ML-DSA state\n");
    free (prv_key);
    return crypto_memory_alloc_fail;
  }

  /* Initialize state for ML-DSA-87, maxMessageLength must be >= msg_len */
  ipp_status = ippsMLDSA_Init (state, (Ipp32s)msg_len, ML_DSA_87);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_Init failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Get sign scratch buffer size */
  ipp_status = ippsMLDSA_SignBufferGetSize (&sign_buf_sz, state);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_SignBufferGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  sign_buf = (Ipp8u *)malloc (sign_buf_sz);
  if (NULL == sign_buf) {
    printf ("ERROR: Failed to allocate ML-DSA sign scratch buffer\n");
    result = crypto_memory_alloc_fail;
    goto cleanup;
  }

  /* Sign the message (ctx=NULL, ctxLen=0, rndFunc=NULL uses RDRAND) */
  ipp_status = ippsMLDSA_Sign (
    (const Ipp8u *)msg, (Ipp32s)msg_len,
    NULL, 0,                          /* no context string */
    prv_key, signature,
    state, sign_buf,
    NULL, NULL                        /* use RDRAND */
  );

  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_Sign failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  *sig_len = (size_t)info.signatureSize;

  if (verbose) {
    printf ("ML-DSA-87 signature generation succeeded, signature length: %zu\n", *sig_len);
  }

  result = crypto_ok;

cleanup:
  if (sign_buf) {
    free (sign_buf);
  }

  if (state) {
    free (state);
  }

  if (prv_key) {
    explicit_bzero (prv_key, (size_t)info.privateKeySize);
    free (prv_key);
  }

  return result;
}

/*
 * ML-DSA-87 signature verification using IPPC library.
 */
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
  IppStatus         ipp_status    = ippStsNoErr;
  bool              result        = false;
  IppsMLDSAState    *state        = NULL;
  Ipp8u             *verify_buf   = NULL;
  Ipp32s            state_size    = 0;
  Ipp32s            verify_buf_sz = 0;
  IppsMLDSAInfo     info;
  Ipp32s            is_valid      = 0;

  (void)sig_len;    /* ML-DSA-87 signature has a fixed size */
  (void)pubkey_len; /* ML-DSA-87 pubkey has a fixed size */

  /* Get key sizes for validation */
  ipp_status = ippsMLDSA_GetInfo (&info, ML_DSA_87);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_GetInfo failed: %s\n", ippcpGetStatusString (ipp_status));
    return false;
  }

  /* Get IPPC state size */
  ipp_status = ippsMLDSA_GetSize (&state_size);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_GetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    return false;
  }

  state = (IppsMLDSAState *)malloc (state_size);
  if (NULL == state) {
    printf ("ERROR: Failed to allocate ML-DSA state\n");
    return false;
  }

  /* Initialize state for ML-DSA-87, maxMessageLength must be >= msg_len */
  ipp_status = ippsMLDSA_Init (state, (Ipp32s)msg_len, ML_DSA_87);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_Init failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  /* Get verify scratch buffer size */
  ipp_status = ippsMLDSA_VerifyBufferGetSize (&verify_buf_sz, state);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_VerifyBufferGetSize failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  verify_buf = (Ipp8u *)malloc (verify_buf_sz);
  if (NULL == verify_buf) {
    printf ("ERROR: Failed to allocate ML-DSA verify scratch buffer\n");
    goto cleanup;
  }

  /* Verify the signature (ctx=NULL, ctxLen=0) */
  ipp_status = ippsMLDSA_Verify (
    (const Ipp8u *)msg, (Ipp32s)msg_len,
    NULL, 0,                          /* no context string */
    (const Ipp8u *)public_key,
    (const Ipp8u *)signature,
    &is_valid,
    state, verify_buf
  );

  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: ippsMLDSA_Verify failed: %s\n", ippcpGetStatusString (ipp_status));
    goto cleanup;
  }

  if (is_valid != 1) {
    printf ("ERROR: ML-DSA-87 signature verification failed (invalid signature)\n");
    goto cleanup;
  }

  if (verbose) {
    printf ("ML-DSA-87 signature verification succeeded\n");
  }

  result = true;

cleanup:
  if (verify_buf) {
    free (verify_buf);
  }

  if (state) {
    free (state);
  }

  return result;
}

#endif /* USE_IPPC */
