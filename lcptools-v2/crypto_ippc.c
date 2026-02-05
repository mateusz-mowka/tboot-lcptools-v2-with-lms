#ifdef USE_IPPC

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include "../ippc/cryptography-primitives/include/ippcp.h"
#include "../ippc/cryptography-primitives/include/ippcpdefs.h"
#include "../include/hash.h"
#include "../include/lcp3.h"
#include "crypto_interface.h"
#include "safe_lib.h"
#include "lcputils.h"
#include "crypto_ippc_defines.h"

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
    case TB_HALG_SHA1:
    case TB_HALG_SHA1_LG:
      #pragma GCC diagnostic push
      #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
      method = ippsHashMethod_SHA1 ();
      #pragma GCC diagnostic pop
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
  IppStatus             status = ippStsNoOperation;
  int                   ctx_size;
  IppsHashState_rmf     *p_ctx;
  const IppsHashMethod  *method;

  /* Validate input parameters */
  if ((buf == NULL) || (hash == NULL)) {
    printf ("ERROR: NULL pointer passed to crypto_hash_buffer_internal\n");
    return crypto_nullptr_error;
  }

  if (size == 0) {
    printf ("ERROR: Invalid size (0) passed to crypto_hash_buffer_internal\n");
    return crypto_invalid_size;
  }

  method = get_ipp_hash_method (hash_alg);
  if (method == NULL) {
    return crypto_unknown_hashalg;
  }

  /* Get required context size */
  status = ippsHashGetSize_rmf (&ctx_size);
  if (status != ippStsNoErr) {
    printf ("Error getting hash context size: %d\n", status);
    return crypto_general_fail;
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
    printf ("ERROR: Hash initialization failed: %d\n", status);
    free (p_ctx);
    return crypto_crypto_operation_fail;
  }

  /* Update with message data */
  status = ippsHashUpdate_rmf (buf, size, p_ctx);
  if (status != ippStsNoErr) {
    printf ("ERROR: Hash update failed: %d\n", status);
    free (p_ctx);
    return crypto_crypto_operation_fail;
  }

  /* Finalize and get digest */
  status = ippsHashFinal_rmf (hash, p_ctx);
  if (status != ippStsNoErr) {
    printf ("ERROR: Hash finalization failed: %d\n", status);
    free (p_ctx);
    return crypto_crypto_operation_fail;
  }

  free (p_ctx);
  return crypto_ok;
}

/* Helper function to compare strings (compatible with strcmp) */
int
str8cmp (
  const char  *s1,
  const char  *s2
  )
{
  return strcmp (s1, s2);
}

/* Simple base64 decode function */
uint16_t
base64_decode (
  const uint8_t  *src,
  uint32_t       src_len,
  uint8_t        *dst
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

      c[k] = d[src[i++]];
    }

    if (k >= 2) {
      dst[j++] = (c[0] << 2) | (c[1] >> 4);
    }

    if (k >= 3) {
      dst[j++] = (c[1] << 4) | (c[2] >> 2);
    }

    if (k >= 4) {
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
  if ((num_length_bytes > 4) || (*offset + num_length_bytes > max_size)) {
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
  uint8_t    *p;
  size_t     p_len;
  uint8_t    *q;
  size_t     q_len;
  uint8_t    *dp;
  size_t     dp_len;
  uint8_t    *dq;
  size_t     dq_len;
  uint8_t    *qinv;
  size_t     qinv_len;
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
  if (der_buf[offset] != 0x30) {
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

  /* Skip modulus (n) */
  if (der_parse_integer (der_buf, &offset, der_size, &temp_value, &temp_len) != 0) {
    printf ("ERROR: Failed to parse modulus\n");
    return -1;
  }

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
  if (der_parse_integer (der_buf, &offset, der_size, &params->p, &params->p_len) != 0) {
    printf ("ERROR: Failed to parse prime1 (p)\n");
    return -1;
  }

  /* Parse prime2 (q) */
  if (der_parse_integer (der_buf, &offset, der_size, &params->q, &params->q_len) != 0) {
    printf ("ERROR: Failed to parse prime2 (q)\n");
    return -1;
  }

  /* Parse exponent1 (dP) */
  if (der_parse_integer (der_buf, &offset, der_size, &params->dp, &params->dp_len) != 0) {
    printf ("ERROR: Failed to parse exponent1 (dP)\n");
    return -1;
  }

  /* Parse exponent2 (dQ) */
  if (der_parse_integer (der_buf, &offset, der_size, &params->dq, &params->dq_len) != 0) {
    printf ("ERROR: Failed to parse exponent2 (dQ)\n");
    return -1;
  }

  /* Parse coefficient (qInv) */
  if (der_parse_integer (der_buf, &offset, der_size, &params->qinv, &params->qinv_len) != 0) {
    printf ("ERROR: Failed to parse coefficient (qInv)\n");
    return -1;
  }

  return 0;
}

/* DER key extraction with ASN.1 parsing */
uint8_t
get_key_from_der (
  uint8_t   *der_buf,
  uint16_t  der_size,
  uint8_t   pem_type,
  bool      is_private,
  uint8_t   *key_buf,
  uint16_t  *key_size
  )
{
  UNUSED (pem_type);
  UNUSED (is_private);
  UNUSED (key_buf);
  UNUSED (key_size);

  /* For now, only RSA private keys are supported with full parsing */
  if ((pem_type != PEMTYPE_RSA_PRIVATE) && (pem_type != PEMTYPE__PRIVATE)) {
    printf ("WARNING: get_key_from_der only supports RSA private keys currently\n");
    return crypto_general_fail;
  }

  /* Parse the DER structure - this extracts the CRT parameters but doesn't copy to key_buf
   * The actual key loading is done in rsa_load_private_key_from_file which stores
   * the DER buffer pointer for later use */
  rsa_private_key_params  params;
  if (parse_rsa_private_key_der (der_buf, der_size, &params) != 0) {
    printf ("ERROR: Failed to parse RSA private key DER structure\n");
    return crypto_general_fail;
  }

  /* For RSA private keys, we don't copy to key_buf since we need all the CRT parameters
   * The parsing validates the structure; actual key loading happens in
   * rsa_load_private_key_from_file */
  *key_size = 0;  /* Indicate success but no data copied */
  return crypto_ok;
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
  if (*(pem_data_buf+i-1) == 0x0D) {
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
  if (str8cmp ((char *)p_pem_header, "-----BEGIN EC PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE_EC_PUBLIC;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN EC PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE_EC_PRIVATE;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN RSA PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE_RSA_PUBLIC;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN RSA PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE_RSA_PRIVATE;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN LMS PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE_LMS_PUBLIC;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN LMS PRIVATE KEY-----") == 0) {
    key_type = PEMTYPE_LMS_PRIVATE;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN PUBLIC KEY-----") == 0) {
    key_type = PEMTYPE__PUBLIC;
  } else if (str8cmp ((char *)p_pem_header, "-----BEGIN PRIVATE KEY-----") == 0) {
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
  *p_der_buf = (uint8_t *)malloc ((3*b64_length)/4);
  if (*p_der_buf == NULL) {
    printf ("ERROR: Failed to allocate DER buffer\n");
    return PEMTYPE_UNKNOWN;
  }

  /* Decode PEM Base64 to DER */
  *p_der_size = base64_decode (p_b64_string, b64_length, *p_der_buf);
  if (*p_der_size == 0) {
    printf ("ERROR: Failed to decode PEM\n");
    free (*p_der_buf);
    *p_der_buf = NULL;
    return PEMTYPE_UNKNOWN;
  }

  return key_type;
}

crypto_status
read_input_file (
  const char  *filename,
  uint8_t     **file_data,
  uint32_t    *file_size
  )
{
  FILE    *fp_in;
  size_t  temp_result;

  /* Validate input parameters */
  if ((filename == NULL) || (file_data == NULL) || (file_size == NULL)) {
    printf ("ERROR: NULL pointer passed to read_input_file\n");
    return crypto_nullptr_error;
  }

  /* Open the Input file */
  if ((fp_in = fopen (filename, "rb")) == NULL) {
    printf ("ERROR: Unable to open file: %s\n", filename);
    return crypto_file_io_error;
  }

  /* Get the Input file Size */
  fseek (fp_in, 0, SEEK_END);
  *file_size = ftell (fp_in);

  /* Allocate buffer */
  *file_data = (uint8_t *)malloc (*file_size + 4);
  if (*file_data == NULL) {
    printf ("ERROR: Failed to allocate memory for file data\n");
    fclose (fp_in);
    return crypto_memory_alloc_fail;
  }

  memset (*file_data, 0, *file_size + 4);

  /* Read the contents of input file to memory buffer */
  fseek (fp_in, 0, SEEK_SET);
  temp_result = fread (*file_data, 1, *file_size, fp_in);
  if (temp_result != *file_size) {
    printf ("ERROR: Failed to read complete file\\n");
    free ((void *)*file_data);
    *file_data = NULL;
    fclose (fp_in);
    return crypto_file_io_error;
  }

  /* Close the input file */
  fclose (fp_in);
  return crypto_ok;
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
  uint32_t       file_data_size;
  crypto_status  status;
  uint8_t        *p_der_buf;
  uint16_t       der_size = 0;
  uint8_t        pem_type = 0;

  status = read_input_file (filename, &p_file_data_buf, &file_data_size);
  if (status != crypto_ok) {
    printf ("Error reading Key file\n");
    return crypto_general_fail;
  }

  /* First let's see if it is PEM or DER or raw key */
  /* if PEM, first bytes == '----BEGIN' */
  /* if DER, first byte == 0x30 */
  /* else binary */

  if ((memcmp (p_file_data_buf, "-----BEG", 8) != 0) || (file_data_size <= 0x80)) {
    /* Not a PEM */
    p_der_buf = p_file_data_buf;
    der_size  = file_data_size;
  } else {
    pem_type = get_der_from_pem ((char *)p_file_data_buf, file_data_size, &p_der_buf, &der_size);
    if (der_size == 0) {
      printf ("ERROR: Corrupted PEM file\n");
      free ((void *)p_file_data_buf);
      return crypto_general_fail;
    }

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
        default:
          *alg_id = HASH_ALG_TYPE_NULL;
          break;
      }
    }

    switch (pem_type) {
      case PEMTYPE_RSA_PUBLIC:
      case PEMTYPE_EC_PUBLIC:
      case PEMTYPE_LMS_PUBLIC:
        if (is_private) {
          printf ("ERROR: Wrong key type (%s)\n", filename);
          if (p_der_buf != p_file_data_buf) {
            free ((void *)p_der_buf);
          }

          free ((void *)p_file_data_buf);
          return crypto_general_fail;
        }

        break;
      case PEMTYPE_EC_PRIVATE:
      case PEMTYPE_RSA_PRIVATE:
      case PEMTYPE_LMS_PRIVATE:
        if (!is_private) {
          printf ("ERROR: Wrong key type (%s)\n", filename);
          if (p_der_buf != p_file_data_buf) {
            free ((void *)p_der_buf);
          }

          free ((void *)p_file_data_buf);
          return crypto_general_fail;
        }

        break;
      case PEMTYPE_UNKNOWN:
      case PEMTYPE_INVALID:
        /* could be binary key */
        break;
      default:
        break;
    }
  }

  /* We are here because either the file is a valid PEM and we decoded it to a DER
   * and p_der_buf points to a buffer containing the ASN.1 encoded DER
   * or it was not a PEM file (and p_der_buf points to original file data)
   */

  /* Do we have a valid DER? */
  if ((der_size != 0) && (*p_der_buf == 0x30)) {
    status = get_key_from_der (p_der_buf, der_size, pem_type, is_private, key_buf, key_size);

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
      free ((void *)p_file_data_buf);
      if ((p_der_buf != p_file_data_buf) && (p_der_buf != NULL)) {
        free ((void *)p_der_buf);
      }

      return crypto_ok;
    }
  }

  /* We are here because file is not a valid PEM or DER -- let's test for binary */
  if (p_der_buf != p_file_data_buf) {
    free ((void *)p_der_buf);
  }

  /* Handle binary key formats */
  if (is_private && ((file_data_size == 32) || (file_data_size == 48))) {
    /* Binary ECC private key */
    if (alg_id != NULL) {
      *alg_id = KEY_ALG_TYPE_ECC;
    }

    if (*key_size < file_data_size) {
      printf ("ERROR: Key too large %d (max: %d)\n", file_data_size, *key_size);
      *key_size = 0;
      free ((void *)p_file_data_buf);
      return crypto_general_fail;
    }

    memcpy (key_buf, p_file_data_buf, file_data_size);
    buffer_reverse_byte_order (key_buf, file_data_size);
    *key_size = file_data_size;
    free ((void *)p_file_data_buf);
    return crypto_ok;
  } else if (!is_private && ((file_data_size == (2*32)) || (file_data_size == (2*48)))) {
    /* Binary ECC public key */
    if (alg_id != NULL) {
      *alg_id = KEY_ALG_TYPE_ECC;
    }

    if (*key_size * 2 < file_data_size) {
      printf ("ERROR: Key too large %d (max: %d)\n", file_data_size, *key_size);
      *key_size = 0;
      free ((void *)p_file_data_buf);
      return crypto_general_fail;
    }

    memcpy (key_buf, p_file_data_buf, file_data_size);
    buffer_reverse_byte_order (key_buf, file_data_size/2);
    buffer_reverse_byte_order (key_buf + file_data_size/2, file_data_size/2);
    *key_size = file_data_size/2;
    free ((void *)p_file_data_buf);
    return crypto_ok;
  } else if (((file_data_size == 256) || (file_data_size == 384))) {
    /* Binary RSA key - keep in big-endian format to match OpenSSL */
    if (alg_id != NULL) {
      *alg_id = KEY_ALG_TYPE_RSA;
    }

    memcpy (key_buf, p_file_data_buf, file_data_size);
    /* Note: RSA keys are kept in big-endian format (no byte reversal) */
    *key_size = file_data_size;
    free ((void *)p_file_data_buf);
    return crypto_ok;
  } else if ((file_data_size == (LMS_PUBLIC_KEY_MAX_BYTES + 4)) ||
             (file_data_size == LMS_PUBLIC_KEY_MAX_BYTES))
  {
    /* Binary LMS public Key */
    if (alg_id != NULL) {
      *alg_id = KEY_ALG_TYPE_LMS;
    }

    if (file_data_size == LMS_PUBLIC_KEY_MAX_BYTES + 4) {
      file_data_size -= 4;
      memcpy (key_buf, p_file_data_buf + 4, file_data_size);
    } else {
      memcpy (key_buf, p_file_data_buf, file_data_size);
    }

    *key_size = file_data_size;
    free ((void *)p_file_data_buf);
    return crypto_ok;
  } else if ((file_data_size == LMS_PRIVATE_KEY_MAX_BYTES) ||
             (file_data_size == LMS_PRIVATE_KEY_MAX_BYTES + 4))
  {
    /* Binary LMS private Key */
    if (alg_id != NULL) {
      *alg_id = KEY_ALG_TYPE_LMS;
    }

    if (file_data_size == LMS_PRIVATE_KEY_MAX_BYTES + 4) {
      file_data_size -= 4;
      memcpy (key_buf, p_file_data_buf + 4, file_data_size);
    } else {
      memcpy (key_buf, p_file_data_buf, file_data_size);
    }

    buffer_reverse_byte_order (key_buf, file_data_size);
    *key_size = file_data_size;
    free ((void *)p_file_data_buf);
    return crypto_ok;
  }

  printf ("ERROR: Invalid Key (%s)\n", filename);
  free ((void *)p_file_data_buf);
  return crypto_general_fail;
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
  int         *key_size_bits
  )
{
  uint8_t                 *file_data = NULL;
  uint32_t                file_size  = 0;
  uint8_t                 *der_buf   = NULL;
  uint16_t                der_size   = 0;
  uint8_t                 pem_type   = 0;
  crypto_status           status;
  rsa_private_key_params  params;
  IppStatus               ipp_status;
  IppsRSAPrivateKeyState  *priv_key = NULL;
  IppsBigNumState         *p_bn = NULL, *q_bn = NULL;
  IppsBigNumState         *dp_bn = NULL, *dq_bn = NULL, *qinv_bn = NULL;
  int                     key_ctx_size = 0;
  int                     factor_bits_p, factor_bits_q;

  /* Read the file */
  status = read_input_file (privkey_file, &file_data, &file_size);
  if (status != crypto_ok) {
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
  } else if (file_data[0] == 0x30) {
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
  factor_bits_p  = params.p_len * 8;
  factor_bits_q  = params.q_len * 8;
  *key_size_bits = (factor_bits_p + factor_bits_q);

  /* Create BigNum structures from the parsed parameters */
  if (create_bignum_from_bytes (params.p, params.p_len, &p_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for p\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (params.q, params.q_len, &q_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for q\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (params.dp, params.dp_len, &dp_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for dP\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (params.dq, params.dq_len, &dq_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for dQ\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (params.qinv, params.qinv_len, &qinv_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for qInv\n");
    goto cleanup;
  }

  /* Get size for private key context */
  ipp_status = ippsRSA_GetSizePrivateKeyType2 (factor_bits_p, factor_bits_q, &key_ctx_size);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA private key size: %d\n", ipp_status);
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
    printf ("ERROR: Failed to initialize RSA private key: %d\n", ipp_status);
    free (priv_key);
    priv_key = NULL;
    goto cleanup;
  }

  /* Set private key parameters */
  ipp_status = ippsRSA_SetPrivateKeyType2 (p_bn, q_bn, dp_bn, dq_bn, qinv_bn, priv_key);
  if (ipp_status != ippStsNoErr) {
    printf ("ERROR: Failed to set RSA private key parameters: %d\n", ipp_status);
    free (priv_key);
    priv_key = NULL;
    goto cleanup;
  }

cleanup:
  /* Free temporary resources */
  if (der_buf) {
    free (der_buf);
  }

  if (p_bn) {
    free (p_bn);
  }

  if (q_bn) {
    free (q_bn);
  }

  if (dp_bn) {
    free (dp_bn);
  }

  if (dq_bn) {
    free (dq_bn);
  }

  if (qinv_bn) {
    free (qinv_bn);
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
  int                     key_size_bits   = 0;
  int                     buffer_size     = 0;
  uint8_t                 *scratch_buffer = NULL;

  if ((sig_block == NULL) || (digest == NULL) || (privkey_file == NULL)) {
    printf ("ERROR: crypto_rsa_sign_internal called with NULL pointer\n");
    return crypto_nullptr_error;
  }

  /* Load private key */
  priv_key = rsa_load_private_key_from_file (privkey_file, &key_size_bits);
  if (priv_key == NULL) {
    printf ("ERROR: Failed to load RSA private key\n");
    return crypto_general_fail;
  }

  /* Get hash method */
  hash_method = get_ipp_hash_method (hash_alg);
  if (hash_method == NULL) {
    printf ("ERROR: Unsupported hash algorithm\n");
    return crypto_unknown_hashalg;
  }

  /* Get buffer size for signing operation */
  status = ippsRSA_GetBufferSizePrivateKey (&buffer_size, priv_key);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA buffer size: %d\n", status);
    return crypto_general_fail;
  }

  /* Allocate scratch buffer */
  scratch_buffer = (uint8_t *)malloc (buffer_size);
  if (scratch_buffer == NULL) {
    printf ("ERROR: Failed to allocate scratch buffer\n");
    return crypto_general_fail;
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
    int  salt_len = 0; /* Salt length, typically hash output length */

    /* Determine salt length based on hash algorithm */
    switch (hash_alg) {
      case TB_HALG_SHA1:
      case TB_HALG_SHA1_LG:
        salt_len = 20;
        break;
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

    status = ippsRSASign_PSS_rmf (
                                  digest->data,
                                  digest->size,
                                  NULL, /* Salt - NULL for auto-generated */
                                  salt_len,
                                  sig_block->data,
                                  priv_key,
                                  NULL, /* No public key needed for signing */
                                  hash_method,
                                  scratch_buffer
                                  );
  } else {
    printf ("ERROR: Unsupported RSA signature algorithm: 0x%04X\n", sig_alg);
    free (scratch_buffer);
    return crypto_general_fail;
  }

  free (scratch_buffer);

  if (status != ippStsNoErr) {
    printf ("ERROR: RSA signing failed with status: %d\n", status);
    return crypto_general_fail;
  }

  return crypto_ok;
}

/* Helper function to extract hash algorithm from PKCS#1 padded signature
 * Used for backwards compatibility with old LCP list formats
 * Based on OpenSSL's pkcs_get_hashalg function */
static uint16_t
pkcs_get_hashalg (
  const unsigned char  *data
  )
{
  uint8_t  der_oid = 0x06;
  size_t   oid_size;

  if (data == NULL) {
    return TPM_ALG_NULL;
  }

  data += 2;   /* Skip 00 01 */
  /* Skip 0xFFs padding and 00 after it */
  do {
    data++;
  } while (*data == 0xFF);

  /* Then move to der_oid */
  data += 5;
  if (*data != der_oid) {
    return TPM_ALG_NULL;
  }

  data += 1;
  /* Read oid size */
  oid_size = *data;
  if (oid_size == 0x05) {
    return TPM_ALG_SHA1;     /* Only SHA1 has this size */
  }

  /* Move to the last byte to see what alg is used */
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
  uint8_t                digest[SHA512_LENGTH];   /* Large enough for any hash */
  size_t                 digest_size;
  int                    key_size_bits;
  int                    pub_exp_bits     = 32; /* Typical public exponent is 65537 (0x010001) */
  int                    pub_key_size     = 0;
  int                    buffer_size      = 0;
  uint8_t                *scratch_buffer  = NULL;
  int                    is_valid         = 0;
  bool                   result           = false;
  uint8_t                pub_exp[]        = { 0x01, 0x00, 0x01 }; /* 65537 in big-endian */
  uint16_t               original_hashAlg = hashAlg;              /* Save original */

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
                /* Perform encryption (which is sig^e mod n = original padded message) */
                if (ippsRSA_Encrypt (sig_bn, result_bn, temp_key, NULL) == ippStsNoErr) {
                  /* Extract result to byte array */
                  if (ippsGetOctString_BN (decrypted_sig, pubkey->size, result_bn) == ippStsNoErr) {
                    /* Extract hash algorithm from decrypted signature */
                    hashAlg = pkcs_get_hashalg (decrypted_sig);
                    if (hashAlg != TPM_ALG_NULL) {
                      printf ("INFO: Extracted hash algorithm 0x%04X from signature (old list format)\\n", hashAlg);
                    }
                  }
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

      if ((hashAlg == TPM_ALG_NULL) || (hashAlg == original_hashAlg)) {
        printf ("ERROR: Failed to extract hash algorithm from signature\\n");
        return false;
      }
    }
  }

  /* Determine digest size based on hash algorithm */
  switch (hashAlg) {
    case TB_HALG_SHA1:
    case TB_HALG_SHA1_LG:
      digest_size = SHA1_LENGTH;
      break;
    case TB_HALG_SHA256:
      digest_size = SHA256_LENGTH;
      break;
    case TB_HALG_SHA384:
      digest_size = SHA384_LENGTH;
      break;
    case TB_HALG_SHA512:
      digest_size = SHA512_LENGTH;
      break;
    default:
      printf ("ERROR: Unsupported hash algorithm: 0x%04X\\n", hashAlg);
      return false;
  }

  /* Hash the data */
  if (crypto_hash_buffer_internal (data->data, data->size, digest, hashAlg) != crypto_ok) {
    printf ("ERROR: Failed to hash data for verification\n");
    return false;
  }

  /* Get hash method for IPPC */
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
    printf ("ERROR: Failed to get RSA public key size: %d\n", status);
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
    printf ("ERROR: Failed to initialize RSA public key: %d\n", status);
    goto cleanup;
  }

  /* Set public key parameters */
  status = ippsRSA_SetPublicKey (modulus_bn, exp_bn, pub_key);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to set RSA public key: %d\n", status);
    goto cleanup;
  }

  /* Get buffer size for verification */
  status = ippsRSA_GetBufferSizePublicKey (&buffer_size, pub_key);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get RSA buffer size: %d\n", status);
    goto cleanup;
  }

  /* Allocate scratch buffer */
  scratch_buffer = (uint8_t *)malloc (buffer_size);
  if (scratch_buffer == NULL) {
    printf ("ERROR: Failed to allocate scratch buffer\n");
    goto cleanup;
  }

  /* Verify signature based on signature algorithm */
  if (sig_alg == TPM_ALG_RSASSA) {
    /* PKCS#1 v1.5 verification */
    status = ippsRSAVerify_PKCS1v15_rmf (
                                         digest,
                                         digest_size,
                                         signature->data,
                                         &is_valid,
                                         pub_key,
                                         hash_method,
                                         scratch_buffer
                                         );
  } else if (sig_alg == TPM_ALG_RSAPSS) {
    /* PSS verification */
    status = ippsRSAVerify_PSS_rmf (
                                    digest,
                                    digest_size,
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
    printf ("ERROR: RSA verification failed with status: %d\n", status);
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

  /* Determine digest size and curve based on hash algorithm (match OpenSSL behavior) */
  switch (hashalg) {
    case TB_HALG_SHA1:
    case TB_HALG_SHA1_LG:
      digest_size = SHA1_LENGTH;
      /* For SHA-1, use key size to determine curve */
      if ((pubkey_x->size != 32) && (pubkey_x->size != 48)) {
        printf ("ERROR: Unsupported EC key size: %zu bytes\n", pubkey_x->size);
        return false;
      }

      break;
    case TB_HALG_SHA256:
      digest_size = SHA256_LENGTH;
      /* OpenSSL uses secp256k1 for SHA-256, but IPPC doesn't have it built-in */
      /* Fall back to P-256 (secp256r1) - this is a known limitation */
      if (pubkey_x->size != 32) {
        printf ("ERROR: SHA-256 requires 32-byte EC key (P-256)\n");
        return false;
      }

      break;
    case TB_HALG_SHA384:
      digest_size = SHA384_LENGTH;
      if (pubkey_x->size != 48) {
        printf ("ERROR: SHA-384 requires 48-byte EC key (P-384)\n");
        return false;
      }

      break;
    case TB_HALG_SHA512:
      digest_size = SHA512_LENGTH;
      if (pubkey_x->size != 48) {
        printf ("ERROR: SHA-512 requires 48-byte EC key (P-384)\n");
        return false;
      }

      break;
    case TB_HALG_SM3:
      /* SM2 algorithm uses SM3 hash and SM2 curve */
      digest_size = 32;  /* SM3 produces 256-bit hash */
      if (pubkey_x->size != 32) {
        printf ("ERROR: SM2 requires 32-byte EC key\n");
        return false;
      }

      break;
    default:
      printf ("ERROR: Unsupported hash algorithm: 0x%04X\n", hashalg);
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
  } else if (pubkey_x->size == 32) {
    gfp_method = ippsGFpMethod_p256r1 ();
  } else if (pubkey_x->size == 48) {
    gfp_method = ippsGFpMethod_p384r1 ();
  } else {
    printf ("ERROR: Unsupported EC key size: %zu bytes\n", pubkey_x->size);
    return false;
  }

  /* Get size for GFp context */
  status = ippsGFpGetSize (pubkey_x->size * 8, &gfp_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get GFp size: %d\n", status);
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
    printf ("ERROR: Failed to initialize GFp context: %d\n", status);
    goto cleanup;
  }

  /* Get size for EC context */
  status = ippsGFpECGetSize (gfp, &ec_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get EC size: %d\n", status);
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
  } else if (pubkey_x->size == 32) {
    status = ippsGFpECInitStd256r1 (gfp, ec);
  } else {
    status = ippsGFpECInitStd384r1 (gfp, ec);
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize EC curve: %d\n", status);
    goto cleanup;
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
    printf ("ERROR: Failed to get EC point size: %d\n", status);
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
    printf ("ERROR: Failed to initialize EC point: %d\n", status);
    goto cleanup;
  }

  status = ippsGFpECSetPointRegular (pubkey_x_bn, pubkey_y_bn, pub_point, ec);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to set EC point coordinates: %d\n", status);
    goto cleanup;
  }

  /* Get scratch buffer size */
  status = ippsGFpECScratchBufferSize (1, ec, &scratch_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get scratch buffer size: %d\n", status);
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
    printf ("ERROR: EC signature verification failed with status: %d\n", status);
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

  /* Determine digest size based on hash algorithm and validate key size */
  switch (hashalg) {
    case TB_HALG_SHA1:
    case TB_HALG_SHA1_LG:
      digest_size = SHA1_LENGTH;
      if ((priv_key_size != 32) && (priv_key_size != 48)) {
        printf ("ERROR: Unsupported EC key size: %d bytes\n", priv_key_size);
        return false;
      }

      break;
    case TB_HALG_SHA256:
      digest_size = SHA256_LENGTH;
      if (priv_key_size != 32) {
        printf ("ERROR: SHA-256 requires 32-byte EC key (P-256)\n");
        return false;
      }

      break;
    case TB_HALG_SHA384:
      digest_size = SHA384_LENGTH;
      if (priv_key_size != 48) {
        printf ("ERROR: SHA-384 requires 48-byte EC key (P-384)\n");
        return false;
      }

      break;
    case TB_HALG_SHA512:
      digest_size = SHA512_LENGTH;
      if (priv_key_size != 48) {
        printf ("ERROR: SHA-512 requires 48-byte EC key (P-384)\n");
        return false;
      }

      break;
    case TB_HALG_SM3:
      /* SM2 algorithm */
      digest_size = 32;  /* SM3 produces 256-bit hash */
      if (priv_key_size != 32) {
        printf ("ERROR: SM2 requires 32-byte EC key\n");
        return false;
      }

      break;
    default:
      printf ("ERROR: Unsupported hash algorithm: 0x%04X\n", hashalg);
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
  } else if (priv_key_size == 32) {
    gfp_method = ippsGFpMethod_p256r1 ();
  } else if (priv_key_size == 48) {
    gfp_method = ippsGFpMethod_p384r1 ();
  } else {
    printf ("ERROR: Unsupported EC key size: %d bytes\n", priv_key_size);
    return false;
  }

  /* Get size for GFp context */
  status = ippsGFpGetSize (priv_key_size * 8, &gfp_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get GFp size: %d\n", status);
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
    printf ("ERROR: Failed to initialize GFp context: %d\n", status);
    goto cleanup;
  }

  /* Get size for EC context */
  status = ippsGFpECGetSize (gfp, &ec_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get EC size: %d\n", status);
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
  } else if (priv_key_size == 32) {
    status = ippsGFpECInitStd256r1 (gfp, ec);
  } else {
    status = ippsGFpECInitStd384r1 (gfp, ec);
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize EC curve: %d\n", status);
    goto cleanup;
  }

  /* Create BigNum structures */
  if (create_bignum_from_bytes (digest, digest_size, &msg_digest_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for message digest\n");
    goto cleanup;
  }

  if (create_bignum_from_bytes (priv_key_buf, priv_key_size, &priv_key_bn) != ippStsNoErr) {
    printf ("ERROR: Failed to create BigNum for private key\n");
    goto cleanup;
  }

  /* Allocate BigNum for signature components (r and s) */
  status = ippsBigNumGetSize (priv_key_size, &bn_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get BigNum size: %d\n", status);
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
    printf ("ERROR: Failed to initialize BigNum for signature R: %d\n", status);
    goto cleanup;
  }

  status = ippsBigNumInit (priv_key_size, sig_s_bn);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to initialize BigNum for signature S: %d\n", status);
    goto cleanup;
  }

  /* Get size for EC point */
  status = ippsGFpECPointGetSize (ec, &point_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get EC point size: %d\n", status);
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
    printf ("ERROR: Failed to initialize EC point: %d\n", status);
    goto cleanup;
  }

  /* Get scratch buffer size */
  status = ippsGFpECScratchBufferSize (2, ec, &scratch_size);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to get scratch buffer size: %d\n", status);
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
    printf ("ERROR: Failed to derive public key: %d\n", status);
    goto cleanup;
  }

  /* Sign the digest with ECDSA or SM2 */
  if ((hashalg == TB_HALG_SM3) && (sigalg == TPM_ALG_SM2)) {
    /* Use SM2 signing - requires ephemeral private key (NULL to let IPPC generate) */
    status = ippsGFpECSignSM2 (msg_digest_bn, priv_key_bn, NULL, sig_r_bn, sig_s_bn, ec, scratch_buffer);
  } else {
    /* Use standard ECDSA signing */
    status = ippsGFpECSignDSA (msg_digest_bn, priv_key_bn, NULL, sig_r_bn, sig_s_bn, ec, scratch_buffer);
  }

  if (status != ippStsNoErr) {
    printf ("ERROR: EC signing failed with status: %d\n", status);
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
    printf ("ERROR: Failed to extract signature R: %d\n", status);
    goto cleanup;
  }

  status = ippsGetOctString_BN (s_data, priv_key_size, sig_s_bn);
  if (status != ippStsNoErr) {
    printf ("ERROR: Failed to extract signature S: %d\n", status);
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

  if (sig_r_bn) {
    free (sig_r_bn);
  }

  if (sig_s_bn) {
    free (sig_s_bn);
  }

  return result_ok;
}

#endif /* USE_IPP_CRYPTO */
