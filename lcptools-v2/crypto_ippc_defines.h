#ifndef LCPT_CRYPTO_IPPC_DEFINES_H
#define LCPT_CRYPTO_IPPC_DEFINES_H
#define       PEMTYPE_INVALID      0xFF
#define       PEMTYPE_UNKNOWN      0
#define       PEMTYPE_EC_PRIVATE   1
#define       PEMTYPE_EC_PUBLIC    2
#define       PEMTYPE_EC_PARAMS    3
#define       PEMTYPE_RSA_PRIVATE  4
#define       PEMTYPE_RSA_PUBLIC   5
#define       PEMTYPE_RSA_PARAMS   6
#define       PEMTYPE__PRIVATE     7
/* 8 intentionally skipped — legacy gap */
#define       PEMTYPE__PUBLIC      9
#define       PEMTYPE__PARAMS      10
#define PEMTYPE_LMS_PRIVATE        11
#define PEMTYPE_LMS_PUBLIC         12
#define KEY_ALG_TYPE_RSA           0x01
#define KEY_ALG_TYPE_ECC           0x23
#define KEY_ALG_TYPE_LMS           0x70
#define HASH_ALG_TYPE_NULL         0x10
#define RSA_KEY_MIN_BYTES          (2048/8)
#define RSA_KEY_MAX_BYTES          (3072/8)
#define ECC_KEY_LEN_MIN_BYTES      (256/8)
#define ECC_KEY_LEN_MAX_BYTES      (384/8)
#define LMS_PUBLIC_KEY_MAX_BYTES   1372
#define LMS_PRIVATE_KEY_MAX_BYTES  1372

/* ML-DSA key file types */
#define PEMTYPE_MLDSA_PRIVATE      13
#define PEMTYPE_MLDSA_PUBLIC       14
#define KEY_ALG_TYPE_MLDSA         0xA1

/* LMS tree identifier length in bytes */
#define I_LEN  16

/* Offset to leaf index in LMS private key file format:
 * 4 bytes (levels) + 4 bytes (LMOTS algo) + 4 bytes (LMS algo) + 16 bytes (key_id) */
#define LMS_LEAF_INDEX_OFFSET  28

/* Helper function declarations */
extern uint16_t
base64_decode (
  const uint8_t  *src,
  uint32_t       src_len,
  uint8_t        *dst,
  uint32_t       dst_max_len
  );

extern int
str8cmp (
  const char  *s1,
  const char  *s2
  );

extern void
buffer_reverse_byte_order (
  uint8_t  *buffer,
  size_t   length
  );

#endif // LCPT_CRYPTO_IPPC_DEFINES_H
