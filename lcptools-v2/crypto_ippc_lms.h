#ifndef LCPT_CRYPTO_IPPC_LMS_H
#define LCPT_CRYPTO_IPPC_LMS_H

#include "ippc/cryptography-primitives/include/ippcp.h"
#include "crypto.h"

/*
 * Mirror of IPPC internal _cpLMOTSSignatureState.
 * Must match the layout in sources/include/stateful_sig/lms_internal/lmots.h.
 *
 * WARNING: These mirror structs are tied to IPPC 1.4.0 internal layout.
 * Any IPPC library update must re-validate them.  The algorithm fields are
 * checked at runtime after keygen/sign as a sanity guard.
 */

typedef struct {
  IppsLMOTSAlgo    _lmotsOIDAlgo;
  Ipp8u            *pC;
  Ipp8u            *pY;
} lms_ots_sig_mirror;

/*
 * Mirror of IPPC internal _cpLMSSignatureState.
 * Must match the layout in sources/include/stateful_sig/lms_internal/lms.h.
 */
typedef struct {
  Ipp32u                _idCtx;
  Ipp32u                _q;
  lms_ots_sig_mirror    _lmotsSig;
  IppsLMSAlgo           _lmsOIDAlgo;
  Ipp8u                 *_pAuthPath;
} lms_sig_state_mirror;

/*
 * Mirror of IPPC internal _cpLMSPrivateKeyState.
 * Must match the layout in sources/include/stateful_sig/lms_internal/lms.h.
 */
typedef struct {
  Ipp32u           _idCtx;
  IppsLMSAlgo      lmsOIDAlgo;
  IppsLMOTSAlgo    lmotsOIDAlgo;
  Ipp32u           q;
  Ipp32s           extraBufSize;
  Ipp8u            *pSecretSeed;
  Ipp8u            *pI;
  Ipp8u            *pExtraBuf;
} lms_privkey_mirror;

/*
 * Context for providing a deterministic seed/I to ippsLMSKeyGen
 * instead of random generation.
 */
typedef struct {
  const uint8_t    *seed;
  const uint8_t    *identifier;
  int              call_count;
} lms_keygen_rng_ctx;

/*
 * Supported LMS algorithm: LMS_SHA256_M24_H20 + LMOTS_SHA256_N24_W4
 *
 * Parameters:
 *   n = 24  (LMOTS hash output size, SHA256/192)
 *   p = 51  (number of Winternitz hash chains)
 *   h = 20  (Merkle tree height)
 *   m = 24  (LMS tree node hash size, SHA256/192)
 */
#define LMS_SIGN_N  LMOTS_SIGNATURE_N_SIZE     /* 24 */
#define LMS_SIGN_P  LMOTS_SIGNATURE_P_SIZE     /* 51 */
#define LMS_SIGN_H  LMS_SIGNATURE_H_HEIGHT     /* 20 */
#define LMS_SIGN_M  LMS_SIGNATURE_M_SIZE       /* 24 */

/*
 * LMS private key file format for LMS_SHA256_M24_H20 + LMOTS_SHA256_N24_W4:
 *
 * Offset  0: 8 bytes  - sequence counter (leaf index q, big-endian uint64)
 * Offset  8: 16 bytes - compressed parameter sets (2 bytes per HSS level, 0xFF padding)
 * Offset 24: 24 bytes - master secret seed (n = 24 for SHA256/192)
 * Offset 48: 16 bytes - I value (Merkle tree identifier)
 * Total:  64 bytes
 *
 * Expected compressed params: LM type = 0x09 (LMS_SHA256_M24_H20 - 4),
 *                             LMOTS type = 0x07 (LMOTS_SHA256_N24_W4)
 */
#define LMS_PRV_COUNTER_OFFSET    0
#define LMS_PRV_COUNTER_SIZE      8
#define LMS_PRV_PARAMS_OFFSET     8
#define LMS_PRV_SEED_OFFSET       24
#define LMS_PRV_I_SIZE            16
#define LMS_PRV_EXPECTED_SIZE     (LMS_PRV_SEED_OFFSET + LMS_SIGN_N + LMS_PRV_I_SIZE) /* 64 */
#define LMS_PRV_COMPRESSED_LM     0x09                                                /* LMS_SHA256_M24_H20 enum(13) - 4 */
#define LMS_PRV_COMPRESSED_LMOTS  0x07                                                /* LMOTS_SHA256_N24_W4 enum(7) */

/*
 * Total serialized LMS signature size (including HSS NSPK prefix):
 * NSPK (4) + Q (4) + LMOTS_type (4) + C (24) + Y (24*51=1224) + LMS_type (4) + Path (20*24=480)
 * = 1744 bytes
 */
#define LMS_SIGN_TOTAL_SIZE  (sizeof (uint32_t)                         /* NSPK */  \
                              + sizeof (uint32_t)                       /* Q */     \
                              + sizeof (uint32_t)                       /* LMOTS type */ \
                              + LMS_SIGN_N                              /* C */     \
                              + (size_t)LMS_SIGN_N * LMS_SIGN_P         /* Y */     \
                              + sizeof (uint32_t)                       /* LMS type */ \
                              + (size_t)LMS_SIGN_H * LMS_SIGN_M)        /* Path */

#endif /* LCPT_CRYPTO_IPPC_LMS_H */
