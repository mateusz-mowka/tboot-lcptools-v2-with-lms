/*
 * Google Test unit tests for the crypto module.
 *
 * Tests cover:
 *   - Hashing (SHA-1, SHA-256, SHA-384, SHA-512)
 *   - ML-DSA-87 signing and verification (PEM key files)
 *   - NULL-parameter guard checks on the dispatch layer (crypto.c)
 *
 * Build:  make USE_IPPC=1        (from lcptools-v2/tests/)
 * Run:    make USE_IPPC=1 test
 */

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>
#include <unistd.h>

/* OpenSSL C API for EC key generation helper */
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* The crypto headers are plain C; lcp3.h uses flexible array members
   in nested structs which is invalid C++, so we include only crypto.h
   and define the constants we need directly. */
extern "C" {
#include "crypto.h"
}

/* Digest lengths*/
#define CRYPTO_SHA1_LENGTH    20

/* Constants from lcp3.h that we need for tests */
#define TPM_ALG_SHA1    0x0004
#define TPM_ALG_SHA256  0x000B
#define TPM_ALG_SHA384  0x000C
#define TPM_ALG_SHA512  0x000D

#define MLDSA87_PUBKEY_SIZE     2592
#define MLDSA87_PRIVKEY_SIZE    4896
#define MLDSA87_SIGNATURE_SIZE  4627

/* Signature algorithm constants from lcp3.h */
#define TPM_ALG_RSASSA  0x0014
#define TPM_ALG_RSAPSS  0x0016
#define TPM_ALG_ECDSA   0x0018

/* LCP list version */
#define LCP_TPM20_POLICY_LIST2_1_VERSION_300  0x0300

/* LMS signature size for SHA256_M24_H20 + LMOTS_SHA256_N24_W4:
 * NSPK(4) + Q(4) + LMOTS_type(4) + C(24) + Y(24*51) + LMS_type(4) + Path(20*24)
 * = 1744 bytes */
#define LMS_TOTAL_SIGNATURE_SIZE  1744

/* Globals referenced by liblcp.a (defined in crtpollist.c normally) */
extern "C" {
    bool verbose = false;
}

/* ------------------------------------------------------------------ */
/*  Helper: RAII temp-file name generator (unlinks on destruction)     */
/* ------------------------------------------------------------------ */
class TempFile {
public:
    explicit TempFile(const std::string &suffix) {
        char tmpl[] = "/tmp/crypto_test_XXXXXX";
        int fd = mkstemp(tmpl);
        EXPECT_NE(fd, -1);
        if (fd == -1) {
            // mkstemp failed; leave path_ as the template so destructor cleanup is harmless
            path_ = tmpl;
            return;
        }
        close(fd);
        std::string target = std::string(tmpl) + suffix;
        /* rename the mkstemp file to include the suffix */
        if (rename(tmpl, target.c_str()) == 0) {
            path_ = target;
        } else {
            ADD_FAILURE() << "Failed to rename temporary file '" << tmpl
                          << "' to '" << target << "'";
            // Fall back to using the original mkstemp path so destructor can clean it up
            path_ = tmpl;
        }
    }
    ~TempFile() { std::remove(path_.c_str()); }
    const char *c_str() const { return path_.c_str(); }
private:
    std::string path_;
};

/*
 * Generate an ML-DSA-87 key pair as PEM files using the OpenSSL EVP API.
 * Returns true on success, false if ML-DSA-87 is not supported.
 */
static bool generate_mldsa_pem_keys(const char *pub_path, const char *priv_path) {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    if (!kctx) return false;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    EVP_PKEY_CTX_free(kctx);

    FILE *fp = fopen(priv_path, "wb");
    if (!fp) { EVP_PKEY_free(pkey); return false; }
    if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fclose(fp); EVP_PKEY_free(pkey); return false;
    }
    fclose(fp);

    fp = fopen(pub_path, "wb");
    if (!fp) { EVP_PKEY_free(pkey); return false; }
    if (PEM_write_PUBKEY(fp, pkey) != 1) {
        fclose(fp); EVP_PKEY_free(pkey); return false;
    }
    fclose(fp);

    EVP_PKEY_free(pkey);
    return true;
}

/* ================================================================== */
/*  Hash tests                                                         */
/* ================================================================== */

class CryptoHashTest : public ::testing::Test {};

/*
 * SHA-1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d
 * (RFC 3174 test vector)
 */
TEST_F(CryptoHashTest, SHA1_UnknownHashAlg) {
    const unsigned char msg[] = "abc";
    unsigned char digest[CRYPTO_SHA1_LENGTH] = {};

    crypto_status st = crypto_hash_buffer(msg, 3, digest, TPM_ALG_SHA1);
    ASSERT_EQ(st, crypto_unknown_hashalg);
}

/*
 * SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
 *                  b00361a3 96177a9c b410ff61 f20015ad
 */
TEST_F(CryptoHashTest, SHA256_KnownVector) {
    const unsigned char msg[] = "abc";
    unsigned char digest[CRYPTO_SHA256_LENGTH] = {};
    const unsigned char expected[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    crypto_status st = crypto_hash_buffer(msg, 3, digest, TPM_ALG_SHA256);
    ASSERT_EQ(st, crypto_ok);
    EXPECT_EQ(memcmp(digest, expected, CRYPTO_SHA256_LENGTH), 0);
}

/*
 * SHA-384("abc") = cb00753f45a35e8b...  (NIST FIPS 180-4)
 */
TEST_F(CryptoHashTest, SHA384_KnownVector) {
    const unsigned char msg[] = "abc";
    unsigned char digest[CRYPTO_SHA384_LENGTH] = {};
    const unsigned char expected[] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };

    crypto_status st = crypto_hash_buffer(msg, 3, digest, TPM_ALG_SHA384);
    ASSERT_EQ(st, crypto_ok);
    EXPECT_EQ(memcmp(digest, expected, CRYPTO_SHA384_LENGTH), 0);
}

/*
 * SHA-512("abc") = ddaf35a193617aba...  (NIST FIPS 180-4)
 */
TEST_F(CryptoHashTest, SHA512_KnownVector) {
    const unsigned char msg[] = "abc";
    unsigned char digest[CRYPTO_SHA512_LENGTH] = {};
    const unsigned char expected[] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };

    crypto_status st = crypto_hash_buffer(msg, 3, digest, TPM_ALG_SHA512);
    ASSERT_EQ(st, crypto_ok);
    EXPECT_EQ(memcmp(digest, expected, CRYPTO_SHA512_LENGTH), 0);
}

/* Empty message: hashing zero-length data is valid and produces the
   well-known SHA-256 digest of the empty string. */
TEST_F(CryptoHashTest, SHA256_EmptyMessage) {
    unsigned char digest[CRYPTO_SHA256_LENGTH] = {};
    /* SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    static const unsigned char expected[CRYPTO_SHA256_LENGTH] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    crypto_status st = crypto_hash_buffer((const unsigned char *)"", 0,
                                          digest, TPM_ALG_SHA256);
    EXPECT_EQ(st, crypto_ok);
    EXPECT_EQ(memcmp(digest, expected, CRYPTO_SHA256_LENGTH), 0);
}

/* Determinism: hashing the same data twice yields the same digest */
TEST_F(CryptoHashTest, SHA256_Deterministic) {
    const unsigned char msg[] = "The quick brown fox jumps over the lazy dog";
    unsigned char d1[CRYPTO_SHA256_LENGTH] = {};
    unsigned char d2[CRYPTO_SHA256_LENGTH] = {};

    ASSERT_EQ(crypto_hash_buffer(msg, sizeof(msg) - 1, d1, TPM_ALG_SHA256), crypto_ok);
    ASSERT_EQ(crypto_hash_buffer(msg, sizeof(msg) - 1, d2, TPM_ALG_SHA256), crypto_ok);
    EXPECT_EQ(memcmp(d1, d2, CRYPTO_SHA256_LENGTH), 0);
}

/* Different messages produce different digests */
TEST_F(CryptoHashTest, SHA256_DifferentMessages) {
    const unsigned char m1[] = "hello";
    const unsigned char m2[] = "world";
    unsigned char d1[CRYPTO_SHA256_LENGTH] = {};
    unsigned char d2[CRYPTO_SHA256_LENGTH] = {};

    ASSERT_EQ(crypto_hash_buffer(m1, 5, d1, TPM_ALG_SHA256), crypto_ok);
    ASSERT_EQ(crypto_hash_buffer(m2, 5, d2, TPM_ALG_SHA256), crypto_ok);
    EXPECT_NE(memcmp(d1, d2, CRYPTO_SHA256_LENGTH), 0);
}

/* ================================================================== */
/*  NULL-parameter guard tests (crypto.c dispatch layer)               */
/* ================================================================== */

class CryptoNullParamTest : public ::testing::Test {};

TEST_F(CryptoNullParamTest, MldsaReadPubkey_NullFile) {
    unsigned char buf[MLDSA87_PUBKEY_SIZE];
    EXPECT_FALSE(crypto_read_mldsa_pubkey(NULL, buf, sizeof(buf)));
}

TEST_F(CryptoNullParamTest, MldsaReadPubkey_NullBuf) {
    EXPECT_FALSE(crypto_read_mldsa_pubkey("/tmp/dummy.pem", NULL, 1));
}

TEST_F(CryptoNullParamTest, MldsaVerify_NullMsg) {
    unsigned char sig[1] = {0};
    unsigned char pub[1] = {0};
    EXPECT_FALSE(crypto_mldsa_verify_signature(NULL, 1, sig, 1, pub, 1));
}

TEST_F(CryptoNullParamTest, MldsaVerify_NullSig) {
    unsigned char msg[1] = {0};
    unsigned char pub[1] = {0};
    EXPECT_FALSE(crypto_mldsa_verify_signature(msg, 1, NULL, 1, pub, 1));
}

TEST_F(CryptoNullParamTest, MldsaVerify_NullPubkey) {
    unsigned char msg[1] = {0};
    unsigned char sig[1] = {0};
    EXPECT_FALSE(crypto_mldsa_verify_signature(msg, 1, sig, 1, NULL, 1));
}

TEST_F(CryptoNullParamTest, MldsaSign_NullMsg) {
    unsigned char sig[1] = {0};
    size_t len = 1;
    EXPECT_EQ(crypto_mldsa_sign_data(NULL, 1, sig, &len, "/tmp/k.prv"),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, MldsaSign_NullSig) {
    unsigned char msg[1] = {0};
    size_t len = 1;
    EXPECT_EQ(crypto_mldsa_sign_data(msg, 1, NULL, &len, "/tmp/k.prv"),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, MldsaSign_NullSigLen) {
    unsigned char msg[1] = {0};
    unsigned char sig[1] = {0};
    EXPECT_EQ(crypto_mldsa_sign_data(msg, 1, sig, NULL, "/tmp/k.prv"),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, MldsaSign_NullPrivkey) {
    unsigned char msg[1] = {0};
    unsigned char sig[1] = {0};
    size_t len = 1;
    EXPECT_EQ(crypto_mldsa_sign_data(msg, 1, sig, &len, NULL),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, LmsVerify_NullMsg) {
    unsigned char sig[1] = {0};
    unsigned char pub[1] = {0};
    EXPECT_FALSE(crypto_lms_verify_signature(NULL, 1, sig, 1, pub, 1));
}

TEST_F(CryptoNullParamTest, LmsSign_NullMsg) {
    unsigned char sig[1] = {0};
    size_t len = 1;
    EXPECT_EQ(crypto_lms_sign_data(NULL, 1, sig, &len, "/tmp/k.prv", NULL, 0),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, RsaReadPubkey_NullFile) {
    unsigned char *key = NULL;
    size_t ks = 0;
    EXPECT_EQ(crypto_read_rsa_pubkey(NULL, &key, &ks), crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, RsaReadPubkey_NullKeysize) {
    unsigned char *key = NULL;
    EXPECT_EQ(crypto_read_rsa_pubkey("/tmp/dummy", &key, NULL), crypto_nullptr_error);
}

/* Additional NULL-parameter guards for crypto_read_ecdsa_pubkey */
TEST_F(CryptoNullParamTest, EcdsaReadPubkey_NullFile) {
    uint8_t *qx = NULL, *qy = NULL;
    size_t ks = 0;
    EXPECT_EQ(crypto_read_ecdsa_pubkey(NULL, &qx, &qy, &ks), crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, EcdsaReadPubkey_NullQx) {
    uint8_t *qy = NULL;
    size_t ks = 0;
    EXPECT_EQ(crypto_read_ecdsa_pubkey("/tmp/dummy", NULL, &qy, &ks), crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, EcdsaReadPubkey_NullQy) {
    uint8_t *qx = NULL;
    size_t ks = 0;
    EXPECT_EQ(crypto_read_ecdsa_pubkey("/tmp/dummy", &qx, NULL, &ks), crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, EcdsaReadPubkey_NullKeysize) {
    uint8_t *qx = NULL, *qy = NULL;
    EXPECT_EQ(crypto_read_ecdsa_pubkey("/tmp/dummy", &qx, &qy, NULL), crypto_nullptr_error);
}

/* NULL-parameter guards for crypto_rsa_sign */
TEST_F(CryptoNullParamTest, RsaSign_NullSigBlock) {
    unsigned char dbuf[32] = {};
    crypto_sized_buffer digest = {32, dbuf};
    EXPECT_EQ(crypto_rsa_sign(NULL, &digest, TPM_ALG_RSASSA, TPM_ALG_SHA256, "/tmp/k.pem"),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, RsaSign_NullDigest) {
    unsigned char buf[256] = {};
    crypto_sized_buffer sig = {256, buf};
    EXPECT_EQ(crypto_rsa_sign(&sig, NULL, TPM_ALG_RSASSA, TPM_ALG_SHA256, "/tmp/k.pem"),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, RsaSign_NullPrivkeyFile) {
    unsigned char buf[256] = {};
    unsigned char dbuf[32] = {};
    crypto_sized_buffer sig = {256, buf};
    crypto_sized_buffer digest = {32, dbuf};
    EXPECT_EQ(crypto_rsa_sign(&sig, &digest, TPM_ALG_RSASSA, TPM_ALG_SHA256, NULL),
              crypto_nullptr_error);
}

/* NULL-parameter guards for crypto_verify_rsa_signature */
TEST_F(CryptoNullParamTest, RsaVerify_NullData) {
    unsigned char buf[1] = {};
    crypto_sized_buffer pubkey = {1, buf};
    crypto_sized_buffer sig = {1, buf};
    EXPECT_FALSE(crypto_verify_rsa_signature(NULL, &pubkey, &sig,
                                              TPM_ALG_SHA256, TPM_ALG_RSASSA,
                                              LCP_TPM20_POLICY_LIST2_1_VERSION_300));
}

TEST_F(CryptoNullParamTest, RsaVerify_NullPubkey) {
    unsigned char buf[1] = {};
    crypto_sized_buffer data = {1, buf};
    crypto_sized_buffer sig = {1, buf};
    EXPECT_FALSE(crypto_verify_rsa_signature(&data, NULL, &sig,
                                              TPM_ALG_SHA256, TPM_ALG_RSASSA,
                                              LCP_TPM20_POLICY_LIST2_1_VERSION_300));
}

TEST_F(CryptoNullParamTest, RsaVerify_NullSignature) {
    unsigned char buf[1] = {};
    crypto_sized_buffer data = {1, buf};
    crypto_sized_buffer pubkey = {1, buf};
    EXPECT_FALSE(crypto_verify_rsa_signature(&data, &pubkey, NULL,
                                              TPM_ALG_SHA256, TPM_ALG_RSASSA,
                                              LCP_TPM20_POLICY_LIST2_1_VERSION_300));
}

/* NULL-parameter guards for crypto_verify_ec_signature */
TEST_F(CryptoNullParamTest, EcVerify_NullData) {
    unsigned char buf[1] = {};
    crypto_sized_buffer qx = {1, buf}, qy = {1, buf};
    crypto_sized_buffer r = {1, buf}, s = {1, buf};
    EXPECT_FALSE(crypto_verify_ec_signature(NULL, &qx, &qy, &r, &s,
                                             TPM_ALG_ECDSA, TPM_ALG_SHA256));
}

TEST_F(CryptoNullParamTest, EcVerify_NullPubkeyX) {
    unsigned char buf[1] = {};
    crypto_sized_buffer data = {1, buf}, qy = {1, buf};
    crypto_sized_buffer r = {1, buf}, s = {1, buf};
    EXPECT_FALSE(crypto_verify_ec_signature(&data, NULL, &qy, &r, &s,
                                             TPM_ALG_ECDSA, TPM_ALG_SHA256));
}

/* NULL-parameter guards for crypto_ec_sign_data */
TEST_F(CryptoNullParamTest, EcSign_NullData) {
    unsigned char buf[48] = {};
    crypto_sized_buffer r = {48, buf}, s = {48, buf};
    EXPECT_FALSE(crypto_ec_sign_data(NULL, &r, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256,
                                      "/tmp/k.pem"));
}

TEST_F(CryptoNullParamTest, EcSign_NullR) {
    unsigned char msg_data[] = "test";
    unsigned char buf[48] = {};
    crypto_sized_buffer data = {4, msg_data};
    crypto_sized_buffer s = {48, buf};
    EXPECT_FALSE(crypto_ec_sign_data(&data, NULL, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256,
                                      "/tmp/k.pem"));
}

TEST_F(CryptoNullParamTest, EcSign_NullPrivkeyFile) {
    unsigned char msg_data[] = "test";
    unsigned char buf[48] = {};
    crypto_sized_buffer data = {4, msg_data};
    crypto_sized_buffer r = {48, buf}, s = {48, buf};
    EXPECT_FALSE(crypto_ec_sign_data(&data, &r, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256, NULL));
}

/* Additional NULL-parameter guards for LMS */
TEST_F(CryptoNullParamTest, LmsVerify_NullSignature) {
    unsigned char msg[1] = {0};
    unsigned char pub[1] = {0};
    EXPECT_FALSE(crypto_lms_verify_signature(msg, 1, NULL, 1, pub, 1));
}

TEST_F(CryptoNullParamTest, LmsVerify_NullPubkey) {
    unsigned char msg[1] = {0};
    unsigned char sig[1] = {0};
    EXPECT_FALSE(crypto_lms_verify_signature(msg, 1, sig, 1, NULL, 1));
}

TEST_F(CryptoNullParamTest, LmsSign_NullSig) {
    unsigned char msg[1] = {0};
    size_t len = 1;
    EXPECT_EQ(crypto_lms_sign_data(msg, 1, NULL, &len, "/tmp/k.prv", NULL, 0),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, LmsSign_NullSigLen) {
    unsigned char msg[1] = {0};
    unsigned char sig[1] = {0};
    EXPECT_EQ(crypto_lms_sign_data(msg, 1, sig, NULL, "/tmp/k.prv", NULL, 0),
              crypto_nullptr_error);
}

TEST_F(CryptoNullParamTest, LmsSign_NullPrivkey) {
    unsigned char msg[1] = {0};
    unsigned char sig[1] = {0};
    size_t len = 1;
    EXPECT_EQ(crypto_lms_sign_data(msg, 1, sig, &len, NULL, NULL, 0),
              crypto_nullptr_error);
}

/* ================================================================== */
/*  RSA functional tests                                               */
/* ================================================================== */

/*
 * RSA test fixture.
 *
 * crypto_read_rsa_pubkey returns modulus in LE (LCP policy list convention).
 * crypto_verify_rsa_signature expects the modulus in BE.
 * The fixture byte-reverses after reading so modulus_ is BE.
 */
class RsaTest : public ::testing::Test {
protected:
    void SetUp() override {
        prv_file_ = new TempFile(".pem");
        pub_file_ = new TempFile(".pem");

        /* Generate RSA-2048 key pair in traditional PKCS#1 PEM format.
         * OpenSSL 3.x genrsa defaults to PKCS#8, but the crypto module's
         * parse_rsa_private_key_der expects PKCS#1 RSAPrivateKey format. */
        std::string cmd = "openssl genrsa -traditional -out " + std::string(prv_file_->c_str()) +
                          " 2048 2>/dev/null";
        ASSERT_EQ(system(cmd.c_str()), 0) << "openssl genrsa failed";

        cmd = "openssl rsa -in " + std::string(prv_file_->c_str()) +
              " -pubout -out " + std::string(pub_file_->c_str()) + " 2>/dev/null";
        ASSERT_EQ(system(cmd.c_str()), 0) << "openssl rsa -pubout failed";

        /* Read public key modulus (returns LE) */
        unsigned char *key = NULL;
        size_t keysize = 0;
        crypto_status st = crypto_read_rsa_pubkey(pub_file_->c_str(), &key, &keysize);
        ASSERT_EQ(st, crypto_ok) << "crypto_read_rsa_pubkey failed";
        ASSERT_NE(key, nullptr);
        modulus_.assign(key, key + keysize);
        free(key);

        /* Convert LE → BE for verify (which uses BN_bin2bn / ippsSetOctString_BN) */
        std::reverse(modulus_.begin(), modulus_.end());
    }

    void TearDown() override {
        delete prv_file_;
        delete pub_file_;
    }

    TempFile *prv_file_ = nullptr;
    TempFile *pub_file_ = nullptr;
    std::vector<unsigned char> modulus_;
};

/* Read RSA public key from PEM file */
TEST_F(RsaTest, ReadPubkey_ValidPem) {
    unsigned char *key = NULL;
    size_t keysize = 0;
    crypto_status st = crypto_read_rsa_pubkey(pub_file_->c_str(), &key, &keysize);
    ASSERT_EQ(st, crypto_ok);
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(keysize, 256u);  /* RSA-2048 modulus = 2048/8 = 256 bytes */
    free(key);
}

/* Reading nonexistent file fails */
TEST_F(RsaTest, ReadPubkey_NonexistentFile) {
    unsigned char *key = NULL;
    size_t keysize = 0;
    crypto_status st = crypto_read_rsa_pubkey("/tmp/nonexistent_rsa_key_12345.pem",
                                               &key, &keysize);
    EXPECT_NE(st, crypto_ok);
}

/* RSA PKCS#1 v1.5 sign -> verify round-trip */
TEST_F(RsaTest, SignVerify_RSASSA) {
    const unsigned char msg[] = "Test message for RSA PKCS#1 v1.5 signing";

    /* crypto_rsa_sign hashes internally — pass raw message */
    std::vector<unsigned char> sig_buf(modulus_.size());
    crypto_sized_buffer sig = {sig_buf.size(), sig_buf.data()};
    crypto_sized_buffer data = {sizeof(msg) - 1, const_cast<unsigned char *>(msg)};

    ASSERT_EQ(crypto_rsa_sign(&sig, &data, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                               prv_file_->c_str()), crypto_ok);

    /* Verify (also hashes internally) */
    crypto_sized_buffer pubkey = {modulus_.size(), modulus_.data()};
    crypto_sized_buffer signature = {sig_buf.size(), sig_buf.data()};

    EXPECT_TRUE(crypto_verify_rsa_signature(&data, &pubkey, &signature,
                                             TPM_ALG_SHA256, TPM_ALG_RSASSA,
                                             LCP_TPM20_POLICY_LIST2_1_VERSION_300));
}

/* RSA-PSS sign -> verify round-trip */
TEST_F(RsaTest, SignVerify_RSAPSS) {
    const unsigned char msg[] = "Test message for RSA-PSS signing";

    /* crypto_rsa_sign hashes internally — pass raw message */
    std::vector<unsigned char> sig_buf(modulus_.size());
    crypto_sized_buffer sig = {sig_buf.size(), sig_buf.data()};
    crypto_sized_buffer data = {sizeof(msg) - 1, const_cast<unsigned char *>(msg)};

    ASSERT_EQ(crypto_rsa_sign(&sig, &data, TPM_ALG_RSAPSS, TPM_ALG_SHA256,
                               prv_file_->c_str()), crypto_ok);

    crypto_sized_buffer pubkey = {modulus_.size(), modulus_.data()};
    crypto_sized_buffer signature = {sig_buf.size(), sig_buf.data()};

    EXPECT_TRUE(crypto_verify_rsa_signature(&data, &pubkey, &signature,
                                             TPM_ALG_SHA256, TPM_ALG_RSAPSS,
                                             LCP_TPM20_POLICY_LIST2_1_VERSION_300));
}

/* Verification fails with tampered message */
TEST_F(RsaTest, Verify_TamperedMessage) {
    const unsigned char msg[] = "Original RSA message";

    std::vector<unsigned char> sig_buf(modulus_.size());
    crypto_sized_buffer sig = {sig_buf.size(), sig_buf.data()};
    crypto_sized_buffer data = {sizeof(msg) - 1, const_cast<unsigned char *>(msg)};

    ASSERT_EQ(crypto_rsa_sign(&sig, &data, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                               prv_file_->c_str()), crypto_ok);

    unsigned char bad_msg[] = "Original RSA Xessage";
    crypto_sized_buffer bad_data = {sizeof(bad_msg) - 1, bad_msg};
    crypto_sized_buffer pubkey = {modulus_.size(), modulus_.data()};
    crypto_sized_buffer signature = {sig_buf.size(), sig_buf.data()};

    EXPECT_FALSE(crypto_verify_rsa_signature(&bad_data, &pubkey, &signature,
                                              TPM_ALG_SHA256, TPM_ALG_RSASSA,
                                              LCP_TPM20_POLICY_LIST2_1_VERSION_300));
}

/* Verification fails with wrong key */
TEST_F(RsaTest, Verify_WrongKey) {
    const unsigned char msg[] = "Wrong RSA key test";

    std::vector<unsigned char> sig_buf(modulus_.size());
    crypto_sized_buffer sig = {sig_buf.size(), sig_buf.data()};
    crypto_sized_buffer data = {sizeof(msg) - 1, const_cast<unsigned char *>(msg)};

    ASSERT_EQ(crypto_rsa_sign(&sig, &data, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                               prv_file_->c_str()), crypto_ok);

    /* Generate a different RSA key pair */
    TempFile prv2(".pem"), pub2(".pem");
    std::string cmd = "openssl genrsa -traditional -out " + std::string(prv2.c_str()) + " 2048 2>/dev/null";
    ASSERT_EQ(system(cmd.c_str()), 0);
    cmd = "openssl rsa -in " + std::string(prv2.c_str()) +
          " -pubout -out " + std::string(pub2.c_str()) + " 2>/dev/null";
    ASSERT_EQ(system(cmd.c_str()), 0);

    unsigned char *key2 = NULL;
    size_t ks2 = 0;
    ASSERT_EQ(crypto_read_rsa_pubkey(pub2.c_str(), &key2, &ks2), crypto_ok);

    /* Convert LE → BE for verify */
    std::reverse(key2, key2 + ks2);

    crypto_sized_buffer wrong_pubkey = {ks2, key2};
    crypto_sized_buffer signature = {sig_buf.size(), sig_buf.data()};

    EXPECT_FALSE(crypto_verify_rsa_signature(&data, &wrong_pubkey, &signature,
                                              TPM_ALG_SHA256, TPM_ALG_RSASSA,
                                              LCP_TPM20_POLICY_LIST2_1_VERSION_300));
    free(key2);
}

/* Signing with nonexistent private key file fails */
TEST_F(RsaTest, Sign_NonexistentKey) {
    unsigned char hash[CRYPTO_SHA256_LENGTH] = {};
    std::vector<unsigned char> sig_buf(256);
    crypto_sized_buffer sig = {sig_buf.size(), sig_buf.data()};
    crypto_sized_buffer digest = {CRYPTO_SHA256_LENGTH, hash};

    EXPECT_NE(crypto_rsa_sign(&sig, &digest, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                               "/tmp/nonexistent_rsa_prv_12345.pem"), crypto_ok);
}

/* ================================================================== */
/*  ECC functional tests                                               */
/* ================================================================== */

#ifdef USE_IPPC
/*
 * Helper: generate P-256 EC key pair as raw binary files.
 * Private key: 32 bytes (little-endian, TPM convention)
 * Public key:  64 bytes (qx_le || qy_le)
 *
 * The IPPC crypto module reads ECC keys in raw binary format.
 * Binary keys are byte-reversed upon reading to convert
 * from little-endian (TPM) to big-endian (IPPC BigNum).
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static bool generate_ec_p256_binary_keys(const char *priv_path, const char *pub_path) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key || !EC_KEY_generate_key(ec_key)) {
        if (ec_key) EC_KEY_free(ec_key);
        return false;
    }

    const BIGNUM *priv_bn = EC_KEY_get0_private_key(ec_key);
    const EC_POINT *pub_pt = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);

    BIGNUM *x = BN_new(), *y = BN_new();
    bool ok = false;

    if (x && y && EC_POINT_get_affine_coordinates_GFp(group, pub_pt, x, y, NULL)) {
        unsigned char priv_be[32], qx_be[32], qy_be[32];
        BN_bn2binpad(priv_bn, priv_be, 32);
        BN_bn2binpad(x, qx_be, 32);
        BN_bn2binpad(y, qy_be, 32);

        /* Reverse to little-endian (TPM convention for binary key files) */
        unsigned char priv_le[32], pub_le[64];
        for (int i = 0; i < 32; i++) {
            priv_le[i] = priv_be[31 - i];
            pub_le[i] = qx_be[31 - i];
            pub_le[32 + i] = qy_be[31 - i];
        }

        FILE *fp = fopen(priv_path, "wb");
        if (fp) {
            fwrite(priv_le, 1, 32, fp);
            fclose(fp);
            fp = fopen(pub_path, "wb");
            if (fp) {
                fwrite(pub_le, 1, 64, fp);
                fclose(fp);
                ok = true;
            }
        }
    }

    if (x) BN_free(x);
    if (y) BN_free(y);
    EC_KEY_free(ec_key);
    return ok;
}
#pragma GCC diagnostic pop

#else /* OpenSSL backend */
/*
 * Helper: generate P-256 EC key pair as PEM files.
 * The OpenSSL crypto module reads ECC keys in PEM format.
 */
static bool generate_ec_p256_pem_keys(const char *priv_path, const char *pub_path) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "openssl ecparam -genkey -name prime256v1 -noout -out %s 2>/dev/null && "
             "openssl ec -in %s -pubout -out %s 2>/dev/null",
             priv_path, priv_path, pub_path);
    return system(cmd) == 0;
}
#endif /* USE_IPPC */

/*
 * ECC test fixture.
 * IPPC backend:   uses binary key files (little-endian TPM convention).
 * OpenSSL backend: uses PEM key files (P-256).
 *
 * crypto_read_ecdsa_pubkey returns coordinates in LE (TPM convention).
 * crypto_verify_ec_signature expects coordinates in BE.
 * The fixture byte-reverses after reading so qx_/qy_ are BE.
 */
class EccTest : public ::testing::Test {
protected:
    void SetUp() override {
#ifdef USE_IPPC
        prv_file_ = new TempFile(".bin");
        pub_file_ = new TempFile(".bin");
        ASSERT_TRUE(generate_ec_p256_binary_keys(prv_file_->c_str(), pub_file_->c_str()))
            << "Failed to generate EC P-256 binary key pair";
#else
        prv_file_ = new TempFile(".pem");
        pub_file_ = new TempFile(".pem");
        ASSERT_TRUE(generate_ec_p256_pem_keys(prv_file_->c_str(), pub_file_->c_str()))
            << "Failed to generate EC P-256 PEM key pair";
#endif

        /* Read public key coordinates via the crypto module (returns LE) */
        uint8_t *qx = NULL, *qy = NULL;
        size_t key_size = 0;
        crypto_status st = crypto_read_ecdsa_pubkey(pub_file_->c_str(), &qx, &qy, &key_size);
        ASSERT_EQ(st, crypto_ok) << "crypto_read_ecdsa_pubkey failed";
        ASSERT_EQ(key_size, 32u);

        qx_.assign(qx, qx + key_size);
        qy_.assign(qy, qy + key_size);
        free(qx);
        free(qy);

        /* Convert LE → BE for verify (which uses BN_bin2bn / ippsSetOctString_BN) */
        std::reverse(qx_.begin(), qx_.end());
        std::reverse(qy_.begin(), qy_.end());
    }

    void TearDown() override {
        delete prv_file_;
        delete pub_file_;
    }

    TempFile *prv_file_ = nullptr;
    TempFile *pub_file_ = nullptr;
    std::vector<unsigned char> qx_, qy_;
};

/* Read ECC public key from key file */
TEST_F(EccTest, ReadPubkey_Valid) {
    uint8_t *qx = NULL, *qy = NULL;
    size_t key_size = 0;
    crypto_status st = crypto_read_ecdsa_pubkey(pub_file_->c_str(), &qx, &qy, &key_size);
    ASSERT_EQ(st, crypto_ok);
    ASSERT_NE(qx, nullptr);
    ASSERT_NE(qy, nullptr);
    EXPECT_EQ(key_size, 32u);  /* P-256 coordinate = 32 bytes */
    free(qx);
    free(qy);
}

/* Reading nonexistent file fails */
TEST_F(EccTest, ReadPubkey_NonexistentFile) {
    uint8_t *qx = NULL, *qy = NULL;
    size_t key_size = 0;
    crypto_status st = crypto_read_ecdsa_pubkey("/tmp/nonexistent_ecc_key_12345.bin",
                                                 &qx, &qy, &key_size);
    EXPECT_NE(st, crypto_ok);
}

/* ECDSA P-256 sign -> verify round-trip */
TEST_F(EccTest, SignVerify_ECDSA) {
    unsigned char msg[] = "Test message for ECDSA P-256 signing";
    crypto_sized_buffer data = {sizeof(msg) - 1, msg};

    unsigned char r_buf[32] = {}, s_buf[32] = {};
    crypto_sized_buffer r = {32, r_buf}, s = {32, s_buf};

    ASSERT_TRUE(crypto_ec_sign_data(&data, &r, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256,
                                     prv_file_->c_str()))
        << "crypto_ec_sign_data failed";

    crypto_sized_buffer qx = {qx_.size(), qx_.data()};
    crypto_sized_buffer qy = {qy_.size(), qy_.data()};

    EXPECT_TRUE(crypto_verify_ec_signature(&data, &qx, &qy, &r, &s,
                                            TPM_ALG_ECDSA, TPM_ALG_SHA256));
}

/* Verification fails with tampered message */
TEST_F(EccTest, Verify_TamperedMessage) {
    unsigned char msg[] = "Original ECC message";
    crypto_sized_buffer data = {sizeof(msg) - 1, msg};

    unsigned char r_buf[32] = {}, s_buf[32] = {};
    crypto_sized_buffer r = {32, r_buf}, s = {32, s_buf};

    ASSERT_TRUE(crypto_ec_sign_data(&data, &r, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256,
                                     prv_file_->c_str()));

    unsigned char bad_msg[] = "Original ECC Xessage";
    crypto_sized_buffer bad_data = {sizeof(bad_msg) - 1, bad_msg};
    crypto_sized_buffer qx = {qx_.size(), qx_.data()};
    crypto_sized_buffer qy = {qy_.size(), qy_.data()};

    EXPECT_FALSE(crypto_verify_ec_signature(&bad_data, &qx, &qy, &r, &s,
                                             TPM_ALG_ECDSA, TPM_ALG_SHA256));
}

/* Verification fails with wrong key */
TEST_F(EccTest, Verify_WrongKey) {
    unsigned char msg[] = "Wrong ECC key test";
    crypto_sized_buffer data = {sizeof(msg) - 1, msg};

    unsigned char r_buf[32] = {}, s_buf[32] = {};
    crypto_sized_buffer r = {32, r_buf}, s = {32, s_buf};

    ASSERT_TRUE(crypto_ec_sign_data(&data, &r, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256,
                                     prv_file_->c_str()));

    /* Generate a different key pair */
#ifdef USE_IPPC
    TempFile prv2(".bin"), pub2(".bin");
    ASSERT_TRUE(generate_ec_p256_binary_keys(prv2.c_str(), pub2.c_str()));
#else
    TempFile prv2(".pem"), pub2(".pem");
    ASSERT_TRUE(generate_ec_p256_pem_keys(prv2.c_str(), pub2.c_str()));
#endif

    uint8_t *qx2 = NULL, *qy2 = NULL;
    size_t ks2 = 0;
    ASSERT_EQ(crypto_read_ecdsa_pubkey(pub2.c_str(), &qx2, &qy2, &ks2), crypto_ok);

    /* Convert LE → BE for verify */
    std::reverse(qx2, qx2 + ks2);
    std::reverse(qy2, qy2 + ks2);

    crypto_sized_buffer wrong_qx = {ks2, qx2};
    crypto_sized_buffer wrong_qy = {ks2, qy2};

    EXPECT_FALSE(crypto_verify_ec_signature(&data, &wrong_qx, &wrong_qy, &r, &s,
                                             TPM_ALG_ECDSA, TPM_ALG_SHA256));
    free(qx2);
    free(qy2);
}

/* Signing with nonexistent key file fails */
TEST_F(EccTest, Sign_NonexistentKey) {
    unsigned char msg_data[] = "test";
    crypto_sized_buffer data = {4, msg_data};
    unsigned char r_buf[32] = {}, s_buf[32] = {};
    crypto_sized_buffer r = {32, r_buf}, s = {32, s_buf};

    EXPECT_FALSE(crypto_ec_sign_data(&data, &r, &s, TPM_ALG_ECDSA, TPM_ALG_SHA256,
                                      "/tmp/nonexistent_ecc_prv_12345.bin"));
}

/* ================================================================== */
/*  ML-DSA-87 functional tests                                         */
/* ================================================================== */

class MldsaTest : public ::testing::Test {
protected:
    void SetUp() override {
        pub_file_ = new TempFile(".pem");
        prv_file_ = new TempFile(".pem");
        ASSERT_TRUE(generate_mldsa_pem_keys(pub_file_->c_str(), prv_file_->c_str()))
            << "ML-DSA-87 PEM key generation failed (OpenSSL may lack ML-DSA support)";
        /* Load the raw public key via the crypto abstraction layer */
        pubkey_.resize(MLDSA87_PUBKEY_SIZE);
        ASSERT_TRUE(crypto_read_mldsa_pubkey(pub_file_->c_str(),
                    pubkey_.data(), pubkey_.size()))
            << "Failed to read ML-DSA-87 public key from PEM";
    }

    void TearDown() override {
        delete pub_file_;
        delete prv_file_;
    }

    TempFile *pub_file_ = nullptr;
    TempFile *prv_file_ = nullptr;
    std::vector<unsigned char> pubkey_;
};

/* Sign → Verify round-trip */
TEST_F(MldsaTest, SignVerify_RoundTrip) {
    const unsigned char msg[] = "Test message for ML-DSA-87 sign/verify";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    crypto_status st = crypto_mldsa_sign_data(
        msg, sizeof(msg) - 1,
        sig.data(), &sig_len,
        prv_file_->c_str());
    ASSERT_EQ(st, crypto_ok);
    EXPECT_EQ(sig_len, (size_t)MLDSA87_SIGNATURE_SIZE);

    bool valid = crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size());
    EXPECT_TRUE(valid);
}

/* Signing a different message produces a different signature */
TEST_F(MldsaTest, Sign_DifferentMessages) {
    const unsigned char m1[] = "message one";
    const unsigned char m2[] = "message two";
    std::vector<unsigned char> s1(MLDSA87_SIGNATURE_SIZE);
    std::vector<unsigned char> s2(MLDSA87_SIGNATURE_SIZE);
    size_t len1 = s1.size(), len2 = s2.size();

    ASSERT_EQ(crypto_mldsa_sign_data(m1, sizeof(m1) - 1, s1.data(), &len1,
                                     prv_file_->c_str()), crypto_ok);
    ASSERT_EQ(crypto_mldsa_sign_data(m2, sizeof(m2) - 1, s2.data(), &len2,
                                     prv_file_->c_str()), crypto_ok);

    EXPECT_NE(memcmp(s1.data(), s2.data(), MLDSA87_SIGNATURE_SIZE), 0);
}

/* Verification fails if the message is tampered */
TEST_F(MldsaTest, Verify_TamperedMessage) {
    const unsigned char msg[] = "Original message";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, sizeof(msg) - 1, sig.data(),
                                     &sig_len, prv_file_->c_str()), crypto_ok);

    unsigned char bad_msg[] = "Original Xessage";  /* one byte changed */
    bool valid = crypto_mldsa_verify_signature(
        bad_msg, sizeof(bad_msg) - 1,
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size());
    EXPECT_FALSE(valid);
}

/* Verification fails if the signature is tampered */
TEST_F(MldsaTest, Verify_TamperedSignature) {
    const unsigned char msg[] = "Integrity check";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, sizeof(msg) - 1, sig.data(),
                                     &sig_len, prv_file_->c_str()), crypto_ok);

    /* Flip a byte in the middle of the signature */
    sig[sig_len / 2] ^= 0xFF;

    bool valid = crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size());
    EXPECT_FALSE(valid);
}

/* Verification fails with wrong public key */
TEST_F(MldsaTest, Verify_WrongKey) {
    const unsigned char msg[] = "Wrong key test";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, sizeof(msg) - 1, sig.data(),
                                     &sig_len, prv_file_->c_str()), crypto_ok);

    /* Generate a different key pair */
    TempFile pub2(".pem"), prv2(".pem");
    ASSERT_TRUE(generate_mldsa_pem_keys(pub2.c_str(), prv2.c_str()));

    std::vector<unsigned char> wrong_pub(MLDSA87_PUBKEY_SIZE);
    ASSERT_TRUE(crypto_read_mldsa_pubkey(pub2.c_str(),
                wrong_pub.data(), wrong_pub.size()));

    bool valid = crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        wrong_pub.data(), wrong_pub.size());
    EXPECT_FALSE(valid);
}

/* Signing with nonexistent private key file returns error */
TEST_F(MldsaTest, Sign_NonexistentKey) {
    const unsigned char msg[] = "test";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    crypto_status st = crypto_mldsa_sign_data(
        msg, sizeof(msg) - 1,
        sig.data(), &sig_len,
        "/tmp/nonexistent_key_file_12345.prv");
    EXPECT_NE(st, crypto_ok);
}

/* Buffer too small for signature */
TEST_F(MldsaTest, Sign_BufferTooSmall) {
    const unsigned char msg[] = "test";
    std::vector<unsigned char> sig(100);  /* way too small */
    size_t sig_len = sig.size();

    crypto_status st = crypto_mldsa_sign_data(
        msg, sizeof(msg) - 1,
        sig.data(), &sig_len,
        prv_file_->c_str());
    EXPECT_NE(st, crypto_ok);
}

/* Sign and verify a large message */
TEST_F(MldsaTest, SignVerify_LargeMessage) {
    std::vector<unsigned char> msg(64 * 1024);
    /* Fill with a pattern */
    for (size_t i = 0; i < msg.size(); i++)
        msg[i] = (unsigned char)(i & 0xFF);

    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg.data(), msg.size(),
                                     sig.data(), &sig_len,
                                     prv_file_->c_str()), crypto_ok);

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg.data(), msg.size(),
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size()));
}

/* Sign and verify a 1-byte message */
TEST_F(MldsaTest, SignVerify_MinimalMessage) {
    const unsigned char msg[] = {0x42};
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, 1, sig.data(), &sig_len,
                                     prv_file_->c_str()), crypto_ok);

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg, 1,
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size()));
}

/* ================================================================== */
/*  ML-DSA-87: raw binary and DER key format tests                     */
/* ================================================================== */

/*
 * Helper: extract raw private key bytes from a PEM file.
 * Uses EVP_PKEY_get_raw_private_key() (OpenSSL 3.5+).
 * Returns empty vector on failure.
 */
static std::vector<unsigned char> extract_raw_privkey(const char *pem_path) {
    std::vector<unsigned char> raw;
    FILE *fp = fopen(pem_path, "rb");
    if (!fp) return raw;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return raw;

    size_t len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &len) != 1 || len == 0) {
        EVP_PKEY_free(pkey);
        return raw;
    }
    raw.resize(len);
    if (EVP_PKEY_get_raw_private_key(pkey, raw.data(), &len) != 1) {
        raw.clear();
    }
    EVP_PKEY_free(pkey);
    return raw;
}

/*
 * Helper: write a DER-encoded public key file from a PEM public key file.
 * Returns true on success.
 */
static bool write_der_pubkey(const char *pem_path, const char *der_path) {
    FILE *fp = fopen(pem_path, "rb");
    if (!fp) return false;
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return false;

    fp = fopen(der_path, "wb");
    if (!fp) { EVP_PKEY_free(pkey); return false; }
    int rc = i2d_PUBKEY_fp(fp, pkey);
    fclose(fp);
    EVP_PKEY_free(pkey);
    return rc == 1;
}

/*
 * Helper: write a DER-encoded private key file (PKCS#8) from PEM.
 * Returns true on success.
 */
static bool write_der_privkey(const char *pem_path, const char *der_path) {
    FILE *fp = fopen(pem_path, "rb");
    if (!fp) return false;
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) return false;

    fp = fopen(der_path, "wb");
    if (!fp) { EVP_PKEY_free(pkey); return false; }
    int rc = i2d_PKCS8PrivateKey_fp(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    EVP_PKEY_free(pkey);
    return rc == 1;
}

/*
 * Helper: write raw bytes to a file.
 * Returns true on success.
 */
static bool write_binary_file(const char *path,
                              const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return false;
    bool ok = fwrite(data, 1, len, fp) == len;
    fclose(fp);
    return ok;
}

/* Read a raw binary public key and confirm it matches PEM-loaded key */
TEST_F(MldsaTest, ReadPubkey_RawBinary) {
    TempFile raw_pub(".bin");
    ASSERT_TRUE(write_binary_file(raw_pub.c_str(),
                                  pubkey_.data(), pubkey_.size()));

    std::vector<unsigned char> loaded(MLDSA87_PUBKEY_SIZE);
    ASSERT_TRUE(crypto_read_mldsa_pubkey(raw_pub.c_str(),
                loaded.data(), loaded.size()));

    EXPECT_EQ(memcmp(pubkey_.data(), loaded.data(), MLDSA87_PUBKEY_SIZE), 0)
        << "Raw binary pubkey does not match PEM-loaded pubkey";
}

/* Sign with raw binary private key, verify with PEM-loaded public key */
TEST_F(MldsaTest, SignVerify_RawBinaryPrivkey) {
    /* Extract raw private key from PEM */
    std::vector<unsigned char> raw_priv = extract_raw_privkey(prv_file_->c_str());
    ASSERT_EQ(raw_priv.size(), (size_t)MLDSA87_PRIVKEY_SIZE)
        << "Failed to extract raw ML-DSA-87 private key";

    TempFile raw_prv(".bin");
    ASSERT_TRUE(write_binary_file(raw_prv.c_str(),
                                  raw_priv.data(), raw_priv.size()));

    const unsigned char msg[] = "Raw binary privkey sign test";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    crypto_status st = crypto_mldsa_sign_data(
        msg, sizeof(msg) - 1,
        sig.data(), &sig_len,
        raw_prv.c_str());
    ASSERT_EQ(st, crypto_ok) << "Signing with raw binary private key failed";
    EXPECT_EQ(sig_len, (size_t)MLDSA87_SIGNATURE_SIZE);

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size()))
        << "Verification failed for signature from raw binary key";
}

/* Full round-trip with raw binary keys: sign with raw privkey, verify with raw pubkey */
TEST_F(MldsaTest, SignVerify_RawBinaryRoundTrip) {
    /* Extract raw private key */
    std::vector<unsigned char> raw_priv = extract_raw_privkey(prv_file_->c_str());
    ASSERT_EQ(raw_priv.size(), (size_t)MLDSA87_PRIVKEY_SIZE);

    TempFile raw_prv(".bin");
    ASSERT_TRUE(write_binary_file(raw_prv.c_str(),
                                  raw_priv.data(), raw_priv.size()));

    /* Write raw binary public key */
    TempFile raw_pub(".bin");
    ASSERT_TRUE(write_binary_file(raw_pub.c_str(),
                                  pubkey_.data(), pubkey_.size()));

    /* Load pubkey from raw binary file */
    std::vector<unsigned char> pub_loaded(MLDSA87_PUBKEY_SIZE);
    ASSERT_TRUE(crypto_read_mldsa_pubkey(raw_pub.c_str(),
                pub_loaded.data(), pub_loaded.size()));

    /* Sign and verify */
    const unsigned char msg[] = "Raw binary round-trip test";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, sizeof(msg) - 1,
                                     sig.data(), &sig_len,
                                     raw_prv.c_str()), crypto_ok);

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pub_loaded.data(), pub_loaded.size()));
}

/* Read a DER-encoded public key */
TEST_F(MldsaTest, ReadPubkey_DER) {
    TempFile der_pub(".der");
    ASSERT_TRUE(write_der_pubkey(pub_file_->c_str(), der_pub.c_str()));

    std::vector<unsigned char> loaded(MLDSA87_PUBKEY_SIZE);
    ASSERT_TRUE(crypto_read_mldsa_pubkey(der_pub.c_str(),
                loaded.data(), loaded.size()));

    EXPECT_EQ(memcmp(pubkey_.data(), loaded.data(), MLDSA87_PUBKEY_SIZE), 0)
        << "DER pubkey does not match PEM-loaded pubkey";
}

/* Sign with a DER-encoded private key */
TEST_F(MldsaTest, SignVerify_DERPrivkey) {
    TempFile der_prv(".der");
    ASSERT_TRUE(write_der_privkey(prv_file_->c_str(), der_prv.c_str()));

    const unsigned char msg[] = "DER privkey sign test";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    crypto_status st = crypto_mldsa_sign_data(
        msg, sizeof(msg) - 1,
        sig.data(), &sig_len,
        der_prv.c_str());
    ASSERT_EQ(st, crypto_ok) << "Signing with DER private key failed";

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pubkey_.data(), pubkey_.size()))
        << "Verification failed for signature from DER key";
}

/* Cross-format: sign with DER privkey, verify with raw binary pubkey */
TEST_F(MldsaTest, SignVerify_DERSign_RawVerify) {
    TempFile der_prv(".der");
    ASSERT_TRUE(write_der_privkey(prv_file_->c_str(), der_prv.c_str()));

    TempFile raw_pub(".bin");
    ASSERT_TRUE(write_binary_file(raw_pub.c_str(),
                                  pubkey_.data(), pubkey_.size()));

    std::vector<unsigned char> pub_loaded(MLDSA87_PUBKEY_SIZE);
    ASSERT_TRUE(crypto_read_mldsa_pubkey(raw_pub.c_str(),
                pub_loaded.data(), pub_loaded.size()));

    const unsigned char msg[] = "Cross-format: DER sign, raw verify";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, sizeof(msg) - 1,
                                     sig.data(), &sig_len,
                                     der_prv.c_str()), crypto_ok);

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pub_loaded.data(), pub_loaded.size()));
}

/* Cross-format: sign with raw binary privkey, verify with DER-loaded pubkey */
TEST_F(MldsaTest, SignVerify_RawSign_DERVerify) {
    std::vector<unsigned char> raw_priv = extract_raw_privkey(prv_file_->c_str());
    ASSERT_EQ(raw_priv.size(), (size_t)MLDSA87_PRIVKEY_SIZE);

    TempFile raw_prv(".bin");
    ASSERT_TRUE(write_binary_file(raw_prv.c_str(),
                                  raw_priv.data(), raw_priv.size()));

    TempFile der_pub(".der");
    ASSERT_TRUE(write_der_pubkey(pub_file_->c_str(), der_pub.c_str()));

    std::vector<unsigned char> pub_loaded(MLDSA87_PUBKEY_SIZE);
    ASSERT_TRUE(crypto_read_mldsa_pubkey(der_pub.c_str(),
                pub_loaded.data(), pub_loaded.size()));

    const unsigned char msg[] = "Cross-format: raw sign, DER verify";
    std::vector<unsigned char> sig(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    ASSERT_EQ(crypto_mldsa_sign_data(msg, sizeof(msg) - 1,
                                     sig.data(), &sig_len,
                                     raw_prv.c_str()), crypto_ok);

    EXPECT_TRUE(crypto_mldsa_verify_signature(
        msg, sizeof(msg) - 1,
        sig.data(), sig_len,
        pub_loaded.data(), pub_loaded.size()));
}

/* ================================================================== */
/*  LMS functional tests (IPPC backend)                                */
/*  Note: LMS sign is computationally expensive (~30-60s) due to the   */
/*  H20 Merkle tree reconstruction. All assertions are combined into   */
/*  one test to minimize the number of sign operations.                */
/* ================================================================== */

#ifdef USE_IPPC

/* Helper: read a binary file into a vector */
static std::vector<unsigned char> read_binary_file(const char *path) {
    std::vector<unsigned char> data;
    FILE *fp = fopen(path, "rb");
    if (!fp) return data;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data.resize(sz);
    if (fread(data.data(), 1, sz, fp) != (size_t)sz) data.clear();
    fclose(fp);
    return data;
}

/* Helper: copy a file */
static bool copy_binary_file(const char *src, const char *dst) {
    auto data = read_binary_file(src);
    if (data.empty()) return false;
    FILE *fp = fopen(dst, "wb");
    if (!fp) return false;
    bool ok = fwrite(data.data(), 1, data.size(), fp) == data.size();
    fclose(fp);
    return ok;
}

class LmsTest : public ::testing::Test {
protected:
    void SetUp() override {
        /* Use key files from the tests/ directory (cwd when running tests) */
        prv_bak_ = "lms_m24_h20_w4.prv";
        pub_bak_ = "lms_m24_h20_w4.pub";

        pubkey_ = read_binary_file(pub_bak_);
        auto prv = read_binary_file(prv_bak_);
        has_keys_ = !pubkey_.empty() && !prv.empty();
    }

    const char *prv_bak_;
    const char *pub_bak_;
    std::vector<unsigned char> pubkey_;
    bool has_keys_ = false;
};

/*
 * Combined LMS test: sign a message, verify the signature, then
 * check that verification fails with tampered message and tampered signature.
 * Done in one test to avoid repeated Merkle tree reconstruction.
 */
TEST_F(LmsTest, SignVerify_And_TamperChecks) {
    if (!has_keys_) GTEST_SKIP() << "LMS key files not found (lms_m24_h20_w4.prv / .pub)";

    /* Copy private key to temp file (signing increments the leaf counter) */
    TempFile prv_copy(".prv");
    ASSERT_TRUE(copy_binary_file(prv_bak_, prv_copy.c_str()));

    const unsigned char msg[] = "Test message for LMS sign/verify round-trip";
    std::vector<unsigned char> sig(LMS_TOTAL_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    /* Sign */
    crypto_status st = crypto_lms_sign_data(msg, sizeof(msg) - 1,
                                             sig.data(), &sig_len,
                                             prv_copy.c_str(), NULL, 0);
    ASSERT_EQ(st, crypto_ok) << "LMS sign failed";
    EXPECT_EQ(sig_len, (size_t)LMS_TOTAL_SIGNATURE_SIZE);

    /* Verify valid signature */
    EXPECT_TRUE(crypto_lms_verify_signature(msg, sizeof(msg) - 1,
                                             sig.data(), sig_len,
                                             pubkey_.data(), pubkey_.size()))
        << "LMS round-trip verification failed";

    /* Verify fails with tampered message */
    unsigned char bad_msg[] = "Test message for LMS sign/verify round-Xrip";
    EXPECT_FALSE(crypto_lms_verify_signature(bad_msg, sizeof(bad_msg) - 1,
                                              sig.data(), sig_len,
                                              pubkey_.data(), pubkey_.size()))
        << "LMS should reject tampered message";

    /* Verify fails with tampered signature */
    std::vector<unsigned char> bad_sig(sig);
    bad_sig[sig_len / 2] ^= 0xFF;
    EXPECT_FALSE(crypto_lms_verify_signature(msg, sizeof(msg) - 1,
                                              bad_sig.data(), sig_len,
                                              pubkey_.data(), pubkey_.size()))
        << "LMS should reject tampered signature";
}

/* LMS sign with nonexistent key file fails */
TEST_F(LmsTest, Sign_NonexistentKey) {
    const unsigned char msg[] = "test";
    std::vector<unsigned char> sig(LMS_TOTAL_SIGNATURE_SIZE);
    size_t sig_len = sig.size();

    crypto_status st = crypto_lms_sign_data(msg, sizeof(msg) - 1,
                                             sig.data(), &sig_len,
                                             "/tmp/nonexistent_lms_prv_12345.prv",
                                             NULL, 0);
    EXPECT_NE(st, crypto_ok);
}

#endif /* USE_IPPC */
