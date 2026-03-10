/*
 * lcputils.c: misc. LCP helper fns
 *
 * Copyright (c) 2014, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <safe_lib.h>
#include <snprintf_s.h>
#define PRINT   printf
#include "../../include/config.h"
#include "../../include/hash.h"
#include "../../include/uuid.h"
#include "../../include/lcp3.h"
#include "polelt_plugin.h"
#include "lcputils.h"
#include "pollist2.h"
#include "crypto.h"

void ERROR(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void LOG(const char *fmt, ...)
{
    va_list ap;

    if ( verbose ) {
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
}

void DISPLAY(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

size_t strlcpy(char *dst, const char *src, size_t siz)
{
    strcpy_s(dst, siz, src);
    return strnlen_s(dst, siz);
}

void dump_hex(const char *prefix, const void *data, size_t n, uint16_t line_length)
{
    unsigned int i = 0;
    while ( i < n ) {
        if ( i % line_length == 0 && prefix != NULL ) {
            DISPLAY("%s", prefix);
        }
        DISPLAY("%02x ", *(uint8_t *)data++);
        i++;
        if ( i % line_length == 0 ) {
            DISPLAY("\n");
        }
    }
    if ( i % line_length != 0 ) {
        DISPLAY("\n");
    }
}

void parse_comma_sep_ints(char *s, uint16_t ints[], unsigned int *nr_ints)
{
    unsigned int nr = 0;

    while ( true ) {
        char *str = strsep(&s, ",");
        if ( str == NULL || nr == *nr_ints )
            break;
        ints[nr++] = strtoul(str, NULL, 0);
    }
    *nr_ints = nr;
    return;
}

void *read_file(const char *file, size_t *length, bool fail_ok)
{
    LOG("[read_file]\n");
    LOG("read_file: filename=%s\n", file);
    FILE *fp = fopen(file, "rb");
    if ( fp == NULL ) {
        if ( !fail_ok )
            ERROR("Error: failed to open file %s: %s\n", file,
                    strerror(errno));
        return NULL;
    }

    /* find size */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    if (len <= 0) {
        ERROR("Error: failed to get file length or file is empty.\n");
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    void *data = malloc(len);
    if ( data == NULL ) {
        ERROR("Error: failed to allocate %d bytes memory\n", len);
        fclose(fp);
        return NULL;
    }

    if ( fread(data, len, 1, fp) != 1 ) {
        ERROR("Error: reading file %s\n", file);
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    if ( length != NULL )
        *length = len;
    LOG("read file succeed!\n");
    return data;
}

bool write_file(const char *file, const void *data, size_t size, size_t offset)
{
    LOG("[write_file]\n");
    FILE *fp = fopen(file, "wb");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s for writing: %s\n",
                file, strerror(errno));
        return false;
    }
    fseek(fp, offset, SEEK_SET);
    if ( fwrite(data, size, 1, fp) != 1 ) {
        ERROR("Error: writing file %s\n", file);
        fclose(fp);
        return false;
    }
    fclose(fp);
    LOG("write file succeed!\n");
    return true;
}

bool parse_line_hashes(const char *line, tb_hash_t *hash, uint16_t alg)
{
    /* skip any leading whitespace */
    while ( *line != '\0' && isspace(*line) )
        line++;

    /* rest of line is hex of hash */
    unsigned int i = 0;
    while ( *line != '\0' && *line != '\n' ) {
        char *next;
        switch (alg) {
        case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA1:
            hash->sha1[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA256:
            hash->sha256[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        case TPM_ALG_SHA384:
            hash->sha384[i++] = (uint8_t)strtoul(line, &next, 16);
            break;
        default:
            ERROR("Error: unsupported alg: 0x%x\n",alg);
            return false;
        }
        if ( next == line )      /* done */
            break;
        line = next;
        /* spaces at end cause strtoul() to interpret as 0, so skip them */
        while ( *line != '\0' && !isxdigit(*line) )
            line++;
    }

    if ( i != get_hash_size(alg) ) {
        ERROR("Error: incorrect number of chars for hash\n");
        return false;
    }

    return true;
}

bool parse_file(const char *filename, bool (*parse_line)(const char *line))
{
    if ( filename == NULL || parse_line == NULL )
        return false;

    LOG("reading hashes file %s...\n", filename);

    FILE *fp = fopen(filename, "r");
    if ( fp == NULL ) {
        ERROR("Error: failed to open file %s (%s)\n", filename, strerror(errno));
        return false;
    }

    static char line[1024];
    while ( true ) {
        char *s = fgets(line, sizeof(line), fp);

        if ( s == NULL ) {
            fclose(fp);
            return true;
        }

        LOG("read line: %s\n", line);

        if ( !(*parse_line)(line) ) {
            fclose(fp);
            return false;
        }
    }

    fclose(fp);
    return false;
}

const char *hash_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_SHA1:
        return "TPM_ALG_SHA1";
    case TPM_ALG_SHA256:
        return "TPM_ALG_SHA256";
    case TPM_ALG_SHA384:
        return "TPM_ALG_SHA384";
    case TPM_ALG_SHA512:
        return "TPM_ALG_SHA512";
    case TPM_ALG_SM3_256:
        return "TPM_ALG_SM3_256";
    case TPM_ALG_SM2:
        return "TPM_ALG_SM2";
    case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
        return "LCP_POLHALG_SHA1";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

const char *key_alg_to_str(uint16_t alg)
{
    switch (alg)
    {
    case TPM_ALG_RSA:
        return "TPM_ALG_RSA";
    case TPM_ALG_ECC:
        return "TPM_ALG_ECC";
    case TPM_ALG_LMS:
        return "TPM_ALG_LMS";
    case TCG_ALG_MLDSA:
        return "TCG_ALG_MLDSA";
    default:
        return "";
    }
}

const char *sig_alg_to_str(uint16_t alg)
{
    static char buf[32];
    switch(alg){
    case TPM_ALG_RSASSA:
        return "TPM_ALG_RSASSA";
    case TPM_ALG_ECDSA:
        return "TPM_ALG_ECDSA";
    case TPM_ALG_SM2:
        return "TPM_ALG_SM2";
    case TPM_ALG_RSAPSS:
        return "TPM_ALG_RSAPSS";
    case TPM_ALG_SM3_256:
        return "TPM_ALG_SM3_256";
    case TPM_ALG_NULL:
        return "TPM_ALG_NULL";
    case LCP_POLSALG_RSA_PKCS_15:
        return "LCP_POLSALG_RSA_PKCS_15";
    case TPM_ALG_LMS:
        return "TPM_ALG_LMS";
    case TCG_ALG_MLDSA:
        return "TCG_ALG_MLDSA";
    default:
        snprintf_s_i(buf, sizeof(buf), "unknown (%u)", alg);
        return buf;
    }
}

uint16_t str_to_hash_alg(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_SM3_256;
    else
        return  TPM_ALG_NULL;
}

uint16_t str_to_lcp_hash_mask(const char *str)
{
    if (strcmp(str,"sha1") == 0)
        return TPM_ALG_MASK_SHA1;
    else if (strcmp(str,"sha256") == 0)
        return TPM_ALG_MASK_SHA256;
    else if (strcmp(str,"sha384") == 0)
        return TPM_ALG_MASK_SHA384;
    else if (strcmp(str,"sha512") == 0)
        return TPM_ALG_MASK_SHA512;
    else if (strcmp(str,"sm3") == 0)
        return TPM_ALG_MASK_SM3_256;
    else if(strncmp(str, "0X", 2) == 0 || strncmp(str, "0x", 2) == 0)
        return strtoul(str, NULL, 0);
    else
        return  TPM_ALG_MASK_NULL;
}

uint16_t str_to_sig_alg(const char *str) {
    if (strcmp(str,"rsa-pkcs15") == 0)
        return LCP_POLSALG_RSA_PKCS_15;
    if( strcmp(str,"rsa-ssa") == 0 || strcmp(str,"rsassa") == 0 || strcmp(str,"rsa") == 0  )
        return TPM_ALG_RSASSA;
    if ( strcmp(str,"ecdsa") == 0)
        return TPM_ALG_ECDSA;
    if ( strcmp(str,"sm2") == 0)
        return TPM_ALG_SM2;
    if( strcmp(str,"rsa-pss") == 0 || strcmp(str,"rsapss") == 0 )
        return TPM_ALG_RSAPSS;
    if (strcmp(str,"lms") == 0)
        return TPM_ALG_LMS;
    if (strcmp(str,"mldsa") == 0)
        return TCG_ALG_MLDSA;
    else {
        LOG("Unrecognized signature alg, assuming TPM_ALG_NULL");
        return TPM_ALG_NULL;
    }
}

uint32_t str_to_sig_alg_mask(const char *str, const uint16_t version, size_t size)
{
    uint16_t lcp_major_ver = version & 0xFF00;
    if( lcp_major_ver == LCP_VER_2_0 ) {
        //signature algorithm mask is undefined in LCPv2
        return SIGN_ALG_MASK_NULL;
    }
    else if( lcp_major_ver == LCP_VER_3_0 ) {
        if (strncmp(str, "rsa-2048-sha1", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_2048_SHA1;
        }
        else if (strncmp(str, "rsa-2048-sha256", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_2048_SHA256;
        }
        else if (strncmp(str, "rsa-3072-sha256", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_3072_SHA256;
        }
        else if (strncmp(str, "rsa-3072-sha384", size) == 0) {
            return SIGN_ALG_MASK_RSASSA_3072_SHA384;
        }
        else if (strncmp(str, "ecdsa-p256", size) == 0) {
            return SIGN_ALG_MASK_ECDSA_P256;
        }
        else if (strncmp(str, "ecdsa-p384", size) == 0) {
            return SIGN_ALG_MASK_ECDSA_P384;
        }
        else if (strncmp(str, "sm2", size) == 0) {
            return SIGN_ALG_MASK_SM2;
        }
        else if (strncmp(str, "lms", size) == 0) {
            return (SIGN_ALG_MASK_LMS_P56B | SIGN_ALG_MASK_LMS_SHA256_M32_H20);
        }
        else if (strncmp(str, "mldsa", size) == 0) {
            return SIGN_ALG_MASK_MLDSA_87;
        }
        else if(strncmp(str, "0X", 2) == 0 || strncmp(str, "0x", 2) == 0){
            return strtoul(str, NULL, 0);
        }
        else{
            //Format unrecognized
            return SIGN_ALG_MASK_NULL;
        }
    }
    else
        return SIGN_ALG_MASK_NULL;
}
uint16_t str_to_pol_ver(const char *str)
{
    if( strcmp(str,"2.0") == 0)
       return LCP_VER_2_0;
    else if ( strcmp(str,"2.1") == 0)
        return LCP_VER_2_1;
    else if ( strcmp(str,"2.2") == 0)
        return LCP_VER_2_2;
    else if ( strcmp(str,"2.3") == 0)
        return LCP_VER_2_3;
    else if ( strcmp(str,"2.4") == 0)
        return LCP_VER_2_4;
    else if ( strcmp(str,"3.0") == 0)
        return LCP_VER_3_0;
    else if ( strcmp(str,"3.1") == 0)
        return LCP_VER_3_1;
    else if ( strcmp(str, "3.2") == 0)
        return LCP_VER_3_2;
    else
        return LCP_VER_NULL;
}

uint16_t convert_hash_alg_to_mask(uint16_t hash_alg)
{
    LOG("convert_hash_alg_to_mask hash_alg = 0x%x\n", hash_alg);
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return TPM_ALG_MASK_SHA1;
    case TPM_ALG_SHA256:
        return TPM_ALG_MASK_SHA256;
    case TPM_ALG_SHA384:
        return TPM_ALG_MASK_SHA384;
    case TPM_ALG_SHA512:
        return TPM_ALG_MASK_SHA512;
    case TPM_ALG_SM3_256:
        return TPM_ALG_MASK_SM3_256;
    default:
        return 0;
    }
    return 0;
}

size_t get_lcp_hash_size(uint16_t hash_alg)
{
    switch(hash_alg){
    case TPM_ALG_SHA1:
        return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256:
        return SHA256_DIGEST_SIZE;
    case TPM_ALG_SHA384:
        return SHA384_DIGEST_SIZE;
    case TPM_ALG_SHA512:
        return SHA512_DIGEST_SIZE;
    case TPM_ALG_SM3_256:
        return SM3_256_DIGEST_SIZE;
    case LCP_POLHALG_SHA1: //Legacy value for TPM 1.2
        return SHA1_DIGEST_SIZE;
    default:
        return 0;
    }
    return 0;
}

bool verify_rsa_signature(sized_buffer *data, sized_buffer *pubkey, sized_buffer *signature,
                          uint16_t hashAlg, uint16_t sig_alg, uint16_t list_ver)
/*
This function: verifies policy list's rsapss and rsassa signatures using pubkey

In: Data - pointer to sized buffer with signed LCP policy list contents:
    LCP_POLICY_LIST2_1 - entire list up to KeyAndSignature field (that includes
    RevoCation counter) i.e. KeyAndSignatureOffset bytes of data from the list.
    LCP_POLICY_LIST and LCP_POLICY_LIST2 - entire list minus the signature field.

    pubkey - pointer to sized buffer containing public key in BE form
    signature - pointer to sized buffer containing signature in BE form

    hashAlg - LCP_SIGNATURE2_1->RsaKeyAndSignature.Signature.HashAlg i.e. hash
              alg defined for the list signature. Or TPM_HASHALG_NULL if hashalg
              is not a member of list structure (it will be read from signature)
    sig_alg - signature algorithm of the list
    list_ver - specify list version: LCP_POLICY_LIS, LCP_POLICY_LIST2 or 
    LCP_POLICY_LIST2_1

Out: true/false on verification success or failure
*/
{
    if(data == NULL){
        return false;
    }
    if(pubkey == NULL){
        return false;
    }
    if(signature == NULL){
        return false;
    }

    crypto_sized_buffer c_data = { .size = data->size, .data = data->data };
    crypto_sized_buffer c_pubkey = { .size = pubkey->size, .data = pubkey->data };
    crypto_sized_buffer c_signature = { .size = signature->size, .data = signature->data };
    return crypto_verify_rsa_signature(&c_data, &c_pubkey, &c_signature, hashAlg, sig_alg, list_ver);
}

bool verify_ec_signature(sized_buffer *data, sized_buffer *pubkey_x, 
                         sized_buffer *pubkey_y, sized_buffer *sig_r,
                         sized_buffer *sig_s, uint16_t sigalg, uint16_t hashalg)
{
     /*
    This function: verifies ecdsa or SM2 signature using pubkey (lists 2.0 and 2.1 only!)

    In: Data - LCP policy list contents:

    LCP_LIST_2_1: entire list up to KeyAndSignature field (that includes 
        RevoCation counter) i.e. hash of KeyAndSignatureOffset bytes of the list.

    LCP_LIST_2: entire list up to the r member of the Signature field that is 
                sizeof list - 2 * keysize

    sized_buffers:
    pubkey_x - public key x coordinate (must be BE) 
    pubkey_y - public key y coordinate (must be BE)
    sig_r and sig_s - buffers containing signature bytes BE

    sigalg - signature algorithm used to sign list (must be ecdsa or sm2)
    hashAlg - hash algorithm used to create digest

    Out: true/false on verification success or failure
*/
    if(data == NULL){
        return false;
    }

    if(pubkey_x == NULL){
        return false;
    }

    if(pubkey_y == NULL){
        return false;
    }

    if(sig_r == NULL){
        return false;
    }

    if(sig_s == NULL){
        return false;
    }

    crypto_sized_buffer c_data = { .size = data->size, .data = data->data };
    crypto_sized_buffer c_pubkey_x = { .size = pubkey_x->size, .data = pubkey_x->data };
    crypto_sized_buffer c_pubkey_y = { .size = pubkey_y->size, .data = pubkey_y->data };
    crypto_sized_buffer c_sig_r = { .size = sig_r->size, .data = sig_r->data };
    crypto_sized_buffer c_sig_s = { .size = sig_s->size, .data = sig_s->data };
    return crypto_verify_ec_signature(&c_data, &c_pubkey_x, &c_pubkey_y,
    &c_sig_r, &c_sig_s, sigalg, hashalg);
}

bool ec_sign_data(sized_buffer *data, sized_buffer *r, sized_buffer *s, uint16_t sigalg,
                                        uint16_t hashalg, const char *privkey_file)
{
    /*
    This function: Performs the signing operation on the policy list data 
    using OpenSSL SM2 and ECDSA functions.

    In: pointer to data to sign, pointers to buffers for r and s parts (must be BE),
    sigalg to use (must be TPM_ALG_SM2/ECDSA), hashalg (must be 
    TPM_ALG_SHA256/SHA384/SM3_256) path to private key.

    Out: True on success, false on failure
    */
    if(data == NULL){
        return false;
    }

    if(r == NULL){
        return false;
    }

    if(s == NULL){
        return false;
    }

    if(privkey_file == NULL){
        return false;
    }

    crypto_sized_buffer c_data = { .size = data->size, .data = data->data };
    crypto_sized_buffer c_r = { .size = r->size, .data = r->data };
    crypto_sized_buffer c_s = { .size = s->size, .data = s->data };
    return crypto_ec_sign_data(&c_data, &c_r, &c_s, sigalg, hashalg, privkey_file);
}

void buffer_reverse_byte_order(uint8_t *buffer, size_t length)
/*Works in place, modifies passed buffer*/
{
    uint8_t temp;
    int left_index = 0;
    int right_index = length - 1;
    while (right_index > left_index) {
        temp = buffer[right_index];
        buffer[right_index] = buffer[left_index];
        buffer[left_index] = temp;
        left_index++;
        right_index--;
    }
}

sized_buffer *allocate_sized_buffer(size_t size) {
    /*
        Allocate size bytes of memory for a buffer and return it
        or NULL on failure.
    */
    sized_buffer *buffer = NULL;
    if (size == 0) {
        ERROR("Error: buffer size must be at least 1.\n");
        return NULL;
    }
    buffer = malloc(size + offsetof(sized_buffer, data));
    if (buffer == NULL) {
        ERROR("Error: failed to allocate buffer.\n");
        return NULL;
    }
    return buffer;
}

char *strip_fname_extension(const char *fname)
/**
 * Strip extension from a filename.
 *
 * @param fname The input filename.
 * @return A new string with the extension removed. Or a copy of original
 *         string if there's no extension. Caller must free the memory.
 *         Returns NULL on error or if input is NULL.
 */
{
    size_t len = 0x00;
    const char *dot = NULL;
    const char *slash = NULL;
    char *result = NULL;
    if (fname == NULL) {
        ERROR("Error: filename is NULL.\n");
        return NULL;
    }
    
    // Find the last occurrence of '.' and '/'
    dot = strrchr(fname, '.');
    slash = strrchr(fname, '/');
    
    // If no dot found or dot is part of directory path, return a copy of original
    if (dot == NULL || (slash != NULL && dot < slash)) {
        result = strdup(fname);
        if (result == NULL) {
            ERROR("Error: failed to allocate memory for filename.\n");
            return NULL;
        }
        return result;
    }
    
    // Calculate size needed for the result string (without extension)
    len = dot - fname;
    
    // Allocate memory for the result
    result = calloc(len + 1, 1); // +1 for null terminator
    if (result == NULL) {
        ERROR("Error: failed to allocate memory for filename.\n");
        return NULL;
    }
    
    // Copy the filename without the extension
    int status = memcpy_s(result, len + 1, fname, len);
    if (status != 0) {
        ERROR("Error: memcpy_s failed while copying filename.\n");
        free(result);
        return NULL;
    }
    
    return result;
}

static const char *lms_type_to_str(uint16_t type)
{
    switch (type) {
        case LMOTS_SHA256_N24_W4:
            return "LMOTS_SHA256_N24_W4";
        case LMOTS_SHA256_N32_W4:
            return "LMOTS_SHA256_N32_W4";
        case LMS_SHA256_M32_H20:
            return "LMS_SHA256_M32_H20";
        case LMS_SHA256_M24_H20:
            return "LMS_SHA256_M24_H20";
        default:
            return "Unknown";
    }
}

void print_xdr_lms_key_info(const lms_xdr_key_data *key) 
{
    if (key == NULL) {
        ERROR("Error: key is NULL.\n");
        return;
    }
    DISPLAY("LMS Public Key is in XDR format, which is Big Endian.\n");
    DISPLAY("LMS Public Key:\n");
    DISPLAY("   LMS Type: 0x%x (%s)\n", ntohl(key->LmsType), lms_type_to_str(ntohl(key->LmsType)));
    DISPLAY("   LMOTS Type: 0x%x (%s)\n", ntohl(key->LmotsType), lms_type_to_str(ntohl(key->LmotsType)));
    DISPLAY("   LMS Key Identifier:\n");
    print_hex("      ", (const void *) &key->I, 16);
    DISPLAY("   LMS tree 1st node string:\n");
    print_hex("      ", (const void *) &key->T1, 32);
        
}
void print_lms_signature(const lms_signature_block *sig) 
{
    if (sig == NULL) {
        ERROR("Error: signature is NULL.\n");
        return;
    }
    DISPLAY("LMS Signature:\n");
    DISPLAY("    LMS leaf number: 0x%x\n", ntohl(sig->Q));
    DISPLAY("    LMOTS Signature:\n");
    DISPLAY("        LMOTS Type: 0x%x (%s)\n", ntohl(sig->Lmots.Type), lms_type_to_str(ntohl(sig->Lmots.Type)));
    DISPLAY("        LMOTS Seed:\n");
    dump_hex("            ", (const void *) &sig->Lmots.Seed, SHA256_192_DIGEST_SIZE, 32);
    DISPLAY("        LMOTS Signature Block:\n");
    dump_hex("            ", (const void *) &sig->Lmots.Y, LMOTS_SIGNATURE_BLOCK_SIZE, 32);
    DISPLAY("    LMS Type: 0x%x (%s)\n", ntohl(sig->LmsType), lms_type_to_str(ntohl(sig->LmsType)));
    DISPLAY("    LMS PATH:\n");
    dump_hex("            ", (const void *) &sig->Path, LMS_SIGNATURE_BLOCK_SIZE, 32);
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
