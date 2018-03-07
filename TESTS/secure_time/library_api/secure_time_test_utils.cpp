#include "secure_time_test_utils.h"
#include "secure_time/secure_time_spe.h"
#include "unity.h"
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

mbedtls_entropy_context entropy = {0};

void provision_data(
    const secure_time_schema_t *schema,
    const uint8_t *pubkey,
    size_t pubkey_size
    )
{
    TEST_ASSERT_EQUAL_HEX(0, secure_time_set_stored_schema(schema));
    TEST_ASSERT_EQUAL_HEX(0, secure_time_set_stored_public_key(pubkey, pubkey_size));
}

void create_blob(
    uint64_t time,
    uint8_t *nonce,
    size_t nonce_size,
    const secure_time_schema_t *schema,
    uint8_t *blob,
    size_t blob_size
    )
{
    size_t time_size = 4;

    if (TIME_FORMAT_BINARY64 == schema->time_format) {
        time_size = 8;
    }

    TEST_ASSERT((schema->time_offset + time_size) <= blob_size);
    TEST_ASSERT((schema->nonce_offset + nonce_size) <= blob_size);
    if (schema->time_offset > schema->nonce_offset) {
        TEST_ASSERT((schema->time_offset - schema->nonce_offset) >= nonce_size);
    }
    else {
        TEST_ASSERT((schema->nonce_offset - schema->time_offset) >= time_size);
    }

    uint8_t *time_ptr = blob + schema->time_offset;
    for (uint32_t i = time_size; i > 0; i--) {
        *time_ptr++ = (unsigned char)(time >> (8 * (i - 1)));
    }

    uint8_t *nonce_ptr = blob + schema->nonce_offset;
    memcpy(nonce_ptr, nonce, nonce_size);
}

void sign_blob(
    const uint8_t *blob,
    size_t blob_size,
    const uint8_t *privkey,
    size_t privkey_size,
    uint8_t *sign,
    size_t *sign_size
    )
{
    mbedtls_pk_context pk = {0};
    mbedtls_pk_init(&pk);
    TEST_ASSERT_EQUAL_HEX(0, mbedtls_pk_parse_key(&pk, privkey, privkey_size, NULL, 0));

    mbedtls_md_context_t md_ctx = {0};
    unsigned char hash[MBEDTLS_MD_MAX_SIZE] = {0};
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    mbedtls_ctr_drbg_context ctr_drbg = {0};

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    TEST_ASSERT_NOT_NULL(md_info);

    mbedtls_md_init(&md_ctx);
    TEST_ASSERT_EQUAL_HEX(0, mbedtls_md_setup(&md_ctx, md_info, 0));
    TEST_ASSERT_EQUAL_HEX(0, mbedtls_md_starts(&md_ctx));
    TEST_ASSERT_EQUAL_HEX(0, mbedtls_md_update(&md_ctx, blob, blob_size));
    TEST_ASSERT_EQUAL_HEX(0, mbedtls_md_finish(&md_ctx, hash));
    mbedtls_md_free(&md_ctx);

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    TEST_ASSERT_EQUAL_HEX(0, mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0));

    TEST_ASSERT_EQUAL_HEX(0, mbedtls_pk_sign(&pk, md_type, hash, 0, sign, sign_size, mbedtls_ctr_drbg_random, &ctr_drbg));
}
