/* Copyright (c) 2018 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <secure_time_utils.h>
#include "greentea-client/test_env.h"
#include "unity.h"
#include "utest.h"
#include "secure_time_spe.h"
#include "secure_time_storage.h"
#include "secure_time_test_utils.h"
#include "nvstore.h"

#ifdef ENABLE_LIBGCOV_PORT
#include "libgcov-embedded.h"
#endif

using namespace utest::v1;

#define SECURE_TIME_TEST_SECS_PER_MINUTE    (60)
#define SECURE_TIME_TEST_SECS_PER_HOUR      (60 * SECURE_TIME_TEST_SECS_PER_MINUTE)
#define SECURE_TIME_TEST_SECS_PER_DAY       (24 * SECURE_TIME_TEST_SECS_PER_HOUR)

#define SECURE_TIME_TEST_DEFAULT_TIME       (2555562978ULL)

const uint8_t default_prvkey[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x47, 0x2d, 0x6d, 0x08, 0x7c,
    0xeb, 0x6d, 0x4c, 0xb1, 0xa1, 0x20, 0xb4, 0x80, 0x5f, 0x47, 0x78, 0xd6,
    0xa5, 0x69, 0xf7, 0x34, 0xf2, 0xa2, 0x85, 0xb1, 0x5d, 0xae, 0xfa, 0x53,
    0x57, 0x33, 0x7b, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x7f, 0x4a, 0x31,
    0xc8, 0x30, 0xbf, 0x71, 0x0a, 0x62, 0x91, 0xd9, 0xef, 0x54, 0xfa, 0x66,
    0xe4, 0xab, 0xe9, 0xfa, 0x80, 0x12, 0x42, 0xdc, 0x16, 0x9f, 0x09, 0x37,
    0x4d, 0xc6, 0x8c, 0x06, 0x03, 0x51, 0x9b, 0x1d, 0xd2, 0x36, 0x69, 0xe6,
    0xc8, 0x30, 0x62, 0x44, 0x5d, 0xe5, 0x15, 0xb4, 0x9c, 0x9f, 0x9b, 0x23,
    0x0a, 0x00, 0x1f, 0x8b, 0x4e, 0x8c, 0x8f, 0x5e, 0x80, 0x46, 0x71, 0xdc,
    0xb4
};

static const uint8_t default_pubkey[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0x7f, 0x4a, 0x31, 0xc8, 0x30, 0xbf, 0x71, 0x0a, 0x62,
    0x91, 0xd9, 0xef, 0x54, 0xfa, 0x66, 0xe4, 0xab, 0xe9, 0xfa, 0x80, 0x12,
    0x42, 0xdc, 0x16, 0x9f, 0x09, 0x37, 0x4d, 0xc6, 0x8c, 0x06, 0x03, 0x51,
    0x9b, 0x1d, 0xd2, 0x36, 0x69, 0xe6, 0xc8, 0x30, 0x62, 0x44, 0x5d, 0xe5,
    0x15, 0xb4, 0x9c, 0x9f, 0x9b, 0x23, 0x0a, 0x00, 0x1f, 0x8b, 0x4e, 0x8c,
    0x8f, 0x5e, 0x80, 0x46, 0x71, 0xdc, 0xb4
};

static const secure_time_schema_t default_schema = {
    SIGNATURE_ALG_SHA256_ECDSA,
    TIME_FORMAT_BINARY32,
    0,
    4,
    SECURE_TIME_NONCE_MAX_TIMEOUT_SECONDS
};

uint8_t sign[SECURE_TIME_TESTS_MAX_SIGN_SIZE_BYTES] = {0};
uint8_t sign2[SECURE_TIME_TESTS_MAX_SIGN_SIZE_BYTES] = {0};

static void time_before_nonce(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
}

static void time_after_nonce(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    schema.nonce_offset = 0;
    schema.time_offset = 8;
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
}

static void time_size_64_bit(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    schema.time_format = TIME_FORMAT_BINARY64;
    schema.nonce_offset = 10;
    uint64_t set_time = ((uint64_t)1 << 32) | SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
}

static void non_aligned(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    schema.time_offset = 3;
    schema.nonce_offset = 10;
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
}

static void nonce_offset_overflow(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, 6, default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_INVALID_BLOB_SIZE,
        secure_time_set_trusted(blob, 6, sign, sign_len)
        );
}

static void time_offset_overflow(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    schema.nonce_offset = 0;
    schema.time_offset = 8;
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, 10, default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_INVALID_BLOB_SIZE,
        secure_time_set_trusted(blob, 10, sign, sign_len)
        );
}

static void malformed_signature(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);

    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());

    secure_time_get_nonce(sizeof(nonce), &nonce);
    create_blob(set_time + 1000, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    sign[0] ^= 1; // Flip 1st bit of signature
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SIGNATURE_VERIFICATION_FAILED,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(10, set_time, secure_time_get());
}

void wrong_nonce(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint8_t blob2[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    size_t sign_len2 = 0;
    provision_data(&schema, default_pubkey, sizeof(default_pubkey));

    uint32_t nonce1, nonce2;
    secure_time_get_nonce(sizeof(nonce1), &nonce1);
    create_blob(set_time, (uint8_t *)&nonce1, sizeof(nonce1), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);

    secure_time_get_nonce(sizeof(nonce2), &nonce2);
    create_blob((set_time + 1000), (uint8_t *)&nonce2, sizeof(nonce2), &schema, blob2, sizeof(blob2));
    sign_blob(blob2, sizeof(blob2), default_prvkey, sizeof(default_prvkey), sign2, &sign_len2);

    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_NONCE_NOT_MATCH,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob2, sizeof(blob2), sign2, sign_len2)
        );
}

void wrong_nonce2(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint8_t blob2[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    size_t sign_len2 = 0;
    provision_data(&schema, default_pubkey, sizeof(default_pubkey));

    uint32_t nonce1, nonce2;
    secure_time_get_nonce(sizeof(nonce1), &nonce1);
    create_blob(set_time, (uint8_t *)&nonce1, sizeof(nonce1), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);

    secure_time_get_nonce(sizeof(nonce2), &nonce2);
    create_blob((set_time + 1000), (uint8_t *)&nonce2, sizeof(nonce2), &schema, blob2, sizeof(blob2));
    sign_blob(blob2, sizeof(blob2), default_prvkey, sizeof(default_prvkey), sign2, &sign_len2);

    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_SUCCESS,
        secure_time_set_trusted(blob2, sizeof(blob2), sign2, sign_len2)
        );
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_NONCE_MISSING,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
}

static void replay_blob(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);

    provision_data(&schema, default_pubkey, sizeof(default_pubkey));
    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);

    TEST_ASSERT_EQUAL_HEX(0, secure_time_set_trusted(blob, sizeof(blob), sign, sign_len));
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());

    wait(4);

    // Send the blob again
    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_NONCE_MISSING,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(7, set_time, secure_time_get());
}

void nonce_timeout(void)
{
    secure_time_schema_t schema = default_schema;
    uint8_t blob[16] = {0};
    uint64_t set_time = SECURE_TIME_TEST_DEFAULT_TIME;
    size_t sign_len = 0;
    schema.nonce_timeout = 2;
    provision_data(&schema, default_pubkey, sizeof(default_pubkey));

    uint32_t nonce = 0;
    secure_time_get_nonce(sizeof(nonce), &nonce);
    wait(3);

    create_blob(set_time, (uint8_t *)&nonce, sizeof(nonce), &schema, blob, sizeof(blob));
    sign_blob(blob, sizeof(blob), default_prvkey, sizeof(default_prvkey), sign, &sign_len);
    uint64_t curr_time = secure_time_get();

    TEST_ASSERT_EQUAL_HEX(
        SECURE_TIME_NONCE_TIMEOUT,
        secure_time_set_trusted(blob, sizeof(blob), sign, sign_len)
        );
    TEST_ASSERT_UINT64_WITHIN(3, curr_time, secure_time_get());
}

void normal_set_forward_no_storage_update(void)
{
    uint64_t curr_time = SECURE_TIME_TEST_DEFAULT_TIME;
    uint64_t set_time = curr_time + (SECURE_TIME_MIN_STORAGE_FORWARD_LATENCY_SEC - 100);
    uint64_t stored_time = 0;

    secure_time_update_boot_time(curr_time);
    secure_time_set_stored_time(curr_time);

    secure_time_set(set_time);
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
    TEST_ASSERT_TRUE(secure_time_get_stored_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(curr_time, stored_time);
}

void normal_set_forward_with_storage_update(void)
{
    uint64_t curr_time = SECURE_TIME_TEST_DEFAULT_TIME;
    uint64_t set_time = curr_time + (SECURE_TIME_MIN_STORAGE_FORWARD_LATENCY_SEC + 100);
    uint64_t stored_time = 0;

    secure_time_update_boot_time(curr_time);
    secure_time_set_stored_time(curr_time);

    secure_time_set(set_time);
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
    TEST_ASSERT_TRUE(secure_time_get_stored_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(set_time, stored_time);
}

void normal_set_forward_with_storage_update2(void)
{
    uint64_t curr_time = SECURE_TIME_TEST_DEFAULT_TIME;
    uint64_t set_time = curr_time + (SECURE_TIME_MIN_STORAGE_FORWARD_LATENCY_SEC - 100);
    uint64_t stored_time = 0;

    secure_time_update_boot_time(curr_time);
    secure_time_set_stored_time(curr_time - (SECURE_TIME_MIN_STORAGE_IDLE_LATENCY_SEC + 100));

    secure_time_set(set_time);
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
    TEST_ASSERT_TRUE(secure_time_get_stored_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(set_time, stored_time);
}

void normal_set_backward_no_drift(void)
{
    uint64_t curr_time = SECURE_TIME_TEST_DEFAULT_TIME;
    uint64_t set_time = curr_time - ((30 * SECURE_TIME_TEST_SECS_PER_MINUTE) + 100);
    uint64_t back_time = set_time - (10 * SECURE_TIME_TEST_SECS_PER_DAY);
    uint64_t stored_time = 0;

    secure_time_update_boot_time(curr_time);
    secure_time_set_stored_time(curr_time);
    secure_time_set_stored_back_time(back_time);

    secure_time_set(set_time);
    TEST_ASSERT_UINT64_WITHIN(3, curr_time, secure_time_get());
    TEST_ASSERT_TRUE(secure_time_get_stored_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(curr_time, stored_time);
    TEST_ASSERT_TRUE(secure_time_get_stored_back_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(back_time, stored_time);
}

void normal_set_backward_with_drift(void)
{
    uint64_t curr_time = SECURE_TIME_TEST_DEFAULT_TIME;
    uint64_t set_time = curr_time - ((30 * SECURE_TIME_TEST_SECS_PER_MINUTE) - 100);
    uint64_t back_time = set_time - (10 * SECURE_TIME_TEST_SECS_PER_DAY);
    uint64_t stored_time = 0;

    secure_time_update_boot_time(curr_time);
    secure_time_set_stored_time(curr_time);

    // Can't set backwards if no STORED_BACK entry in storage
    secure_time_set(set_time);
    TEST_ASSERT_UINT64_WITHIN(3, curr_time, secure_time_get());
    TEST_ASSERT_TRUE(secure_time_get_stored_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(curr_time, stored_time);
    TEST_ASSERT_FALSE(secure_time_get_stored_back_time(&stored_time));

    secure_time_set_stored_back_time(back_time);
    TEST_ASSERT_TRUE(secure_time_get_stored_back_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(back_time, stored_time);

    secure_time_set(set_time);
    TEST_ASSERT_UINT64_WITHIN(3, set_time, secure_time_get());
    TEST_ASSERT_TRUE(secure_time_get_stored_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(set_time, stored_time);
    TEST_ASSERT_TRUE(secure_time_get_stored_back_time(&stored_time));
    TEST_ASSERT_EQUAL_UINT64(set_time, stored_time);
}

utest::v1::status_t storage_setup(const Case *const source, const size_t index_of_case)
{
    NVStore &nvstore = NVStore::get_instance();
    TEST_ASSERT_EQUAL(NVSTORE_SUCCESS, nvstore.reset());

    // Call the default handler for proper reporting
    return greentea_case_setup_handler(source, index_of_case);
}

// Test cases
Case cases[] = {
    Case("Set trusted: Time before nonce in blob", time_before_nonce),
    Case("Set trusted: Time after nonce in blob", time_after_nonce),
    Case("Set trusted: 64 bit time in blob", time_size_64_bit),
    Case("Set trusted: Non-aligned data in blob", non_aligned),
    Case("Set trusted: Nonce offset overflow in blob", nonce_offset_overflow),
    Case("Set trusted: Time offset overflow in blob", time_offset_overflow),
    Case("Set trusted: Malformed signature", malformed_signature),
    Case("Set trusted: Wrong nonce #1", wrong_nonce),
    Case("Set trusted: Wrong nonce #2", wrong_nonce2),
    Case("Set trusted: Replay same blob", replay_blob),
    Case("Set trusted: Nonce timeout", nonce_timeout),
    Case("Set normal: Forward time, no storage update", storage_setup, normal_set_forward_no_storage_update),
    Case("Set normal: Forward time, with storage update #1", storage_setup, normal_set_forward_with_storage_update),
    Case("Set normal: Forward time, with storage update #2", storage_setup, normal_set_forward_with_storage_update2),
    Case("Set normal: Backward time, no clock drift", storage_setup, normal_set_backward_no_drift),
    Case("Set normal: Backward time, clock drift", storage_setup, normal_set_backward_with_drift),
};

utest::v1::status_t test_setup(const size_t number_of_cases)
{
   // Setup Greentea using a reasonable timeout in seconds
#ifndef NO_GREENTEA
   GREENTEA_SETUP(20, "default_auto");
#endif
   return verbose_test_setup_handler(number_of_cases);
}

Specification specification(test_setup, cases);

int main()
{
#ifdef ENABLE_LIBGCOV_PORT
    on_exit(collect_coverage, NULL);
    static_init();
#endif
   !Harness::run(specification);
   return 0;
}
