#ifndef __SECURE_TIME_TEST_UTILS__
#define __SECURE_TIME_TEST_UTILS__

#include <stdint.h>
#include <stdlib.h>

#define SECURE_TIME_TESTS_MAX_SIGN_SIZE_BYTES     (1024UL)

// forward declaration
typedef struct secure_time_schema secure_time_schema_t;

void provision_data(
    const secure_time_schema_t *schema,
    const uint8_t *pubkey,
    size_t pubkey_size
    );

void create_blob(
    uint64_t time,
    uint8_t *nonce,
    size_t nonce_size,
    const secure_time_schema_t *schema,
    uint8_t *blob,
    size_t blob_size
    );

void sign_blob(
    const uint8_t *blob,
    size_t blob_size,
    const uint8_t *privkey,
    size_t privkey_size,
    uint8_t *sign,
    size_t *sign_size
    );

#endif // __SECURE_TIME_TEST_UTILS__
