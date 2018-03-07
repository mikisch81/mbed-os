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
#include "secure_time_utils.h"
#include "secure_time_spe.h"
#include "secure_time_storage.h"
#include "secure_time_crypto.h"
#include "mbed_error.h"
#include "platform/mbed_rtc_time.h"
#include <string.h>

#define SECURE_TIME_NONCE_GENERATION_TIME_INVALID       UINT64_MAX

/*
 * Enumeration for the possible directions for setting the time.
 */
typedef enum {
    SECURE_TIME_FORWARD = 1,
    SECURE_TIME_BACKWARDS = 2
} SecureTimeDirection;

/*
 * Structure containing context of the NONCE.
 */
typedef struct nonce_ctx {
    uint64_t generation_time;  /* Timestamp of last generated NONCE. */
    uint8_t *nonce;            /* Pointer to nonce buffer. */
    size_t nonce_size;         /* Size in bytes of nonce buffer */
} nonce_data_t;

static nonce_data_t g_trusted_time_nonce = {
    .generation_time = SECURE_TIME_NONCE_GENERATION_TIME_INVALID,
    .nonce = NULL,
    .nonce_size = 0
};

static uint64_t extract_time_from_blob(
    uint8_t *blob,
    size_t blob_len,
    uint32_t offset,
    TimeFormat format
    )
{
    uint64_t time = 0;
    uint64_t time_h = 0;

    switch (format) {
        case TIME_FORMAT_BINARY64:
        {
            time_h = ( ((uint32_t)blob[offset] << 24) |
                       ((uint32_t)blob[offset + 1] << 16) |
                       ((uint32_t)blob[offset + 2] << 8) |
                       ((uint32_t)blob[offset + 3] << 0) );
            offset += 4;
        }
        /* Fall-through - no break */
        case TIME_FORMAT_BINARY32:
        {
            uint32_t time_l = ( ((uint32_t)blob[offset] << 24) |
                                ((uint32_t)blob[offset + 1] << 16) |
                                ((uint32_t)blob[offset + 2] << 8) |
                                ((uint32_t)blob[offset + 3] << 0) );
            time = ((uint64_t)time_h << 32) | time_l;
            break;
        }
        default:
            error("Unsupported time format!");
    }

    return time;
}

static void invalidate_nonce(nonce_data_t *nonce_data)
{
    nonce_data->generation_time = SECURE_TIME_NONCE_GENERATION_TIME_INVALID;
    nonce_data->nonce_size = 0;
    if (NULL != nonce_data->nonce) {
        free(nonce_data->nonce);
        nonce_data->nonce = NULL;
    }
}

static bool is_nonce_valid(nonce_data_t *nonce)
{
    return ( (SECURE_TIME_NONCE_GENERATION_TIME_INVALID != nonce->generation_time) &&
             (nonce->nonce_size > 0) &&
             (NULL != nonce) );
}

static int32_t extract_nonce_and_verify(
    const uint8_t *blob, size_t blob_size,
    const secure_time_schema_t *schema
    )
{
    const uint8_t *blob_nonce = blob + schema->nonce_offset;

    if (!is_nonce_valid(&g_trusted_time_nonce)) {
        return SECURE_TIME_NONCE_MISSING;
    }

    if (0 != memcmp(blob_nonce, g_trusted_time_nonce.nonce, g_trusted_time_nonce.nonce_size)) {
        return SECURE_TIME_NONCE_NOT_MATCH;
    }

    if ((secure_time_get() - g_trusted_time_nonce.generation_time) >= schema->nonce_timeout) {
        // If invalidation timeout expired, invalidate SPE nonce.
        invalidate_nonce(&g_trusted_time_nonce);
        return SECURE_TIME_NONCE_TIMEOUT;
    }

    return SECURE_TIME_SUCCESS;
}

static int32_t validate_blob(const void *blob, size_t blob_size, secure_time_schema_t *schema)
{
    int32_t rc = SECURE_TIME_SUCCESS;
    size_t time_size = 4;
    if (TIME_FORMAT_BINARY64 == schema->time_format) {
        time_size = 8;
    }
    if ( ((schema->time_offset + time_size) > blob_size) ||
         ((schema->nonce_offset + g_trusted_time_nonce.nonce_size) > blob_size) ) {
        rc = SECURE_TIME_INVALID_BLOB_SIZE;
    }
    return rc;;
}

int32_t secure_time_get_nonce(size_t nonce_size, void *nonce)
{
    if (!nonce) {
        error("nonce is NULL!");
    }
    if (nonce_size < SECURE_TIME_MIN_NONCE_SIZE_BYTES) {
        return SECURE_TIME_BAD_PARAMS;
    }

    // Invalidate any existing nonce
    invalidate_nonce(&g_trusted_time_nonce);

    g_trusted_time_nonce.nonce = (uint8_t *)malloc(nonce_size);
    if (NULL == g_trusted_time_nonce.nonce) {
        error("Failed to allocate memory for nonce!");
    }

    secure_time_generate_random_bytes(nonce_size, g_trusted_time_nonce.nonce);
    memcpy(nonce, g_trusted_time_nonce.nonce, nonce_size);
    g_trusted_time_nonce.nonce_size = nonce_size;
    g_trusted_time_nonce.generation_time = secure_time_get();
    return SECURE_TIME_SUCCESS;
}

int32_t secure_time_set_trusted(
    const void *blob,
    size_t blob_size,
    const void *sign,
    size_t sign_size
    )
{
    int rc = SECURE_TIME_SUCCESS;
    if (!blob || (0 == blob_size)) {
        error("blob is NULL or size 0!");
    }
    if (!sign || (0 == sign_size)) {
        error("signature is NULL or size 0!");
    }

    // Read the verification public key and the blob schema from secure storage.
    size_t pubkey_size = 0;
    secure_time_schema_t schema = {SIGNATURE_ALG_INVALID, TIME_FORMAT_INVALID, 0, 0, 0};

    rc = secure_time_get_stored_public_key_size(&pubkey_size);
    if (SECURE_TIME_SUCCESS != rc) {
        error("Failed to read the public key size! (rc=%d)", rc);
    }
    uint8_t *pubkey = (uint8_t *)malloc(pubkey_size);
    if (!pubkey) {
        error("Failed to allocate memory for public key data!");
    }
    rc = secure_time_get_stored_public_key(pubkey, pubkey_size, &pubkey_size);
    if (SECURE_TIME_SUCCESS != rc) {
        error("Failed to read the public key! (rc=%d)", rc);
    }

    rc = secure_time_get_stored_schema(&schema);
    if (SECURE_TIME_SUCCESS != rc) {
        error("Failed to read the schema! (rc=%d)", rc);
    }

    // Validate blob according to schema
    rc = validate_blob(blob, blob_size, &schema);
    if (SECURE_TIME_SUCCESS == rc) {
        // Calculate hash of blob according to the schema signature algorithm and
        // verify the signature of the blob using the public key and calculated hash.
        rc = secure_time_verify_blob_signature(
            blob,
            blob_size,
            sign,
            sign_size,
            pubkey,
            pubkey_size,
            &schema
            );
    }
    if (SECURE_TIME_SUCCESS == rc) {
        // Extract the new time value from the blob according to the schema.
        uint64_t new_time = extract_time_from_blob(
            (uint8_t *)blob,
            blob_size,
            schema.time_offset,
            schema.time_format
            );

        // Extract the nonce from the blob and verify its' correctness and freshness.
        // In case the the nonce is different than the last generated nonce or is too old,
        // the call is ignored.
        rc = extract_nonce_and_verify((const uint8_t *)blob, blob_size, &schema);
        if (SECURE_TIME_SUCCESS == rc) {
            // Get current RTC time.
            uint64_t rtc_time = (uint64_t)time(NULL);

            // Set RTC with new time if it is around 1-2 minutes forward/backward
            // than current RTC time.
            if(llabs(new_time - rtc_time) > SECURE_TIME_MIN_RTC_LATENCY_SEC) {
                set_time(new_time);
            }

            // Read the current stored time from secure storage.
            uint64_t stored_time = 0;
            secure_time_get_stored_time(&stored_time);

            SecureTimeDirection direction = (new_time > stored_time) ?
                                            SECURE_TIME_FORWARD :
                                            SECURE_TIME_BACKWARDS;
            bool set_storage = false;

            // If new time is less than 1 day forward or less than 1-2 minutes backwards
            // do not update secure storage.
            if (SECURE_TIME_FORWARD == direction) {
                set_storage = (new_time - stored_time) > SECURE_TIME_MIN_STORAGE_FORWARD_LATENCY_SEC;
            } else {
                set_storage = (stored_time - new_time) > SECURE_TIME_MIN_STORAGE_BACKWARD_LATENCY_SEC;
            }

            if (set_storage) {
                // Write the new time to secure storage entry of last backwards time.
                secure_time_set_stored_back_time(new_time);

                // Write the new time to secure storage entry of current stored time.
                secure_time_set_stored_time(new_time);
            }

            // Update the SPE delta value as the new time minus current SPE tick count.
            secure_time_update_boot_time(new_time);

            // Invalidate nonce
            invalidate_nonce(&g_trusted_time_nonce);
        }
    }

    return rc;
}

static void set_time_forward(uint64_t new_time, uint64_t curr_os_time)
{
    // Update the SPE delta value as the new time minus current SPE tick count.
    secure_time_update_boot_time(new_time);

    // Set RTC with new time if it is around 1-2 minutes forward than current time.
    uint64_t rtc_time = (uint64_t)time(NULL);
    if((new_time - rtc_time) > SECURE_TIME_MIN_RTC_LATENCY_SEC) {
        set_time(new_time);
    }

    // Write new time to secure storage entry of current stored time if it's more than 1 day forward
    // than current OS time.
    bool set_storage = (new_time - curr_os_time) > SECURE_TIME_MIN_STORAGE_FORWARD_LATENCY_SEC;
    if (set_storage) {
        secure_time_set_stored_time(new_time);
    }
}

static int32_t set_time_backwards(uint64_t new_time, uint64_t curr_os_time)
{
    uint64_t stored_back_time = 0;
    bool stored_back_time_exist = secure_time_get_stored_back_time(&stored_back_time);

    // For each day between stored_back_time and new_time we can move backwards by up to 3 minutes:
    // Which is same as up to 480 seconds for each second in this interval.
    // So: (A) MAX_BACK_SECONDS = (new_time - stored_back_time)/480
    //     (B) (curr_os_time - new_time) <= MAX_BACK_SECONDS
    //     (A & B) (curr_os_time - new_time) <= (new_time - stored_back_time)/480
    bool set_back = ( stored_back_time_exist &&
                      (new_time > stored_back_time) &&
                      ((curr_os_time - new_time) <= (new_time - stored_back_time)/480) );
    if (set_back) {
        // Update the SPE delta value as the new time minus current SPE tick count.
        secure_time_update_boot_time(new_time);

        // Write the new time to secure storage entry of last backwards time and current stored time.
        secure_time_set_stored_back_time(new_time);
        secure_time_set_stored_time(new_time);
        return SECURE_TIME_SUCCESS;
    }
    return SECURE_TIME_NOT_ALLOWED;
}

int32_t secure_time_set(uint64_t new_time)
{
    // Get the current time in the device.
    uint64_t curr_os_time = secure_time_get();
    SecureTimeDirection direction = (new_time > curr_os_time) ?
                                    SECURE_TIME_FORWARD :
                                    SECURE_TIME_BACKWARDS;

    if (SECURE_TIME_FORWARD == direction) {
        set_time_forward(new_time, curr_os_time);
    } else {
        return set_time_backwards(new_time, curr_os_time);
    }

    uint64_t stored_time = 0;
    secure_time_get_stored_time(&stored_time);

    // Write the new time to secure storage entry of current stored time
    // if new time is more than around 5-6 days forward than current stored time.
    if ( (new_time > stored_time) &&
         ((new_time - stored_time) > SECURE_TIME_MIN_STORAGE_IDLE_LATENCY_SEC) ) {
        secure_time_set_stored_time(new_time);
    }
    return SECURE_TIME_SUCCESS;
}

uint64_t secure_time_get(void)
{
    uint64_t boot_time = secure_time_get_boot_time();
    uint64_t secs_since_boot = secure_time_get_seconds_since_boot();
    return (boot_time > 0) ? (boot_time + secs_since_boot) : 0;
}
