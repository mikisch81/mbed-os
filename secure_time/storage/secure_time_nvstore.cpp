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
#include "secure_time_storage.h"
#include "secure_time_spe.h"
#include "nvstore.h"
#include "mbed_toolchain.h"
#include "mbed_error.h"

/* NVStore indexes */
#define SECURE_TIME_NVSTORE_IDX_MIN                     (10UL)
#define SECURE_TIME_STORED_PUBKEY_NVSTORE_IDX           (SECURE_TIME_NVSTORE_IDX_MIN)
#define SECURE_TIME_STORED_SCHEMA_NVSTORE_IDX           (SECURE_TIME_NVSTORE_IDX_MIN + 1)
#define SECURE_TIME_STORED_TIME_NVSTORE_IDX             (SECURE_TIME_NVSTORE_IDX_MIN + 2)
#define SECURE_TIME_STORED_BACK_TIME_NVSTORE_IDX        (SECURE_TIME_NVSTORE_IDX_MIN + 3)

MBED_WEAK int32_t secure_time_set_stored_schema(const secure_time_schema_t *schema)
{
    if (NULL == schema) {
        error("schema is NULL!");
    }
    if (!validate_schema(schema)) {
        return SECURE_TIME_ILLEGAL_SCHEMA;
    }
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.set(
        SECURE_TIME_STORED_SCHEMA_NVSTORE_IDX,
        sizeof(*schema),
        schema
        );
    return rc;
}

MBED_WEAK int32_t secure_time_get_stored_schema(secure_time_schema_t *schema)
{
    if (NULL == schema) {
        error("schema is NULL!");
    }
    uint16_t len = 0;
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.get(
        SECURE_TIME_STORED_SCHEMA_NVSTORE_IDX,
        sizeof(*schema),
        schema,
        len
        );
    return rc;
}

MBED_WEAK int32_t secure_time_set_stored_public_key(const void* pubkey, size_t key_size)
{
    if (NULL == pubkey) {
        error("pubkey is NULL!");
    }
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.set(SECURE_TIME_STORED_PUBKEY_NVSTORE_IDX, key_size, pubkey);
    return rc;
}

MBED_WEAK int32_t secure_time_get_stored_public_key(uint8_t *pubkey, size_t size, size_t *actual_size)
{
    if (NULL == pubkey) {
        error("pubkey is NULL!");
    }
    if (NULL == actual_size) {
        error("actual_size is NULL!");
    }
    uint16_t len = 0;
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.get(
        SECURE_TIME_STORED_PUBKEY_NVSTORE_IDX,
        size,
        pubkey,
        len
        );
    *actual_size = (size_t)len;
    return rc;
}

MBED_WEAK int32_t secure_time_get_stored_public_key_size(size_t *actual_size)
{
    if (NULL == actual_size) {
        error("actual_size is NULL!");
    }
    uint16_t len = 0;
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.get_item_size(SECURE_TIME_STORED_PUBKEY_NVSTORE_IDX, len);
    *actual_size = (size_t)len;
    return rc;
}

void secure_time_set_stored_time(uint64_t new_time)
{
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.set(SECURE_TIME_STORED_TIME_NVSTORE_IDX, sizeof(uint64_t), &new_time);
    if (NVSTORE_SUCCESS != rc) {
        error("Failed to set STORED_TIME to NVStore! (rc=%d)", rc);
    }
}

bool secure_time_get_stored_time(uint64_t *stored_time)
{
    if (NULL == stored_time) {
        error("stored_time is NULL!");
    }
    NVStore &nvstore = NVStore::get_instance();
    uint16_t len = 0;
    int rc = nvstore.get(SECURE_TIME_STORED_TIME_NVSTORE_IDX, sizeof(uint64_t), stored_time, len);
    if ((NVSTORE_SUCCESS != rc) && (NVSTORE_NOT_FOUND != rc)) {
        error("Failed to get STORED_TIME from NVStore! (rc=%d)", rc);
    }
    else if ((sizeof(uint64_t) != len) && (NVSTORE_NOT_FOUND != rc)) {
        error("Length of STORED_TIME entry too short! (%uh)", len);
    }
    return (NVSTORE_SUCCESS == rc);
}

void secure_time_set_stored_back_time(uint64_t new_time)
{
    NVStore &nvstore = NVStore::get_instance();
    int rc = nvstore.set(SECURE_TIME_STORED_BACK_TIME_NVSTORE_IDX, sizeof(uint64_t), &new_time);
    if (NVSTORE_SUCCESS != rc) {
        error("Failed to set STORED_BACK_TIME to NVStore! (rc=%d)", rc);
    }
}

bool secure_time_get_stored_back_time(uint64_t *stored_back_time)
{
    if (NULL == stored_back_time) {
        error("stored_back_time is NULL!");
    }
    NVStore &nvstore = NVStore::get_instance();
    uint16_t len = 0;
    int rc = nvstore.get(SECURE_TIME_STORED_BACK_TIME_NVSTORE_IDX, sizeof(uint64_t), stored_back_time, len);
    if ((NVSTORE_SUCCESS != rc) && (NVSTORE_NOT_FOUND != rc)) {
        error("Failed to get STORED_BACK_TIME from NVStore! (rc=%d)", rc);
    }
    else if ((sizeof(uint64_t) != len) && (NVSTORE_NOT_FOUND != rc)) {
        error("Length of STORED_BACK_TIME entry too short! (%uh)", len);
    }
    return (NVSTORE_SUCCESS == rc);
}
