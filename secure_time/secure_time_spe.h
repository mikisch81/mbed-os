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
#ifndef __SECURE_TIME_SPE_H__
#define __SECURE_TIME_SPE_H__

#include <stdint.h>
#include <stdlib.h>

#include "secure_time.h"

/** @addtogroup Secure-Time-API
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/**< Maximum time a nonce is valid after generation.*/
#define SECURE_TIME_NONCE_MAX_TIMEOUT_SECONDS           (300UL)

/**< Minimum supported nonce size in bytes.*/
#define SECURE_TIME_MIN_NONCE_SIZE_BYTES                (4UL)

/**< Maximum supported nonce size in bytes.*/
#define SECURE_TIME_MAX_NONCE_SIZE_BYTES                (32UL)

/**
 * Enumeration for the possible blob signature algorithms
 */
typedef enum signature_alg {
    SIGNATURE_ALG_INVALID = 0,      /**< Invalid algorithm type */
    SIGNATURE_ALG_SHA256_ECDSA = 1, /**< ECDSA on a SHA256 hash */
    SIGNATURE_ALG_MAX = SIGNATURE_ALG_SHA256_ECDSA
} SignatureAlg;

/**
 * Enumeration for the possible time formats in blobs
 */
typedef enum time_format {
    TIME_FORMAT_INVALID = 0,    /**< Invalid time format */
    TIME_FORMAT_BINARY32 = 1,   /**< 32-bit binary format */
    TIME_FORMAT_BINARY64 = 2,   /**< 64-bit binary format */
    TIME_FORMAT_MAX = TIME_FORMAT_BINARY64
} TimeFormat;

/**
 * Structure containing the fields of the schema describing a trusted-time blob.
 */
typedef struct secure_time_schema {
    SignatureAlg signature_alg;  /**< The signature algorithm used to sign/verify the blob.*/
    TimeFormat time_format;      /**< The time format of the time value inside the blob.*/
    size_t time_offset;          /**< Offset in bytes of the time value from the start of the blob.*/
    size_t nonce_offset;         /**< Offset in bytes of the nonce value from the start of the blob.*/
    uint32_t nonce_timeout;      /**< Timeout value in seconds for nonce invalidation.*/
} secure_time_schema_t;

/**
 * Factory-setup provisioning of schema to be used by secure_time_set_trusted().
 * Defined as a weak function which by default tries to write the schema to NVStore.
 * If the user wants to provision the schema differently than this function needs
 * to be implemented by the user according to the provisioning method, as well as
 * secure_time_get_stored_schema().
 *
 * @param[in] schema    Schema which describes the blob.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_set_stored_schema(const secure_time_schema_t *schema);

/**
 * Return the previously-provisioned schema.
 * Defined as a weak function which by default tries to read the schema from NVStore.
 * If the user provisioned the schema differently (By implementing secure_time_set_stored_schema())
 * than this function also needs to be implemented.
 *
 * @param[out] schema    Pointer to the schema structure to be filled.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_get_stored_schema(secure_time_schema_t *schema);

/**
 * Factory-setup provisioning of public key to be used by secure_time_set_trusted().
 * Defined as a weak function which by default tries to write the public key to NVStore.
 * If the user wants to provision the public key differently than this function needs
 * to be implemented by the user according to the provisioning method, as well as
 * secure_time_get_stored_public_key().
 *
 * @param[in] pubkey    Public key for blob verification.
 * @param[in] key_size  Size in bytes of public key.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_set_stored_public_key(const void* pubkey, size_t key_size);

/**
 * Return the previously-provisioned public key.
 * Defined as a weak function which by default tries to read the public key from NVStore.
 * If the user provisioned the public key differently (By implementing secure_time_set_stored_public_key())
 * than this function also needs to be implemented.
 *
 * @param[out] pubkey       Buffer to fill with the public key.
 * @param[in]  size         Size in bytes of the buffer.
 * @param[out] actual_size  Actual size in bytes of the returned public key.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_get_stored_public_key(uint8_t *pubkey, size_t size, size_t *actual_size);

/**
 * Return the size in bytes of the previously-provisioned public key.
 * Defined as a weak function which by default tries to read the public key from NVStore.
 * If the user provisioned the public key differently (By implementing secure_time_set_stored_public_key())
 * than this function also needs to be implemented.
 *
 * @param[out] actual_size  Actual size in bytes of the returned public key.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_get_stored_public_key_size(size_t *actual_size);

#ifdef __cplusplus
}
#endif

/** @}*/ // end of Secure-Time-API group

#endif // __SECURE_TIME_SPE_H__
