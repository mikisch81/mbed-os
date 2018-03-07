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
#ifndef __SECURE_TIME_H__
#define __SECURE_TIME_H__

#include <stdint.h>
#include <stdlib.h>

/** @addtogroup Secure-Time-API
 *  The C interface for setting and getting secure time.
 *  All functions are blocking.
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define SECURE_TIME_SUCCESS                             (0UL)
#define SECURE_TIME_BAD_PARAMS                          (-1L)
#define SECURE_TIME_ILLEGAL_SCHEMA                      (-2L)
#define SECURE_TIME_INVALID_BLOB_SIZE                   (-3L)
#define SECURE_TIME_SIGNATURE_VERIFICATION_FAILED       (-4L)
#define SECURE_TIME_NONCE_MISSING                       (-5L)
#define SECURE_TIME_NONCE_NOT_MATCH                     (-6L)
#define SECURE_TIME_NONCE_TIMEOUT                       (-7L)
#define SECURE_TIME_NOT_ALLOWED                         (-8L)

/**
 * Generate variable-sized nonce\n
 * This nonce will be used in the next invocation of secure_time_set_trusted()
 * to verify the trusted time blob freshness.
 *
 * @param[in]  nonce_size  Size in bytes of nonce buffer.
 * @param[out] nonce       Buffer to hold the generated nonce.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_get_nonce(size_t nonce_size, void *nonce);

/**
 * Set the secure time from a trusted time source.
 * The time is encapsulated inside blob which is signed with the trusted time sources' private key.
 * The blob will be verified with the trusted time sources' public key.
 *
 * @param[in] blob       Buffer which holds the blob.
 * @param[in] blob_size  Size in bytes of blob.
 * @param[in] sign       Buffer which holds the signature of the blob.
 * @param[in] sign_size  Size in bytes of signature.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_set_trusted(
    const void *blob,
    size_t blob_size,
    const void *sign,
    size_t sign_size
    );

/**
 * Set the secure time from an arbitrary time source.
 *
 * @param[in] new_time  Time value in seconds since EPOCH.
 * @return 0 or negative error code if failed.
 */
int32_t secure_time_set(uint64_t new_time);

/**
 * Return the current secure-time value.
 *
 * @return 64-bit value which can be:\n
 *         @a time in seconds since EPOCH.\n
 *         @a 0 in case of an error or if secure_time_set_(un)trusted was not called yet.
 */
uint64_t secure_time_get(void);

#ifdef __cplusplus
}
#endif

/** @}*/ // end of Secure-Time-API group

#endif // __SECURE_TIME_H__
