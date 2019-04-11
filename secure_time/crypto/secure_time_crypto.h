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
#ifndef __SECURE_TIME_CRYPTO_H__
#define __SECURE_TIME_CRYPTO_H__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// forward declaration
typedef struct secure_time_schema secure_time_schema_t;

/*
 * Verify the signature of a blob with a public key which corresponds to the private key
 * used to sign the blob.
 * The cryptographic algorithm to use is defined in the given schema.
 *
 * @param[in] blob         Buffer which holds the blob.
 * @param[in] blob_size    Size in bytes of blob.
 * @param[in] sign         Buffer which holds the signature of the blob.
 * @param[in] sign_size    Size in bytes of signature.
 * @param[in] pubkey       Buffer which holds the public key.
 * @param[in] pubkey_size  Size in bytes of public key.
 * @param[in] schema       Pointer to the schema structure.
 * @return SECURE_TIME_SUCCESS or negative error code if failed.
 */
int32_t secure_time_verify_blob_signature(
    const void *blob,
    size_t blob_size,
    const void *sign,
    size_t sign_size,
    const void *pubkey,
    size_t pubkey_size,
    secure_time_schema_t *schema
    );

/*
 * Generate a sequence of random bytes.
 *
 * @param[in]  size         Size in bytes of the random buffer
 * @param[out] random_buf   Buffer to fill with the generated random bytes.
 */
void secure_time_generate_random_bytes(size_t size, void *random_buf);

#ifdef __cplusplus
}
#endif

#endif // __SECURE_TIME_CRYPTO_H__
