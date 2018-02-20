/*
 * Copyright (c) 2018 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#ifndef __NVSTORE_INT_FLASH_WRAPPER_H
#define __NVSTORE_INT_FLASH_WRAPPER_H

#include <stdio.h>
#include <stdint.h>

/*
 * This is a simple wrapper for the FlashIAP class, supplying basic flash functionality.
 */

#define NVSTORE_BLANK_FLASH_VAL 0xFF

/**
 * @brief Returns flash sector size, given address.
 *
 * @param[in]  address              Flash address.
 *
 * @returns sector size (bytes).
 */
size_t nvstore_int_flash_get_sector_size(uint32_t address);

/**
 * @brief Returns flash start.
 *
 * @returns flash start.
 */
size_t nvstore_int_flash_get_flash_start();

/**
 * @brief Returns flash size.
 *
 * @returns flash size.
 */
size_t nvstore_int_flash_get_flash_size();

/**
 * @brief Initialises flash.
 *
 * @returns 0 on success, return code otherwise.
 */
int nvstore_int_flash_init(void);

/**
 * @brief Deinitialises flash.
 *
 * @returns 0 on success, return code otherwise.
 */
int nvstore_int_flash_deinit(void);

/**
 * @brief Reads from flash into user buffer, given address and size.
 *
 * @param[in]  size                 Read size
 *
 * @param[in]  address              Flash address.
 *
 * @param[in]  buffer               User buffer.
 *
 * @returns 0 on success, return code otherwise.
 */
int nvstore_int_flash_read(size_t size, uint32_t address, uint32_t *buffer);

/**
 * @brief Erases a chain of sectors, given address and size.
 *
 * @param[in]  size                 Erase size
 *
 * @param[in]  address              Flash address.
 *
 * @returns 0 on success, return code otherwise.
 */
int nvstore_int_flash_erase(uint32_t address, size_t size);

/**
 * @brief Writes from user buffer to the flash, given address and size.
 *
 * @param[in]  size                 Write size
 *
 * @param[in]  address              Flash address.
 *
 * @param[in]  buffer               User buffer.
 *
 * @returns 0 on success, return code otherwise.
 */
int nvstore_int_flash_write(size_t size, uint32_t address, const uint32_t *buffer);

#endif
