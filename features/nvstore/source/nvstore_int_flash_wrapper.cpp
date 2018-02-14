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



// ----------------------------------------------------------- Includes -----------------------------------------------------------

#include "nvstore_int_flash_wrapper.h"
#include "nvstore_shared_lock.h"
#ifdef DEVICE_FLASH
#include "FlashIAP.h"
#endif
#include <stdlib.h>

// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define MIN(a,b)            ((a) < (b) ? (a) : (b))
#define MAX(a,b)            ((a) > (b) ? (a) : (b))

#define MAX_PAGE_SIZE   16

#ifdef DEVICE_FLASH
static mbed::FlashIAP flash;
#endif

static size_t get_page_size(void)
{
#ifdef DEVICE_FLASH
    return MIN(flash.get_page_size(), MAX_PAGE_SIZE);
#else
    return 0;
#endif
}

static int program_flash(size_t size, uint32_t address, const uint8_t *buffer)
{
#ifdef DEVICE_FLASH
    int ret;
    uint32_t page_size, aligned_size, remainder;
    uint8_t rem_buf[MAX_PAGE_SIZE];

    page_size = get_page_size();
    remainder = size % page_size;
    aligned_size = size - remainder;
    if (aligned_size) {
        ret = flash.program(buffer, address, aligned_size);

        if (ret) {
            return -1;
        }
        address += aligned_size;
        buffer += aligned_size;
    }

    if (!remainder) {
        return 0;
    }

    memset(rem_buf, NVSTORE_BLANK_FLASH_VAL, page_size);
    memcpy(rem_buf, buffer, remainder);
    ret = flash.program(buffer, address, page_size);
    if (ret) {
        return -1;
    }
#endif

    return 0;
}

size_t nvstore_int_flash_get_sector_size(uint32_t address)
{
#ifdef DEVICE_FLASH
    return flash.get_sector_size(address);
#else
    return 0;
#endif
}

int nvstore_int_flash_init(void)
{
#ifdef DEVICE_FLASH
    int ret;

    ret = flash.init();
    if (ret) {
        return -1;
    }
#endif

    return 0;
}

int nvstore_int_flash_deinit(void)
{
#ifdef DEVICE_FLASH
    int ret;

    ret = flash.deinit();
    if (ret) {
        return -1;
    }
#endif

    return 0;
}

int nvstore_int_flash_read(size_t size, uint32_t address, uint32_t *buffer)
{
#ifdef DEVICE_FLASH
    int ret;

    if (!buffer) {
        return -1;
    }

    if (!size)
    {
        return -1;
    }
    ret = flash.read(buffer, address, size);

    if (ret) {
        return -1;
    }
#endif

    return 0;
}


int nvstore_int_flash_erase(uint32_t address, size_t size)
{
#ifdef DEVICE_FLASH
    int ret;
    size_t sector_size = nvstore_int_flash_get_sector_size(address);

    if ((!size) || (size % sector_size) || (address % sector_size)) {
        return -1;
    }

    // No need to iterate over sectors - Flash driver's erase API does it for us
    ret = flash.erase(address, sector_size);
    if (ret) {
        return -1;
    }
#endif

    return 0;
}


int nvstore_int_flash_write(size_t size, uint32_t address, const uint32_t *buffer)
{
#ifdef DEVICE_FLASH
    int ret;
    uint32_t page_size = get_page_size();
    uint32_t sector_size = nvstore_int_flash_get_sector_size(address);
    uint32_t chunk;
    uint8_t *buf = (uint8_t *) buffer;

    if ((!size) || (!buffer) || (address % page_size)) {
        return -1;
    }

    while (size) {
        chunk = MIN(sector_size - (address % sector_size), size);
        ret = program_flash(chunk, address, buf);
        if (ret) {
            return -1;
        }
        size -= chunk;
        address += chunk;
        buf += chunk;
        sector_size = nvstore_int_flash_get_sector_size(address);
    }
#endif

    return 0;
}


