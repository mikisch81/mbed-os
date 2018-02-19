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

#ifdef DEVICE_FLASH

#include "nvstore_int_flash_wrapper.h"
#include "nvstore_shared_lock.h"
#include "FlashIAP.h"
#include "mbed_assert.h"
#include <stdlib.h>
#include <algorithm>

// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define MAX_PAGE_SIZE   16

static mbed::FlashIAP *flash = 0;

static size_t get_page_size(void)
{
    return std::min(flash->get_page_size(), (uint32_t) MAX_PAGE_SIZE);
}

static int program_flash(size_t size, uint32_t address, const uint8_t *buffer)
{
    int ret;
    uint32_t page_size, aligned_size, remainder;
    uint8_t rem_buf[MAX_PAGE_SIZE];

    page_size = get_page_size();
    remainder = size % page_size;
    aligned_size = size - remainder;
    if (aligned_size) {
        ret = flash->program(buffer, address, aligned_size);

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
    ret = flash->program(buffer, address, page_size);
    if (ret) {
        return -1;
    }

    return 0;
}

size_t nvstore_int_flash_get_sector_size(uint32_t address)
{
    return flash->get_sector_size(address);
}

size_t nvstore_int_flash_get_flash_start()
{
    return flash->get_flash_start();
}

size_t nvstore_int_flash_get_flash_size()
{
    return flash->get_flash_size();
}

int nvstore_int_flash_init(void)
{
    int ret;

    if (flash) {
        return 0;
    }

    flash = new mbed::FlashIAP;
    MBED_ASSERT(flash);

    ret = flash->init();
    if (ret) {
        return -1;
    }

    return 0;
}

int nvstore_int_flash_deinit(void)
{
    int ret;

    if (!flash) {
        return 0;
    }

    ret = flash->deinit();
    if (ret) {
        return -1;
    }

    delete flash;
    flash = 0;

    return 0;
}

int nvstore_int_flash_read(size_t size, uint32_t address, uint32_t *buffer)
{
    int ret;

    if (!buffer) {
        return -1;
    }

    if (!size)
    {
        return -1;
    }
    ret = flash->read(buffer, address, size);

    if (ret) {
        return -1;
    }

    return 0;
}


int nvstore_int_flash_erase(uint32_t address, size_t size)
{
    int ret;
    size_t sector_size = nvstore_int_flash_get_sector_size(address);

    if ((!size) || (size % sector_size) || (address % sector_size)) {
        return -1;
    }

    // No need to iterate over sectors - Flash driver's erase API does it for us
    ret = flash->erase(address, size);
    if (ret) {
        return -1;
    }

    return 0;
}


int nvstore_int_flash_write(size_t size, uint32_t address, const uint32_t *buffer)
{
    int ret;
    uint32_t page_size = get_page_size();
    uint32_t sector_size = nvstore_int_flash_get_sector_size(address);
    uint32_t chunk;
    uint8_t *buf = (uint8_t *) buffer;

    if ((!size) || (!buffer) || (address % page_size)) {
        return -1;
    }

    while (size) {
        chunk = std::min(sector_size - (address % sector_size), (uint32_t) size);
        ret = program_flash(chunk, address, buf);
        if (ret) {
            return -1;
        }
        size -= chunk;
        address += chunk;
        buf += chunk;
        sector_size = nvstore_int_flash_get_sector_size(address);
    }

    return 0;
}


#endif
