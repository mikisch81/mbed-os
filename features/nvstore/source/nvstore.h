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

#ifndef __NVSTORE_H
#define __NVSTORE_H

// These addresses need to be configured according to board (in mbed_lib.json)
#if defined(NVSTORE_AREA_1_ADDRESS) && defined(NVSTORE_AREA_1_SIZE) && \
    defined(NVSTORE_AREA_2_ADDRESS) && defined(NVSTORE_AREA_2_SIZE) && \
    defined(DEVICE_FLASH)
#define NVSTORE_ENABLED 1
#endif

#if NVSTORE_ENABLED
#include <stdint.h>
#include <stdio.h>
#include "platform/NonCopyable.h"
#include "nvstore_int_flash_wrapper.h"
#include "nvstore_shared_lock.h"

enum {
    NVSTORE_SUCCESS                =  0,
    NVSTORE_READ_ERROR             = -1,
    NVSTORE_WRITE_ERROR            = -2,
    NVSTORE_NOT_FOUND              = -3,
    NVSTORE_DATA_CORRUPT           = -4,
    NVSTORE_BAD_VALUE              = -5,
    NVSTORE_BUFF_TOO_SMALL         = -6,
    NVSTORE_FLASH_AREA_TOO_SMALL   = -7,
    NVSTORE_OS_ERROR               = -8,
    NVSTORE_BUFF_NOT_ALIGNED       = -9,
    NVSTORE_ALREADY_EXISTS         = -10,
};

#ifndef NVSTORE_MAX_KEYS
#define NVSTORE_MAX_KEYS 16
#endif

class NVStore : private mbed::NonCopyable<NVStore> {
public:

/**
 * @brief As a singleton, return the single instance of the class.
 *        Reason for this class being a singleton is the following:
 *        - Ease the use for users of this class not having to coordinate instantiations.
 *        - Lazy instantiation of internal data (which we can't achieve with simple static classes).
 *
 * @returns Singleton instance reference.
 */
    static NVStore& get_instance()
    {
        // Use this implementation of singleton (Meyer's) rather than the one that allocates
        // the instance on the heap, as it ensures destruction at program end (preventing warnings
        // from memory checking tools such as valgrind).
        static NVStore instance;
        return instance;
    }

    virtual ~NVStore();

/**
 * @brief Returns number of keys.
 *
 * @returns Number of keys.
 */
    uint16_t get_max_keys() const;

/**
 * @brief Set number of keys.
 *
 * @returns None.
 */
    void set_max_keys(uint16_t num_keys);

/**
 * @brief Returns one item of data programmed on Flash, given key.
 *
 * @param[in]  key                  Key of stored item.
 *
 * @param[in]  buf_len_bytes        Length of input buffer in bytes.
 *
 * @param[in]  buf                  Buffer to store data on (must be aligned to a 32 bit boundary).
 *
 * @param[out] actual_len_bytes     Actual length of returned data
 *
 * @returns NVSTORE_SUCCESS           Value was found on Flash.
 *          NVSTORE_NOT_FOUND         Value was not found on Flash.
 *          NVSTORE_READ_ERROR        Physical error reading data.
 *          NVSTORE_DATA_CORRUPT      Data on Flash is corrupt.
 *          NVSTORE_BAD_VALUE         Bad value in any of the parameters.
 *          NVSTORE_BUFF_TOO_SMALL    Not enough memory in user buffer.
 *          NVSTORE_BUFF_NOT_ALIGNED  Buffer not aligned to 32 bits.
 */
    int get(uint16_t key, uint16_t buf_len_bytes, uint32_t *buf, uint16_t &actual_len_bytes);

/**
 * @brief Returns size of the data programmed on Flash, given key.
 *
 * @param[in]  key                  Key of stored item.
 *
 * @param[out] actual_len_bytes     Actual length of item
 *
 * @returns NVSTORE_SUCCESS           Value was found on Flash.
 *          NVSTORE_NOT_FOUND         Value was not found on Flash.
 *          NVSTORE_READ_ERROR        Physical error reading data.
 *          NVSTORE_DATA_CORRUPT      Data on Flash is corrupt.
 *          NVSTORE_BAD_VALUE         Bad value in any of the parameters.
 */
    int get_item_size(uint16_t key, uint16_t &actual_len_bytes);


/**
 * @brief Programs one item of data on Flash, given key.
 *
 * @param[in]  key                  Key of stored item.
 *
 * @param[in]  buf_len_bytes        Item length in bytes.
 *
 * @param[in]  buf                  Buffer containing data  (must be aligned to a 32 bit boundary).
 *
 * @returns NVSTORE_SUCCESS           Value was successfully written on Flash.
 *          NVSTORE_WRITE_ERROR       Physical error writing data.
 *          NVSTORE_BAD_VALUE         Bad value in any of the parameters.
 *          NVSTORE_FLASH_AREA_TOO_SMALL
 *                                 Not enough space in Flash area.
 *          NVSTORE_BUFF_NOT_ALIGNED  Buffer not aligned to 32 bits.
 *          NVSTORE_ALREADY_EXISTS    Item set with write once API already exists.
 *
 */
    int set(uint16_t key, uint16_t buf_len_bytes, const uint32_t *buf);

/**
 * @brief Programs one item of data on Flash, given key, allowing no consequent sets to this key.
 *
 * @param[in]  key                  Key of stored item.
 *
 * @param[in]  buf_len_bytes        Item length in bytes.
 *
 * @param[in]  buf                  Buffer containing data  (must be aligned to a 32 bit boundary).
 *
 * @returns NVSTORE_SUCCESS           Value was successfully written on Flash.
 *          NVSTORE_WRITE_ERROR       Physical error writing data.
 *          NVSTORE_BAD_VALUE         Bad value in any of the parameters.
 *          NVSTORE_FLASH_AREA_TOO_SMALL
 *                                 Not enough space in Flash area.
 *          NVSTORE_BUFF_NOT_ALIGNED  Buffer not aligned to 32 bits.
 *          NVSTORE_ALREADY_EXISTS    Item set with write once API already exists.
 *
 */
    int set_once(uint16_t key, uint16_t buf_len_bytes, const uint32_t *buf);


/**
 * @brief Remove an item from flash.
 *
 * @param[in]  key                  Key of stored item.
 *
 * @returns NVSTORE_SUCCESS           Value was successfully written on Flash.
 *          NVSTORE_WRITE_ERROR       Physical error writing data.
 *          NVSTORE_BAD_VALUE         Bad value in any of the parameters.
 *          NVSTORE_FLASH_AREA_TOO_SMALL
 *                                 Not enough space in Flash area.
 *          NVSTORE_BUFF_NOT_ALIGNED  Buffer not aligned to 32 bits.
 *
 */
    int remove(uint16_t key);

/**
 * @brief Initializes NVStore component.
 *
 * @returns NVSTORE_SUCCESS       Initialization completed successfully.
 *          NVSTORE_READ_ERROR    Physical error reading data.
 *          NVSTORE_WRITE_ERROR   Physical error writing data (on recovery).
 *          NVSTORE_FLASH_AREA_TOO_SMALL
 *                             Not enough space in Flash area.
 */
    int init();

/**
 * @brief Deinitializes NVStore component.
 *        Warning: This function is not thread safe and should not be called
 *        concurrently with other NVStore functions.
 *
 * @returns NVSTORE_SUCCESS       Deinitialization completed successfully.
 */
    int deinit();

/**
 * @brief Reset Flash NVStore areas.
 *        Warning: This function is not thread safe and should not be called
 *        concurrently with other NVStore functions.
 *
 * @returns NVSTORE_SUCCESS       Reset completed successfully.
 *          NVSTORE_READ_ERROR    Physical error reading data.
 *          NVSTORE_WRITE_ERROR   Physical error writing data.
 */
    int reset();

/**
 * @brief Return NVStore size (area size).
 *
 * @returns NVStore size.
 */
    uint32_t size();


/**
 * @brief Returns one item of data programmed on Flash, given key.
 *        This is a self contained version of the get function (not requiring init), traversing the flash each time if triggered.
 *        This function is NOT thread safe. Its implementation is here for the case we want to minimise code size for clients
 *        such as boot loaders, performing minimal accesses to NVstore. In this case all other APIs can be commented out.
 *
 * @param[in]  key                  Key of stored item (must be between 0-15).
 *
 * @param[in]  buf_len_bytes        Length of input buffer in bytes.
 *
 * @param[in]  buf                  Buffer to store data on (must be aligned to a 32 bit boundary).
 *
 * @param[out] actual_len_bytes     Actual length of returned data
 *
 * @returns NVSTORE_SUCCESS           Value was found on Flash.
 *          NVSTORE_NOT_FOUND         Value was not found on Flash.
 *          NVSTORE_READ_ERROR        Physical error reading data.
 *          NVSTORE_DATA_CORRUPT      Data on Flash is corrupt.
 *          NVSTORE_BAD_VALUE         Bad value in any of the parameters.
 *          NVSTORE_BUFF_TOO_SMALL    Not enough memory in user buffer.
 *          NVSTORE_BUFF_NOT_ALIGNED  Buffer not aligned to 32 bits.
 */
    int probe(uint16_t key, uint16_t buf_len_bytes, uint32_t *buf, uint16_t &actual_len_bytes);

private:
    int _init_done;
    uint32_t _init_attempts;
    uint8_t _active_area;
    uint16_t _max_keys;
    uint16_t _active_area_version;
    uint32_t _free_space_offset;
    uint32_t _size;
    NVstoreSharedLock _lock;
    uint32_t *_offset_by_key;

    // Private constructor, as class is a singleton
    NVStore();

    int flash_read_area(uint8_t area, uint32_t offset, uint32_t len_bytes, uint32_t *buf);
    int flash_write_area(uint8_t area, uint32_t offset, uint32_t len_bytes, const uint32_t *buf);
    int flash_erase_area(uint8_t area);

    int calc_empty_space(uint8_t area, uint32_t &offset);

    int read_record(uint8_t area, uint32_t offset, uint16_t buf_len_bytes, uint32_t *buf,
                              uint16_t &actual_len_bytes, int validate_only, int &valid,
                              uint16_t &key, uint16_t &flags, uint32_t &next_offset);

    int write_record(uint8_t area, uint32_t offset, uint16_t key, uint16_t flags,
                               uint32_t data_len, const uint32_t *data_buf, uint32_t &next_offset);

    int write_master_record(uint8_t area, uint16_t version, uint32_t &next_offset);

    int copy_record(uint8_t from_area, uint32_t from_offset, uint32_t to_offset,
                              uint32_t &next_offset);

    int garbage_collection(uint16_t key, uint16_t flags, uint16_t buf_len_bytes, const uint32_t *buf);

    int do_get(uint16_t key, uint16_t buf_len_bytes, uint32_t *buf, uint16_t &actual_len_bytes,
                         int validate_only);

    int do_set(uint16_t key, uint16_t buf_len_bytes, const uint32_t *buf, uint16_t flags);

};

#endif // NVSTORE_ENABLED

#endif


