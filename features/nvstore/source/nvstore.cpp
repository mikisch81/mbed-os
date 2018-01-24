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

#include "nvstore.h"
#include "nvstore_int_flash_wrapper.h"
#include "nvstore_shared_lock.h"
#include "mbed_critical.h"
#include "mbed_assert.h"
#include "thread.h"
#include <string.h>
#include <stdio.h>

#if NVSTORE_ENABLED

// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define PR_ERR printf
#define PR_INFO printf
#define PR_DEBUG printf

#define MIN(a,b)            ((a) < (b) ? (a) : (b))
#define MAX(a,b)            ((a) > (b) ? (a) : (b))

#define DELETE_ITEM_FLAG  0x8000
#define SET_ONCE_FLAG     0x4000
#define HEADER_FLAG_MASK  0xF000

#define MASTER_RECORD_KEY 0xFFE
#define NO_KEY            0xFFF

typedef struct {
    uint16_t key_and_flags;
    uint16_t length;
    uint32_t mac;
} record_header_t __attribute__((aligned(4)));


#define OFFS_BY_KEY_AREA_MASK     0x80000000
#define OFFS_BY_KEY_SET_ONCE_MASK 0x40000000
#define OFFS_BY_KEY_FLAG_MASK     0xC0000000
#define OFFS_BY_KEY_AREA_BIT_POS      31
#define OFFS_BY_KEY_SET_ONCE_BIT_POS  30

#define FLASH_MINIMAL_PROG_UNIT 8

#define MASTER_RECORD_BLANK_FIELD_SIZE FLASH_MINIMAL_PROG_UNIT

typedef struct {
    uint16_t version;
    uint16_t reserved1;
    uint32_t reserved2;
} master_record_data_t __attribute__((aligned(4)));

#define MASTER_RECORD_SIZE sizeof(master_record_data_t)

#define MEDITATE_TIME_MS 1

typedef struct
{
    uint32_t address;
    size_t   size;
} nvstore_area_data_t;

const nvstore_area_data_t flash_area_params[] =
{
        {NVSTORE_AREA_1_ADDRESS, NVSTORE_AREA_1_SIZE},
        {NVSTORE_AREA_2_ADDRESS, NVSTORE_AREA_2_SIZE}
};

typedef enum {
    AREA_STATE_NONE = 0,
    AREA_STATE_EMPTY,
    AREA_STATE_VALID,
} area_state_e;

#define INITIAL_CRC 0xFFFFFFFF

// -------------------------------------------------- Local Functions Declaration ----------------------------------------------------

// -------------------------------------------------- Functions Implementation ----------------------------------------------------

// Safely increment an integer (depending on if we're thread safe or not)
// Parameters :
// value         - [IN]   Pointer to variable.
// size          - [IN]   Increment.
// Return        : Value after increment.
int32_t safe_increment(uint32_t &value, uint32_t increment)
{
    return core_util_atomic_incr_u32(&value, increment);
}

// Check whether a buffer is aligned.
// Parameters :
// buf           - [IN]   Data buffer.
// size          - [IN]   Alignment size.
// Return        : Boolean result.
static inline int is_buf_aligned(const void *buf, uint32_t size)
{
    return (((size_t) buf / size * size) == (size_t) buf);
}

// Align a value to a specified size.
// Parameters :
// val           - [IN]   Value.
// size          - [IN]   Size.
// Return        : Aligned value.
static inline uint32_t align_up(uint32_t val, uint32_t size)
{
    return (((val-1) / size) + 1) * size;
}

// CRC32 calculation. Supports "rolling" calculation (using the initial value).
// Parameters :
// init_crc      - [IN]   Initial CRC.
// data_len      - [IN]   Buffer's data length.
// data_buf      - [IN]   Data buffer.
// Return        : CRC.
static uint32_t crc32(uint32_t init_crc, uint32_t data_len, uint8_t *data_buf)
{
    uint32_t i, j;
    uint32_t crc, mask;

    crc = init_crc;
    for (i = 0; i < data_len; i++) {
       crc = crc ^ (uint32_t) (data_buf[i]);
       for (j = 0; j < 8; j++) {
          mask = -(crc & 1);
          crc = (crc >> 1) ^ (0xEDB88320 & mask);
       }
    }
    return crc;
}

NVStore::NVStore() : _init_done(0), _init_attempts(0), _active_area(0), _max_keys(NVSTORE_MAX_KEYS),
               _active_area_version(0), _free_space_offset(0), _size(0), _offset_by_key(0)
{
}

NVStore::~NVStore()
{
    if (_init_done) {
        deinit();
    }
}

uint16_t NVStore::get_max_keys() const
{
    return _max_keys;
}

void NVStore::set_max_keys(uint16_t num_keys)
{
    MBED_ASSERT(num_keys < MASTER_RECORD_KEY);
    _max_keys = num_keys;
    // User is allowed to change number of types. As this affects init, need to deinitialize now.
    // Don't call init right away - it is lazily called by get/set functions if needed.
    deinit();
}

// Flash access helper functions, using area and offset notations

// Read from flash, given area and offset.
// Parameters :
// area          - [IN]   Flash area.
// offset        - [IN]   Offset in area.
// len_bytes     - [IN]   Length in bytes.
// buf           - [IN]   Data buffer.
// Return        : 0 on success. Error code otherwise.
int NVStore::flash_read_area(uint8_t area, uint32_t offset, uint32_t len_bytes, uint32_t *buf)
{
    return nvstore_int_flash_read(len_bytes, flash_area_params[area].address + offset, buf);
}

// Write to flash, given area and offset.
// Parameters :
// area          - [IN]   Flash area.
// offset        - [IN]   Offset in area.
// len_bytes     - [IN]   Length in bytes.
// buf           - [IN]   Data buffer.
// Return        : 0 on success. Error code otherwise.
int NVStore::flash_write_area(uint8_t area, uint32_t offset, uint32_t len_bytes, const uint32_t *buf)
{
    return nvstore_int_flash_write(len_bytes, flash_area_params[area].address + offset, buf);
}

// Erase a flash area, given area.
// Parameters :
// area          - [IN]   Flash area.
// Return        : 0 on success. Error code otherwise.
int NVStore::flash_erase_area(uint8_t area)
{
    return nvstore_int_flash_erase(flash_area_params[area].address, flash_area_params[area].size);
}


// Scan start of latest continuous empty area in flash area.
// Parameters :
// area          - [IN]   Flash area.
// offset        - [OUT]  Blank chunk offset.
// Return        : 0 on success. Error code otherwise.
int NVStore::calc_empty_space(uint8_t area, uint32_t &offset)
{
    uint32_t buf[32];
    uint8_t *chbuf;
    uint32_t i, j;
    int ret;

    offset = _size;
    for (i = 0; i < _size / sizeof(buf); i++) {
        offset -= sizeof(buf);
        ret = flash_read_area(area, offset, sizeof(buf), buf);
        if (ret)
            return ret;
        chbuf = (uint8_t *) buf;
        for (j = sizeof(buf); j > 0; j--) {
            if (chbuf[j-1] != NVSTORE_BLANK_FLASH_VAL) {
                offset += j;
                return 0;
            }
        }
    }
    return 0;
}

// Read a record from a given area and offset.
// Parameters :
// area          - [IN]   Flash area.
// offset        - [IN]   Record offset.
// buf_len_bytes - [IN]   Length of user buffer in byte.
// buf           - [IN]   User buffer.
// actual_len_bytes
//               - [Out]  Actual length of returned data.
// validate_only - [IN]   Just validate (don't return user data).
// valid         - [Out]  Is record valid.
// key           - [Out]  Record key.
// flags         - [Out]  Record flags.
// next_offset   - [Out]  If valid, offset of next record.
// Return        : NVSTORE_SUCCESS on success. Error code otherwise.
int NVStore::read_record(uint8_t area, uint32_t offset, uint16_t buf_len_bytes, uint32_t *buf,
                                uint16_t &actual_len_bytes, int validate_only, int &valid,
                                uint16_t &key, uint16_t &flags, uint32_t &next_offset)
{
    uint32_t int_buf[32];
    uint32_t *buf_ptr;
    uint32_t data_len, chunk_len;
    int os_ret;
    record_header_t header;
    uint32_t crc = INITIAL_CRC;

    valid = 1;

    os_ret = flash_read_area(area, offset, sizeof(header), (uint32_t *) &header);
    if (os_ret) {
        return NVSTORE_READ_ERROR;
    }

    crc = crc32(crc, sizeof(header) - sizeof(header.mac), (uint8_t *) &header);

    actual_len_bytes = 0;
    key = header.key_and_flags & ~HEADER_FLAG_MASK;
    flags = header.key_and_flags & HEADER_FLAG_MASK;

    if ((key >= _max_keys) && (key != MASTER_RECORD_KEY)) {
        valid = 0;
        return NVSTORE_SUCCESS;
    }

    data_len = header.length;
    offset += sizeof(header);

    // In case of validate only enabled, we use our internal buffer for data reading,
    // instead of the user one. This allows us to use a smaller buffer, on which CRC
    // is continuously calculated.
    if (validate_only) {
        buf_ptr = int_buf;
        buf_len_bytes = sizeof(int_buf);
    }
    else {
        if (data_len > buf_len_bytes) {
            offset += data_len;
            actual_len_bytes = data_len;
            next_offset = align_up(offset, FLASH_MINIMAL_PROG_UNIT);
            return NVSTORE_BUFF_TOO_SMALL;
        }
        buf_ptr = buf;
    }

    while (data_len) {
        chunk_len = MIN(data_len, buf_len_bytes);
        os_ret = flash_read_area(area, offset, chunk_len, buf_ptr);
        if (os_ret) {
            return NVSTORE_READ_ERROR;
        }
        crc = crc32(crc, chunk_len, (uint8_t *) buf_ptr);
        data_len -= chunk_len;
        offset += chunk_len;
    }

    if (header.mac != crc) {
        valid = 0;
        return NVSTORE_SUCCESS;
    }

    actual_len_bytes = header.length;
    next_offset = align_up(offset, FLASH_MINIMAL_PROG_UNIT);

    return NVSTORE_SUCCESS;
}

// Write a record in a given area and offset.
// Parameters :
// area          - [IN]   Flash area.
// offset        - [IN]   Record offset.
// key           - [IN]   Record key.
// flags         - [IN]   Record flags
// data_len      - [IN]   Record's data length.
// data_buf      - [IN]   Record's data buffer.
// next_offset   - [Out]  offset of next record.
// Return        : NVSTORE_SUCCESS on success. Error code otherwise.
int NVStore::write_record(uint8_t area, uint32_t offset, uint16_t key, uint16_t flags,
                                 uint32_t data_len, const uint32_t *data_buf, uint32_t &next_offset)
{
    record_header_t header;
    uint32_t crc = INITIAL_CRC;
    int os_ret;
    uint32_t write_len;

    header.key_and_flags = key | flags;
    header.length = data_len;
    header.mac = 0; // Satisfy compiler
    crc = crc32(crc, sizeof(header) - sizeof(header.mac), (uint8_t *) &header);
    if (data_len)
        crc = crc32(crc, data_len, (uint8_t *) data_buf);
    header.mac = crc;

    os_ret = flash_write_area(area, offset, sizeof(header), (uint32_t *)&header);
    if (os_ret) {
        return NVSTORE_WRITE_ERROR;
    }

    if (data_len) {
        offset += sizeof(header);
        write_len = data_len;
        os_ret = flash_write_area(area, offset, write_len, data_buf);
        if (os_ret) {
            return NVSTORE_WRITE_ERROR;
        }
        offset += data_len;
    }

    next_offset = align_up(offset, FLASH_MINIMAL_PROG_UNIT);
    return NVSTORE_SUCCESS;
}

// Write a master record in a given area.
// Parameters :
// area          - [IN]   Flash area.
// version       - [IN]   Version.
// next_offset   - [Out]  offset of next record.
// Return        : NVSTORE_SUCCESS on success. Error code otherwise.
int NVStore::write_master_record(uint8_t area, uint16_t version, uint32_t &next_offset)
{
    master_record_data_t master_rec;

    master_rec.version = version;
    master_rec.reserved1 = 0;
    master_rec.reserved2 = 0;
    return write_record(area, 0, MASTER_RECORD_KEY, 0, sizeof(master_rec),
                        (uint32_t*) &master_rec, next_offset);
}

// Copy a record from a given area and offset to another offset in the other area.
// Parameters :
// from_area     - [IN]   Flash area to copy from.
// from_offset   - [IN]   Record offset in current area.
// to_offset     - [IN]   Record offset in new area.
// next_offset   - [Out]  Offset of next record in the new area.
// Return        : NVSTORE_SUCCESS on success. Error code otherwise.
int NVStore::copy_record(uint8_t from_area, uint32_t from_offset, uint32_t to_offset,
                                uint32_t &next_offset)
{
    uint32_t int_buf[32];
    uint32_t data_len, chunk_len;
    int os_ret;
    record_header_t header;

    // This function assumes that the source record is valid, so no need to recalculate CRC.

    os_ret = flash_read_area(from_area, from_offset, sizeof(header), (uint32_t *) &header);
    if (os_ret) {
        return NVSTORE_READ_ERROR;
    }

    data_len = header.length;

    // No need to copy records whose flags indicate deletion
    if (header.key_and_flags & DELETE_ITEM_FLAG) {
        next_offset = align_up(to_offset, FLASH_MINIMAL_PROG_UNIT);
        return NVSTORE_SUCCESS;
    }

    // no need to align record size here, as it won't change the outcome of this condition
    if (to_offset + sizeof(header) + data_len >= _size) {
        return NVSTORE_FLASH_AREA_TOO_SMALL;
    }

    os_ret = flash_write_area(1-from_area, to_offset, sizeof(header), (uint32_t *)&header);
    if (os_ret) {
        return NVSTORE_WRITE_ERROR;
    }

    from_offset += sizeof(header);
    to_offset += sizeof(header);

    while (data_len) {
        chunk_len = MIN(data_len, sizeof(int_buf));
        os_ret = flash_read_area(from_area, from_offset, chunk_len, int_buf);
        if (os_ret) {
            return NVSTORE_READ_ERROR;
        }
        os_ret = flash_write_area(1-from_area, to_offset, chunk_len, int_buf);
        if (os_ret) {
            return NVSTORE_WRITE_ERROR;
        }

        data_len -= chunk_len;
        from_offset += chunk_len;
        to_offset += chunk_len;
    }

    next_offset = align_up(to_offset, FLASH_MINIMAL_PROG_UNIT);
    return NVSTORE_SUCCESS;
}

// Perform the garbage collection process.
// Parameters :
// key           - [IN]   Item's key.
// buf_len_bytes - [IN]   Item length in bytes.
// buf           - [IN]   Pointer to user buffer.
// Return      : NVSTORE_SUCCESS on success. Error code otherwise.
int NVStore::garbage_collection(uint16_t key, uint16_t flags, uint16_t buf_len_bytes, const uint32_t *buf)
{
    uint32_t curr_offset, new_area_offset, next_offset;
    uint8_t curr_area;
    int ret;

    new_area_offset = sizeof(record_header_t) + sizeof(master_record_data_t);

    // If GC is triggered by a set item request, we need to first write that item in the new location,
    // otherwise we may either write it twice (if already included), or lose it in case we decide
    // to skip it at garbage collection phase (and the system crashes).
    if ((key != NO_KEY) && !(flags & DELETE_ITEM_FLAG)) {
        ret = write_record(1 - _active_area, new_area_offset, key, 0, buf_len_bytes, buf, next_offset);
        if (ret != NVSTORE_SUCCESS) {
            PR_ERR("nvstore_garbage_collection: write_record failed with ret %d\n", ret);
            return ret;
        }
        _offset_by_key[key] = new_area_offset | (1-_active_area) << OFFS_BY_KEY_AREA_BIT_POS |
                                (((flags & SET_ONCE_FLAG) != 0) << OFFS_BY_KEY_SET_ONCE_BIT_POS);
        new_area_offset = next_offset;
    }

    // Now iterate on all types, and copy the ones who have valid offsets (meaning that they exist)
    // to the other area.
    for (key = 0; key < _max_keys; key++) {
        curr_offset = _offset_by_key[key];
        uint16_t save_flags = curr_offset & OFFS_BY_KEY_AREA_MASK;
        curr_area = (uint8_t) (curr_offset >> OFFS_BY_KEY_AREA_BIT_POS) & 1;
        curr_offset &= ~OFFS_BY_KEY_FLAG_MASK;
        if ((!curr_offset) || (curr_area != _active_area))
            continue;
        ret = copy_record(curr_area, curr_offset, new_area_offset, next_offset);
        if (ret != NVSTORE_SUCCESS) {
            PR_ERR("nvstore_garbage_collection: copy_record failed with ret %d\n", ret);
            return ret;
        }
        _offset_by_key[key] = new_area_offset | (1-curr_area) << OFFS_BY_KEY_AREA_BIT_POS | save_flags;
        new_area_offset = next_offset;
    }

    // Now write master record, with version incremented by 1.
    _active_area_version++;
    ret = write_master_record(1 - _active_area, _active_area_version, next_offset);
    if (ret != NVSTORE_SUCCESS) {
        PR_ERR("nvstore_garbage_collection: write_master_record failed with ret %d\n", ret);
        return ret;
    }

    _free_space_offset = new_area_offset;

    // Only now we can switch to the new active area
    _active_area = 1 - _active_area;

    // The older area doesn't concern us now. Erase it now.
    if (flash_erase_area(1 - _active_area))
        return NVSTORE_WRITE_ERROR;

    return ret;
}


// Get API logics helper function. Serves both Get & Get item size APIs.
// Parameters :
// key              - [IN]   Item's key.
// buf_len_bytes    - [IN]   Item length in bytes.
// buf              - [IN]   Pointer to user buffer.
// actual_len_bytes - [OUT]  Actual length of returned data.
// validate_only    - [IN]   Just validate (don't return user data).
// Return      : NVSTORE_SUCCESS on success. Error code otherwise.
int NVStore::do_get(uint16_t key, uint16_t buf_len_bytes, uint32_t *buf, uint16_t &actual_len_bytes,
                           int validate_only)
{
    int ret = NVSTORE_SUCCESS;
    uint32_t record_offset, next_offset;
    uint8_t area;
    uint16_t read_type, flags;
    int valid;

    if (!_init_done) {
        ret = init();
        if (ret != NVSTORE_SUCCESS) {
            return ret;
        }
    }

    if (key >= _max_keys) {
        return NVSTORE_BAD_VALUE;
    }


    if (!buf)
        buf_len_bytes = 0;

    if (buf_len_bytes && !is_buf_aligned(buf, sizeof(uint32_t))) {
        return NVSTORE_BUFF_NOT_ALIGNED;
    }

    // We only have issues if we read during GC, so shared lock is required.
    _write_lock.shared_lock();
    record_offset = _offset_by_key[key];

    if (!record_offset) {
        _write_lock.shared_unlock();
        return NVSTORE_NOT_FOUND;
    }

    area = (uint8_t) (record_offset >> OFFS_BY_KEY_AREA_BIT_POS) & 1;
    record_offset &= ~OFFS_BY_KEY_FLAG_MASK;

    ret = read_record(area, record_offset, buf_len_bytes, buf,
                      actual_len_bytes, validate_only, valid,
                      read_type, flags, next_offset);
    if ((ret == NVSTORE_SUCCESS) && !valid) {
        ret = NVSTORE_DATA_CORRUPT;
    }

    _write_lock.shared_unlock();
    return ret;
}

// Start of API functions

int NVStore::get(uint16_t key, uint16_t buf_len_bytes, uint32_t *buf, uint16_t &actual_len_bytes)
{
    return do_get(key, buf_len_bytes, buf, actual_len_bytes, 0);
}

int NVStore::get_item_size(uint16_t key, uint16_t &actual_len_bytes)
{
    return do_get(key, 0, NULL, actual_len_bytes, 1);
}

int NVStore::do_set(uint16_t key, uint16_t buf_len_bytes, const uint32_t *buf, uint16_t flags)
{
    int ret = NVSTORE_SUCCESS;
    uint32_t record_offset, record_size, new_free_space;
    uint32_t next_offset;
    uint8_t save_active_area;

    if (!_init_done) {
        ret = init();
        if (ret != NVSTORE_SUCCESS) {
            return ret;
        }
    }

    if (key >= _max_keys) {
        return NVSTORE_BAD_VALUE;
    }

    if (!buf)
        buf_len_bytes = 0;

    if (buf_len_bytes && !is_buf_aligned(buf, sizeof(uint32_t))) {
        return NVSTORE_BUFF_NOT_ALIGNED;
    }

    if ((flags & DELETE_ITEM_FLAG) && !_offset_by_key[key]) {
        return NVSTORE_NOT_FOUND;
    }

    if (_offset_by_key[key] & OFFS_BY_KEY_SET_ONCE_MASK) {
        return NVSTORE_ALREADY_EXISTS;
    }

    // writers do not lock each other exclusively, but can operate in parallel.
    // Shared lock is in order to prevent GC from operating (which uses exclusive lock).
    _write_lock.shared_lock();

    save_active_area = _active_area;
    record_size = align_up(sizeof(record_header_t) + buf_len_bytes, FLASH_MINIMAL_PROG_UNIT);

    // Parallel operation of writers is allowed due to this atomic operation. This operation
    // produces an offset on which each writer can work separately, without being interrupted
    // by the other writer. The only mutual resource here is _free_space_offset - which
    // gets the correct value because of this atomic increment.
    new_free_space = safe_increment(_free_space_offset, record_size);
    record_offset = new_free_space - record_size;

    // If we cross the area limit, we need to invoke GC. However, we should consider all the cases
    // where writers work in parallel, and we only want the FIRST writer to invoke GC.
    if (new_free_space >= _size) {
        // In the case we have crossed the limit, but the initial offset was still before the limit, this
        // means we are the first writer (common case). Exclusively lock _write_lock, and invoke GC.
        if (record_offset < _size) {
            _write_lock.promote();
            ret = garbage_collection(key, flags, buf_len_bytes, buf);
            _write_lock.exclusive_unlock();
            return ret;
        }
        else {
            // In the case we have crossed the limit, and the initial offset was also after the limit,
            // this means we are not the first writer (uncommon case). Just wait for GC to complete.
            // then write the record.
            _write_lock.shared_unlock();
            for (;;) {
                rtos::Thread::wait(MEDITATE_TIME_MS);
                _write_lock.shared_lock();
                new_free_space = safe_increment(_free_space_offset, record_size);
                // Use the same logics as before to check whether GC is complete
                if (new_free_space < _size) {
                    record_offset = new_free_space - _free_space_offset;
                    break;
                }
                _write_lock.shared_unlock();
            }
        }
    }

    // Now write the record
    ret = write_record(_active_area, record_offset, key, flags, buf_len_bytes, buf, next_offset);
    if (ret != NVSTORE_SUCCESS) {
        _write_lock.shared_unlock();
        return ret;
    }

    // Update _offset_by_key. High bit indicates area.
    if (flags & DELETE_ITEM_FLAG)
        _offset_by_key[key] = 0;
    else
        _offset_by_key[key] = record_offset | (_active_area << OFFS_BY_KEY_AREA_BIT_POS) |
                                (((flags & SET_ONCE_FLAG) != 0) << OFFS_BY_KEY_SET_ONCE_BIT_POS);

    _write_lock.shared_unlock();

    return NVSTORE_SUCCESS;
}

int NVStore::set(uint16_t key, uint16_t buf_len_bytes, const uint32_t *buf)
{
    return do_set(key, buf_len_bytes, buf, 0);
}

int NVStore::set_once(uint16_t key, uint16_t buf_len_bytes, const uint32_t *buf)
{
    return do_set(key, buf_len_bytes, buf, SET_ONCE_FLAG);
}

int NVStore::remove(uint16_t key)
{
    return do_set(key, 0, NULL, DELETE_ITEM_FLAG);
}

int NVStore::init()
{
    uint8_t area;
    uint16_t key;
    uint16_t flags;
    int os_ret;
    int ret = NVSTORE_SUCCESS;
    uint32_t _init_attempts_val;
    area_state_e area_state[NVSTORE_NUM_AREAS];
    uint32_t free_space_offset_of_area[NVSTORE_NUM_AREAS];
    uint16_t versions[NVSTORE_NUM_AREAS];
    uint32_t next_offset;
    master_record_data_t master_rec;
    uint16_t actual_len_bytes;
    int valid;

    if (_init_done)
        return NVSTORE_SUCCESS;

    // This handles the case that init function is called by more than one thread concurrently.
    // Only the one who gets the value of 1 in _init_attempts_val will proceed, while others will
    // wait until init is finished.
    _init_attempts_val = safe_increment(_init_attempts, 1);
    if (_init_attempts_val != 1) {
        while(!_init_done)
            rtos::Thread::wait(MEDITATE_TIME_MS);
        return NVSTORE_SUCCESS;
    }

    _offset_by_key = new uint32_t[_max_keys];
    MBED_ASSERT(_offset_by_key);

    for (key = 0; key < _max_keys; key++) {
        _offset_by_key[key] = 0;
    }

    _size = (uint32_t) -1;
    nvstore_int_flash_init();
    for (area = 0; area < NVSTORE_NUM_AREAS; area++) {
        area_state[area] = AREA_STATE_NONE;
        free_space_offset_of_area[area] =  0;
        versions[area] = 0;

        size_t sector_size = nvstore_int_flash_get_sector_size(flash_area_params[area].address);
        MBED_ASSERT(flash_area_params[area].size >= sector_size);
        MBED_ASSERT((flash_area_params[area].size % sector_size) == 0);

        _size = MIN(_size, flash_area_params[area].size);

        // Find start of empty space at the end of the area. This serves for both
        // knowing whether the area is empty and for the record traversal at the end.
        os_ret = calc_empty_space(area, free_space_offset_of_area[area]);
        MBED_ASSERT(!os_ret);

        if (!free_space_offset_of_area[area]) {
            area_state[area] = AREA_STATE_EMPTY;
            continue;
        }

        // Check validity of master record
        ret = read_record(area, 0, sizeof(master_rec), (uint32_t *) &master_rec,
                          actual_len_bytes, 0, valid,
                          key, flags, next_offset);
        MBED_ASSERT((ret == NVSTORE_SUCCESS) || (ret == NVSTORE_BUFF_TOO_SMALL));
        if (ret == NVSTORE_BUFF_TOO_SMALL) {
            // Buf too small error means that we have a corrupt master record -
            // treat it as such
            valid = 0;
        }

        // We have a non valid master record, in a non-empty area. Just erase the area.
        if ((!valid) || (key != MASTER_RECORD_KEY)) {
            os_ret = flash_erase_area(area);
            MBED_ASSERT(!os_ret);
            area_state[area] = AREA_STATE_EMPTY;
            continue;
        }
        versions[area] = master_rec.version;

        // Place _free_space_offset after the master record (for the traversal,
        // which takes place after this loop).
        _free_space_offset = next_offset;
        area_state[area] = AREA_STATE_VALID;

        // Unless both areas are valid (a case handled later), getting here means
        // that we found our active area.
        _active_area = area;
        _active_area_version = versions[area];
    }

    // In case we have two empty areas, arbitrarily assign 0 to the active one.
    if ((area_state[0] == AREA_STATE_EMPTY) && (area_state[1] == AREA_STATE_EMPTY)) {
        _active_area = 0;
        ret = write_master_record(_active_area, 1, _free_space_offset);
        MBED_ASSERT(ret == NVSTORE_SUCCESS);
        _init_done = 1;
        return NVSTORE_SUCCESS;
    }

    // In case we have two valid areas, choose the one having the higher version (or 0
    // in case of wrap around). Erase the other one.
    if ((area_state[0] == AREA_STATE_VALID) && (area_state[1] == AREA_STATE_VALID)) {
        if ((versions[0] > versions[1]) || (!versions[0]))
            _active_area = 0;
        else
            _active_area = 1;
        _active_area_version = versions[_active_area];
        os_ret = flash_erase_area(1 - _active_area);
        MBED_ASSERT(!os_ret);
    }

    // Traverse area until reaching the empty space at the end or until reaching a faulty record
    while (_free_space_offset < free_space_offset_of_area[_active_area]) {
        ret = read_record(_active_area, _free_space_offset, 0, NULL,
                          actual_len_bytes, 1, valid,
                          key, flags, next_offset);
        MBED_ASSERT(ret == NVSTORE_SUCCESS);

        // In case we have a faulty record, this probably means that the system crashed when written.
        // Perform a garbage collection, to make the the other area valid.
        if (!valid) {
            ret = garbage_collection(NO_KEY, 0, 0, NULL);
            break;
        }
        if (flags & DELETE_ITEM_FLAG)
            _offset_by_key[key] = 0;
        else
            _offset_by_key[key] = _free_space_offset | (_active_area << OFFS_BY_KEY_AREA_BIT_POS) |
                                    (((flags & SET_ONCE_FLAG) != 0) << OFFS_BY_KEY_SET_ONCE_BIT_POS);
        _free_space_offset = next_offset;
    }

    _init_done = 1;
    return NVSTORE_SUCCESS;
}

int NVStore::deinit()
{
    if (_init_done) {
        nvstore_int_flash_deinit();
        delete[] _offset_by_key;
    }

    _init_attempts = 0;
    _init_done = 0;

    return NVSTORE_SUCCESS;
}

int NVStore::reset()
{
    uint8_t area;
    int os_ret;

    // Erase both areas, and reinitialize the module. This is totally not thread safe,
    // as init doesn't take the case of re-initialization into account. It's OK, as this function
    // should only be called in pre-production cases.
    for (area = 0; area < NVSTORE_NUM_AREAS; area++) {
        os_ret = flash_erase_area(area);
        if (os_ret)
            return NVSTORE_WRITE_ERROR;
    }

    deinit();
    return init();
}

uint32_t NVStore::size()
{
    if (!_init_done) {
        init();
    }

    return _size;
}

#ifdef NVSTORE_TESTING

int NVStore::force_garbage_collection(void)
{
    int ret;

    if (!_init_done) {
        ret = init();
        if (ret != NVSTORE_SUCCESS)
            return ret;
    }

    _write_lock.exclusive_lock();
    ret = garbage_collection(NO_KEY, 0, 0, NULL);
    _write_lock.exclusive_release();
    return ret;
}

#endif


int NVStore::probe(uint16_t key, uint16_t buf_len_bytes, uint32_t *buf, uint16_t &actual_len_bytes)
{

    uint8_t area;
    int sel_area = -1;
    uint16_t read_type;
    uint16_t flags;
    int os_ret;
    int ret = NVSTORE_SUCCESS, save_ret = NVSTORE_SUCCESS;
    uint32_t free_space_offset_of_area = 0;
    uint32_t curr_offset = 0, next_offset;
    master_record_data_t master_rec;
    uint16_t prev_version = 0;
    uint16_t tmp_actual_len_bytes;
    int valid;
    int found = 0;

    for (area = 0; area < NVSTORE_NUM_AREAS; area++) {
        // Check validity of master record
        ret = read_record(area, 0, sizeof(master_rec), (uint32_t *) &master_rec,
                          actual_len_bytes, 0, valid,
                          read_type, flags, next_offset);
        if (ret != NVSTORE_SUCCESS) {
            if (ret == NVSTORE_BUFF_TOO_SMALL) {
                // Buf too small error means that we have a corrupt master record -
                // treat it as such, move to next area.
                continue;
            }
            else {
                PR_ERR("nvstore_probe_type: read_record failed with err code 0x%x\n", ret);
                return ret;
            }
        }

        // We have a non valid master record, move to next area.
        if ((!valid) || (read_type != MASTER_RECORD_KEY)) {
            continue;
        }

        // Use similar logic of init's way of handling two valid areas (without erasing them of course)
        if ((area == 1) && (sel_area > 0)) {
            if ((!prev_version) || (prev_version > master_rec.version)) {
                // leave selected area as 0
                break;
            }
        }

        prev_version = master_rec.version;
        curr_offset = next_offset;
        sel_area = area;
    }

    if (sel_area < 0) {
        return NVSTORE_NOT_FOUND;
    }

    area = (uint8_t) sel_area;
    os_ret = calc_empty_space(area, free_space_offset_of_area);
    if (os_ret) {
        PR_ERR("nvstore_probe_type: calc_empty_space failed with err code 0x%lx\n",
                (unsigned long) os_ret);
        return NVSTORE_READ_ERROR;
    }

    // Traverse area until reaching the empty space at the end or until reaching a faulty record
    found = false;
    while (curr_offset < free_space_offset_of_area) {
        // first just verify, then read to user buffer
        ret = read_record(area, curr_offset, 0, NULL,
                          tmp_actual_len_bytes, 1, valid,
                          read_type, flags, next_offset);
        if (ret != NVSTORE_SUCCESS) {
            PR_ERR("nvstore_probe_type: read_record failed with err code 0x%x\n", ret);
            return ret;
        }
        if (!valid) {
            break;
        }

        if (read_type == key) {
            if (flags & DELETE_ITEM_FLAG) {
                found = false;
            }
            else {
                save_ret = read_record(area, curr_offset, buf_len_bytes, buf,
                                  actual_len_bytes, false, valid,
                                  read_type, flags, next_offset);
                found = true;
            }
        }
        curr_offset = next_offset;
    }

    if (!found) {
        return NVSTORE_NOT_FOUND;
    }

    return save_ret;
}

#endif // NVSTORE_ENABLED
