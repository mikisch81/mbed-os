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

#include "nvstore_shared_lock.h"
#include "mbed_critical.h"
#ifdef MBED_CONF_RTOS_PRESENT
#include "Thread.h"
#endif
#include <stdio.h>


// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define MEDITATE_TIME_MS 1

// -------------------------------------------------- Functions Implementation ----------------------------------------------------


NVstoreSharedLock::NVstoreSharedLock() : _ctr(0), _mutex(0)
{
    reset();
}

NVstoreSharedLock::~NVstoreSharedLock()
{
    delete _mutex;
}

int NVstoreSharedLock::reset()
{
    // Reallocate mutex. Good in cases it's taken by a terminated thread (can be relevant in tests).
    if (_mutex) {
        delete _mutex;
        _mutex = 0;
    }

    if (!_mutex) {
        _mutex = new PlatformMutex;
        MBED_ASSERT(_mutex);
    }

    _ctr = 0;

    return 0;
}

int NVstoreSharedLock::shared_lock()
{
    _mutex->lock();

    core_util_atomic_incr_u32(&_ctr, 1);

    _mutex->unlock();
    return NVSTORE_OS_OK;
}

int NVstoreSharedLock::shared_unlock()
{
    int val = core_util_atomic_decr_u32(&_ctr, 1);
    if (val < 0) {
        return NVSTORE_OS_RTOS_ERR;
    }

    return NVSTORE_OS_OK;
}

int NVstoreSharedLock::exclusive_lock()
{
    _mutex->lock();

#ifdef MBED_CONF_RTOS_PRESENT
    while(_ctr)
        rtos::Thread::wait(MEDITATE_TIME_MS);
#endif

    return NVSTORE_OS_OK;
}

int NVstoreSharedLock::exclusive_unlock()
{
    _mutex->unlock();

    return NVSTORE_OS_OK;
}

int NVstoreSharedLock::promote()
{
    _mutex->lock();
#ifdef MBED_CONF_RTOS_PRESENT
    while(_ctr > 1) {
        rtos::Thread::wait(MEDITATE_TIME_MS);
    }
#endif

    if (_ctr != 1) {
        return NVSTORE_OS_RTOS_ERR;
    }

    core_util_atomic_decr_u32(&_ctr, 1);

    return NVSTORE_OS_OK;
}

