/*
 * Copyright (c) 2016 ARM Limited. All rights reserved.
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

#include "mbed.h"

#include "mbed_critical.h"
#include "rtos/thread.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef NVSTORE_THREAD_SAFE
#define NVSTORE_THREAD_SAFE 1
#endif


// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define MEDITATE_TIME_MS 100

typedef struct {
    uint32_t ctr;
    rtos::Mutex  mutex;
} shared_lock_priv_t;

// -------------------------------------------------- Functions Implementation ----------------------------------------------------


SharedLock::SharedLock() : ctr(0)
{
}

SharedLock::~SharedLock()
{
}

int SharedLock::shared_lock()
{
#if NVSTORE_THREAD_SAFE
    mutex.lock();

    core_util_atomic_incr_u32(&ctr, 1);

    mutex.unlock();
#endif
    return NVSTORE_OS_OK;
}

int SharedLock::shared_unlock()
{
#if NVSTORE_THREAD_SAFE
    int val = core_util_atomic_decr_u32(&ctr, 1);
    if (val < 0) {
        return NVSTORE_OS_RTOS_ERR;
    }
#endif

    return NVSTORE_OS_OK;
}

int SharedLock::exclusive_lock()
{
#if NVSTORE_THREAD_SAFE
    mutex.lock();

    while(ctr)
        rtos::Thread::wait(MEDITATE_TIME_MS);
#endif

    return NVSTORE_OS_OK;
}

int SharedLock::exclusive_unlock()
{
#if NVSTORE_THREAD_SAFE
    mutex.unlock();
#endif

    return NVSTORE_OS_OK;
}

int SharedLock::promote()
{
#if NVSTORE_THREAD_SAFE

    mutex.lock();
    while(ctr > 1) {
        rtos::Thread::wait(MEDITATE_TIME_MS);
    }

    if (ctr != 1) {
        return NVSTORE_OS_RTOS_ERR;
    }

    core_util_atomic_decr_u32(&ctr, 1);
#endif

    return NVSTORE_OS_OK;
}

