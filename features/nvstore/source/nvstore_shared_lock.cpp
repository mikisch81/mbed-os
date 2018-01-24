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
#include "rtos/thread.h"
#include <stdio.h>


// --------------------------------------------------------- Definitions ----------------------------------------------------------

#define MEDITATE_TIME_MS 1

// -------------------------------------------------- Functions Implementation ----------------------------------------------------


SharedLock::SharedLock() : ctr(0)
{
}

SharedLock::~SharedLock()
{
}

int SharedLock::shared_lock()
{
    mutex.lock();

    core_util_atomic_incr_u32(&ctr, 1);

    mutex.unlock();
    return NVSTORE_OS_OK;
}

int SharedLock::shared_unlock()
{
    int val = core_util_atomic_decr_u32(&ctr, 1);
    if (val < 0) {
        return NVSTORE_OS_RTOS_ERR;
    }

    return NVSTORE_OS_OK;
}

int SharedLock::exclusive_lock()
{
    mutex.lock();

    while(ctr)
        rtos::Thread::wait(MEDITATE_TIME_MS);

    return NVSTORE_OS_OK;
}

int SharedLock::exclusive_unlock()
{
    mutex.unlock();

    return NVSTORE_OS_OK;
}

int SharedLock::promote()
{
    mutex.lock();
    while(ctr > 1) {
        rtos::Thread::wait(MEDITATE_TIME_MS);
    }

    if (ctr != 1) {
        return NVSTORE_OS_RTOS_ERR;
    }

    core_util_atomic_decr_u32(&ctr, 1);

    return NVSTORE_OS_OK;
}

