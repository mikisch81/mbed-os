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



#ifndef __NVSTORE_SHARED_LOCK_H
#define __NVSTORE_SHARED_LOCK_H

#include <stdint.h>
#include "rtos/Mutex.h"

enum {
    NVSTORE_OS_OK          =  0,
    NVSTORE_OS_RTOS_ERR    = -1,
    NVSTORE_OS_INV_ARG_ERR = -2,
    NVSTORE_OS_NO_MEM_ERR  = -3,
};

/**
 * SharedLock, implements a shared/exclusive lock (AKA RW lock).
 * This class doesn't implement this kind of lock in the classic manner (having two Mutexes and a counter).
 * Instead, it uses one Mutex and one atomic counter, favouring the shared usage of the exclusive one.
 */

class NVstoreSharedLock {
public:
    NVstoreSharedLock();
    virtual ~NVstoreSharedLock();

    /**
     * @brief Locks the shared lock in a shared manner.
     *
     * @returns 0 for success, error code otherwise.
     */
    int shared_lock();

    /**
     * @brief Unlocks the shared lock in a shared manner.
     *
     * @returns 0 for success, error code otherwise.
     */
    int shared_unlock();

    /**
     * @brief Locks the shared lock in an exclusive manner.
     *
     * @returns 0 for success, error code otherwise.
     */
    int exclusive_lock();

    /**
     * @brief Unlocks the shared lock in an exclusive manner.
     *
     * @returns 0 for success, error code otherwise.
     */
    int exclusive_unlock();

    /**
     * @brief Promotes the shared lock from shared to exclusive.
     *
     * @returns 0 for success, error code otherwise.
     */
    int promote();

private:
    uint32_t ctr;
    rtos::Mutex  mutex;
};


#endif
