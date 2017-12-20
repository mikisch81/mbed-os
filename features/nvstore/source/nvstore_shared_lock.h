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



#ifndef __NVSTORE_OS_WRAPPER_H
#define __NVSTORE_OS_WRAPPER_H

#include <stdint.h>
#include "rtos/Mutex.h"

enum {
    NVSTORE_OS_OK          =  0,
    NVSTORE_OS_RTOS_ERR    = -1,
    NVSTORE_OS_INV_ARG_ERR = -2,
    NVSTORE_OS_NO_MEM_ERR  = -3,
};

class SharedLock {
public:
    SharedLock();
    virtual ~SharedLock();

    int shared_lock();
    int shared_unlock();
    int exclusive_lock();
    int exclusive_unlock();
    int promote();
private:
    uint32_t ctr;
    rtos::Mutex  mutex;
};


#endif
