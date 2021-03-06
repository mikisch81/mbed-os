/*
 * Copyright (c) 2018, Arm Limited and affiliates.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "QUECTEL_UG96_CellularContext.h"

namespace mbed {

QUECTEL_UG96_CellularContext::QUECTEL_UG96_CellularContext(ATHandler &at, CellularDevice *device, const char *apn) :
    AT_CellularContext(at, device, apn)
{
}

QUECTEL_UG96_CellularContext::~QUECTEL_UG96_CellularContext()
{
}

bool QUECTEL_UG96_CellularContext::stack_type_supported(nsapi_ip_stack_t stack_type)
{
    return stack_type == IPV4_STACK ? true : false;
}

nsapi_error_t QUECTEL_UG96_CellularContext::do_user_authentication()
{
    if (_pwd && _uname) {
        _at.cmd_start("AT+QICSGP=");
        _at.write_int(_cid);
        _at.write_int(1); // context type 1=IPv4
        _at.write_string(_apn);
        _at.write_string(_uname);
        _at.write_string(_pwd);
        _at.write_int(_authentication_type);
        _at.cmd_stop();
        _at.resp_start();
        _at.resp_stop();
        if (_at.get_last_error() != NSAPI_ERROR_OK) {
            return NSAPI_ERROR_AUTH_FAILURE;
        }
    }

    return NSAPI_ERROR_OK;
}

} /* namespace mbed */
