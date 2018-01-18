/****************************************************************************
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef RT_MANAGER_H_
#define RT_MANAGER_H_

#include "ocf_types.h"

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

ocf_result_t ocf_init(ocf_mode_t mode, const char *manufacturer_name, ocf_dmv_t data_model_ver_bit);
ocf_result_t ocf_terminate(void);

#endif

#ifdef __cplusplus
}
#endif							// __cplusplus
