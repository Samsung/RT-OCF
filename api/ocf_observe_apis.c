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

#include "rt_observe.h"
#include "rt_rep.h"

ocf_result_t ocf_observe_register(ocf_endpoint_s *endpoint, const char *uri_path, observe_callback callback)
{
	return rt_observe_register(endpoint, uri_path, callback);
}

ocf_result_t ocf_observe_deregister(ocf_endpoint_s *endpoint, const char *uri_path)
{
	return rt_observe_deregister(endpoint, uri_path);
}

ocf_result_t ocf_observe_notify(const char *href, ocf_rep_encoder_s rep)
{
	return rt_observe_notify(href, (rt_rep_encoder_s *)rep);
}
