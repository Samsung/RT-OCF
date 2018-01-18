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

#include "rt_resources.h"
#include "rt_sec_persistent_storage.h"
#include "rt_sec_cred_resource.h"
#include "rt_resources_manager.h"
#include "rt_rep.h"
#include "rt_logger.h"
#include "rt_sec_types.h"
#include "rt_mem.h"

#define TAG "RT_SEC_CRED"

static const char *rt_encoding_string[] = {
	"oic.sec.encoding.raw",
	"oic.sec.encoding.base64",
	"oic.sec.encoding.pem",
	"oic.sec.encoding.der"
};

static rt_sec_credential_s *g_sec_cred = NULL;
static rt_resource_s *g_cred_resource = NULL;

// static rt_rep_encoder_s *rt_convert_cred_to_payload(rt_sec_credential_s *cred, bool response)
rt_rep_encoder_s *rt_convert_cred_to_payload(rt_sec_credential_s *cred, bool response)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	//TODO : Delete this after testing
	if (cred == NULL) {
		cred = g_sec_cred;
	}
	//TODO : Delete this after testing

	RT_VERIFY_NON_NULL_RET(cred, TAG, "cred", NULL);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_uuid_str_t uuid_str;

	if (response) {
		rt_res_add_if_rt_rep(rep, g_cred_resource);
	}

	rt_rep_encoder_s *cred_array = rt_rep_encoder_init(OCF_REP_ARRAY);

	rt_node_s *itr = cred->creds.head;
	while (itr) {
		rt_rep_encoder_s *cred_map = rt_rep_encoder_init(OCF_REP_MAP);

		rt_sec_creds_s *var = (rt_sec_creds_s *) rt_list_get_item(&g_sec_cred->creds, itr);

		//Set credid
		rt_rep_add_int_to_map(cred_map, OCF_CREDID_NAME, var->cred_id);

		//Set subjectuuid
		if (rt_uuid_is_astrict(var->subject_id)) {
			rt_rep_add_string_to_map(cred_map, OCF_SUBJECTUUID_NAME, OCF_WILDCARD_ALL);
		} else {
			rt_uuid_uuid2str(var->subject_id, uuid_str, RT_UUID_STR_LEN);
			rt_rep_add_string_to_map(cred_map, OCF_SUBJECTUUID_NAME, uuid_str);
		}

		//Set credtype
		rt_rep_add_int_to_map(cred_map, OCF_CREDTYPE_NAME, var->cred_type);

		//Set period
		rt_rep_add_string_to_map(cred_map, OCF_PERIOD_NAME, var->period);

		//Optional Start
		//Set credusage
		if (var->cred_usage != NULL) {
			rt_rep_add_string_to_map(cred_map, OCF_CREDUSAGE_NAME, var->cred_usage);
		}
		//Set publicdata
		if (var->public_data.data != NULL) {
			rt_rep_encoder_s *key_data = rt_rep_encoder_init(OCF_REP_MAP);
			rt_rep_add_string_to_map(key_data, OCF_ENCODING_NAME, rt_encoding_string[var->public_data.encoding]);
			if (var->public_data.encoding == RT_ENCODING_PEM) {
				rt_rep_add_string_to_map(key_data, OCF_KEY_DATA_NAME, (char *)var->public_data.data);
			} else if (var->public_data.encoding == RT_ENCODING_DER) {
				rt_rep_add_byte_to_map(key_data, OCF_KEY_DATA_NAME, var->public_data.data, var->public_data.len);
			}
			rt_rep_add_map_to_map(cred_map, OCF_PUBLICDATA_NAME, key_data);
			rt_rep_encoder_release(key_data);
		}
		//Set privatedata
		if (var->private_data.data != NULL) {
			rt_rep_encoder_s *key_data = rt_rep_encoder_init(OCF_REP_MAP);
			rt_rep_add_string_to_map(key_data, OCF_ENCODING_NAME, rt_encoding_string[var->private_data.encoding]);
			if (var->private_data.encoding == RT_ENCODING_BASE64) {
				rt_rep_add_string_to_map(key_data, OCF_KEY_DATA_NAME, (response ? "" : (char *)var->private_data.data));
			} else if (var->private_data.encoding == RT_ENCODING_RAW) {
				rt_rep_add_byte_to_map(key_data, OCF_KEY_DATA_NAME, var->private_data.data, (response ? 0 : var->private_data.len));
			}
			rt_rep_add_map_to_map(cred_map, OCF_PRIVATEDATA_NAME, key_data);
			rt_rep_encoder_release(key_data);
		}
		//Set optional data
		if (var->optional_data.data != NULL) {
			rt_rep_encoder_s *key_data = rt_rep_encoder_init(OCF_REP_MAP);
			rt_rep_add_string_to_map(key_data, OCF_ENCODING_NAME, rt_encoding_string[var->optional_data.encoding]);
			if (var->optional_data.encoding == RT_ENCODING_PEM) {
				rt_rep_add_string_to_map(key_data, OCF_KEY_DATA_NAME, (char *)var->optional_data.data);
			} else if (var->optional_data.encoding == RT_ENCODING_DER) {
				rt_rep_add_byte_to_map(key_data, OCF_KEY_DATA_NAME, var->optional_data.data, var->optional_data.len);
			}
			rt_rep_add_bool_to_map(key_data, OCF_REVSTAT_NAME, var->optional_data.revstat);

			rt_rep_add_map_to_map(cred_map, OCF_OPTIONALDATA_NAME, key_data);
			rt_rep_encoder_release(key_data);
		}
		rt_rep_add_map_to_array(cred_array, cred_map);
		rt_rep_encoder_release(cred_map);

		itr = itr->next;
	}

	rt_rep_add_array_to_map(rep, OCF_CREDS_NAME, cred_array);
	rt_rep_encoder_release(cred_array);

	// Set rowneruuid
	if (rt_uuid_is_empty(cred->rowner_id) == false) {
		rt_uuid_uuid2str(cred->rowner_id, uuid_str, RT_UUID_STR_LEN);
		rt_rep_add_string_to_map(rep, OCF_ROWNERUUID_NAME, uuid_str);
	}

	RT_LOG_D(TAG, "%s : OUT", __func__);
	return rep;
}

static ocf_result_t rt_convert_payload_to_cred(rt_sec_credential_s *out, rt_rep_decoder_s *rep)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_rep_decoder_s credential;
	rt_rep_decoder_s cred[1];
	rt_rep_decoder_s key_data[1];
	ocf_result_t ret = OCF_OK;
	size_t len;
	char *cbor_string = NULL;

	ret = rt_rep_get_array_from_map(rep, OCF_CREDS_NAME, &credential);
	if (ret != OCF_OK) {
		goto exit;
	}
	uint16_t num = 0;
	ret = rt_rep_get_array_length(&credential, &num);
	int i;
	for (i = 0; i < num; i++) {
		rt_rep_get_map_from_array(&credential, i, cred);

		// rt_sec_creds_s initialize
		rt_sec_creds_s *item = (rt_sec_creds_s *) rt_mem_alloc(sizeof(rt_sec_creds_s));
		RT_VERIFY_NON_NULL_RET(item, TAG, "item is null", OCF_MEM_FULL);
		item->cred_usage = NULL;
		item->period = NULL;
		item->public_data.data = NULL;
		item->private_data.data = NULL;
		item->optional_data.data = NULL;
		memset(item->subject_id, 0, RT_UUID_LEN);

		// Set cred_id
		item->cred_id = g_sec_cred->max_cred_id++;

		// Set subject uuid
		ret = rt_rep_get_string_length_from_map(cred, OCF_SUBJECTUUID_NAME, &len);
		if (ret != OCF_OK) {
			goto exit;
		}
		if (OCF_WILDCARD_LEN == len) {
			memcpy(item->subject_id, OCF_WILDCARD_ALL, OCF_WILDCARD_LEN + 1);
		} else if (0 < len) {
			cbor_string = rt_mem_alloc(len + 1);
			RT_VERIFY_NON_NULL_RET(cbor_string, TAG, "cbor_string is null", OCF_MEM_FULL);
			ret = rt_rep_get_string_from_map(cred, OCF_SUBJECTUUID_NAME, cbor_string);
			if (ret != OCF_OK) {
				goto exit;
			}
			ret = rt_uuid_str2uuid(cbor_string, item->subject_id);
			if (ret != OCF_OK) {
				goto exit;
			}
			rt_mem_free(cbor_string);
			cbor_string = NULL;
		}
		// Set cred type
		ret = rt_rep_get_int_from_map(cred, OCF_CREDTYPE_NAME, (int *)&item->cred_type);
		if (ret != OCF_OK) {
			goto exit;
		}
		// Set cred usage
		if (OCF_OK == rt_rep_get_string_length_from_map(cred, OCF_CREDUSAGE_NAME, &len)) {
			if (0 < len) {
				item->cred_usage = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(item->cred_usage, TAG, "item->cred_usage is null", OCF_MEM_FULL);
				ret = rt_rep_get_string_from_map(cred, OCF_CREDUSAGE_NAME, item->cred_usage);
				if (ret != OCF_OK) {
					goto exit;
				}
			}
		}
		// Set period
		if (OCF_OK == rt_rep_get_string_length_from_map(cred, OCF_PERIOD_NAME, &len)) {
			if (0 < len) {
				item->period = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(item->period, TAG, "item->period is null", OCF_MEM_FULL);
				ret = rt_rep_get_string_from_map(cred, OCF_PERIOD_NAME, item->period);
				if (ret != OCF_OK) {
					goto exit;
				}
			}
		}
		// Set public data
		if (OCF_OK == rt_rep_get_map_from_map(cred, OCF_PUBLICDATA_NAME, key_data)) {
			rt_rep_get_string_length_from_map(key_data, OCF_ENCODING_NAME, &len);
			if (0 < len) {
				cbor_string = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(cbor_string, TAG, "cbor_string is null", OCF_MEM_FULL);
				ret = rt_rep_get_string_from_map(key_data, OCF_ENCODING_NAME, cbor_string);
				if (ret != OCF_OK) {
					goto exit;
				}

				if (strncmp(cbor_string, rt_encoding_string[RT_ENCODING_DER], len) == 0) {
					item->public_data.encoding = RT_ENCODING_DER;
					ret = rt_rep_get_byte_length_from_map(key_data, OCF_KEY_DATA_NAME, &item->public_data.len);
					if (ret != OCF_OK) {
						goto exit;
					}
					item->public_data.data = rt_mem_alloc(item->public_data.len);
					RT_VERIFY_NON_NULL_RET(item->public_data.data, TAG, "item->public_data.data is null", OCF_MEM_FULL);
					ret = rt_rep_get_byte_from_map(key_data, OCF_KEY_DATA_NAME, item->public_data.data);
					if (ret != OCF_OK) {
						goto exit;
					}
				} else if (strncmp(cbor_string, rt_encoding_string[RT_ENCODING_PEM], len) == 0) {
					item->public_data.encoding = RT_ENCODING_PEM;
					ret = rt_rep_get_string_length_from_map(key_data, OCF_KEY_DATA_NAME, &item->public_data.len);
					if (ret != OCF_OK) {
						goto exit;
					}
					item->public_data.data = rt_mem_alloc(item->public_data.len + 1);
					RT_VERIFY_NON_NULL_RET(item->public_data.data, TAG, "item->public_data.data is null", OCF_MEM_FULL);
					ret = rt_rep_get_string_from_map(key_data, OCF_KEY_DATA_NAME, (char *)item->public_data.data);
					if (ret != OCF_OK) {
						goto exit;
					}
				}
				rt_mem_free(cbor_string);
				cbor_string = NULL;
			}
		}
		// Set optional data
		if (OCF_OK == rt_rep_get_map_from_map(cred, OCF_OPTIONALDATA_NAME, key_data)) {
			rt_rep_get_bool_from_map(key_data, OCF_REVSTAT_NAME, &item->optional_data.revstat);
			ret = rt_rep_get_string_length_from_map(key_data, OCF_ENCODING_NAME, &len);
			if (0 < len) {
				cbor_string = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(cbor_string, TAG, "cbor_string is null", OCF_MEM_FULL);
				ret = rt_rep_get_string_from_map(key_data, OCF_ENCODING_NAME, cbor_string);
				if (ret != OCF_OK) {
					goto exit;
				}

				if (strncmp(cbor_string, rt_encoding_string[RT_ENCODING_DER], len) == 0) {
					item->optional_data.encoding = RT_ENCODING_DER;
					ret = rt_rep_get_byte_length_from_map(key_data, OCF_KEY_DATA_NAME, &item->optional_data.len);
					if (ret != OCF_OK) {
						goto exit;
					}
					item->optional_data.data = rt_mem_alloc(item->optional_data.len);
					RT_VERIFY_NON_NULL_RET(item->optional_data.data, TAG, "item->optional_data.data is null", OCF_MEM_FULL);
					ret = rt_rep_get_byte_from_map(key_data, OCF_KEY_DATA_NAME, item->optional_data.data);
					if (ret != OCF_OK) {
						goto exit;
					}
				} else if (strncmp(cbor_string, rt_encoding_string[RT_ENCODING_PEM], len) == 0) {
					item->optional_data.encoding = RT_ENCODING_PEM;
					ret = rt_rep_get_string_length_from_map(key_data, OCF_KEY_DATA_NAME, &item->optional_data.len);
					if (ret != OCF_OK) {
						goto exit;
					}
					item->optional_data.data = rt_mem_alloc(item->optional_data.len + 1);
					RT_VERIFY_NON_NULL_RET(item->optional_data.data, TAG, "item->optional_data.data is null", OCF_MEM_FULL);
					ret = rt_rep_get_string_from_map(key_data, OCF_KEY_DATA_NAME, (char *)item->optional_data.data);
					if (ret != OCF_OK) {
						goto exit;
					}
				}
				rt_mem_free(cbor_string);
				cbor_string = NULL;
			}
		}
		// Set private data
		if (OCF_OK == rt_rep_get_map_from_map(cred, OCF_PRIVATEDATA_NAME, key_data)) {
			len = 0;
			rt_rep_get_string_length_from_map(key_data, OCF_ENCODING_NAME, &len);
			if (0 < len) {
				cbor_string = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(cbor_string, TAG, "cbor_string is null", OCF_MEM_FULL);
				ret = rt_rep_get_string_from_map(key_data, OCF_ENCODING_NAME, cbor_string);
				if (ret != OCF_OK) {
					goto exit;
				}

				if (strncmp(cbor_string, rt_encoding_string[RT_ENCODING_RAW], len) == 0) {
					item->private_data.encoding = RT_ENCODING_RAW;
					ret = rt_rep_get_byte_length_from_map(key_data, OCF_KEY_DATA_NAME, &item->private_data.len);
					if (ret != OCF_OK) {
						goto exit;
					}
					item->private_data.data = rt_mem_alloc(item->private_data.len);
					RT_VERIFY_NON_NULL_RET(item->private_data.data, TAG, "item->private_data.data is null", OCF_MEM_FULL);
					ret = rt_rep_get_byte_from_map(key_data, OCF_KEY_DATA_NAME, item->private_data.data);
					if (ret != OCF_OK) {
						goto exit;
					}
				} else if (strncmp(cbor_string, rt_encoding_string[RT_ENCODING_BASE64], len) == 0) {
					item->private_data.encoding = RT_ENCODING_BASE64;
					ret = rt_rep_get_string_length_from_map(key_data, OCF_KEY_DATA_NAME, &item->private_data.len);
					if (ret != OCF_OK) {
						goto exit;
					}
					item->private_data.data = rt_mem_alloc(item->private_data.len + 1);
					RT_VERIFY_NON_NULL_RET(item->private_data.data, TAG, "item->private_data.data is null", OCF_MEM_FULL);
					ret = rt_rep_get_string_from_map(key_data, OCF_KEY_DATA_NAME, (char *)item->private_data.data);
					if (ret != OCF_OK) {
						goto exit;
					}
				}
				rt_mem_free(cbor_string);
				cbor_string = NULL;
			}
		}
		rt_list_insert(&out->creds, &item->node);
	}

	len = 0;
	rt_rep_get_string_length_from_map(rep, OCF_ROWNERUUID_NAME, &len);
	if (0 < len) {
		cbor_string = rt_mem_alloc(len + 1);
		RT_VERIFY_NON_NULL_RET(cbor_string, TAG, "cbor_string is null", OCF_MEM_FULL);
		ret = rt_rep_get_string_from_map(rep, OCF_ROWNERUUID_NAME, cbor_string);
		if (ret != OCF_OK) {
			goto exit;
		}
		ret = rt_uuid_str2uuid(cbor_string, out->rowner_id);
		if (ret != OCF_OK) {
			goto exit;
		}
		rt_mem_free(cbor_string);
		cbor_string = NULL;
	}

exit:
	if (cbor_string != NULL) {
		rt_mem_free(cbor_string);
		cbor_string = NULL;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return ret;
}

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	rt_rep_encoder_s *rep = rt_convert_cred_to_payload(g_sec_cred, true);

	rt_response_send((rt_request_s *) request, rep, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep);

	RT_LOG_D(TAG, "%s : OUT", __func__);
}

static void post_handler_func(ocf_request_s request, ocf_rep_decoder_s *data)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	// size_t size = 0;
	rt_sec_credential_s *credential = rt_mem_alloc(sizeof(rt_sec_credential_s));
	RT_VERIFY_NON_NULL_VOID(credential, TAG, "credential is null");
	
	// TODO: Need to update post handler for cred resource
	// ret = rt_convert_payload_to_cred(credential, data);
	// rt_sec_cred_update(credential);

	rt_mem_free(credential);
	credential = NULL;

	RT_LOG_D(TAG, "%s : OUT", __func__);
}

static ocf_result_t rt_sec_init_cred_resource(void)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	if (g_cred_resource != NULL) {
		RT_LOG_D(TAG, "cred already init");
		return OCF_ALREADY_INIT;
	}

	g_cred_resource = rt_res_new_resource(OCF_CRED_HREF);
	rt_res_set_discoverable(g_cred_resource, true);
	rt_res_set_observable(g_cred_resource, false);
	rt_res_set_interface(g_cred_resource, OIC_IF_BASELINE);
	const char *g_cred_resource_types[1] = { OCF_CRED_RT };
	rt_res_set_resource_types(g_cred_resource, g_cred_resource_types, 1);
	// TODO : Add put, post, delete handler
	rt_res_set_request_handler(g_cred_resource, OCF_GET, get_handler_func);
	rt_res_set_secure(g_cred_resource, true);
	// TODO : Should sync with device protocol
	rt_res_set_resource_protocol(g_cred_resource, OCF_COAP | OCF_COAPS | OCF_COAP_TCP | OCF_COAPS_TCP);

	RT_LOG_D(TAG, "%s : OUT", __func__);

	return rt_res_register_resource(g_cred_resource);
}

ocf_result_t rt_sec_cred_init(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_rep_decoder_s *rep = NULL;

	if (g_sec_cred != NULL) {
		RT_LOG_W(TAG, "cred already init");
		return OCF_ALREADY_INIT;
	}
	g_sec_cred = (rt_sec_credential_s *) rt_mem_alloc(sizeof(rt_sec_credential_s));
	RT_VERIFY_NON_NULL_RET(g_sec_cred, TAG, "g_sec_cred is null", OCF_MEM_FULL);

	ocf_result_t ret = rt_sec_load_ps(RT_SEC_CRED, &rep);
	if (OCF_OK != ret) {
		goto exit;
	}

	rt_list_init(&g_sec_cred->creds, sizeof(rt_sec_creds_s), RT_MEMBER_OFFSET(rt_sec_creds_s, node));
	memset(g_sec_cred->rowner_id, 0, RT_UUID_LEN);
	g_sec_cred->max_cred_id = 1;

	if (rt_convert_payload_to_cred(g_sec_cred, rep) != OCF_OK) {
		ret = OCF_ERROR;
		goto exit;
	}

	rt_rep_decoder_release(rep);
	rep = NULL;

	rt_sec_init_cred_resource();

exit:
	if (rep) {
		rt_rep_decoder_release(rep);
	}
	RT_LOG_D(TAG, "%s : OUT", __func__);
	return ret;
}

ocf_result_t rt_sec_cred_get_by_subjectuuid(const rt_uuid_t uuid, rt_sec_creds_s **cred)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	ocf_result_t ret = OCF_ERROR;

	rt_node_s *itr = g_sec_cred->creds.head;
	while (itr) {
		rt_sec_creds_s *var = (rt_sec_creds_s *) rt_list_get_item(&g_sec_cred->creds, itr);
		itr = itr->next;
		if (memcmp(uuid, var->subject_id, RT_UUID_LEN) == 0) {
			*cred = var;
			ret = OCF_OK;
			break;
		}
	}

	RT_LOG_D(TAG, "%s : OUT", __func__);
	return ret;
}

ocf_result_t rt_sec_cred_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (NULL == g_sec_cred) {
		RT_LOG_W(TAG, "cred resource is not initialized");
		return OCF_ERROR;
	}

	rt_node_s *itr = g_sec_cred->creds.head;
	while (itr) {
		rt_sec_creds_s *var = (rt_sec_creds_s *) rt_list_get_item(&g_sec_cred->creds, itr);
		itr = itr->next;
		if (var->cred_usage != NULL) {
			rt_mem_free(var->cred_usage);
			var->cred_usage = NULL;
		}
		if (var->period != NULL) {
			rt_mem_free(var->period);
			var->period = NULL;
		}
		if (var->public_data.data != NULL) {
			rt_mem_free(var->public_data.data);
			var->public_data.data = NULL;
		}
		if (var->optional_data.data != NULL) {
			rt_mem_free(var->optional_data.data);
			var->optional_data.data = NULL;
		}
		if (var->private_data.data != NULL) {
			rt_mem_free(var->private_data.data);
			var->private_data.data = NULL;
		}
		rt_mem_free(var);
	}
	rt_mem_free(g_sec_cred);
	g_sec_cred = NULL;
	g_cred_resource = NULL;
	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_sec_cred_get_psk(const uint8_t *uuid, size_t uuid_len, uint8_t *psk, size_t *psk_len)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(psk, TAG, "psk is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(uuid, TAG, "uuid is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(psk_len, TAG, "psk_len is NULL", OCF_INVALID_PARAM);
	if (RT_UUID_LEN != uuid_len) {
		RT_LOG_E(TAG, "UUID is invaild length, %s OUT", __func__);
		return OCF_INVALID_PARAM;
	}
	rt_sec_creds_s *cred = NULL;
	if (OCF_OK == rt_sec_cred_get_by_subjectuuid(uuid, &cred) && (SYMMETRIC_PAIR_WISE_KEY == cred->cred_type)) {
		if (RT_ENCODING_RAW == cred->private_data.encoding) {
			*psk_len = cred->private_data.len;
			memcpy(psk, cred->private_data.data, *psk_len);
			RT_LOG_D(TAG, "%s OUT", __func__);
			return OCF_OK;
		}
		//TODO : Add other encoding types
		else if (RT_ENCODING_BASE64 == cred->private_data.encoding) {
		}
	}
	RT_LOG_E(TAG, "Can not find subject matched credential, %s OUT", __func__);
	return OCF_ERROR;
}
