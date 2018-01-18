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
#include "rt_collection.h"
#include "rt_utils.h"
#include "rt_list.h"
#include "rt_mem.h"

#define TAG "RT_COL_RES"

typedef struct _rt_resource_links_s {
	rt_resource_s *link;
	rt_node_s node;
} rt_resource_links_s;

ocf_result_t rt_res_add_link_item(rt_resource_s *rsc_parent, rt_resource_s *rsc_child)
{
	RT_VERIFY_NON_NULL_RET(rsc_parent, TAG, "parent is null", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(rsc_child, TAG, "child is null", OCF_INVALID_PARAM);

// TODO, please find out other ways to check whether it is in resource list or not
//       such as comparing pointer address.
	if (!rt_res_get_resource_by_href(rsc_child->href)) {
		RT_LOG_E(TAG, "%s is in Resource list", rsc_child->href);
		return OCF_INVALID_PARAM;
	}
// check oic.if.ll
	/*  rt_resource_s *rsc_parent_already_existing = NULL;
	   rsc_parent_already_existing=rt_res_get_resource_by_href(rsc_parent->href);
	   if(rsc_parent_already_existing)
	   link_ptr = rsc_parent_already_existing->links_list;
	   else
	   link_ptr = rsc_parent->links_list;
	 */

	// the first implementation: only new resource is avaliale to have links
	// TODO:
	if (rt_res_get_resource_by_href(rsc_parent->href)) {
		return OCF_INVALID_PARAM;
	}

	if (!rsc_parent->links_list) {
		rsc_parent->links_list = rt_mem_alloc(sizeof(rt_list_s));
		if (!rsc_parent->links_list) {
			return OCF_NO_MEMORY;
		}

		rt_list_init(rsc_parent->links_list, sizeof(rt_resource_links_s), RT_MEMBER_OFFSET(rt_resource_links_s, node));

	}

	if (rt_list_search(rsc_parent->links_list, RT_MEMBER_OFFSET(rt_resource_links_s, link), RT_MEMBER_SIZE(rt_resource_links_s, link), rsc_child)) {
		return OCF_OK;
	}

	rt_resource_links_s *link_item = rt_mem_alloc(sizeof(rt_resource_links_s));

	if (!link_item) {
		return OCF_NO_MEMORY;
	}

	link_item->link = rsc_child;

	rt_list_insert(rsc_parent->links_list, &link_item->node);

	return OCF_OK;
}

ocf_result_t rt_res_remove_link_item(rt_resource_s *rsc_parent, rt_resource_s *rsc_child)
{
	// TODO
	return OCF_OK;
}

ocf_result_t rt_res_remove_links(rt_resource_s *parent)
{
	RT_VERIFY_NON_NULL_RET(parent, TAG, "Resource is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(parent->links_list, TAG, "not Collection Resource", OCF_OK);

	rt_list_terminate(parent->links_list, NULL);
	rt_mem_free(parent->links_list);
	parent->links_list = NULL;

	return OCF_OK;
}

ocf_result_t rt_res_init_links(void)
{
	// TODO
	return OCF_OK;
}

ocf_result_t rt_res_terminate_links(void)
{
	// TODO
	return OCF_OK;
}
