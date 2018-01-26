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

#ifndef __RT_OCF_SEC_TYPES_H
#define __RT_OCF_SEC_TYPES_H

// doxm
#define OCF_DOXM_HREF "/oic/sec/doxm"
#define OCF_DOXM_RT "oic.r.doxm"
#define OCF_DOXM_OXMS "oxms"
#define OCF_DOXM_OXMSEL "oxmsel"
#define OCF_DOXM_SCT "sct"
#define OCF_DOXM_OWNED "owned"
#define OCF_DOXM_DEVICEUUID "deviceuuid"
#define OCF_DOXM_DEVOWNERUUID "devowneruuid"

//cred
#define OCF_CRED_HREF "/oic/sec/cred"
#define OCF_CRED_RT "oic.r.cred"
#define OCF_CREDS_NAME "creds"
#define OCF_CREDID_NAME "credid"
#define OCF_SUBJECTUUID_NAME "subjectuuid"
#define OCF_CREDTYPE_NAME "credtype"
#define OCF_CREDUSAGE_NAME "credusage"
#define OCF_PERIOD_NAME "period"
#define OCF_PUBLICDATA_NAME "publicdata"
#define OCF_OPTIONALDATA_NAME "optionaldata"
#define OCF_PRIVATEDATA_NAME "privatedata"
#define OCF_ENCODING_NAME "encoding"
#define OCF_KEY_DATA_NAME "data"
#define OCF_REVSTAT_NAME "revstat"

//acl2
#define OCF_ACL2_HREF "/oic/sec/acl2"
#define OCF_ACL2_RT "oic.r.acl2"
#define OCF_ACL_LIST "aclist2"
#define OCF_ACL_ID "aceid"
#define OCF_ACL_SUBJECT "subject"
#define OCF_ACL_UUID "uuid"
#define OCF_ACL_CONNTYPE "conntype"
#define OCF_ACL_RESOURCES "resources"
#define OCF_ACL_HREF "href"
#define OCF_ACL_PERMISSION "permission"
#define OCF_ACL_AUTH_CRYPT "auth-crypt"
#define OCF_ACL_ANON_CLEAR "anon-clear"
#define OCF_ACL_WILDCARD_NAME "wc"
#define OCF_ACL_WILDCARD_DISCOVERIABLE "+"
#define OCF_ACL_WILDCARD_NON_DISCOVERIABLE "-"
#define OCF_PERMISSION_CREATE  (1 << 0)
#define OCF_PERMISSION_READ    (1 << 1)
#define OCF_PERMISSION_WRITE   (1 << 2)
#define OCF_PERMISSION_DELETE  (1 << 3)
#define OCF_PERMISSION_NOTIFY  (1 << 4)

//pstat
#define OCF_PSTAT_HREF "/oic/sec/pstat"
#define OCF_PSTAT_RT "oic.r.pstat"
#define OCF_PSTAT_DOS "dos"
#define OCF_PSTAT_STATE "s"
#define OCF_PSTAT_PENDING "p"
#define OCF_PSTAT_ISOP "isop"
#define OCF_PSTAT_CM "cm"
#define OCF_PSTAT_TM "tm"
#define OCF_PSTAT_OM "om"
#define OCF_PSTAT_SM "sm"

//security resource common
#define OCF_ROWNERUUID_NAME "rowneruuid"
#define OCF_WILDCARD_ALL "*"
#define OCF_WILDCARD_LEN (1)

#endif
