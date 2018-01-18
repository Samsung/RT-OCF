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

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "ocf_rep.h"
#include "ocf_request.h"
#include "ocf_resources.h"	//TODO: to be removed

#include "rt_manager.h"			// TODO: refactory

/* Generating SVR dat files */
static const char TEMP_DOXM_PATH[] = "test_svr_doxm_client.dat";
static const char TEMP_CRED_PATH[] = "test_svr_cred_client.dat";
static const char TEMP_ACL2_PATH[] = "test_svr_acl2_client.dat";
static const char TEMP_PSTAT_PATH[] = "test_svr_pstat_client.dat";

const char TEMP_DOXM_DATA[] = {
	0xa7, 0x64, 0x6f, 0x78, 0x6d, 0x73, 0x81, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x78, 0x6d, 0x73, 0x65, 0x6c, 0x1b,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x73, 0x63, 0x74,
	0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x65, 0x6f, 0x77,
	0x6e, 0x65, 0x64, 0xf5, 0x6a, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x75,
	0x75, 0x69, 0x64, 0x78, 0x24, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
	0x31, 0x2d, 0x31, 0x31, 0x31, 0x31, 0x2d, 0x31, 0x31, 0x31, 0x31, 0x2d,
	0x31, 0x31, 0x31, 0x31, 0x2d, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
	0x31, 0x31, 0x31, 0x31, 0x31, 0x6c, 0x64, 0x65, 0x76, 0x6f, 0x77, 0x6e,
	0x65, 0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x34, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34,
	0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x6a, 0x72, 0x6f, 0x77,
	0x6e, 0x65, 0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34,
	0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
};

const char TEMP_CRED_DATA[] = {
	0xa2, 0x65, 0x63, 0x72, 0x65, 0x64, 0x73, 0x81, 0xa5, 0x66, 0x63, 0x72,
	0x65, 0x64, 0x69, 0x64, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x6b, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x75, 0x75, 0x69,
	0x64, 0x78, 0x24, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x2d,
	0x33, 0x33, 0x33, 0x33, 0x2d, 0x33, 0x33, 0x33, 0x33, 0x2d, 0x33, 0x33,
	0x33, 0x33, 0x2d, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
	0x33, 0x33, 0x33, 0x68, 0x63, 0x72, 0x65, 0x64, 0x74, 0x79, 0x70, 0x65,
	0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x66, 0x70, 0x65,
	0x72, 0x69, 0x6f, 0x64, 0x78, 0x1f, 0x32, 0x30, 0x31, 0x35, 0x30, 0x36,
	0x33, 0x30, 0x54, 0x30, 0x36, 0x30, 0x30, 0x30, 0x30, 0x2f, 0x32, 0x30,
	0x39, 0x39, 0x30, 0x39, 0x32, 0x30, 0x54, 0x32, 0x32, 0x30, 0x30, 0x30,
	0x30, 0x6b, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x64, 0x61, 0x74,
	0x61, 0xa2, 0x68, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x74,
	0x6f, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x63, 0x2e, 0x65, 0x6e, 0x63, 0x6f,
	0x64, 0x69, 0x6e, 0x67, 0x2e, 0x72, 0x61, 0x77, 0x64, 0x64, 0x61, 0x74,
	0x61, 0x50, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x6a, 0x72, 0x6f, 0x77, 0x6e, 0x65,
	0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x34, 0x34, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34,
	0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
};

const char TEMP_ACL2_DATA[] = {
	0xa2, 0x67, 0x61, 0x63, 0x6c, 0x69, 0x73, 0x74, 0x32, 0x81, 0xa4, 0x65,
	0x61, 0x63, 0x65, 0x69, 0x64, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x67, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0xa1, 0x68,
	0x63, 0x6f, 0x6e, 0x6e, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x61, 0x6e, 0x6f,
	0x6e, 0x2d, 0x63, 0x6c, 0x65, 0x61, 0x72, 0x69, 0x72, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x73, 0x81, 0xa1, 0x64, 0x68, 0x72, 0x65, 0x66,
	0x6d, 0x2f, 0x6f, 0x69, 0x63, 0x2f, 0x73, 0x65, 0x63, 0x2f, 0x64, 0x6f,
	0x78, 0x6d, 0x6a, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f,
	0x6e, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x6a, 0x72,
	0x6f, 0x77, 0x6e, 0x65, 0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34,
	0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34,
	0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
};

const char TEMP_PSTAT_DATA[] = {
	0xa7, 0x63, 0x64, 0x6f, 0x73, 0xa2, 0x61, 0x73, 0x1b, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x70, 0xf4, 0x64, 0x69, 0x73, 0x6f,
	0x70, 0xf5, 0x62, 0x63, 0x6d, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x62, 0x74, 0x6d, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x62, 0x6f, 0x6d, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x04, 0x62, 0x73, 0x6d, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x04, 0x6a, 0x72, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x75, 0x75, 0x69,
	0x64, 0x78, 0x24, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x2d,
	0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x2d, 0x34, 0x34,
	0x34, 0x34, 0x2d, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34,
	0x34, 0x34, 0x34
};

FILE *test_doxm_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(TEMP_DOXM_PATH, mode);
}

FILE *test_cred_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(TEMP_CRED_PATH, mode);
}

FILE *test_acl2_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(TEMP_ACL2_PATH, mode);
}

FILE *test_pstat_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(TEMP_PSTAT_PATH, mode);
}

void create_security_data_files(void)
{
	int fd;
	if (0 < (fd = open(TEMP_DOXM_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_DOXM_DATA, sizeof(TEMP_DOXM_DATA));
		close(fd);
	}
	if (0 < (fd = open(TEMP_CRED_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_CRED_DATA, sizeof(TEMP_CRED_DATA));
		close(fd);
	}
	if (0 < (fd = open(TEMP_ACL2_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_ACL2_DATA, sizeof(TEMP_ACL2_DATA));
		close(fd);
	}
	if (0 < (fd = open(TEMP_PSTAT_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_PSTAT_DATA, sizeof(TEMP_PSTAT_DATA));
		close(fd);
	}
}

void remove_security_data_files(void)
{
	unlink(TEMP_DOXM_PATH);
	unlink(TEMP_CRED_PATH);
	unlink(TEMP_ACL2_PATH);
	unlink(TEMP_PSTAT_PATH);
}

/* Generating SVR dat files */

static const char *blue_uri = "/light/blue";
static const char *red_uri = "/light/red";

static bool g_blue_value = false;
static bool g_red_value = false;

static char g_payload[1024] = "ABCED";

static ocf_endpoint_s g_endpoint;
static char *g_href;

#define MAX_REMOTE_RESOURCES 1000
#define MAX_ENDPOINT 1000
static int remote_resources_count = 0;
static ocf_remote_resource_s remote_resources_array[MAX_REMOTE_RESOURCES];

static int endpoint_count = 0;

static bool has_direct_input_for_endpoint(int argc);
static void set_endpoint(char *argv[], ocf_endpoint_s *endpoint);
static void set_payload(char *argv[]);
static void parse_argument(int argc, char *argv[], ocf_endpoint_s *endpoint);

static void print_endpoint(ocf_endpoint_s endpoint);
static void print_endpoints(ocf_endpoint_list_s *list);
static void print_remote_resources(ocf_remote_resource_s *resources);
static void print_stored_remote_resources(void);
static void print_stored_endpoint(void);
static void copy_href(ocf_remote_resource_s *dest, ocf_remote_resource_s *src);
static void copy_resource_type(ocf_remote_resource_s *dest, ocf_remote_resource_s *src);
static void copy_endpoint_list(ocf_remote_resource_s *dest, ocf_remote_resource_s *src);
static void store_remote_resources(ocf_remote_resource_s *resources);
static void extract_endpoint(void);
static void select_remote_resources(void);
static bool set_endpoint_with_user_input(ocf_endpoint_s *endpoint);

static bool terminated = false;

static void discover_callback(ocf_remote_resource_s *remote_resources, ocf_response_result_t response_result)
{
	printf("discover resources!!!!\n");

	if (!remote_resources) {
		printf("error  : remote_resources is null\n");
		return;
	}

	if (OCF_RESPONSE_RESOURCE_CREATED > response_result || response_result > OCF_RESPONSE_CONTENT) {
		printf("error  : response_result is error with %d \n", response_result);
		return;
	}
	// print_remote_resources(remote_resources);
	store_remote_resources(remote_resources);
	print_stored_remote_resources();
}

static void light_blue_get_callback(ocf_rep_decoder_s rep, const ocf_response_result_t response_result)
{
	printf("received!!!!\n");

	if (!rep) {
		printf("error  : rep is null\n");
		return;
	}

	if (OCF_RESPONSE_RESOURCE_CREATED > response_result || response_result > OCF_RESPONSE_CONTENT) {
		printf("error  : response_result is error with %d \n", response_result);
		return;
	}

	printf("==============================================\n");
	bool temp_value = false;
	if (OCF_OK == ocf_rep_get_bool_from_map(rep, "value", &temp_value)) {
		printf("value : %d\n", temp_value);
		g_blue_value = temp_value;
	}

	printf("==============================================\n");
}

static void light_red_get_callback(ocf_rep_decoder_s rep, const ocf_response_result_t response_result)
{
	printf("received!!!!\n");

	if (!rep) {
		printf("error  : rep is null\n");
		return;
	}

	if (OCF_RESPONSE_RESOURCE_CREATED > response_result || response_result > OCF_RESPONSE_CONTENT) {
		printf("error  : response_result is error with %d \n", response_result);
		return;
	}

	printf("==============================================\n");
	bool temp_value = false;
	if (OCF_OK == ocf_rep_get_bool_from_map(rep, "value", &temp_value)) {
		printf("value : %d\n", temp_value);
		g_red_value = temp_value;
	}

	printf("==============================================\n");
}

static void light_blue_post_callback(ocf_rep_decoder_s rep, const ocf_response_result_t response_result)
{
	printf("blue post_callback is received!!!!\n");
	// rep could be NULL  when server sends NULL payload although response_result is OK

	if (OCF_RESPONSE_RESOURCE_CREATED > response_result || response_result > OCF_RESPONSE_CONTENT) {
		printf("error  : response_result is error with %d \n", response_result);
		return;
	}

	printf("==============================================\n");
	printf("OK - it received 2.xx\n");

	if (rep == NULL) {
		return;
	}

	bool temp_value = 0;
	if (OCF_OK == ocf_rep_get_bool_from_map(rep, "value", &temp_value)) {
		printf("blue value : %d\n", temp_value);
		g_blue_value = temp_value;
	}
	printf("==============================================\n");

	return;

}

static void light_red_post_callback(ocf_rep_decoder_s rep, const ocf_response_result_t response_result)
{
	printf("red post_callback is received!!!!\n");
	// rep could be NULL  when server sends NULL payload although response_result is OK

	if (OCF_RESPONSE_RESOURCE_CREATED > response_result || response_result > OCF_RESPONSE_CONTENT) {
		printf("error  : response_result is error with %d \n", response_result);
		return;
	}

	printf("==============================================\n");
	printf("OK - it received 2.xx\n");

	if (rep == NULL) {
		return;
	}

	bool temp_value = 0;
	if (OCF_OK == ocf_rep_get_bool_from_map(rep, "value", &temp_value)) {
		printf("RED value : %d\n", temp_value);
		g_red_value = temp_value;
	}
	printf("==============================================\n");

	return;

}

static void delete_callback(ocf_rep_decoder_s rep, const ocf_response_result_t response_result)
{
	printf("==============================================\n");
	printf("response_result is %d \n", response_result);
	printf("==============================================\n");

}

static ocf_rep_encoder_s create_light_representation(char *light)
{
	ocf_rep_encoder_s rep = NULL;
	if (0 == strcmp(blue_uri, light)) {
		rep = ocf_rep_encoder_init(OCF_REP_MAP);
		printf("g_blue_value: %d\n", g_blue_value);
		ocf_rep_add_bool_to_map(rep, "value", (g_blue_value ? false : true));
		printf("g_blue_value: %d\n", ~g_blue_value);
	} else if (0 == strcmp(red_uri, light)) {
		rep = ocf_rep_encoder_init(OCF_REP_MAP);
		ocf_rep_add_bool_to_map(rep, "value", (g_red_value ? false : true));
	} else {
		printf("[create_light_representation()] Invalid light: %s\n", light);
	}

	return rep;
}

/* Set PS handler */
static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

/* Set PS handler */

int main(int argc, char *argv[])
{
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);
	ocf_endpoint_s endpoint;

	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);

	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);

	if (has_direct_input_for_endpoint(argc)) {
		parse_argument(argc, argv, &endpoint);
	} else {
		printf("==================================\n");
		printf("No direct input for endpoint!!!\n");
		printf("Please do discovery resources...\n");
		printf("==================================\n");
	}

	char key;
	terminated = false;

	while (1) {
		printf("Discovery(d) / Show remote resources(r) / Select remote resource(s)\n");
		printf("\t/ Termination(q) / Termination without mem_terminate(w) \n");
		printf("\t/ Request Get Method(g) / Post(U) / Delete(e) : \n");
		printf("\t/ Observe(b) / Observer Cancel(n) : ");
		fflush(stdin);
		scanf("%c", &key);

		switch (key) {
		case 'b':
		case 'B':
			printf("[OBSERVE] Requested!");
			if (0 == strcmp(blue_uri, g_href)) {
				ocf_observe_register(&g_endpoint, g_href, light_blue_get_callback);
			} else if (0 == strcmp(red_uri, g_href)) {
				ocf_observe_register(&g_endpoint, g_href, light_red_get_callback);
			} else {
				printf("Error: Invalid uri");
			}
			break;

		case 'n':
		case 'N':
			printf("[OBSERVE_CANCEL] Requested!");
			ocf_observe_deregister(&endpoint, blue_uri);
			break;

		case 'd':
		case 'D':
			remote_resources_count = 0;
			endpoint_count = 0;
			ocf_discovery(discover_callback, NULL);
			break;
		case 'g':
		case 'G': {
			const char *query = "if=oic.if.baseline";

			printf("==================================\n");
			printf("Uri : %s\n", g_href);
			printf("Query : %s\n", query);
			print_endpoint(g_endpoint);
			printf("==================================\n");
			if (0 == strcmp(blue_uri, g_href)) {
				ocf_request_get_send(&g_endpoint, g_href, query, true, light_blue_get_callback);
			} else if (0 == strcmp(red_uri, g_href)) {
				ocf_request_get_send(&g_endpoint, g_href, query, true, light_red_get_callback);
			} else {
				printf("error: invalid uri");
			}

			break;
		}
		case 'u':				// post : update
		case 'U': {
			const char *query = "if=oic.if.baseline";
			ocf_rep_encoder_s rep = NULL;
			if (0 == strcmp(blue_uri, g_href)) {
				rep = create_light_representation(g_href);
				ocf_request_post_send(&g_endpoint, g_href, query, rep, true, light_blue_post_callback);
			} else if (0 == strcmp(red_uri, g_href)) {
				rep = create_light_representation(g_href);
				ocf_request_post_send(&g_endpoint, g_href, query, rep, true, light_red_post_callback);
			} else {
				printf("error: invalid uri");
			}

			if (rep) {
				ocf_rep_encoder_release(rep);
			}
			break;
		}
		//TODO::DELETE
		case 'e':				// delete
		case 'E': {

			if (set_endpoint_with_user_input(&endpoint)) {
				ocf_request_delete_send(&endpoint, blue_uri, NULL, NULL, true, delete_callback);
				ocf_request_delete_send(&endpoint, red_uri, NULL, NULL, true, delete_callback);
			}
			break;
		}
		case 'r':
		case 'R':
			// print_stored_endpoint();
			print_stored_remote_resources();
			break;
		case 's':
		case 'S':
			// print_stored_endpoint();
			print_stored_remote_resources();
			select_remote_resources();
			break;
		case 'q':
		case 'Q':
			ocf_terminate();
			remove_security_data_files();
			return 0;
		}
	}
	return 0;
}

static void store_endpoints(ocf_endpoint_list_s *list, ocf_endpoint_s *array)
{
	int index = 0;
	ocf_endpoint_list_s *itr = list;
	while (itr) {
		array[index++] = itr->endpoint;
		itr = itr->next;
	}
}

static void select_remote_resources(void)
{
	int resource_number = 0;
	int endpoint_number = 0;
	ocf_endpoint_s endpoint_array[MAX_ENDPOINT];

	printf("Input resource number: ");
	fflush(stdin);
	scanf("%d", &resource_number);

	char *href = remote_resources_array[resource_number].href;
	ocf_endpoint_list_s *list = remote_resources_array[resource_number].endpoint_list;

	print_endpoints(list);
	store_endpoints(list, endpoint_array);

	printf("Input endpoint number: ");
	fflush(stdin);
	scanf("%d", &endpoint_number);

	g_endpoint = endpoint_array[endpoint_number];
	g_href = href;

	print_endpoint(g_endpoint);
	printf("href: %s\n", g_href);
}

static void print_endpoint(ocf_endpoint_s endpoint)
{
	char buffer[40];
	rt_endpoint_get_addr_str(&endpoint, buffer, sizeof(buffer));
	printf("endpoint address: %s\n", buffer);
	printf("endpoint port: %d\n", endpoint.port);
	printf("endpoint flag: %d\n", endpoint.flags);

}

static void print_endpoints(ocf_endpoint_list_s *list)
{
	int index = 0;
	ocf_endpoint_list_s *itr = list;
	printf("==============================================\n");

	while (itr) {
		printf("%d: \n", index++);
		print_endpoint(itr->endpoint);
		itr = itr->next;
		printf("----------------------------------------------\n");
	}
	printf("==============================================\n");

}

static void print_remote_resources(ocf_remote_resource_s *resources)
{
	printf("==============================================\n");
	printf("OK - it received 2.xx\n");
	ocf_remote_resource_s *itr = resources;
	while (itr) {
		printf("uri: %s\n", itr->href);
		ocf_endpoint_list_s *endpoint_list = itr->endpoint_list;
		if (NULL != endpoint_list) {
			print_endpoints(endpoint_list);
		}
		itr = itr->next;
		printf("----------------------------------------------\n");
	}
	printf("==============================================\n");
}

static void print_stored_remote_resources(void)
{
	printf("==============================================\n");
	printf("show stored_remote_resources\n");
	printf("==============================================\n");
	int i;
	for (i = 0; i < remote_resources_count; i++) {
		printf("%d:\n", i);
		printf("uri: %s\n", remote_resources_array[i].href);
		if (NULL != remote_resources_array[i].endpoint_list) {
			print_endpoint(remote_resources_array[i].endpoint_list->endpoint);
		}
		printf("----------------------------------------------\n");
	}
	printf("==============================================\n");
	printf("end of stored_remote_resources\n");
	printf("number of resources: %d\n", remote_resources_count);
	printf("==============================================\n");
}

static void copy_href(ocf_remote_resource_s *dest, ocf_remote_resource_s *src)
{
	dest->href = (char *)malloc(src->href_len + 1);
	dest->href_len = src->href_len;
	strncpy(dest->href, src->href, src->href_len);
	dest->href[src->href_len] = '\0';
}

static void copy_resource_type(ocf_remote_resource_s *dest, ocf_remote_resource_s *src)
{
	dest->resource_types = NULL;
	rt_resource_type_list_s *resource_types = src->resource_types;
	rt_resource_type_list_s *prev = NULL;
	while (resource_types) {
		rt_resource_type_list_s *new_resource = (rt_resource_type_list_s *)malloc(sizeof(rt_resource_type_list_s));
		int str_len = strlen(resource_types->resource_type);
		new_resource->resource_type = (char *)malloc(str_len);
		strncpy(new_resource->resource_type, resource_types->resource_type, str_len);

		if (prev != NULL) {
			prev->next = new_resource;
		} else {
			dest->resource_types = new_resource;
		}
		prev = new_resource;
		resource_types = resource_types->next;
	}
}

static void copy_endpoint_list(ocf_remote_resource_s *dest, ocf_remote_resource_s *src)
{
	dest->endpoint_list = NULL;
	ocf_endpoint_list_s *endpoint_list = src->endpoint_list;
	ocf_endpoint_list_s *prev = NULL;
	while (endpoint_list) {
		ocf_endpoint_list_s *new_endpoint = (ocf_endpoint_list_s *)malloc(sizeof(ocf_endpoint_list_s));
		new_endpoint->endpoint = endpoint_list->endpoint;
		new_endpoint->next = NULL;

		if (prev != NULL) {
			prev->next = new_endpoint;
		} else {
			dest->endpoint_list = new_endpoint;
		}
		prev = new_endpoint;
		endpoint_list = endpoint_list->next;
	}
}

static void store_remote_resources(ocf_remote_resource_s *resources)
{
	if (resources == NULL) {
		printf("resource is NULL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		return;
	}

	printf("==============================================\n");
	printf("store_remote_resources\n");
	printf("resources: %p\n", resources);
	ocf_remote_resource_s *current_resource = resources;
	while (current_resource) {

		ocf_remote_resource_s *p = &remote_resources_array[remote_resources_count];
		copy_href(p, current_resource);
		copy_resource_type(p, current_resource);
		copy_endpoint_list(p, current_resource);
		p->interfaces = current_resource->interfaces;
		p->p = current_resource->p;

		remote_resources_count++;
		current_resource = current_resource->next;
	}
}

static bool has_direct_input_for_endpoint(int argc)
{
	if (argc == 3 || argc == 4) {
		return true;
	}
	return false;
}

static void set_endpoint(char *argv[], ocf_endpoint_s *endpoint)
{
	char ip[20];
	int port;

	strncpy(ip, argv[1], strlen(argv[1]));
	ip[strlen(argv[1])] = '\0';
	port = atoi(argv[2]);
	printf("remote_ip : %s\n", ip);
	printf("port : %d\n", port);
	rt_endpoint_set(endpoint, ip, port, OCF_DEFAULT_FLAGS | OCF_UDP | OCF_IPV4);
}

static void set_payload(char *argv[])
{
	strncpy(g_payload, argv[3], strlen(argv[3]));
	g_payload[strlen(argv[3])] = '\0';
}

static void parse_argument(int argc, char *argv[], ocf_endpoint_s *endpoint)
{
	set_endpoint(argv, endpoint);
	if (argc == 4) {
		set_payload(argv);
	}
}

static bool set_endpoint_with_user_input(ocf_endpoint_s *endpoint)
{
	char ip[20];
	int port;
	printf("remote_ip : ");
	scanf("%19s", ip);
	printf("port : ");
	scanf("%d", &port);
	if (OCF_OK != rt_endpoint_set(endpoint, ip, port, OCF_SECURE | OCF_UDP | OCF_IPV4)) {
		return false;
	}
	return true;
}
