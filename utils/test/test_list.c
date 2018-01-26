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

#include "unity.h"
#include "unity_fixture.h"
#include <stdio.h>
#include <time.h>
#include "rt_mem.h"
#include "rt_list.h"
#include "rt_thread.h"
#include "rt_utils.h"

#define TAG "TEST_LIST"

typedef struct _list_exam {
	char a;
	int b;
	long c;
	rt_node_s node;
} list_exam_s;

#define NUM_THD 8
#define NUM_NODE 500

static rt_list_s _list;

static int thread_id[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

TEST_GROUP(test_list);

TEST_SETUP(test_list)
{
	rt_mem_pool_init();
	rt_list_init(&_list, sizeof(list_exam_s), RT_MEMBER_OFFSET(list_exam_s, node));
}

TEST_TEAR_DOWN(test_list)
{
	rt_mem_pool_terminate();
}

TEST(test_list, list_init_test)
{
	TEST_ASSERT_NULL(_list.head);
	TEST_ASSERT_NULL(_list.tail);
	TEST_ASSERT_EQUAL_INT(0, _list.count);
}

TEST(test_list, list_insert)
{
	list_exam_s item = { 1, 2, 3 };

	rt_list_insert(&_list, &item.node);

	TEST_ASSERT_EQUAL_MEMORY(&item.node, _list.head, sizeof(item.node));
	TEST_ASSERT_EQUAL_MEMORY(&item.node, _list.tail, sizeof(item.node));
	TEST_ASSERT_EQUAL_INT(1, _list.count);
}

TEST(test_list, list_insert_one_delete_it)
{
	list_exam_s item1 = { 1, 2, 3 };
	int key = 2;
	rt_list_insert(&_list, &item1.node);

	rt_list_delete(&_list, RT_MEMBER_OFFSET(list_exam_s, b), RT_MEMBER_SIZE(list_exam_s, b), &key);

	TEST_ASSERT_NULL(_list.head);
	TEST_ASSERT_NULL(_list.tail);
	TEST_ASSERT_EQUAL_INT(0, _list.count);
}

TEST(test_list, list_delete)
{
	list_exam_s item1 = { 1, 2, 3 };
	list_exam_s item2 = { 4, 5, 6 };

	int key = 2;

	rt_list_insert(&_list, &item1.node);
	rt_list_insert(&_list, &item2.node);

	rt_list_delete(&_list, RT_MEMBER_OFFSET(list_exam_s, b), RT_MEMBER_SIZE(list_exam_s, b), &key);

	TEST_ASSERT_EQUAL_MEMORY(&item2.node, _list.head, sizeof(item2.node));
	TEST_ASSERT_EQUAL_MEMORY(&item2.node, _list.tail, sizeof(item2.node));
	TEST_ASSERT_EQUAL_INT(1, _list.count);
}

TEST(test_list, list_delete_middle_item)
{
	list_exam_s item1 = { 1, 2, 3 };
	list_exam_s item2 = { 4, 5, 6 };
	list_exam_s item3 = { 7, 8, 9 };
	list_exam_s *temp;
	int key = 5;

	rt_list_insert(&_list, &item1.node);
	rt_list_insert(&_list, &item2.node);
	rt_list_insert(&_list, &item3.node);

	temp = (list_exam_s *) rt_list_delete(&_list, RT_MEMBER_OFFSET(list_exam_s, b), RT_MEMBER_SIZE(list_exam_s, b), &key);

	TEST_ASSERT_EQUAL_INT(4, temp->a);
	TEST_ASSERT_EQUAL_INT(5, temp->b);
	TEST_ASSERT_EQUAL_INT(6, temp->c);
	TEST_ASSERT_EQUAL_MEMORY(&item1.node, _list.head, sizeof(item2.node));
	TEST_ASSERT_EQUAL_MEMORY(&item3.node, _list.tail, sizeof(item2.node));
	TEST_ASSERT_EQUAL_INT(2, _list.count);
}

TEST(test_list, list_delete_tail_item)
{
	list_exam_s item1 = { 1, 2, 3 };
	list_exam_s item2 = { 4, 5, 6 };
	list_exam_s item3 = { 7, 8, 9 };
	list_exam_s *temp;
	int key = 8;

	rt_list_insert(&_list, &item1.node);
	rt_list_insert(&_list, &item2.node);
	rt_list_insert(&_list, &item3.node);

	temp = (list_exam_s *) rt_list_delete(&_list, RT_MEMBER_OFFSET(list_exam_s, b), RT_MEMBER_SIZE(list_exam_s, b), &key);

	TEST_ASSERT_EQUAL_INT(7, temp->a);
	TEST_ASSERT_EQUAL_INT(8, temp->b);
	TEST_ASSERT_EQUAL_INT(9, temp->c);
	TEST_ASSERT_EQUAL_MEMORY(&item1.node, _list.head, sizeof(item2.node));
	TEST_ASSERT_EQUAL_MEMORY(&item2.node, _list.tail, sizeof(item2.node));
	TEST_ASSERT_EQUAL_INT(2, _list.count);
}

TEST(test_list, list_iterator_get)
{
	list_exam_s item[3] = { {1, 2, 3}
		,
		{4, 5, 6}
		,
		{7, 8, 9}
	};
	int cnt = 0;

	rt_list_insert(&_list, &item[0].node);
	rt_list_insert(&_list, &item[1].node);
	rt_list_insert(&_list, &item[2].node);

	//Then
	rt_node_s *itr = _list.head;
	while (itr) {
		list_exam_s *var = (list_exam_s *) rt_list_get_item(&_list, itr);
		TEST_ASSERT_EQUAL_INT(item[cnt++].c, var->c);
		itr = itr->next;
	}
}

TEST(test_list, list_insert_one_delete_it_by_node)
{
	list_exam_s item1 = { 1, 2, 3 };
	rt_list_insert(&_list, &item1.node);

	rt_list_delete_by_node(&_list, &item1.node);

	TEST_ASSERT_NULL(_list.head);
	TEST_ASSERT_NULL(_list.tail);
	TEST_ASSERT_EQUAL_INT(0, _list.count);
}

TEST(test_list, list_delete_middle_item_by_node)
{
	list_exam_s item1 = { 1, 2, 3 };
	list_exam_s item2 = { 4, 5, 6 };
	list_exam_s item3 = { 7, 8, 9 };
	list_exam_s *temp;

	rt_list_insert(&_list, &item1.node);
	rt_list_insert(&_list, &item2.node);
	rt_list_insert(&_list, &item3.node);

	temp = (list_exam_s *) rt_list_delete_by_node(&_list, &item2.node);

	TEST_ASSERT_EQUAL_INT(4, temp->a);
	TEST_ASSERT_EQUAL_INT(5, temp->b);
	TEST_ASSERT_EQUAL_INT(6, temp->c);
	TEST_ASSERT_EQUAL_MEMORY(&item1.node, _list.head, sizeof(item2.node));
	TEST_ASSERT_EQUAL_MEMORY(&item3.node, _list.tail, sizeof(item2.node));
	TEST_ASSERT_EQUAL_INT(2, _list.count);
}

TEST(test_list, list_delete_tail_item_by_node)
{
	list_exam_s item1 = { 1, 2, 3 };
	list_exam_s item2 = { 4, 5, 6 };
	list_exam_s item3 = { 7, 8, 9 };
	list_exam_s *temp;

	rt_list_insert(&_list, &item1.node);
	rt_list_insert(&_list, &item2.node);
	rt_list_insert(&_list, &item3.node);

	temp = (list_exam_s *) rt_list_delete_by_node(&_list, &item3.node);

	TEST_ASSERT_EQUAL_INT(7, temp->a);
	TEST_ASSERT_EQUAL_INT(8, temp->b);
	TEST_ASSERT_EQUAL_INT(9, temp->c);
	TEST_ASSERT_EQUAL_MEMORY(&item1.node, _list.head, sizeof(item2.node));
	TEST_ASSERT_EQUAL_MEMORY(&item2.node, _list.tail, sizeof(item2.node));
	TEST_ASSERT_EQUAL_INT(2, _list.count);
}

static void *insert_node(void *data)
{
	int i;

	for (i = 0; i < NUM_NODE; i++) {
		list_exam_s *item = rt_mem_alloc(sizeof(list_exam_s));
		rt_list_insert(&_list, &item->node);
	}

	return NULL;
}

static void dummy_func(void *data)
{
	// do nothing. it makes rt_thread_terminate() call pthread_join
	return;
}

TEST(test_list, list_insert_when_add_multiple_nodes_by_multiple_threads_then_thread_safety)
{
	// When 각각의 Thread에서 NUM_NODE개씩 동시에 insert를 했을 때
	struct timeval before, after;

	rt_thread_s thread_info[NUM_THD];

	gettimeofday(&before, NULL);
	int i;
	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_init(&(thread_info[i]), insert_node, NULL, 0, NULL);
	}

	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_terminate(&(thread_info[i]), dummy_func, NULL);
	}

	gettimeofday(&after, NULL);
	int diff_msec = 1000 * (after.tv_sec - before.tv_sec) + (after.tv_usec - before.tv_usec) / 1000;
	printf("Time to CAS insert nodes: %d msec\n", diff_msec);

	// Then NUM_NODE * NUM_THD 개의 node가 되어 있다.
	TEST_ASSERT_EQUAL_INT(NUM_NODE * NUM_THD, _list.count);

	int n = 0;
	while (_list.head) {
		rt_mem_free(rt_list_delete_by_node(&_list, _list.head));
		n++;
	}

	TEST_ASSERT_EQUAL_INT(NUM_NODE * NUM_THD, n);

	rt_list_terminate(&_list, NULL);
}

void rt_list_insert_origin(rt_list_s *list, rt_node_s *node)
{
	RT_VERIFY_NON_NULL_VOID(list, TAG, "list is null");
	RT_VERIFY_NON_NULL_VOID(node, TAG, "node is null");
	pthread_mutex_lock(&list->mutex);
	node->prev = list->tail;
	node->next = NULL;

	if (list->head == NULL && list->tail == NULL) {
		list->head = node;
		list->tail = node;
	} else {
		list->tail->next = node;
		list->tail = node;
	}

	list->count++;
	pthread_mutex_unlock(&list->mutex);
}

void *insert_node_origin(void *data)
{
	int i;

	for (i = 0; i < NUM_NODE; i++) {
		list_exam_s *item = rt_mem_alloc(sizeof(list_exam_s));
		rt_list_insert_origin(&_list, &item->node);
	}

	return 0;
}

IGNORE_TEST(test_list, list_insert_origin_when_add_multiple_nodes_by_multiple_threads_then_thread_safety)
{
	// When 각각의 Thread에서 NUM_NODE개씩 동시에 insert를 했을 때
	struct timeval before, after;

	rt_thread_s thread_info[NUM_THD];

	gettimeofday(&before, NULL);
	int i;
	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_init(&(thread_info[i]), insert_node_origin, NULL, 0, NULL);
	}

	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_terminate(&(thread_info[i]), dummy_func, NULL);
	}

	gettimeofday(&after, NULL);
	int diff_msec = 1000 * (after.tv_sec - before.tv_sec) + (after.tv_usec - before.tv_usec) / 1000;
	printf("Time to LOCK insert nodes: %d msec\n", diff_msec);

	// Then NUM_NODE * NUM_THD 개의 node가 되어 있다.
	TEST_ASSERT_EQUAL_INT(NUM_NODE * NUM_THD, _list.count);

	int n = 0;
	while (_list.head) {
		rt_mem_free(rt_list_delete_by_node(&_list, _list.head));
		n++;
	}

	TEST_ASSERT_EQUAL_INT(NUM_NODE * NUM_THD, n);

	rt_list_terminate(&_list, NULL);
}

list_exam_s items[NUM_THD][NUM_NODE];

static void delete_node_origin(rt_list_s *list, rt_node_s *node)
{
	if (node->prev == NULL && node->next == NULL) {
		list->head = list->tail = NULL;
	} else if (node->prev == NULL) {	//When Head
		node->next->prev = NULL;
		list->head = node->next;
	} else if (node->next == NULL) {	//When Tail
		node->prev->next = NULL;
		list->tail = node->prev;
	} else {
		node->prev->next = node->next;
		node->next->prev = node->prev;
	}

	list->count--;
}

void *rt_list_delete_origin(rt_list_s *list, uint32_t offset, int memb_size, void *key)
{
	RT_VERIFY_NON_NULL_RET(list, TAG, "list is null", NULL);
	pthread_mutex_lock(&list->mutex);
	void *item = rt_list_search(list, offset, memb_size, key);
	if (item == NULL) {
		pthread_mutex_unlock(&list->mutex);
		return NULL;
	}
	rt_node_s *node = (rt_node_s *)((char *)item + list->offset);
	delete_node_origin(list, node);
	pthread_mutex_unlock(&list->mutex);
	return item;
}

void *rt_list_delete_by_node_origin(rt_list_s *list, rt_node_s *node)
{
	RT_VERIFY_NON_NULL_RET(list, TAG, "list is null", NULL);
	RT_VERIFY_NON_NULL_RET(node, TAG, "node is null", NULL);
	pthread_mutex_lock(&list->mutex);

	if (list->count <= 0) {
		pthread_mutex_unlock(&list->mutex);
		return NULL;
	}

	delete_node_origin(list, node);
	pthread_mutex_unlock(&list->mutex);
	return rt_list_get_item(list, node);
}

void *delete_node_runner(void *data)
{
	int i;
	int current_thread_id = *((int *)data);
	for (i = 0; i < NUM_NODE; i++) {
		void *var = rt_list_delete_by_node(&_list, &(items[current_thread_id][i].node));
		TEST_ASSERT_NOT_NULL(var);
	}

	return 0;
}

TEST(test_list, list_delete_when_delete_multiple_nodes_by_multiple_threads_then_thread_safety)
{
	struct timeval before, after;
	rt_thread_s thread_info[NUM_THD];

	// Given
	// NUM_NODE * NUM_THD 만큼 item을 추가하고
	int i = 0, j = 0;
	for (i = 0; i < NUM_THD; i++) {
		for (j = 0; j < NUM_NODE; j++) {
			rt_list_insert(&_list, &(items[i][j].node));
		}
	}

	// When
	// Thread를 NUM_THD 개 생성해서 NUM_NODE 만큼 delete를 했을 때
	gettimeofday(&before, NULL);
	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_init(&(thread_info[i]), delete_node_runner, NULL, 0, thread_id + i);
	}

	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_terminate(&(thread_info[i]), dummy_func, NULL);
	}
	gettimeofday(&after, NULL);
	int diff_msec = 1000 * (after.tv_sec - before.tv_sec) + (after.tv_usec - before.tv_usec) / 1000;
	printf("Time to CAS delete nodes: %d msec\n", diff_msec);
	// Then
	// 다 성공하고 0개가 남는다.
	TEST_ASSERT_EQUAL_INT(0, _list.count);
}

void *delete_node_runner_origin(void *data)
{
	int i;
	int current_thread_id = *((int *)data);
	for (i = 0; i < NUM_NODE; i++) {
		void *var = rt_list_delete_by_node_origin(&_list, &(items[current_thread_id][i].node));
		TEST_ASSERT_NOT_NULL(var);
	}

	return 0;
}

IGNORE_TEST(test_list, list_delete_origin_when_delete_multiple_nodes_by_multiple_threads_then_thread_safety)
{
	struct timeval before, after;
	rt_thread_s thread_info[NUM_THD];

	// Given
	// NUM_NODE * 3 만큼 item을 추가하고
	int i = 0, j = 0;
	for (i = 0; i < NUM_THD; i++) {
		for (j = 0; j < NUM_NODE; j++) {
			rt_list_insert(&_list, &(items[i][j].node));
		}
	}

	// When
	// Thread를 3개 생성해서 NUM_NODE 만큼 delete를 했을 때
	gettimeofday(&before, NULL);
	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_init(&(thread_info[i]), delete_node_runner_origin, NULL, 0, thread_id + i);
	}

	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_terminate(&(thread_info[i]), dummy_func, NULL);
	}
	gettimeofday(&after, NULL);
	int diff_msec = 1000 * (after.tv_sec - before.tv_sec) + (after.tv_usec - before.tv_usec) / 1000;
	printf("Time to LOCK delete nodes: %d msec\n", diff_msec);
	// Then
	// 다 성공하고 0개가 남는다.
	TEST_ASSERT_EQUAL_INT(0, _list.count);
}

TEST_GROUP_RUNNER(test_list)
{
	RUN_TEST_CASE(test_list, list_init_test);
	RUN_TEST_CASE(test_list, list_insert);
	RUN_TEST_CASE(test_list, list_delete);
	RUN_TEST_CASE(test_list, list_insert_one_delete_it);
	RUN_TEST_CASE(test_list, list_delete_middle_item);
	RUN_TEST_CASE(test_list, list_delete_tail_item);
	RUN_TEST_CASE(test_list, list_iterator_get);
	RUN_TEST_CASE(test_list, list_insert_one_delete_it_by_node);
	RUN_TEST_CASE(test_list, list_delete_middle_item_by_node);
	RUN_TEST_CASE(test_list, list_delete_tail_item_by_node);
	RUN_TEST_CASE(test_list, list_insert_when_add_multiple_nodes_by_multiple_threads_then_thread_safety);
	RUN_TEST_CASE(test_list, list_insert_origin_when_add_multiple_nodes_by_multiple_threads_then_thread_safety);
	RUN_TEST_CASE(test_list, list_delete_when_delete_multiple_nodes_by_multiple_threads_then_thread_safety);
	RUN_TEST_CASE(test_list, list_delete_origin_when_delete_multiple_nodes_by_multiple_threads_then_thread_safety);
}

#ifndef CONFIG_ENABLE_RT_OCF
static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_list);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}
#endif
