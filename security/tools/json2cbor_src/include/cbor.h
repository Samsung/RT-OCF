/*
 * Copyright (c) 2014-2017 Pavel Kalvoda <me@pavelkalvoda.com>
 *
 * libcbor is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


#ifndef LIBCBOR_H_
#define LIBCBOR_H_

#include "data.h"
#include "common.h"

#include "arrays.h"
#include "bytestrings.h"
#include "floats_ctrls.h"
#include "ints.h"
#include "maps.h"
#include "strings.h"
#include "tags.h"

#include "encoding.h"
#include "serialization.h"
#include "callbacks.h"
#include "streaming.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
* ============================================================================
* High level decoding
* ============================================================================
*/

/** Loads data item from a buffer
 *
 * @param source The buffer
 * @param source_size
 * @param result[out] Result indicator. #CBOR_ERR_NONE on success
 * @return **new** CBOR item or `NULL` on failure. In that case, \p result contains location and description of the error.
 */
cbor_item_t * cbor_load(cbor_data source,
						size_t source_size,
						struct cbor_load_result * result);

/** Deep copy of an item
 *
 * All the reference counts in the new structure are set to one.
 *
 * @param item[borrow] item to copy
 * @return **new** CBOR deep copy
 */
cbor_item_t * cbor_copy(cbor_item_t * item);

#if CBOR_PRETTY_PRINTER
#include <stdio.h>

void cbor_describe(cbor_item_t * item, FILE * out);
#endif

#ifdef __cplusplus
}
#endif

#endif //LIBCBOR_H_
