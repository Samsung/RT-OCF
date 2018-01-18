#!/bin/bash
FILE=$1
FILENAME=$(echo "$FILE" | sed 's/\.[^\.]*$//')
CBOR="${FILENAME}.cbor"
HEADER="${FILENAME}.h"
sh -c "./json2cbor ${FILE} > ${CBOR}"
sh -c "xxd -i ${CBOR} > ${HEADER}"