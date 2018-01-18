#!/bin/bash

set -e

TOOLS_DIR=$(dirname $0)
TOOLS_INTERNAL_DIR=$(dirname $0)/internal

${TOOLS_DIR}/lint.py $@