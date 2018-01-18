#!/bin/bash

set -e

TOOLS_DIR=$(dirname $0)

${TOOLS_DIR}/memory.py peak $@