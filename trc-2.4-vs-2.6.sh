''#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

#!/bin/bash

[ -e "./scripts/guess.sh" ] && source "./scripts/guess.sh"

. "$(dirname "$(which "$0")")/guess.sh"

te-trc-diff --db=conf/trc-sockapi-ts.xml --html=linux-2.4-vs-2.6.html \
            --1-name="Linux 2.4" --2-name="Linux 2.6" \
            -1 linux-2.4 -1 linux -2 linux-2.6 -2 linux
