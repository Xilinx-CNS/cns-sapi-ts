# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
# What is this script doing here... It should be in scripts/

. $TE_BASE/scripts/guess.sh

if test -z "$TRC_DB" ; then
    TRC_DB="trc-sockapi-ts.xml"
fi
