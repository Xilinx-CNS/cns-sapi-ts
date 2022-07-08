#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

[ -e "./scripts/guess.sh" ] && source "./scripts/guess.sh"

CONFDIR=$SF_TS_CONFDIR
. $TE_BASE/scripts/guess.sh
$TE_BASE/scripts/cfg-check.sh "$@"
