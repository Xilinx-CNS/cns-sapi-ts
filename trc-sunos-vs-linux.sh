#! /bin/sh
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
#
# Script to generate differencies report between SunOS and Linux.
#
# Author: Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
#
# $Id$
#

[ -e "./scripts/guess.sh" ] && source "./scripts/guess.sh"

. "$(dirname "$(which $0)")/guess.sh"

DB="${CONFDIR}/trc-sockapi-ts.xml"

te-trc-diff --db=$DB \
    --html=sunos-vs-linux-2.4.html \
    --title="All differences between SunOS and Linux 2.4" \
    --1-name="Linux 2.4" -1 linux-2.4 -1 linux \
    --2-name="SunOS 5.11" --2-show-keys -2 sunos

te-trc-diff --db=$DB \
    --html=sunos-vs-linux-2.6.html \
    --title="All differences between SunOS and Linux 2.6" \
    --1-name="Linux 2.6" -1 linux-2.6 -1 linux \
    --2-name="SunOS 5.11" --2-show-keys -2 sunos
