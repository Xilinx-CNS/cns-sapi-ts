#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

set -e

# This file should log to stdout a number of key/value pairs that matters when
# storing session into bublik.

pushd "$(dirname "$(which "$0")")" >/dev/null
RUNDIR="$(pwd -P)"
popd >/dev/null

[ "$(basename $RUNDIR)" = "scripts" ] && RUNDIR="${RUNDIR}/.."

[ -e "${RUNDIR}/scripts/guess.sh" ] && source "${RUNDIR}/scripts/guess.sh" >/dev/null

source "${TE_BASE}/scripts/lib"

echo "TE_DIR ${TE_BASE}"
echo "TS_DIR ${TE_TS_DIR}"
echo "CONF_DIR ${SF_TS_CONFDIR}"

# revisions

TEREV=unknown
enter ${TE_BASE} && TEREV=$(hg id -i --debug) && leave
echo "TEREV $TEREV"

TSREV=unknown
enter ${TE_TS_BASE} && TSREV=$(hg id -i --debug) && leave
echo "TSREV $TSREV"

CONFREV=unknown
enter ${SF_TS_CONFDIR} && CONFREV=$(hg id -i --debug) && leave
echo "TSREV $TSREV"

source ${SF_TS_CONFDIR}/script.sfc_onload_gnu > /dev/null
if [ -e "${SFC_ONLOAD_GNU}" ] ; then
    try enter ${SFC_ONLOAD_GNU}

    V5REV="$(hg identify)"
    V5REV_SHORT=$(hg id -i --debug)
    V5DATE=$(hg log -r "${V5REV_SHORT::16}" | grep "date:" | sed "s/date:\ *//")
    echo "V5DATE ${V5DATE}"
    echo "V5REV: ${V5REV}"

    leave
else
    echo "No Onload revision, cause SFC_ONLOAD_GNU is missing"
fi
