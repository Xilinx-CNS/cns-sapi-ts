# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
# Script should be sources to guess TE/conf/Onload TS libs/TS parameters if they're not
# specified in the shell environment.

[ -n "$RUNDIR" ] && GUESS_TOP_DIR="${RUNDIR}"
[ -e "guess.sh" ] && [ -e "../scripts/" ] && GUESS_TOP_DIR="${PWD}/../"
[ -e "scripts/guess.sh" ] && GUESS_TOP_DIR="${PWD}"
[ -z "${GUESS_TOP_DIR}" ] && { echo "Failed to guess where we are" >&2; exit 1 ; }

te_realpath () {
    local which=$1 

    [ -e "$which" ] || echo "$which"
    pushd "$which" >/dev/null
    pwd -P
    popd >/dev/null
}

# TE_BASE
for loop in once ; do
    test -e "${TE_BASE}/dispatcher.sh" && break;

    echo "Guessing TE_BASE"
    export TE_BASE="${GUESS_TOP_DIR}/../te"
    test -e "${TE_BASE}/dispatcher.sh" && break;
    export TE_BASE="${GUESS_TOP_DIR}/../test-environment"
    test -e "${TE_BASE}/dispatcher.sh" && break;

    echo "Cannot import SF shared TS confdir '$TE_BASE'" >&2
    exit 1
done
export TE_BASE=$(te_realpath ${TE_BASE})
echo "TE_BASE=${TE_BASE}"


# SF_TS_CONFDIR
for loop in once ; do
    test -d "${SF_TS_CONFDIR}" && break;

    echo "Guessing SF_TS_CONFDIR"
    export SF_TS_CONFDIR="${GUESS_TOP_DIR}"/../ts-conf
    test -d "${SF_TS_CONFDIR}" && break;
    export SF_TS_CONFDIR="${GUESS_TOP_DIR}"/../conf
    test -d "${SF_TS_CONFDIR}" && break;

    echo "Cannot import SF shared TS confdir '$SF_TS_CONFDIR'" >&2
    exit 1
done
export SF_TS_CONFDIR=$(te_realpath ${SF_TS_CONFDIR})
echo "SF_TS_CONFDIR=${SF_TS_CONFDIR}"

# TE_TS_RIGSDIR
for loop in once ; do
    test -d "${TE_TS_RIGSDIR}" && break;

    echo "Guessing TE_TS_RIGSDIR"
    export TE_TS_RIGSDIR="${GUESS_TOP_DIR}"/../ts-env
    test -d "${TE_TS_RIGSDIR}" && break;
    export TE_TS_RIGSDIR="${GUESS_TOP_DIR}"/../ts-rigs
    test -d "${TE_TS_RIGSDIR}" && break;

    echo "Cannot import SF shared TS confdir '$TE_TS_RIGSDIR'" >&2
    exit 1
done
export TE_TS_RIGSDIR=$(te_realpath ${TE_TS_RIGSDIR})
echo "TE_TS_RIGSDIR=${TE_TS_RIGSDIR}"

# SFC_ONLOAD_LIB
for loop in once ; do
    test -d "${SFC_ONLOAD_LIB}" && break;

    echo "Guessing SFC_ONLOAD_LIB"
    export SFC_ONLOAD_LIB="${GUESS_TOP_DIR}"/../onload-tslib
    test -d "${SFC_ONLOAD_LIB}" && break;
    export SFC_ONLOAD_LIB="${GUESS_TOP_DIR}"/../tslib
    test -d "${SFC_ONLOAD_LIB}" && break;

    echo "Cannot import path to Onload TS libs '$SFC_ONLOAD_LIB'" >&2
    exit 1
done
export SFC_ONLOAD_LIB=$(te_realpath ${SFC_ONLOAD_LIB})
echo "SFC_ONLOAD_LIB=${SFC_ONLOAD_LIB}"

export TE_TS_DIR=${GUESS_TOP_DIR}
