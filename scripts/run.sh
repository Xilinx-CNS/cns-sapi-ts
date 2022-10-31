#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

set -e
pushd "$(dirname "$(which "$0")")" >/dev/null
RUNDIR="$(pwd -P)"
popd >/dev/null

[ "$(basename $RUNDIR)" = "scripts" ] && RUNDIR="$(realpath "${RUNDIR}/..")"
[ -e "${RUNDIR}/scripts/guess.sh" ] && source "${RUNDIR}/scripts/guess.sh"

source "${TE_BASE}/scripts/lib"
source "${TE_BASE}/scripts/lib.grab_cfg"
file_to_src="${TE_TS_RIGSDIR}/scripts/lib/grab_cfg_handlers"
[[ -f "$file_to_src" ]] && source "$file_to_src"

# Include the file if it really exists - this allows sapi-ts not to break.
# It seems that the following functions may become unavailable on some
# TE_TS_RIGSDIR implementations: 'export_cmdclient', 'get_sfx_ifs' and
# 'export_iut_fw_version'.
[[ -e "${TE_TS_RIGSDIR}/scripts/lib.run" ]] \
    && source "${TE_TS_RIGSDIR}/scripts/lib.run"

source "${SF_TS_CONFDIR}/scripts/lib"

if test -z "${TE_TS_SOCKAPI}" -a -d "${RUNDIR}/sockapi-ts" ; then
    export TE_TS_SOCKAPI="${RUNDIR}/sockapi-ts"
fi

if test -z "${SOCKAPI_TS_LIBDIR}" ; then
    if test -d ${RUNDIR}/talib_sockapi_ts ; then
        export SOCKAPI_TS_LIBDIR="${RUNDIR}"
    fi
fi

export SCRIPTS_DIR="${RUNDIR}"

SUITE_SCRIPTS=
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/guess.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/run.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/trc.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/trc-brief.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/trc-tags.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/log.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/html-log.sh"
SUITE_SCRIPTS="${SUITE_SCRIPTS} ${RUNDIR}/live-log.sh"
export SUITE_SCRIPTS

on_exit() {
    call_if_defined grab_cfg_release
}
trap "on_exit" EXIT

usage() {
cat <<EOF
USAGE: run.sh [run.sh options] [dispatcher.sh options]
Options:
  --cfg=<CFG>               Configuration to be used
  --ool=<OOL CFG>           OOL product configuration file
  --ool-profile=<OOL PF>    OOL product profile file
  --ignore-nm               To suppress NetworkManager checking
  --run-ts-no-sfptpd        Enable HW timestamps testing, but without starting
                            SFPTP daemon in timestamps prologue
  --night-testing           This is the night testing run, perform some
                            appropriate actions. For now: do not clear kmemleak
                            on debugging kernels.
  --logs-history=<link>     Link to logs history
EOF
    call_if_defined grab_cfg_print_help

${TE_BASE}/dispatcher.sh --help
exit 1
}

L5_RUN=false
ZF_SHIM_RUN=false
RUN_OPTS="${RUN_OPTS} --trc-comparison=normalised"
RUN_OPTS="${RUN_OPTS} --sniff-not-feed-conf"
RUN_OPTS="${RUN_OPTS} --tester-only-req-logues"
ST_IGNORE_NM=false
ST_IGNORE_ZEROCONF=false
ST_IUT_IS_CMOD=false
is_nonsf=false
cfg_sfx=""
while test -n "$1" ; do
    if call_if_defined grab_cfg_check_opt "$1" ; then
        shift 1
        continue
    fi
    case $1 in
        --help) usage ;;
        --ignore-nm) ST_IGNORE_NM=true ;;
        --ignore-zeroconf) ST_IGNORE_ZEROCONF=true ;;
        --run-ts-no-sfptpd) export ST_RUN_TS_NO_SFPTPD="1" ;;
        --ool-profile=*)
        # OOL specific profiles
        pf=${1#--ool-profile=}
        OOL_PROFILE="$OOL_PROFILE --script=ool/profile:$pf"
        ;;
        --script=ool/profile:*)
        OOL_PROFILE="$OOL_PROFILE $1"
        ;;
        --ool=m32|--ool=m64)
        # Export these variables must occur before the call 'scripts/iut_os'
        export TE_OOL_UL=${1#--ool=}
        export TE_IUT_RPCS_I386_CFLAGS="${TE_IUT_RPCS_I386_CFLAGS} -${TE_OOL_UL}"
        ;;&
        --ool=*)
        # OOL specific configurations
        ool_config=${1#--ool=}
        if [[ "$ool_config" != "${ool_config/bond/}" ]] || \
           [[ "$ool_config" != "${ool_config/team/}" ]] ; then
            export SOCKAPI_TS_BOND=$ool_config
            ool_config=aggregation
        fi
        OOL_SET="$OOL_SET $ool_config"
        if [[ "$ool_config" == "zf_shim" ]] ; then
            ZF_SHIM_RUN=true
        elif [[ "$ool_config" == "onload" ]] ; then
            L5_RUN=true
        fi
        if [[ "$ool_config" != "${ool_config/tproxy/}" ]] ; then
            ST_IP_TRANSPARENT=yes
            OOL_SET="$OOL_SET scalable"
        fi
        ;;
        --cfg=cmod-x3sim-*)
            ST_IUT_IS_CMOD=true
            ;;&
        --cfg=*)
        cfg=${1#--cfg=}

        # Use cfg without '-mlx' as hostname
        hostname="${cfg/%-mlx/}"
        if test "x$hostname" != "x$cfg" ; then
            is_mlx=true
        fi

        RUN_OPTS="${RUN_OPTS} --opts=run/$cfg"
        ${ST_IUT_IS_CMOD} || call_if_defined grab_cfg_process "${cfg}"
            ;;
        --tester-req=!IP6_ONLOAD|--tester-req=!IP6)
            export ST_IPV4_ONLY_RUN=yes
            ;;&
        --tester-req=IP_TRANSPARENT)
            ST_IP_TRANSPARENT=yes
            ;;&
        --tester-req=!IP_TRANSPARENT)
            ST_IP_TRANSPARENT=no
            ;;&
        --tester-*=[^\"]*)
            RUN_OPTS="${RUN_OPTS} ${1%%=*}=\"${1#*=}\""
            ;;
        --night-testing)
            export ST_NIGHT_TESTING=yes
            ;;
        --logs-history=*)
            # Link to logs history
            export TE_NIGHT_LOGS_HISTORY=${1#--logs-history=}
            ;;
        *)  RUN_OPTS="${RUN_OPTS} $1" ;;
    esac
    shift 1
done

export ST_IGNORE_NM
export ST_IGNORE_ZEROCONF
export ST_IUT_IS_CMOD
export L5_RUN=$L5_RUN
export ZF_SHIM_RUN=$ZF_SHIM_RUN

if test "${ZF_SHIM_RUN}" = "true" ; then
    check_sf_zetaferno_dir $OOL_SET
fi

if test -n "${TE_TS_SOCKAPI}" ; then
    RUN_OPTS="${RUN_OPTS} --opts=opts.ts"
fi

if test "${ST_IP_TRANSPARENT}" = "yes" ; then
    RUN_OPTS="${RUN_OPTS} --tester-req=\"ENV-IUT-FAKE-ADDR\""
    # Scalable filters are not supported with AF_XDP. ST-2231.
    if test "x${OOL_SET/af_xdp/}" != "x${OOL_SET}" ; then
        echo -n "WARNING: AF_XPD testing is incompatible "
        echo "with transparent testing!!!"
        exit 1
    fi
    export ST_IP_TRANSPARENT
else
    RUN_OPTS="${RUN_OPTS} --tester-req=\"!ENV-IUT-FAKE-ADDR\""
fi

if test -z "${TE_BUILD}" ; then
    if test "${RUNDIR}" = "$(pwd -P)" ; then
        TE_BUILD="$(pwd -P)/build"
        mkdir -p build
    else
        TE_BUILD="$(pwd -P)"
    fi
    export TE_BUILD
fi

MY_OPTS=
MY_OPTS="${MY_OPTS} --conf-dirs=\"${RUNDIR}/conf:${SF_TS_CONFDIR}:${TE_TS_RIGSDIR}\""
if test -e "${RUNDIR}/sockapi-ts" ; then
    MY_OPTS="${MY_OPTS} --trc-db=${RUNDIR}/trc/trc-sockapi-ts.xml"
fi
MY_OPTS="${MY_OPTS} --trc-html=trc-report.html"
MY_OPTS="${MY_OPTS} --trc-no-total --trc-no-unspec"
MY_OPTS="${MY_OPTS} --trc-key2html=${TE_TS_RIGSDIR}/trc.key2html"

if test "$TE_NOBUILD" = "yes" ; then
    RUN_OPTS="$RUN_OPTS --no-builder --tester-nobuild"
fi

if test -n "$TE_BUILDER_CONF" ; then
    RUN_OPTS="$RUN_OPTS --conf-builder=$TE_BUILDER_CONF"
fi    
if test -n "$TE_TESTER_CONF" ; then
    RUN_OPTS="$RUN_OPTS --conf-tester=$TE_TESTER_CONF"
fi    

OOL_SET=$(${RUNDIR}/scripts/ool_fix_consistency.sh $hostname "$cfg_sfx" $OOL_SET)
AUX_REQS=$(${RUNDIR}/scripts/ool_fix_reqs.py --ools="$OOL_SET" --cfg_sfx="$cfg_sfx")
RUN_OPTS="${RUN_OPTS} ${AUX_REQS}"

if ! $ST_IUT_IS_CMOD && ! $is_nonsf ; then
    export_cmdclient $hostname

    # Note: firmware variants (full/low) applicable for sfc only
    iut_ifs=( $(get_sfx_ifs $hostname sfc "") )
    export_iut_fw_version $hostname ${iut_ifs[0]}
fi

if ! $is_mlx ; then
    OOL_SET=$(fw_var_consistency $OOL_SET)
    if test $? -eq 1 ; then
        exit 1
    fi
fi
RUN_OPTS="$RUN_OPTS $OOL_PROFILE"
for i in $OOL_SET ; do
    if [[ "$i" == "hwport2" ]] ; then
        # This option should be processed before env/sfc
        RUN_OPTS="--script=ool/config/$i $RUN_OPTS"
        echo "RING: hwport2 should be processed before env/sfc," \
             "using hwport2 as the first --script" >&2
    else
        RUN_OPTS="$RUN_OPTS --script=ool/config/$i"
    fi
done

eval "${TE_BASE}/dispatcher.sh ${MY_OPTS} ${RUN_OPTS}"
RESULT=$?

if test ${RESULT} -ne 0 ; then
    echo FAIL
    echo ""
fi

echo -ne "\a"
exit ${RESULT}
