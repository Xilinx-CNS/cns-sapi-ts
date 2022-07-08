#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

set -e
pushd "$(dirname "$(which "$0")")" >/dev/null
RUNDIR="$(pwd -P)"
popd >/dev/null

[ "$(basename $RUNDIR)" = "scripts" ] && RUNDIR="${RUNDIR}/.."
[ -e "${RUNDIR}/scripts/guess.sh" ] && source "${RUNDIR}/scripts/guess.sh"

. ${SF_TS_CONFDIR}/scripts/lib.run

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
  --no-item                 Do not use item for host ownership
  --night-testing           This is the night testing run, perform some
                            appropriate actions. For now: do not clear kmemleak
                            on debugging kernels.
  --logs-history=<link>     Link to logs history

EOF
${TE_BASE}/dispatcher.sh --help
exit 1
}

L5_RUN=false
ZF_SHIM_RUN=false
RUN_OPTS="${RUN_OPTS} --trc-comparison=normalised --build-meson"
RUN_OPTS="${RUN_OPTS} --sniff-not-feed-conf"
RUN_OPTS="${RUN_OPTS} --tester-only-req-logues"
do_item=true
is_cmod=false
is_mlx=false
while test -n "$1" ; do
    case $1 in
        --help) usage ;;
        --ignore-nm) ignore_network_manager="true" ;;
        --ignore-zeroconf) ignore_zeroconf="true" ;;
        --run-ts-no-sfptpd) export ST_RUN_TS_NO_SFPTPD="1" ;;
        --no-item) do_item=false ;;
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
            is_cmod=true
            ;;&
        --cfg=*)
        cfg=${1#--cfg=}

        # Use cfg without '-mlx' as hostname
        hostname="${cfg/%-mlx/}"
        if test "x$hostname" != "x$cfg" ; then
            is_mlx=true
        fi

        RUN_OPTS="${RUN_OPTS} --opts=run/$cfg"
        if $do_item; then
            ${is_cmod} || take_items "$hostname"
        fi
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
MY_OPTS="${MY_OPTS} --conf-dirs=\"${RUNDIR}/conf:${SF_TS_CONFDIR}\""
if test -e "${RUNDIR}/sockapi-ts" ; then
    MY_OPTS="${MY_OPTS} --trc-db=${RUNDIR}/trc/trc-sockapi-ts.xml"
fi
MY_OPTS="${MY_OPTS} --trc-html=trc-report.html"
MY_OPTS="${MY_OPTS} --trc-no-total --trc-no-unspec"
MY_OPTS="${MY_OPTS} --trc-key2html=${SF_TS_CONFDIR}/trc.key2html"

if test "$TE_NOBUILD" = "yes" ; then
    RUN_OPTS="$RUN_OPTS --no-builder --tester-nobuild"
fi

if test -n "$TE_BUILDER_CONF" ; then
    RUN_OPTS="$RUN_OPTS --conf-builder=$TE_BUILDER_CONF"
fi    
if test -n "$TE_TESTER_CONF" ; then
    RUN_OPTS="$RUN_OPTS --conf-tester=$TE_TESTER_CONF"
fi    

if ! $is_cmod ; then
    export_te_workspace_make_dirs "${SF_TS_CONFDIR}/env/$hostname"
    hosts=$(cat ${SF_TS_CONFDIR}/env/$hostname | egrep "(TE_IUT=|TE_TST[0-9]*=)" | sed "s/.*=//")

    if test -z "$ignore_network_manager" ; then
        for curr_host in ${hosts}; do
            [ -n "`ssh $curr_host ps aux 2>/dev/null | egrep NetworkManager.*/var/run/NetworkManager | grep -v grep`" ] || continue
            echo "NetworkManager is running on $curr_host. Use --ignore-nm to suppress warning."
            exit 1
        done
    fi

    if test -z "$ignore_zeroconf" ; then
        for curr_host in ${hosts}; do
            [ -n "`ssh $curr_host /sbin/route 2>/dev/null | grep ^link-local`" ] || continue
            echo "ZEROCONF is enabled on $curr_host. Use --ignore-zeroconf to suppress warning."
            echo "Add 'NOZEROCONF=yes' line to /etc/sysconfig/network to disable ZEROCONF."
            exit 1
        done
    fi
fi

OOL_SET=$(${RUNDIR}/scripts/ool_fix_consistency.sh $hostname $OOL_SET)
AUX_REQS=$(${RUNDIR}/scripts/ool_fix_reqs.py --ools="$OOL_SET")
RUN_OPTS="${RUN_OPTS} ${AUX_REQS}"

if ! $is_cmod && ! $is_mlx ; then
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
