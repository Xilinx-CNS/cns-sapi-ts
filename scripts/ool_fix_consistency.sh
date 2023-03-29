# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
iut_drv="$1" ; shift
iut_dut="$1" ; shift
ool_set=" $@ "

ring() {
    echo "RING: $*" >&2
}

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

#######################################
# Checks whether the 'input_set' contains the 'value' item.
# Globals:
#   None
# Arguments:
#   value       - what to search, can be a pattern
#   input_set   - where to search the 'value'
# Return:
#   0 if the 'value' is found, 1 otherwise
#######################################
is_value_in_set() {
    local value="$1" ; shift
    local input_set="$@"
    local it=

    if [[ -z "$value" ]] ; then
        fail "is_value_in_set(): value argument cannot be empty"
    fi

    if [[ -z "$input_set" ]] ; then
        fail "is_value_in_set(): input_set argument cannot be empty"
    fi

    for it in $input_set ; do
        if [[ "$it" == $value ]] ; then
            return 0
        fi
    done
    return 1
}

#
# Checks whether the 'ool_set' contains the 'value' item
#
# Globals:
#   ool_set - string with ool options separated by spaces
#
# Argumens:
#   value   - what to search, can be a pattern, such as loop[123] or scalable*
#
# Return: 0 if the value is found, 1 otherwise
#
ool_contains() {
    local value="$1" ; shift

    if [[ -z "$value" ]] ; then
        fail "ool_contains(): value cannot be empty"
    fi

    is_value_in_set "$value" "$ool_set"
}

#
# Add 'value' to 'ool_set' if there is none
#
# Globals:
#   ool_set - string with all ool options separated by spaces
#
# Argumens:
#   value   - what to search, can be a pattern, such as loop[123] or scalable*
#   extra_info  - link to a Bug or some additional useful information, optional
#
ool_add() {
    local value="$1" ; shift
    local extra_info="$1"

    if ! ool_contains "$value" ; then
        ool_set+=" $value"
        ring "$extra_info: using --ool=$value"
    fi
}

#
# Remove 'value' from 'ool_set' if it exists
#
# Globals:
#   ool_set - string with all ool options separated by spaces
#
# Argumens:
#   value   - what to search, can be a pattern, such as loop[123] or scalable*
#   extra_info  - link to a Bug or some additional information, optionally
#
ool_remove() {
    local value="$1" ; shift
    local extra_info="$1"
    local it=
    local new_ool_set=""

    if [[ -z "$value" ]] ; then
        fail "ool_remove() value cannot be empty"
    fi

    for it in $ool_set ; do
        if [[ "$it" == $value ]] ; then
            ring "$extra_info: removing --ool=$it"
        else
            new_ool_set+=" $it"
        fi
    done
    ool_set="$new_ool_set "
}

#
# Replace 'from' with 'to' in 'ool_set' if 'from' exists
#
# Globals:
#   ool_set - string with all ool options separated by spaces
#
# Argumens:
#   from    - what to search, can be a pattern, such as loop[123] or scalable*
#   to      - new value
#   extra_info  - link to a Bug or some additional information, optionally
#
ool_replace() {
    local from="$1" ; shift
    local to="$1" ; shift
    local extra_info="$1"
    local it=
    local new_ool_set=""

    if [[ -z "$from" ]] ; then
        fail "ool_replace(): 'from' cannot be empty"
    fi
    if [[ -z "$to" ]] ; then
        fail "ool_replace(): 'to' cannot be empty"
    fi

    for it in $ool_set ; do
        if [[ "$it" == $from ]] ; then
            ring "$extra_info: replacing --ool=$it with --ool=$to"
            new_ool_set+=" $to"
        else
            new_ool_set+=" $it"
        fi
    done
    ool_set="$new_ool_set "
}

#
# Put 'what' before 'follower' in 'ool_set'. If 'follower' does not exist,
# then 'what' will be added to the end.
#
# Globals:
#   ool_set - string with all ool options separated by spaces
#
# Argumens:
#   what        - what to put
#   follower    - follower, can be a pattern, such as loop[123] or scalable*
#   extra_info  - link to a Bug or some additional information, optionally
#
ool_put_before() {
    local what="$1" ; shift
    local follower="$1" ; shift
    local extra_info="$1"

    if [[ -z "$what" ]] ; then
        fail "ool_put_before(): 'what' cannot be empty"
    fi
    if [[ -z "$follower" ]] ; then
        fail "ool_put_before(): 'follower' cannot be empty"
    fi

    local what_was_put=false
    local new_ool_set=""
    local it=
    for it in $ool_set ; do
        if [[ "$it" == "$what" ]] ; then
            if [[ "$what_was_put" == true ]] ; then
                continue
            else
                what_was_put=true
            fi
        elif [[ "$it" == $follower ]] ; then
            if [[ "$what_was_put" == false ]] ; then
                ring "$extra_info: putting --ool=$what before --ool=$it"
                new_ool_set+=" $what"
            fi
        fi
        new_ool_set+=" $it"
    done
    ool_set="$new_ool_set "

    if ! ool_contains "$what" ; then
        ool_add "$what" "$extra_info"
    fi
}

function syscall_fix()
{
    # Bug 81775 comment 1: syscall is supported for x86_64-only
    if ool_contains "syscall" && ool_contains "m32" ; then
        ool_remove "syscall" \
            "syscall_fix: Bug 81775: options syscall and m32 are not compatible"
    fi
}

function ef100soc_fix()
{
    if [[ "$iut_dut" == "ef100_soc" ]] ; then
        # ON-13715: there are few VIs available for EF100 SOC, so we should
        # avoid creating too much stacks.
        if ! ool_contains "reuse_stack" ; then
            ool_replace "no_reuse_pco" "reuse_pco" \
                "EF100/ON-13715: avoid creating too much stacks"
        fi

        # ON-13893: ef100 + tcp_shared_ports should run with reuse_stack only.
        if ool_contains "tcp_shared_ports" ; then
            ool_add "reuse_stack" \
                "EF100/ON-13893: tcp_shared_ports should run with reuse_stack only"
        fi
    fi
}

function x3_fix()
{
    if [[ "$iut_dut" == "x3" ]] ; then
        # ST-2641: there are few VIs available for X3, so we should
        # avoid creating too much stacks.
        if ! ool_contains "reuse_stack" ; then
            ool_replace "no_reuse_pco" "reuse_pco" \
                "X3/ST-2641: avoid creating too much stacks"
        fi
    fi
}

function build_ulhelper_fix()
{
    local info="ulhelper_fix"
    if ool_contains "build_ulhelper" ; then
        ool_replace "loop[1234]" "loop0" "$info"
        ool_add "loop0" "$info"

        ool_replace "epoll[23]" "epoll1" "$info"
        ool_replace "safe_epoll3" "safe_epoll1" "$info"
        # Remove sleep_spin, because it requires epoll3
        ool_remove "sleep_spin" "$info: sleep_spin requires epoll3"
        # Pure safe profile sets epoll2
        ool_replace "safe" "safe_epoll1" "$info: pure safe profile sets epoll2"

        # In theory, scalable works.  But injecting unfiltered packets into
        # kernel does not.  We do not want to look at all these unexpected
        # results.
        ool_remove "scalable*" \
            "$info: do not look at unexpected results with scalable* modes"

        # ST-2070: ulhelper does not support tcp_shared_ports.
        ool_remove "tcp_shared_ports*" "$info/ST-2070"

        # ST-2085: do not test socket_cache in case of ulhelper build
        ool_remove "socket_cache" "$info/ST-2085"
    fi
}

function reuse_stack_fix()
{
    local info="reuse_stack_fix"

    if [[ -z "$scalable_fix_done" ]] ; then
        fail "${info}() should be after scalable_fix()"
    fi

    if ool_contains "reuse_stack" ; then
        ool_replace "loop[234]" "loop1" "$info"
    fi
}

function reuse_pco_fix()
{
    if ool_contains "reuse_pco" && ! ool_contains "no_reuse_pco" ; then
        ool_add "one_cluster" "reuse_pco_fix/Bug 74895"
    fi
}

function scalable_fix()
{
    local info="scalable_fix"
    if ool_contains "*scalable*" ; then
        # The scalable_iut/any modes are not intended for standalone use
        if ool_contains "scalable_iut" || ool_contains "scalable_any" ; then
            local expected_modes="rss_scalable scalable scalable_passive"
            expected_modes+=" scalable_active scalable_active_passive"
            local item_found=false
            local item=
            for item in $expected_modes ; do
                if ool_contains "$item" ; then
                    item_found=true
                    break
                fi
            done
            if [[ "$item_found" = false ]] ; then
                fail "$info: scalable_iut/any mode must be used with one of" \
                     "the following option: $expected_modes"
            fi
        fi

        # Use scalable_any as default. eol6 branch has scalable_any feature.
        if ! ool_contains "scalable_iut" && ! ool_contains "scalable_any" ; then
            ool_put_before "scalable_any" "*scalable*" "$info: set scalable_any as default"
        fi
        # ST-1948: add one_accelerated_link option in some scalable cases
        if ool_contains "scalable_iut" ; then
            # subshell is used here to make the code more readable
            if ool_contains "scalable_passive" \
                || (ool_contains "scalable_active_passive" \
                    && ool_contains "tcp_shared_ports")
            then
                ool_add "one_accelerated_link" "$info/ST-1948"
            fi
        fi
        # Bond/team, vlan and macvlan should go before scalable_iut
        local begin=""
        local end=""
        local add_end=""
        for i in ${ool_set} ; do
            if test "x${i/scalable}" != "x${i}" ; then
                add_end="yes"
            fi
            if test "x$add_end" == "xyes" ; then
                if test "x$i" == "xvlan" -o "x$i" == "xmacvlan" -o \
                    "x$i" == "xipvlan" -o \
                    "x${i/bond/}" != "x$i" -o "x${i/team/}" != "x$i" -o \
                    "x${i/aggregation/}" != "x$i" ; then
                    begin="$begin $i"
                    ring "$info: put '$i' before scalable_iut"
                else
                    end="$end $i"
                fi
            else
                begin="$begin $i"
            fi
        done
        ool_set="$begin $end"

        # Do not add reuse_stack to scalable_active_passive. See config for
        # more info
        if ! ool_contains "scalable_active_passive" ; then
            ool_add "reuse_stack" "$info"
        else
            ool_remove "reuse_stack" \
                "$info: do not add reuse_stack to scalable_active_passive"
            ool_add "one_cluster" "$info/Bug 74895"
            #  Accelerated TCP loopback is unsupported on clustered stack
            ool_replace "loop[1234]" "loop0" \
                "$info: accelerated TCP loopback is unsupported on clustered stack"
            # scalable_active_passive testing works correctly only without
            # reuse_pco mode. Bug 86682 comment 10
            if ! ool_contains "no_reuse_pco" ; then
                if ool_contains "reuse_pco" ; then
                    ool_replace "reuse_pco" "no_reuse_pco" \
                        "$info/Bug-86684, comment 10"
                else
                    ool_add "no_reuse_pco" "$info"
                fi
            fi
        fi
        ool_replace "epoll0" "epoll3" "$info"
        ool_replace "safe_epoll0" "safe_epoll3" "$info"
        if ! ool_contains "scalable_passive" ; then
            ool_replace "epoll1" "epoll3" "$info"
            ool_replace "safe_epoll1" "safe_epoll3" "$info"
        fi
        ool_replace "epoll2" "epoll3" "$info"
        ool_replace "safe" "safe_epoll3" "$info"
        if ! ool_contains "scalable_passive" ; then
            ool_add "epoll3" "$info"
        fi

        if ool_contains "scalable_iut" ; then
            ool_put_before "scalable_iut" "*scalable*" \
                "$info: put scalable_iut before any scalable"
        fi
        if ool_contains "scalable_any" ; then
            ool_put_before "scalable_any" "*scalable*" \
                "$info: put scalable_any before any scalable"
        fi
    fi
    scalable_fix_done=true
}
function socket_cache_fix()
{
    local info="socket_cache_fix"

    if [[ -n "$scalable_fix_done" ]] ; then
        fail "socket_cache_fix() should be before scalable_fix()"
    fi

    if ool_contains "socket_cache" ; then
        ool_replace "epoll[012]" "epoll3" "$info"
        ool_replace "safe_epoll[01]" "safe_epoll3" "$info"
        ool_replace "safe" "safe_epoll3" "$info"
        # Use tcp_shared_ports to enable all kinds of caching.
        ool_add "tcp_shared_ports" "$info/Bug 89030: enable all kinds of caching"
    fi
}

function mt_safe_fix()
{
    if ool_contains "safe*" ; then
        ool_remove "epoll_mt_safe" "mt_safe_fix"
        ool_remove "fds_mt_safe" "mt_safe_fix"
    fi
}

function loop_fix()
{
    local info="loop_fix"
    if ! ool_contains "loop*" ; then
        ool_add "loop0" "$info"
    fi

    # Note: subshell is used here to make the code more readable
    if ool_contains "loop0" \
        || (ool_contains "loop1" && ! ool_contains "reuse_stack")
    then
        ool_add "loop_linux" "$info"
    else
        ool_add "loop_onload" "$info"
    fi
}

function sleep_spin_fix()
{
    local info="sleep_spin_fix"
    if ool_contains "sleep_spin" ; then
        # Use epoll3 in case of sleep_spin.
        ool_replace "epoll[012]" "epoll3" "$info: use epoll3 in case of sleep_spin"
        ool_replace "safe_epoll[01]" "safe_epoll3" "$info: use epoll3 in case of sleep_spin"
        # Pure safe profile uses epoll2 so safe_epoll3 should be used in
        # such case.
        ool_replace "safe" "safe_epoll3" \
            "$info: pure safe profile uses epoll2 - avoid this"
        # Default is epoll1 so epoll3 should be added is there is no epoll
        # ool option.
        if ! ool_contains "epoll*" ; then
            ool_add "epoll3" "$info: use epoll3 by default"
        fi

        # sleep_spin should be used with any spin, so add spin by default
        # if there is no spin ool option.
        ool_add "spin" "$info: sleep_spin should be used with any spin"
    fi
}

function safe_epoll_fix()
{
    # Replace "safe + epollN" options with a single "safe_epollN" option.
    # It fixes the issue related to the order of these options - if "epollN"
    # comes before "safe" we get a TRC tag that does not match the actual
    # behavior, because safe profile does not overwrite EF_UL_EPOLL variable,
    # but still adds the tag. That breaks epoll tests expectations.

    local info="safe_epoll_fix"

    if ool_contains "safe"; then
        ool_replace "epoll0" "safe_epoll0" "$info"
        ool_replace "epoll1" "safe_epoll1" "$info"
        ool_replace "epoll3" "safe_epoll3" "$info"
        ool_contains "safe_epoll*" && ool_remove "safe" "$info"
    fi
}

function epoll_fix()
{
    local info="epoll_fix"

    if [[ -n "$branch_order_fix_done" ]] ; then
        fail "epoll_fix() should be before branch_order_fix()"
    fi

    if ool_contains "epoll_ctl_fast" ; then
        # epoll_ctl_fast should be after safe, so put it in the end
        if ool_contains "safe*" ; then
            ool_set="${ool_set/epoll_ctl_fast/} epoll_ctl_fast"
            ring "$info: epoll_ctl_fast should be after safe - put it in the end"
        fi
    fi

    # libc_close(epoll fd) is not trampolined. ON-12255.
    if ool_contains "default_epoll" ; then
        ool_remove "libc_close" \
            "$info/ON-12255 libc_close(epoll fd) is not trampolined"
    fi
}

# ool/config/disable_timestamps can be switched off in scripts/lib.netns
# script so should be called after ool/config/netns*
function disable_timestamps_fix()
{
    if ool_contains "disable_timestamps" ; then
        ool_set="${ool_set/disable_timestamps/} disable_timestamps"
        ring "disable_timestamps can be switched off by netns, put it in the end"
    fi
}

# Do not test ool/config/pkt_nocomp without reuse_stack and reuse_pco
# according to ST-2051
function pkt_nocomp_fix()
{
    if ool_contains "no_reuse_pco" && ! ool_contains "reuse_stack" ; then
        ool_remove "pkt_nocomp" \
            "ST-2051: avoid using pkt_nocomp without reuse_stack and reuse_pco"
    fi
}

# Option ipvlan should be tested with netns_iut only. ST-2119.
# The ordering is important for netns, bond, vlan, etc.
# It is handled in ool_param_freqs.yaml for night testing.
# There are additional checks in ool/config/* files also.
# For example, it is impossible to use ipvlan together with macvlan,
# or vlan over ipvlan.
# In this case, the important thing is that netns
# must be at the end of the sequence.

function ipvlan_fix()
{
    local info="ipvlan_fix"
    if ool_contains "ipvlan" ; then
        ool_replace "netns_all" "netns_iut" \
            "$info/ST-2119 ipvlan should be tested with netns_iut only"
        ool_add "netns_iut" \
            "$info/ST-2119 ipvlan should be tested with netns_iut only"
    fi
}

# Intel i40e/ice and Mellanox mlx5_core drivers misbehave when Onload injects
# packets to the kernel in case of onload + af_xdp + vlan.
# Bug 11959.
vlan_af_xdp_problematic_drvs="i40e ice mlx5_core"

function aggregation_fix()
{
    local info="aggregation_fix"
    if ool_contains "aggregation" || ool_contains "team*" || ool_contains "bond*" ; then
        # aggregation interface + netns_iut has to be tested with either
        # macvlan/ipvlan or vlan
        if ool_contains "netns_iut" && ! ool_contains "*vlan" ; then
            if ool_contains "af_xdp*" && \
               is_value_in_set "$iut_drv" "$vlan_af_xdp_problematic_drvs" ; then
                # The ordering is important, netns should be after
                # team/bond and after macvlan/ipvlan/vlan;
                # avoid vlan in case of vlan + onload + af_xdp, see Bug-11959
                ool_put_before "macvlan" "netns_iut" \
                    "$info: aggregation + netns_iut should be tested at least with (mac/ip)vlan"
            else
                ool_put_before "vlan" "netns_iut" \
                    "$info: aggregation + netns_iut should be tested at least with (mac/ip)vlan"
            fi
        fi
    fi
}

# All AF_XDP limitations can be found in ON-12141
# Must be called before scalable_fix.
function af_xdp_fix()
{
    local info="af_xdp_fix"
    local avoid_vlan_with_af_xdp_msg="avoid vlan in onload + af_xdp + vlan testing"

    ool_remove "af_xdp_common" \
        "$info: this option is not intended for standalone use"

    # RX/TX HW Timestamps is unsupported
    if ool_contains "af_xdp*" ; then
        ool_add "no_rx_ts" \
            "$info/ON-12141: rx/tx hw timestamps are not supported"

        ool_add "few_stacks" \
            "$info/Bug 11802/ON-12446"

        # phys_mode is not compatible with AF_XDP
        ool_remove "phys_mode" "$info/ON-12141: phys_mode is not compatible"

        # AF_XDP is stable with reuse_pco only if reuse_stack option
        # is not presented.
        # af_xdp_no_filters option should be tested with reuse_stack only.
        # ON-12446.
        if ! ool_contains "reuse_stack" ; then
            if ool_contains "af_xdp_no_filters" ; then
                ool_add "reuse_stack" \
                    "$info/ON-12446: use af_xdp_no_filters with reuse_stack only"
            else
                ool_replace "no_reuse_pco" "reuse_pco" \
                    "$info: without reuse_stack, it is stable only with reuse_pco"
            fi
        fi

        # Scalable filters are not supported
        ool_remove "scalable*" "$info: scalable filters are not supported"

        if ool_contains "zc_af_xdp*" && ool_contains "netns_*" ; then
            if [[ "$iut_drv" == "sfc" ]] ; then
                ool_remove "netns_*" \
                    "$info/SWNETLINUX-4809/Bug 11986: disable netns on SFC NICs with zc_af_xdp"
            fi
        fi

        if ool_contains "tiny_spin" ; then
                ool_remove "tiny_spin" \
                    "$info/Bug 12656: disable tiny_spin with af_xdp"
        fi

        # Intel i40e/ice and Mellanox mlx5_core drivers misbehave when Onload injects
        # packets to the kernel in case of onload + af_xdp + vlan.
        # There is no consistency in case of Mellanox:
        # it was found that vlan + onload + af_xdp on mlx5_core works well
        # in case of Debian 11 with kernels (5.19/5.15) and doesn't
        # work on Ubuntu 22.04.1 LTS with the same kernel versions.
        # Bug 11959.
        if ool_contains "vlan" && \
            is_value_in_set "$iut_drv" "$vlan_af_xdp_problematic_drvs" ; then
            if ool_contains "aggregation" || ool_contains "team*" || ool_contains "bond*" ; then
                if ool_contains "netns_iut" ; then
                    if ! ool_contains "macvlan" && ! ool_contains "ipvlan"; then
                        ool_replace "vlan" "macvlan" \
                            "$info/Bug 11959: $avoid_vlan_with_af_xdp_msg on Intel/Mellanox"
                    fi
                fi
            fi
            ool_remove "vlan" \
                "$info/Bug 11959: $avoid_vlan_with_af_xdp_msg on Intel/Mellanox"
        fi
    else
        # zc_af_xdp should be used only with AF_XDP
        ool_remove "zc_af_xdp" \
            "$info: zc_af_xdp should be used only with af_xdp*"
    fi
}

function defaults_fix()
{
    if ool_contains "onload" ; then
        ool_add "defaults" "defaults_fix"
    fi
}

# ool/config/branch_* should be moved at the end.
# This file takes into account all changes made by other options to
# handle branch-depended requirements
function branch_order_fix()
{
    for i in ${ool_set} ; do
        if test "x${i/branch_}" != "x${i}" ; then
            ool_set="${ool_set/${i}/} $i"
            ring "branch_order_fix: move '${i}' at the end"
            break
        fi
    done
    branch_order_fix_done=true
}

function cplane_default_fix()
{
    if ! ool_contains "cplane_log_to_default" ; then
        ool_add "cplane_log_to_kernel" "cplane_default_fix"
    fi
}

function zf_shim_fix()
{
    if ool_contains "zf_shim" ; then
        if ! ool_contains "nopio" ; then
            ool_add "zf_pio2" "zf_shim_fix: set zf_pio2 by default"
        fi
    fi
}

function cplane_server_grace_timeout_zero_fix() {
    local info="cplane_server_grace_timeout_zero_fix"
    if ool_contains "cplane_server_grace_timeout_zero" ; then
        if ool_contains "reuse_stack" ; then
            ool_remove "cplane_server_grace_timeout_zero" \
                "$info: option is incompatible with reuse_stack"
        fi
        if ! ool_contains "no_reuse_pco" ; then
            ool_remove "cplane_server_grace_timeout_zero" \
                "$info: option is incompatible with reuse_pco"
        fi
    fi
}

# Use reuse_pco by default if no_reuse_pco has not been set
ool_contains "no_reuse_pco" || ool_add "reuse_pco" "set reuse_pco by default"

zf_shim_fix
syscall_fix
ef100soc_fix
x3_fix
build_ulhelper_fix
aggregation_fix
af_xdp_fix
# socket_cache_fix should be before scalable_fix
socket_cache_fix
scalable_fix
# reuse_stack_fix should be after scalable_fix
reuse_stack_fix
mt_safe_fix
loop_fix
reuse_pco_fix
sleep_spin_fix
disable_timestamps_fix
pkt_nocomp_fix
ipvlan_fix
cplane_default_fix
safe_epoll_fix
# epoll_fix should be at the end but before branch_order_fix
epoll_fix
defaults_fix
branch_order_fix
cplane_server_grace_timeout_zero_fix

echo $ool_set
