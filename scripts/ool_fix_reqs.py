#! /usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

import re
import argparse
import sys

parser = argparse.ArgumentParser(
    description='Script based on ool options returns a set '
                'of necessary tester requirements.')
parser.add_argument("--ools", required=True, type=str,
                    help="Set of OOL options")
args = parser.parse_args()

ools_str = args.ools
ools = ools_str.split(" ")
reqs = ""

def ring(msg: str = "") -> None:
    """Print msg with prefix RING to stderr

    Args:
        msg: message to print
    """
    print("RING: " + msg, file=sys.stderr)

def add_req(new_req: str, reason: str = "") -> None:
    """Add new_req to the global reqs

    Args:
        new_req: What to add
        reason: print a reason, optional
    """
    global reqs

    reqs += " --tester-req=" + new_req
    if reason != "":
        reason += ": "
    ring("req_fix: " + reason + "adding --tester-req=" + new_req)

# Socket caching is disabled.
# Do not run FD cahcing tests.
if "socket_cache" not in ools:
    add_req("!FD_CACHING", "socket caching is disabled")

if len(re.findall('scalable', ools_str)) != 0:
    if "scalable_active_passive" not in ools:
        # Scalable, but not scalable_active_passive:
        # Do not run tests which assume RSS scalable filters.
        add_req("!RSS_SCALABLE", "scalable, but not scalable_active_passive")
else:
    # There are no any scalable filters. Add no_scalable ool opt
    # to disable all tests which require some scalable filters
    # being enabled
    add_req("!SCALABLE", "there are no any scalable filters")

# Some tests cannot tolerate more than one level of VLAN or MAC/IP VLAN,
# for example because they create another VLAN over it and the resulting
# interface name is too long.
#
if len(re.findall('vlan|macvlan|ipvlan', ools_str)) > 1:
    add_req("!NO_TWO_IF_LEVELS",
        "some tests cannot tolerate more than one level of VLAN or MAC/IP VLAN")

# Tests marked with SMALL_RLIMIT_NOFILE are not compatible
# with nginx_reverse_proxy and reuse_pco. ST-1120
if "reuse_pco" in ools and "nginx_reverse_proxy" in ools:
    add_req("!SMALL_RLIMIT_NOFILE",
        "ST-1120: tests are not compatible with nginx_reverse_proxy and reuse_pco")

# TCP_TS_ENABLED and TCP_TS_DISABLED are using to allow only
# iterations matching preconfigured TCP timestamps state in
# case of --ool=reuse_stack. ST-1289
if "reuse_stack" in ools:
    if "disable_timestamps" in ools:
        add_req("!TCP_TS_ENABLED", "ST-1289: reuse_stack and disable_timestamps")
    else:
        add_req("!TCP_TS_DISABLED", "ST-1289: reuse_stack")

# default_epoll and default_epoll_pwait use onload extensions
# stackname API (in citp_epoll_ctl_onload_add_new()).
# SCALABLE_FILTERS_ENABLE_WORKER mode is not compatible with this API.
# See ON-11988.
if (("default_epoll" in ools or "default_epoll_pwait" in ools) and
        "scalable_active_passive" in ools):
    add_req("!SCALABLE_FILTERS_ENABLE_WORKER",
        "ON-11988: default_epoll/default_epoll_pwait use onload extenstions API")

# AF_XDP does not hand IPv6 sockets over to the kernel stack with
# ulhelper build in single queue mode. ON-12581.
if "af_xdp_no_filters" in ools and "build_ulhelper" in ools:
    add_req("!IP6", "ON-12581: af_xdp_no_filters + build_ulhelper")

# af_xdp_no_filters supports only one stack. See ST-2164.
if "af_xdp_no_filters" in ools and "reuse_stack" not in ools:
    af_xdp_no_filters_reason = "ST-2164: af_xdp_no_filters supports only one stack"
    add_req("!PIPE", af_xdp_no_filters_reason)
    add_req("!EXEC", af_xdp_no_filters_reason)
    add_req("!SO_LINGER", af_xdp_no_filters_reason)
    add_req("!ENV-LOOPBACK", af_xdp_no_filters_reason)

# loop4 + m32 parameter combination leads to "out of memory" problem described
# in ON-12690.
if "loop4" in ools and "m32" in ools:
    add_req("!NO_LOOP4_M32",
        "ON-12690: loop4 + m32 parameter combination leads to out of memory")

# It is dangerous to run tests checking __[func]_chk() functions
# with normal functions - passing length bigger than the provided
# buffer may result in segfault. So disable such iterations unless
# --ool=use_chk_funcs is specified.
if "use_chk_funcs" not in ools:
    add_req("!CHK_FUNC", "the use_chk_funcs option is not specified")

# Do not run onload_zc_send() iterations with registered ZC buffer, see
# ON-13696.
add_req("!ONLOAD_ZC_SEND_USER_BUF",
        "ON-13696: onload_zc_send() with registered ZC buffer is broken")

print(reqs)
