#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

from sys import argv


def is_pattern_in_list(l, *argv):
    for p in argv:
        for i in l:
            if p in i:
                return True
    return False


def ool_perf_fix(ools):
    # no_rx_ts - by default; otherwise rx_ts is specified
    if "rx_ts" in ools:
        ools.remove("rx_ts")
    else:
        ools.append("no_rx_ts")

    # scalable_any - always on for all scalable modes
    if is_pattern_in_list(ools, "scalable"):
        ools.insert(0, "scalable_any")

    # mt_safe = fds_mt_safe + epoll_mt_safe
    if "mt_safe" in ools:
        ools.remove("mt_safe")
        ools.append("fds_mt_safe")
        ools.append("epoll_mt_safe")

    return ools


if __name__ == "__main__":
    print(",".join(ool_perf_fix(argv[1].split(","))) if len(argv) > 1 else "")
