# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

sources = [
    'derived_instances.c',
    'icmp_send.c',
    'iomux.c',
    'onload.c',
    'onload_rpc.c',
    'parse_icmp.c',
    'sendfile_common.c',
    'sockapi-ts.c',
    'sockapi-ts_apprtt.c',
    'sockapi-ts_bpf.c',
    'sockapi-ts_cns.c',
    'sockapi-ts_env.c',
    'sockapi-ts_monitor.c',
    'sockapi-ts_net_conns.c',
    'sockapi-ts_pcap.c',
    'sockapi-ts_rpc.c',
    'sockapi-ts_rpcs.c',
    'sockapi-ts_stats.c',
    'sockapi-ts_target_build.c',
    'sockapi-ts_tcp.c',
    'vlan_common.c',
    join_paths(onload_tslib_dir, 'lib-ts.c'),
    join_paths(onload_tslib_dir, 'lib-ts_netns.c'),
    join_paths(onload_tslib_dir, 'lib-ts_timestamps.c'),
]

ts_sockapi_lib = static_library('ts_sockapi', sources,
                                include_directories: lib_dir,
                                dependencies: dep_tirpc)
