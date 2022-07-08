# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

arp_lib_sources = [
    'arp_send_recv.c',
]

arp_send_recv_lib = static_library('arp_send_recv', arp_lib_sources,
                                   include_directories: [lib_dir, arp_lib_dir],
                                   dependencies: dep_tirpc)
