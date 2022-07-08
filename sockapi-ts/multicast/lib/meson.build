# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

multicast_lib_sources = [
    'mcast_lib.c',
]

multicast_lib = static_library('mcastn', multicast_lib_sources,
                               include_directories: [lib_dir, multicast_lib_dir],
                               dependencies: dep_tirpc)
