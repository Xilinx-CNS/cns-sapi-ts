# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

reuseport_lib_sources = [
    'reuseport.c',
]

reuseport_lib = static_library('reuseport', reuseport_lib_sources,
                               include_directories: [lib_dir, reuseport_lib_dir],
                               dependencies: dep_tirpc)
