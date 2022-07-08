# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

udptest_lib_sources = [
    'udp_multisrc.c',
]

udptest_lib = static_library('udptest', udptest_lib_sources,
                             include_directories: [lib_dir, udptest_lib_dir],
                             dependencies: dep_tirpc)
