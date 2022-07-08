# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tcptest_lib_sources = [
    'tcp_isn_check.c',
    'tcp_test.c',
]

tcptest_lib = static_library('tcptest', tcptest_lib_sources,
                             include_directories: [lib_dir, tcptest_lib_dir],
                             dependencies: dep_tirpc)
