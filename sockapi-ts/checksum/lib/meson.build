# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
# Socket API Test Suite
# IP/TCP/UDP checksum tests

libchecksum_inc = include_directories('.')

libchecksum_src = [
    'checksum_lib.c',
]

libchecksum = static_library('libchecksum', libchecksum_src,
                             include_directories: [lib_dir, libchecksum_inc],
                             dependencies: dep_tirpc)

libchecksum_dep = declare_dependency(include_directories: libchecksum_inc,
                                     link_with: libchecksum)
