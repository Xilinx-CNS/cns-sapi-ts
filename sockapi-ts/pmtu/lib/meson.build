# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

pmtu_lib_sources = [
    'pmtu_lib.c',
]

pmtu_common_lib = static_library('pmtu_lib', pmtu_lib_sources,
                                 include_directories: [lib_dir, pmtu_lib_dir],
                                 dependencies: dep_tirpc)
