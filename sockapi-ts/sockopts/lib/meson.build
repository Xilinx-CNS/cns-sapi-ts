# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

sockopts_lib_sources = [
    'sockopts_common.c',
]

sockopts_common_lib = static_library('sockopts_common', sockopts_lib_sources,
                                     include_directories: [lib_dir, sockopts_lib_dir],
                                     dependencies: dep_tirpc)
