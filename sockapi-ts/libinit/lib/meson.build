# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

libinit_lib_sources = [
    'init_lib.c',
]

libinit_lib = static_library('libinit_lib', libinit_lib_sources,
                             include_directories: [lib_dir, libinit_lib_dir],
                             dependencies: dep_tirpc)
