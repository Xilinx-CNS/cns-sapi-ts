# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

congestion_lib_sources = [
    'ts_congestion.c',
]

congestion_lib = static_library('congestion_lib', congestion_lib_sources,
                                include_directories: [lib_dir, congestion_lib_dir],
                                dependencies: dep_tirpc)
