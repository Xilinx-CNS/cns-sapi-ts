# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

route_lib_sources = [
    'ts_route.c',
    'ts_route_mpath.c',
]

route_lib = static_library('route_lib', route_lib_sources,
                           include_directories: [lib_dir, route_lib_dir],
                           dependencies: dep_tirpc)
