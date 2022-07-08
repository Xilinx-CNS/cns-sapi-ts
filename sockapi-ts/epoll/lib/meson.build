# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

epoll_lib_sources = [
    'epoll_common.c',
]

epoll_common_lib = static_library('epoll_common', epoll_lib_sources,
                                  include_directories: [lib_dir, epoll_lib_dir],
                                  dependencies: dep_tirpc)
