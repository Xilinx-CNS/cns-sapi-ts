# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

sendrecv_lib_sources = [
    'two_threads_stress.c',
    'rpc_sendrecv.c',
]

sendrecv_lib = static_library('sendrecv', sendrecv_lib_sources,
                              include_directories: [lib_dir, sendrecv_lib_dir],
                              dependencies: dep_tirpc)
