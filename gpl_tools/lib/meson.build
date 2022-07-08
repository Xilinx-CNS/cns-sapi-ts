# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
sources = [
    'ol_cmdline.c',
    'ol_helpers.c',
    'ol_poll.c',
    'ol_pattern.c',
    'ol_ringbuf.c',
    'ol_time.c',
]

gpl_tools_lib_inc = include_directories('.')
gpl_tools_lib = static_library('tools_lib', sources, dependencies: te_deps)
