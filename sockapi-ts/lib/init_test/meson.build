# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
# Note: only shared init_test library is built (which will be used
# by the libinit package together with LD_PRELOAD).

project('init_test', 'c', version : '1.0.0')

add_global_arguments('-Werror', language : 'c')

init_test_sources = files('libtest.c')

shared_library('init_test',
               init_test_sources,
               implicit_include_directories: false,
               dependencies: dependency('threads'))
