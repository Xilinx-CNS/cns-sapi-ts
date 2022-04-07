# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022 OKTET Labs Ltd. All rights reserved.

libtools_inc = include_directories('.')

libtools_src = [
    'tools_lib.c',
]

libtools = static_library('libtools', libtools_src,
                          include_directories: [lib_dir, libtools_inc],
                          dependencies: dep_tirpc)

libtool_dep = declare_dependency(include_directories: libtools_inc,
                                 link_with: libtools)