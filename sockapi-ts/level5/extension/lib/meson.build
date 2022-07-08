# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

level5_extention_lib_template_sources = [
    'template.c',
]

level5_extention_lib_od_send_sources = [
    'od_send.c',
]

level5_extention_template_lib = static_library('level5_extention_template',
                                               level5_extention_lib_template_sources,
                                               include_directories: [lib_dir, level5_extention_lib_dir],
                                               dependencies: dep_tirpc)

level5_extention_od_send_lib = static_library('level5_extention_od_send',
                                              level5_extention_lib_od_send_sources,
                                              include_directories: [lib_dir, level5_extention_lib_dir],
                                              dependencies: dep_tirpc)
