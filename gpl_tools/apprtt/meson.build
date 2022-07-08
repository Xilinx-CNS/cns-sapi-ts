# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

apprtt_deps = [ cc.find_library('pthread', required : true) ]

apprtt_deps += declare_dependency(include_directories: gpl_tools_lib_inc,
                                  link_with: gpl_tools_lib)

apprtt_srcs = [
    'ol_apprtt.c',
    'ol_client.c',
    'ol_server.c',
]

executable('ol-apprtt', sources : apprtt_srcs, dependencies : apprtt_deps)
