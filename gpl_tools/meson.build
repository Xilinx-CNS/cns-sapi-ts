# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

project('gpl_tools', 'c')
cc = meson.get_compiler('c')

add_global_arguments('-Werror', language : 'c')

te_deps = [dependency('jansson', required: false)]

te_cflags = get_option('te_cflags').split()
te_ldflags = get_option('te_ldflags').split()

add_project_arguments(te_cflags, language: 'c')

# Use static implementation of TE libraries
add_project_link_arguments('-Wl,-Bstatic', language: 'c')
add_project_link_arguments(te_ldflags, language: 'c')

# Use shared external (system) libraries and only if are needed
add_project_link_arguments('-Wl,-Bdynamic', language: 'c')
add_project_link_arguments('-Wl,--as-needed', language: 'c')

te_deps += [ dependency('libbsd', required: false) ]

# Build lib
subdir('lib')

# Build apps
apps = [
    'apprtt',
    # ol-ceph tool contains original ceph headers which break sapi-ts building
    # with gcc 11.3.0. We do not want to maintain ceph headers, so just disable
    # the ol-ceph building.
    # 'ceph',
    'nfq_daemon',
]

foreach app : apps
    subdir(app)
endforeach
