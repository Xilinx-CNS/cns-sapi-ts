# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
# The ol-ceph application may be built in two ways from Onload usage point
# of view:
# - resolve Onload functions via dlsym from the libraries listed in LD_PRELOAD
#   (this is how night testing is supposed to work with ol-ceph).
# - statically link needed Onload libraries.
# This is controlled by meson boolean option 'ceph_use_dlsym'. It is true by
# default, i.e. dlsym based way is used by default. If a user set it to false,
# then libciul1 and libonload_ext are being searched in a project source
# directory, and, if presented, are linked with ol-ceph.

cc = meson.get_compiler('c')
ceph_deps = []
c_args = ['-Wall']

ceph_deps += declare_dependency(include_directories: gpl_tools_lib_inc,
                                link_with: gpl_tools_lib)
incdir = include_directories('ceph')

# dlsym(3)
ceph_deps += cc.find_library('dl')

# For ceph headers
if cc.has_header('linux/types.h')
    c_args += [ '-DHAVE_LINUX_TYPES_H=1' ]
endif

ceph_srcs = [
    'ol_ceph.c',
    'ol_ceph_connection.c',
    'ol_ceph_generator.c',
    'ol_ceph_offload.c',
    'ol_ceph_protocol.c',
    'ol_ceph_receiver.c',
]

# Check that we have both zero-copy and mem2mem transmit support.
have_zc = cc.has_header('onload/extensions_zc.h',
                        include_directories: include_directories('.'))
have_efvi_memcpy = cc.has_header_symbol(
                        'etherfabric/ef_vi.h',
                        'ef_vi_transmit_memcpy',
                        include_directories: include_directories('.'))
if have_zc and have_efvi_memcpy
    c_args += [ '-DHAVE_ZC=1' ]
else
    warning('ol-ceph is built without zero-copy support')
endif

use_dlsym = get_option('ceph_use_dlsym')
if use_dlsym
    c_args += [ '-DUSE_DLSYM=1' ]
else
    ceph_deps += cc.find_library('onload_ext', required: true,
                                               dirs: meson.current_source_dir())
    ceph_deps += cc.find_library('ciul1', required: true,
                                          dirs: meson.current_source_dir())
endif

executable('ol-ceph', sources : ceph_srcs, dependencies: ceph_deps,
           c_args: c_args, include_directories : incdir)
