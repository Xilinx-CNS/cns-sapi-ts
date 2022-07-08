# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

sub_dirs = [
    'bpf',
    'ext_stackname',
    'extension',
    'fd_caching',
    'interop',
    'out_of_resources',
    'ulv',
]


install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

foreach sub_dir : sub_dirs
    package_sub_dir = join_paths(package_dir, sub_dir)
    package_sub_tests_c = []
    subdir(sub_dir)
endforeach
