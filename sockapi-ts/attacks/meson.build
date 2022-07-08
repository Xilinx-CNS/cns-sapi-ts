# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

sub_dirs = [
    'ethernet',
    'icmp',
    'ip',
    'tcp',
    'udp',
]


install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

foreach sub_dir : sub_dirs
    package_sub_dir = join_paths(package_dir, sub_dir)
    package_sub_tests_c = []
    subdir(sub_dir)
endforeach
