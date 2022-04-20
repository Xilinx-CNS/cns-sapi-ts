# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
# Socket API Test Suite
# IP/TCP/UDP checksum tests

subdir('lib')

checksum_test_deps = test_deps
checksum_test_deps += libchecksum_dep

tests = [
    'bad_udp_csum',
    'tcp_bad_csum_close',
    'tcp_bad_csum_open',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: checksum_test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ], install_dir: package_dir)
