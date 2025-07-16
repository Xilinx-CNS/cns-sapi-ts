# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

udptest_lib_dir = include_directories('lib')

subdir('lib')

udp_test_deps = test_deps
udp_test_deps += declare_dependency(include_directories: udptest_lib_dir,
                                    link_with: udptest_lib)

tests = [
    'check_double_bind',
    'close_tx_active',
    'epilogue',
    'prologue',
    'receive_before_and_after_connect',
    'recv_connect',
    'recv_from_multiple_sources',
    'recv_from_multiple_sources_two_ifs',
    'reduce_mtu_flood_udp',
    'reuseaddr_connect',
    'round_trip_1',
    'round_trip_2',
    'send_via_os',
    'share_remove_addr',
    'udp_checksum',
    'udp_fork_distrib',
    'udp_send_flow',
    'varied_send'
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: udp_test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

