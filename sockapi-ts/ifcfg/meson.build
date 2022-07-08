# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'if_add_addr_after_listen',
    'if_addr_add_remove_recv',
    'if_addr_assign_order',
    'if_bind_down_use_other_if',
    'if_bind_on_down_if',
    'if_down_nodelay',
    'if_loopback_conn',
    'if_remove_addr_after_bind_dgram',
    'if_remove_addr_after_bind_stream',
    'if_remove_addr_after_connect',
    'if_remove_addr_after_listen',
    'if_remove_addr_after_many_conns',
    'if_source_addr_dgram',
    'if_source_addr_stream',
    'if_up_down',
    'if_up_down_influence',
    'recv_wrong_mac',
    'two_if_on_subnet',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

