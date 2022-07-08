# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

arp_lib_dir = include_directories('lib')

subdir('lib')

arp_test_deps = test_deps
arp_test_deps += declare_dependency(include_directories: arp_lib_dir,
                                    link_with: arp_send_recv_lib)
tests = [
    'arp_change',
    'arp_flooding',
    'arp_packet_pool_empty',
    'arp_table_full',
    'broadcast',
    'common_broadcast',
    'different_subnets',
    'gateway_addr',
    'if_ll_addr_1',
    'if_ll_addr_2',
    'if_scope_check',
    'incomplete_entry',
    'invalid_arp_entry_timeout',
    'invalid_arp_request',
    'many_addresses',
    'new_broadcast_arp',
    'no_outgoing_traffic',
    'permanent_entry_untouched_by_reply',
    'permanent_entry_untouched_by_request',
    'prologue',
    'sa_first_arp_request',
    'stale_entry',
    'tcp_udp_reinforce',
    'udp_send_unavailable_arp',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, arp_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

