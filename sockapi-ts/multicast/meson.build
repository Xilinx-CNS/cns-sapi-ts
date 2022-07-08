# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

multicast_lib_dir = include_directories('lib')

subdir('lib')

multicast_test_deps = test_deps
multicast_test_deps += declare_dependency(include_directories: multicast_lib_dir,
                                          link_with: multicast_lib)
tests = [
    'bind_join_order',
    'bindtodevice_vs_ip_multicast_if',
    'conn_two_socks_same_addr',
    'default_if_for_join',
    'imr_ifindex_vs_imr_address',
    'iomux_multicast',
    'ip_add_drop_membership',
    'ip_add_membership_inval',
    'ip_drop_membership_inval',
    'ip_multicast_if',
    'ip_multicast_if_no_route',
    'ip_multicast_if_optlen',
    'ip_multicast_loop',
    'ip_multicast_loop_default',
    'ip_multicast_ttl',
    'join_leave_different_param',
    'loop_epilogue',
    'loop_prologue',
    'many_stacks_one_group',
    'mcast_bcast_port_unreach',
    'mcast_bind_if',
    'mcast_bind_recv',
    'mcast_bind_send',
    'mcast_bond',
    'mcast_fragmented_mac',
    'mcast_invisible',
    'mcast_mac_via_gw',
    'mcast_multiple_groups',
    'mcast_non_joined_socket',
    'mcast_on_tcp',
    'mcast_onload_handover',
    'mcast_option_different_states',
    'mcast_recv',
    'mcast_recv_two_socks',
    'mcast_route',
    'mcast_send_via_l5',
    'mcast_src_address',
    'mcast_two_sockets',
    'mcast_unicast_inaddr_any',
    'mcast_vlan',
    'mcast_vlan_alien_packet',
    'mcast_vlan_two_sockets',
    'multi_socks_two_stacks',
    'multiple_membership',
    'outgoing_if',
    'recv_zero_ttl',
    'send_all_host_group',
    'send_zero_ttl',
    'source_join',
    'three_pairs_three_stacks',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, multicast_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

