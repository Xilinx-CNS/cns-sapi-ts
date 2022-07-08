# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

route_lib_dir = include_directories('lib')

subdir('lib')

route_test_deps = test_deps
route_test_deps += declare_dependency(include_directories: route_lib_dir,
                                      link_with: route_lib)
tests = [
    'asymmetric',
    'conn_changed_gw',
    'epilogue',
    'if_change_netns',
    'multipath_add_del',
    'multipath_balancing',
    'multipath_del_add_same_conns',
    'multipath_prologue',
    'pbr_criterion',
    'pbr_metric',
    'pbr_oif_gw',
    'pbr_oif_src',
    'pbr_prefix',
    'pbr_rule_combined',
    'pbr_rule_from',
    'pbr_rules_order',
    'pbr_tos',
    'pbr_tos_two_rules',
    'prologue',
    'retransmit_change_route',
    'rt_choose_by_tos',
    'rt_default',
    'rt_hoplimit',
    'rt_icmp_redirect',
    'rt_if_by_dst_dr',
    'rt_if_by_dst_gw',
    'rt_many_subnets_via_gw',
    'rt_metric',
    'rt_prefix_len_flexible',
    'rt_prefix_vs_metric',
    'rt_same_addr_if_down_up',
    'rt_same_addr_if_down_up_one_sock',
    'rt_src_addr',
    'rt_src_based',
    'rt_src_other_if',
    'rt_switched_tos',
    'conn_changed_tos',
    'tcp_loopback_alien',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, route_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

