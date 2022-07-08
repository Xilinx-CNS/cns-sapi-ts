# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

reuseport_lib_dir = include_directories('lib')

subdir('lib')

reuseport_test_deps = test_deps
reuseport_test_deps += declare_dependency(include_directories: reuseport_lib_dir,
                                          link_with: reuseport_lib)
tests = [
    'cluster_restart_all_orphaned',
    'cluster_restart_one_closed',
    'cluster_restart_one_killed',
    'mcast_reuseport',
    'move_fd_reuseport',
    'reuseport_after_bind',
    'reuseport_connect',
    'reuseport_del_addr',
    'reuseport_del_addr_connect',
    'reuseport_epilogue',
    'reuseport_iomux',
    'reuseport_lacp_slave_up',
    'reuseport_load_tcp',
    'reuseport_load_udp',
    'reuseport_prologue',
    'reuseport_rcvtimeo',
    'reuseport_reset_if',
    'reuseport_tcp_time_wait',
    'reuseport_tcp_wild',
    'reuseport_threaded_iomux',
    'reuseport_two_interfaces',
    'reuseport_udp_dst',
    'reuseport_udp_wild',
    'reuseport_uids',
    'reuseport_vs_reuseaddr',
    'several_clusters',
    'socket_closing',
    'tcp_close_listener',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, reuseport_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

