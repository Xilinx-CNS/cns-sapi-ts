# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

services_lib_dir = include_directories('.')

services_lib_sources = [
    'ifconfparse.c',
]

services_lib = static_library('services', services_lib_sources,
                              include_directories: [lib_dir, services_lib_dir])

services_test_deps = test_deps
services_test_deps += declare_dependency(include_directories: services_lib_dir,
                                         link_with: services_lib)

tests = [
    'dhcp_srv',
    'dhcp_srv_bootp',
    'dns_server',
    'epilogue',
    'ftp_client',
    'ftp_file',
    'ftp_many',
    'ftp_put_get',
    'ifconfig_a',
    'ifconfig_get',
    'ifconfig_set',
    'ifconfig_stat',
    'netstat',
    'proc_net_tcp',
    'prologue',
    'rsh_client',
    'rsh_server',
    'slapd_ldapsearch',
    'smtp_srv_clnt',
    'ssh_client',
    'ssh_complex',
    'ssh_port_fwd_clnt',
    'ssh_port_fwd_srv',
    'ssh_server',
    'ssh_x_fwd_clnt',
    'ssh_x_fwd_srv',
    'telnet_client',
    'telnet_server',
    'vnc_client',
    'vnc_server',
    'x_client',
    'x_server',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: services_test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

