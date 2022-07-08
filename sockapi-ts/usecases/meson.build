# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'get_setsockopt',
    'getsockname_getpeername',
    'if_nameindex',
    'ioctl',
    'ipv6_del_ll_addrs_transmit',
    'multi_clients_handler',
    'multiple_listen',
    'pipe',
    'read_write',
    'readv_writev',
    'send_recv',
    'sendmmsg',
    'sendmsg_recvmsg',
    'sendto_recvfrom',
    'server',
    'shutdown',
    'shutdown_rd',
    'shutdown_rdwr',
    'shutdown_wr',
    'socket_close',
    'splice',
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

