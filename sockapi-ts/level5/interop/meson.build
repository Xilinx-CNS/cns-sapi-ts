# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'close_accept',
    'close_after_close',
    'close_connected_socket',
    'close_create_socket',
    'close_fdopen_fclose',
    'close_iomux',
    'close_linger_close',
    'close_listening_socket',
    'close_read',
    'close_shutdown_socket',
    'close_udp_readable_socket',
    'derived_nonblock',
    'nonblock',
    'nonblock_handover',
    'onload_msg_recv_os_inline',
    'pipe_close_pipe',
    'recv_only',
    'send_only',
    'sock_with_flags_acc',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_sub_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_sub_dir,
               dependencies: test_deps)
endforeach

tests_info_xml = custom_target(package_sub_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_sub_dir,
                               input: package_sub_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_sub_dir)

