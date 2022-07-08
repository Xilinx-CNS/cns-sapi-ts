# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'ack_with_data',
    'fork_robust',
    'iomux_after_connect',
    'iomux_one_pipe',
    'iomux_sigmask',
    'iomux_splice_rd',
    'iomux_splice_two_sockets',
    'iomux_splice_wr',
    'iomux_timeout',
    'iomux_wrong_event',
    'many_sockets',
    'mix_fds',
    'multiple_iomux_nonblock_sock',
    'nb_accept_read',
    'notconn',
    'oob',
    'pair_bidir_perf',
    'peer_close',
    'peer_close_before_accept',
    'peer_shut_rd',
    'peer_shut_rdwr',
    'peer_shut_wr',
    'pending_error',
    'pollpri',
    'rdhup',
    'read_write_nbio',
    'ret_count_peer_close',
    'ret_count_rd_wr',
    'sock_shut_rd',
    'sock_shut_rdwr',
    'sock_shut_wr',
    'tcp_usecases',
    'thread_close_sock',
    'thread_shut_sock',
    'timeout_update',
    'trio_bidir_perf',
    'two_sockets',
    'udp_send_flooding',
    'udp_zero_dgram',
    'write_timeout',
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

