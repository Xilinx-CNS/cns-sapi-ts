# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

sendrecv_lib_dir = include_directories('lib')

subdir('lib')

sendrecv_test_deps = test_deps
sendrecv_test_deps += declare_dependency(include_directories: sendrecv_lib_dir,
                                         link_with: sendrecv_lib)
tests = [
    'blk_recv_two_threads',
    'dgram_iov_recv',
    'dgram_iov_send',
    'fill_huge_rcvbuf',
    'largebuff_via_splice',
    'many_recv_threads',
    'oob_overwritten',
    'oob_span',
    'peer_close',
    'recv_data_after_peer_close',
    'recv_dgram_small_buf',
    'recv_dgram_wild',
    'recv_dontwait',
    'recv_dontwait_peer_close',
    'recv_oob_absent',
    'recv_peek_block',
    'recv_peek_dgram',
    'recv_peek_dontwait',
    'recv_peek_many',
    'recv_peek_many_iovec',
    'recv_peek_stream',
    'recv_peek_stream_flow',
    'recv_waitall_dgram',
    'recv_waitall_stream',
    'recv_zero_dgram',
    'recvmmsg',
    'recvmsg_bcast',
    'recvmsg_mcast',
    'recvmsg_peek_trunc',
    'recvmsg_trunc',
    'send_dgram_ip4_to_ip6_sock',
    'send_dontroute',
    'send_dontwait',
    'send_more_dgram',
    'send_more_nodelay_stream',
    'send_more_stream',
    'send_nosignal',
    'send_oob_data',
    'send_recv_shutdown',
    'send_to_incomplete',
    'check_recv_truncate',
    'sendmsg_pktinfo',
    'sendmsg_pktinfo_src',
    'stream_iov_recv',
    'stream_iov_send',
    'two_thrds_simult',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, sendrecv_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

