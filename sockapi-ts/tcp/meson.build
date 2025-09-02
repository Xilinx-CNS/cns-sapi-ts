# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tcptest_lib_dir = include_directories('lib')

subdir('lib')

tcp_test_deps = test_deps
tcp_test_deps += declare_dependency(include_directories: tcptest_lib_dir,
                                    link_with: tcptest_lib)
tests = [
    'ack_out_of_window',
    'close_no_ack',
    'close_send_buf',
    'close_send_buf_no_ack',
    'close_linger',
    'close_linger_lo',
    'closing_time_wait',
    'connect_impossible',
    'connect_impossible_icmp',
    'connect_nb_impossible',
    'connect_nb_impossible_icmp',
    'connect_shutdown_connect',
    'connection_timeout_data',
    'default_tcp_orphan_retries',
    'diff_tuple_diff_isn',
    'fin_data',
    'fin_out_of_window',
    'initial_rto',
    'invalid_ack',
    'ip_fragments',
    'last_ack_connect',
    'last_ack_recv_pkt',
    'listen_backlog_max',
    'listener_closing_states',
    'many_listeners',
    'move_fd_same_tcp',
    'non_accepted_closed',
    'out_of_socks_tcp_loopback',
    'overfill_close',
    'overfill_shutdown_reduce_pmtu',
    'packet_ack_drop',
    'peer_large_window',
    'prologue_timeouts_init',
    'recv_unblock_fin',
    'rst_pkt_without_ack',
    'rst_send_partial',
    'rtt_calc',
    'same_tuple_new_isn',
    'send_block_unblock',
    'send_retrans_fail',
    'shutdown_data',
    'shutdown_fin',
    'shutdown_rst',
    'shutdown_states',
    'syn_ack_distrib',
    'syn_ack_ts_corrupted',
    'syn_bad_addr',
    'syn_recv_fin_wait1',
    'syn_recv_peer_shutdown',
    'syn_resend',
    'syn_sent_fin_ack',
    'syn_sent_func',
    'tcp_close_timeout',
    'tcp_cork_vs_nodelay',
    'tcp_flooder_mult',
    'tcp_fork_distrib',
    'tcp_handle_fin',
    'tcp_handle_rst',
    'tcp_handle_syn',
    'tcp_last_data',
    'tcp_loopback',
    'tcp_server_restart',
    'tcp_small_segment',
    'tcp_small_window',
    'tcp_state_hang',
    'tcp_timeout',
    'tcp_window_update',
    'tcp_zero_window',
    'tcp_zero_window_ext',
    'timestamps_epilogue',
    'timestamps_prologue',
    'ts_recv_values',
    'ts_send',
    'zero_window_after_shrink',
    'fit_window_after_shrink',
    'tsa_gw_prologue',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, tcp_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

