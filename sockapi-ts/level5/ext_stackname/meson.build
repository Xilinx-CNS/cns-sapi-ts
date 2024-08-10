# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
	'bind_move_fd',
	'close_init_stack_after_fork',
	'ef_fork_netif',
	'fcntl_move_fd',
	'ioctl_move_fd',
	'iomux_move_fd',
	'linger_move_fd',
	'listen_move_fd',
	'move_epoll_fd',
	'move_fd_other_user',
	'move_fd_same_udp',
	'move_unsupp_fd',
	'pipe_move_fd',
	'problematic_rxq_move_fd',
	'save_move_restore',
	'set_stackname_caller_dead',
	'set_stackname_move_fd',
	'set_stackname_nochange_restore',
	'set_stackname_null',
	'set_stackname_null_restore',
	'set_stackname_restore_non_saved',
	'set_stackname_save_restore',
	'set_stackname_scope_global',
	'set_stackname_scope_nochange',
	'set_stackname_scope_process',
	'set_stackname_scope_process_ignore',
	'set_stackname_scope_thread',
	'set_stackname_scope_user',
	'set_stackname_scope_user_threads',
	'set_stackname_scope_who',
	'setsockopt_move_fd',
	'shutdown_move_fd',
	'sighandler_move_fd',
	'sock_ping_pong',
	'stack_nochange_move_fd',
	'tcp_conn_move_fd',
	'tcp_conn_move_fd_in_pkt_flow',
	'tcp_overfill_queue_move_fd',
	'unbound_udp_move_fd',
	'unsupp_socket_move_fd',
    'dont_acc_and_set_stackname',
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

