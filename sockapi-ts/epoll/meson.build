# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

epoll_lib_dir = include_directories('lib')

subdir('lib')

epoll_test_deps = test_deps
epoll_test_deps += declare_dependency(include_directories: epoll_lib_dir,
                                      link_with: epoll_common_lib)
tests = [
    'create_close_many',
    'create_close_wait',
    'create_many_close_all',
    'ctl_handover_wait',
    'derived_epoll',
    'derived_epoll_add',
    'derived_epoll_del',
    'derived_epoll_mod',
    'edge_level_triggered_both',
    'edge_level_triggered_et_only',
    'edge_level_triggered_mod',
    'edge_triggered_listen',
    'edge_triggered_out',
    'edge_triggered_refresh',
    'epfd_change_stack',
    'epfd_in_itself',
    'epoll_close_on_exec',
    'epoll_ctl_del_after_exec',
    'epoll_ctl_early',
    'epoll_ctl_thread',
    'epoll_dead_circle',
    'epoll_evnt_queue',
    'epoll_nbio_tcpconnect',
    'epoll_one_shot',
    'epoll_one_shot_out',
    'epoll_one_shot_pipe',
    'epoll_reused_descriptor',
    'epollet_early_shot',
    'event_order',
    'few_in_events',
    'ioctl_on_epfd',
    'maxevents_two_stacks',
    'multi_level_iomux',
    'multiple_same_epfd',
    'small_maxevents',
    'strange_op_on_epfd',
    'tcp_ack_no_event',
    'tcp_listen',
    'tcp_shutdown',
    'wait_epollet_wait',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, epoll_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

