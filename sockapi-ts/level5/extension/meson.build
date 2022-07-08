# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

level5_extention_lib_dir = include_directories('lib')

subdir('lib')

level5_extention_test_deps = test_deps
level5_extention_test_deps += declare_dependency(include_directories: level5_extention_lib_dir,
                                                 link_with: level5_extention_template_lib)

level5_extention_test_deps += declare_dependency(include_directories: level5_extention_lib_dir,
                                                 link_with: level5_extention_od_send_lib)
tests = [
    'delegated_api',
    'msg_onepkt',
    'msg_warm',
    'msg_warm_concurrent',
    'msg_warm_conn_problem',
    'msg_warm_fill_send_buf',
    'msg_warm_large_buf',
    'msg_warm_send_flow',
    'msg_warm_zc_send',
    'od_no_ack',
    'od_overfill_sndbuf',
    'od_send_peer_close',
    'onload_zc_recv_keep',
    'onload_zc_recv_large',
    'zc_send_big_buf_complete',
    'onload_zc_send',
    'oo_epoll',
    'oo_epoll_dont_read',
    'oo_epoll_read',
    'oo_epoll_seg_reordering',
    'simple_ds',
    'template_abort',
    'template_abort_bnb',
    'template_alloc_bnb',
    'template_close',
    'template_hide_ack',
    'template_mult',
    'template_overfill',
    'template_send',
    'template_signal',
    'template_update',
    'template_update_bnb',
    'udp_rx_filter',
    'udp_rx_filter_simple',
    'dont_accelerate',
    'is_present',
    'zc_hlrx_pkts',
    'zc_recv_oob',
    'zc_register_bufs',
    'zc_send_ack_complete',
    'zc_send_mixed_bufs',
    'zc_send_msg_more',
    'zc_send_user_buf_overfill'
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_sub_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_sub_dir,
               dependencies: level5_extention_test_deps)
endforeach

tests_info_xml = custom_target(package_sub_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_sub_dir,
                               input: package_sub_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_sub_dir)

