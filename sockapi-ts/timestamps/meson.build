# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

timestamps_lib_dir = include_directories('.')

timestamp_lib_sources = [
    'timestamps.c',
]

timestamps_lib = static_library('timestamps', timestamp_lib_sources,
                                include_directories: [lib_dir, timestamps_lib_dir],
                                dependencies: dep_tirpc)

timestamps_test_deps = test_deps
timestamps_test_deps += declare_dependency(include_directories: timestamps_lib_dir,
                                           link_with: timestamps_lib)

tests = [
    'epilogue',
    'prologue',
    'siocshwtstamp',
    'siocshwtstamp_tx',
    'ts_env',
    'ts_fin',
    'ts_flow',
    'ts_msg_onepkt',
    'ts_opt_tsonly',
    'ts_queued_packets',
    'ts_read',
    'ts_recvmsg_trunc',
    'ts_select_err_queue',
    'ts_states',
    'ts_tcp_re',
    'ts_tx_ack',
    'ts_tx_opt_id',
    'ts_tx_shut_rd',
    'ts_tx_shut_wr',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: timestamps_test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

