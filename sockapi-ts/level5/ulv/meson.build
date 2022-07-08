# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'netload',
#    'aio',
#    'bad_ipid',
#    'bad_mtu',
#    'bad_pktid',
#    'bad_timer_state',
#    'blocking',
#    'defrag',
#    'dma',
#    'filters',
#    'mmap',
#    'more_pktbufs',
#    'nopage',
#    'open_sock',
#    'pkt_segments',
#    'random',
#    'tcp_accept',
#    'tcp_close',
#    'tcp_processing',
#    'timer_callback',
#    'udp_rx',
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

