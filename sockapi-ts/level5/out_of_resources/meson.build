# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

level5_out_of_resources_lib_dir = include_directories('.')

level5_out_of_resources_lib_sources = [
    'out_of_resources.c',
]

level5_out_of_resources_lib = static_library('out_of_resources', level5_out_of_resources_lib_sources,
                                     include_directories: [lib_dir, level5_out_of_resources_lib_dir],
                                     dependencies: dep_tirpc)

level5_out_of_resources_test_deps = test_deps
level5_out_of_resources_test_deps += declare_dependency(include_directories: level5_out_of_resources_lib_dir,
                                                        link_with: level5_out_of_resources_lib)

tests = [
    'data_flows_few_pkts',
    'epilogue',
    'oof_multicast_gradual',
    'out_of_hw_filters_tcp',
    'out_of_hw_filters_tcp_listen',
    'out_of_hw_filters_udp_bind_connect',
    'out_of_hw_filters_udp_recvfrom',
    'out_of_multicast_filters',
    'out_of_netifs',
    'out_of_packets',
    'out_of_stacks',
    'prologue',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_sub_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_sub_dir,
               dependencies: level5_out_of_resources_test_deps)
endforeach

tests_info_xml = custom_target(package_sub_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_sub_dir,
                               input: package_sub_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_sub_dir)

