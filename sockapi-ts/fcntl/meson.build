# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

fcntl_lib_dir = include_directories('lib')

basic_test_deps = test_deps
basic_test_deps += declare_dependency(include_directories: fcntl_lib_dir)

tests = [
    'async_data',
    'async_postponed',
    'fcntl_after_shutdown',
    'fcntl_async_connect_tcp',
    'fcntl_async_listen',
    'fcntl_async_udp',
    'fcntl_flags_dup',
    'fcntl_flags_dup_pipe',
    'fcntl_getfl',
    'fcntl_getfl_pipe',
    'fcntl_on_accepted',
    'fcntl_pipe_sz',
    'fcntl_pipe_sz_many',
    'setgetown',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, basic_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

