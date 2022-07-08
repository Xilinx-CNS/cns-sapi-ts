# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

libinit_lib_dir = include_directories('lib')

subdir('lib')

libinit_test_deps = test_deps
libinit_test_deps += declare_dependency(include_directories: libinit_lib_dir,
                                        link_with: libinit_lib)
tests = [
    'non_socket_tests',
    'socket_send_tests',
    'socket_recv_tests',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps, libinit_test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

