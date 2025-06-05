# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2025 Oktet, Inc. All rights reserved.

tests = [
    'accept',
    'connect',
    'thread_unblock_accept',
    'thread_unblock_connect',
    'thread_unblock_recv',
    'thread_unblock_send',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)
