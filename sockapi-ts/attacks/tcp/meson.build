# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'land',
    'overlapped',
    'reorder',
    'flood',
    'syn_flood',
    'syn_spoof',
    'syn_cookies',
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

