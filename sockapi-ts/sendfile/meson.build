# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'f2f_serial',
    'f2s_concurrent',
    'f2s_context',
    'f2s_flooder',
    'f2s_flooder2one',
    'f2s_nonblocking',
    'f2s_sendfile2one',
    'f2s_sndtimeo',
    'file2file',
    'file2socket',
    'files2file_socket',
    'illegal_params',
    'illegal_socket_states',
    'io_descriptors',
    'largefile2socket',
    'mtu_sendfile',
    'offset_params',
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

