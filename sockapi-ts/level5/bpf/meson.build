# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

move_fd_lib_dir = include_directories('../ext_stackname')

v5_bpf_test_deps = test_deps
v5_bpf_test_deps += declare_dependency(include_directories: move_fd_lib_dir)

tests = [
    'xdp_attach_to_stack',
    'xdp_one_stack_two_ifs',
    'xdp_same_stack',
    'xdp_two_stacks',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_sub_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_sub_dir,
               dependencies: v5_bpf_test_deps)
endforeach

tests_info_xml = custom_target(package_sub_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_sub_dir,
                               input: package_sub_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_sub_dir)

