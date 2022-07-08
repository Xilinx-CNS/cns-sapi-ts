# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'prologue',
    'xdp_actions',
    'xdp_diff_ifs',
    'xdp_maps',
    'tcp_flags',
    'one_rule_filter',
    'xdp_bpf_helpers',
    'xdp_change_addr',
    'xdp_lpm_rule',
    'xdp_icmp_echo',
    'xdp_perf_event',
    'xdp_prog_load',
    'xdp_maps_functions',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: [test_deps])
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

