# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
#
ts_signal_lib_dir = include_directories('.')

ts_signal_lib_sources = [
    'ts_signal.c',
]

ts_signal_lib = static_library('ts_signal', ts_signal_lib_sources,
                               include_directories: [lib_dir, ts_signal_lib_dir],
                               dependencies: dep_tirpc)

signal_test_deps = test_deps
signal_test_deps += declare_dependency(include_directories: ts_signal_lib_dir,
                                       link_with: ts_signal_lib)

tests = [
    'accept_interrupted_signal',
    'close_interrupted_signal',
    'connect_interrupted_signal',
    'default_signal',
    'inherited_signal',
    'iomux_interrupted_signal',
    'iomux_pending_signal',
    'multithread_signal',
    'out_of_packet',
    'read_interrupted_signal',
    'sa_nocldstop',
    'sa_nocldwait',
    'sa_nodefer',
    'sa_onstack',
    'sa_resethand',
    'sa_resethand_reinstall',
    'sendfile_interrupted_signal',
    'signal_handler_close',
    'signal_stacks_closed',
    'splice_interrupted_signal',
    'write_interrupted_signal',
    'write_interrupted_signal_udp',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: signal_test_deps)
endforeach

tests_info_xml = custom_target(package_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_dir,
                               input: package_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_dir)

