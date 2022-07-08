# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

level5_fd_cache_lib_dir = include_directories('.')

level5_fd_cache_lib_sources = [
    'fd_cache.c',
]

level5_fd_cache_lib = static_library('fd_cache', level5_fd_cache_lib_sources,
                                     include_directories: [lib_dir, level5_fd_cache_lib_dir],
                                     dependencies: dep_tirpc)

level5_fd_cache_test_deps = test_deps
level5_fd_cache_test_deps += declare_dependency(include_directories: level5_fd_cache_lib_dir,
                                                 link_with: level5_fd_cache_lib)

tests = [
    'fd_cache_dup',
    'fd_cache_exec',
    'fd_cache_fork',
    'fd_cache_inherit_flag',
    'fd_cache_ipv4_ipv6',
    'fd_cache_limits',
    'fd_cache_linger',
    'fd_cache_listener_closing',
    'fd_cache_nonblock_sync',
    'fd_cache_opt',
    'fd_cache_reuse',
    'fd_cache_reused_opt',
    'fd_cache_shutdown_reuse',
    'fd_cache_wild',
]

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_sub_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_sub_dir,
               dependencies: level5_fd_cache_test_deps)
endforeach

tests_info_xml = custom_target(package_sub_dir.underscorify() + 'tests-info-xml',
                               install: true, install_dir: package_sub_dir,
                               input: package_sub_tests_c,
                               output: 'tests-info.xml', capture: true,
                               command: [ te_tests_info_sh,
                               meson.current_source_dir() ])

install_data([ 'package.dox', 'package.xml' ],
             install_dir: package_sub_dir)

