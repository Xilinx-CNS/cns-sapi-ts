# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'ethtool_reset',
    'fionbio',
    'fionbio_accept',
    'fionbio_connect',
    'fionbio_thread_unblock_accept',
    'fionbio_thread_unblock_connect',
    'fionbio_thread_unblock_recv',
    'fionbio_thread_unblock_send',
    'fionread_listening',
    'fionread_oob',
    'fionread_pipe',
    'fionread_syn_sent',
    'fionread_tcp',
    'fionread_udp',
    'oob_marker_moves',
    'reset_nic_epilogue',
    'reset_nic_prologue',
    'siocatmark',
    'siocatmark_oobinline',
    'siocethtool_glink',
    'siocethtool_gpermaddr',
    'siocgifaddr',
    'siocgifaddr_no_addr',
    'siocgifbrdaddr',
    'siocgifconf',
    'siocgifhwaddr',
    'siocgifnameindex',
    'siocgstamp',
    'siocgstamp_null',
    'siocgstamp_two_senders',
    'siocif_ifr_name_nonexist',
    'siocifflags',
    'siocifmtu',
    'siocifnetmask',
    'siocpgrp',
    'siocsif_inval_sa_family',
    'siocsif_no_perm',
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

