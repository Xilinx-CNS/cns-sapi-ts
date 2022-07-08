# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

tests = [
    'aio_read',
    'aio_error',
    'aio_write',
    'aio_suspend',
    'kill_process',
    'stress',
    'lio_listio_too_many',
    'lio_listio_bad_mode',
    'lio_listio_cblist_dummy',
    'lio_listio_cblist_with_holes',
    'lio_listio_wait_signal',
    'lio_listio_wait_canceled',
    'lio_listio_wait_failed',
    'lio_listio_wait',
    'lio_listio_nowait',
    'aio_suspend_thread',
    'aio_suspend_timeout',
    'aio_suspend_cblist_dummy',
    'aio_suspend_cblist_with_holes',
    'aio_suspend_not_posted',
    'aio_suspend_completed',
    'aio_suspend_signal',
    'aio_suspend_forever',
    'aio_cancel_thread',
    'aio_cancel_inprogress',
    'aio_cancel_alldone',
    'aio_cancel_many',
    'aio_cancel_write',
    'aio_cancel_read',
    'aio_ret_no_aio_error',
    'aio_ret_failed',
    'aio_fsync_bad_op',
    'aio_fsync_socket',
    'aio_write_blk_write',
    'aio_write_many_socks',
    'aio_write_many_reqs',
    'aio_write_ignore_opcode',
    'aio_read_blk_read',
    'aio_read_many_socks',
    'aio_read_many_reqs',
    'aio_read_ignore_opcode',
    'nested_requests',
    'notify_diff_types',
    'notify_diff_callbacks',
    'notify_diff_signals',
    'notify_callback',
    'notify_signal',
    'notify_thread',
    'too_many_req',
    'post_twice',
    'close_sock',
    'one_buf',
    'bnb_cblist_nent',
    'not_posted_cb',
    'garbage_cb',
    'invalid_fd',
    'aio_fork',
    'lio_listio_file',
    'aio_suspend_file',
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

