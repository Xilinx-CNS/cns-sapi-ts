# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

nfq_daemon_deps = [
    cc.find_library('netfilter_queue', required : true),
    cc.find_library('nfnetlink', required : true)
]

nfq_daemon_srcs = ['nfq_ip_options.c']

executable('nfq_daemon', sources : nfq_daemon_srcs,
           dependencies : nfq_daemon_deps)
