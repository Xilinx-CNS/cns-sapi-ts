#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

from helpers import load_yaml
from os.path import abspath
from os.path import dirname
from os.path import join
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("rand_num", help="Number for random", type=int)
parser.add_argument("iut_host", help="IUT host name")
parser.add_argument("branch", help="Branch name", nargs="?")
parser.add_argument("-s", help="Generate stable kernels for both hosts",
                    action="store_true")
args = parser.parse_args()

with open(join(dirname(abspath(__file__)),
               "gen_kernels.yaml"), "r") as k:
    kernel_data = load_yaml(k)

cfg_list = kernel_data["cfg_list"]
kernel_list = kernel_data["kernel_list"]
for item in cfg_list:
    if args.iut_host in item["hosts"]:
        db = "default_branch"
        db_val = item[db] if db in item else "master"
        branch = args.branch if args.branch else "master"
        if branch in item:
            kernels = item[branch]
        else:
            kernels = item[db_val]

        if not kernels:
            print("Forbidden {}:{}".format(db, db_val))
            break

        stable_kernel = kernel_list[kernels[0]][0]
        rnd_host = args.rand_num % len(item["hosts"])
        rnd = args.rand_num // len(item["hosts"])
        rnd_kernel = kernels[rnd % len(kernels)]
        rnd = rnd // len(kernels)
        rnd_kernel = \
            kernel_list[rnd_kernel][rnd % len(kernel_list[rnd_kernel])]
        if args.s:
            iut_kernel = stable_kernel
        else:
            iut_kernel = rnd_kernel
        if not iut_kernel.isnumeric():
            iut_kernel = "-e " + iut_kernel
        tst_kernel = stable_kernel
        if not tst_kernel.isnumeric():
            tst_kernel = "-e " + tst_kernel
        print("{} {} {}".format(item["hosts"][rnd_host],
                                iut_kernel, tst_kernel))
