#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

import argparse
from os.path import abspath
from os.path import dirname
from os.path import join
from sys import exit
from helpers import load_yaml
from random import seed
from random import choice
from yamale_validate import yamale_invalid


def gen_rnd_ool(ool_set, ool):
    tmp_list = []
    for el, freq in ool.items():
        tmp_list.extend([el] * freq)
    i = choice(tmp_list)
    if i:
        ool_set += i.split(",")


def gen_ools(rnd, freq_file, freq_add=None):
    ools_set = []
    if yamale_invalid(join(dirname(abspath(__file__)), freq_file)):
        print("Invalid freq file:", freq_file)
        exit()
    if freq_add and \
       yamale_invalid(join(dirname(abspath(__file__)), freq_add)):
        print("Invalid freq file:", freq_add)
        exit()
    seed(rnd)
    with open(join(dirname(abspath(__file__)), freq_file),
              "r") as p:
        ools = load_yaml(p)
    ools_add = None
    if freq_add:
        with open(join(dirname(abspath(__file__)), freq_add),
                  "r") as p:
            ools_add = load_yaml(p)
    all_ools = []
    if ools_add:
        for ool in ools_add:
            if type(ool) == dict:
                all_ools.append(ool)
            else:
                for i in ool:
                    all_ools += [x for x in ools if i in x]
    else:
        all_ools = ools
    for ool in all_ools:
        gen_rnd_ool(ools_set, ool)
    return ools_set


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("rand_num", help="Number for random", type=int)
    parser.add_argument("freq_file", help="File name with frequencies ")
    parser.add_argument("freq_add",
                        help="Additional file with freqs, in case of ZF and "
                             "ZFshim testing",
                        nargs="?")
    args = parser.parse_args()

    ool_out = gen_ools(args.rand_num, args.freq_file, args.freq_add)
    print(" ".join(ool_out))
