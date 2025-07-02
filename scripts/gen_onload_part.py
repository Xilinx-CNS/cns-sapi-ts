#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
"""Generate set of ool parameters, tester requirements
   and set of packages (part of testing itself)."""

import argparse
from os.path import abspath
from os.path import dirname
from os.path import join
from sys import exit  # pylint: disable=W0622
from helpers import load_yaml
from sys import argv
from random import shuffle
from yamale_validate import yamale_invalid
from ool_gen_params import gen_ools


def remove_silent(lst, *to_remove):
    for elem in to_remove:
        while elem in lst:
            lst.remove(elem)


def list_subs(lst, a, b):
    return [b if x == a else x for x in lst]


def remove_pattern(lst, pattern):
    return [x for x in lst if pattern not in x]


def is_pattern_in_list(lst, *patterns):
    for pattern in patterns:
        for i in lst:
            if pattern in i:
                return True
    return False


branch_seq = [["eol5"], ["eol6"], ["onload-7.0"], ["onload-7.1"],
              ["eol7"], ["onload-8.0"]]


def older_then(branch1, branch2):
    if not branch1:
        branch1 = ""
    if branch1 in (branch2, ""):
        return False
    for b in branch_seq:
        if branch1 in b and branch2 in b:
            return False
        elif branch2 in b:
            return False
        elif branch1 in b:
            return True


def get_part(part, parts, name_spec=False):
    part_num = 0
    if name_spec:
        for i in range(len(parts)):
            if part in parts[i]:
                part_num = i
                break
    else:
        part_num = int(part)
        part_num = part_num % len(parts)
    return part_num


def fix_testing_parms(host, ools, reqs, sl, slice_name,
                      params, branch, bad_ool_host):
    # Simple parameters fixing
    if "onload" not in ools:
        ools.append("onload")

    if "pure_testing" in ools:
        remove_silent(ools, "pure_testing", "macvlan", "ipvlan",
                      "vlan", "netns_iut", "netns_all")
        ools = remove_pattern(ools, "bond")
        ools = remove_pattern(ools, "team")

    if not older_then(branch, "onload-8.0"):
        # ON-13267: We do not test m32 on
        # branches newer then onload-7.1 anymore
        remove_silent(ools, "m32")
    else:
        # Available starting from master/onload-8.0
        remove_silent(ools, "zc_reg_huge", "zc_reg_huge_align")

    if "m32" in ools:
        remove_silent(ools, "syscall")

    # This fix should go before the next one, or we get incorrect
    # combination: bond+netns without vlan or macvlan
    if older_then(branch, "eol6"):
        ools = list_subs(ools, "scalable_any", "scalable_iut")
        ools = list_subs(ools, "scalable_active_passive", "scalable")
        remove_silent(ools, "cplane_server_grace_timeout_zero",
                      "cplane_no_dump", "macvlan", "syscall", "netns_iut",
                      "netns_all")
        # Switched off for eol5 according to ON-7424
        remove_silent(ools, "scooby", "high_throughput")
        # These parameters do not exist in eol5
        remove_silent(ools, "sleep_spin", "tcp_shared_ports_reuse_fast",
                      "laddr_all")

    if "netns_all" in ools:
        remove_silent(ools, "macvlan", "ipvlan", "vlan")
        ools = remove_pattern(ools, "bond")
        ools = remove_pattern(ools, "team")

    if older_then(branch, "onload-7.0"):
        remove_silent(ools, "ipvlan", "build_cloud")
    if older_then(branch, "onload-7.1"):
        remove_silent(ools, "laddr_prefsrc")
    if older_then(branch, "onload-8.0"):
        remove_silent(ools, "af_xdp_no_filters", "af_xdp", "zc_af_xdp")

    # Remove ipvlan and macvlan if they are not allowed in the host
    if host in params["no_ipvlan"]:
        remove_silent(ools, "ipvlan")
    if host in params["no_vlan_macvlan"]:
        if "vlan" in ools and "macvlan" in ools:
            remove_silent(ools, "macvlan")

    # ST-1567 comment 10
    if "scalable_active_passive" in ools and "no_reuse_pco" not in ools:
        ools = list_subs(ools, "reuse_pco", "no_reuse_pco")

    if "no_reuse_pco" not in ools:
        reqs.append("!SO_REUSEPORT")
        remove_silent(ools, "cplane_server_grace_timeout_zero")

    # Fix according to IUT host
    # ST-1377
    if "high_throughput" in ools and \
       host not in params["medford_host"]:
        reqs.append("!MULTICAST")
    if host in params["no_m32"] or slice_name == "cong_testing":
        remove_silent(ools, "m32")
    if host in params["no_af_xdp"]:
        remove_silent(ools, "af_xdp")
        remove_silent(ools, "af_xdp_no_filters")
        remove_silent(ools, "zc_af_xdp")
    if host in params["no_syscall"]:
        remove_silent(ools, "syscall")
    if host in params["no_netns"]:
        remove_silent(ools, "netns_iut", "netns_all")

    # Here are checks common to EF100 and X3 NICs
    if host in params["ef100_host"] or host in params["x3_host"]:
        # ST-2438: only zc_reg_huge and zc_reg_huge_align are allowed on ef100
        if not any(item in ["zc_reg_huge", "zc_reg_huge_align"]
                   for item in ools):
            ools.append("zc_reg_huge")

    if host in params["ef100_host"] or host in params["x3_host"] or \
       host in params["xf_host"]:
        # ST-2638: X3 and EF100 do no support such packets
        remove_silent(ools, "pkt_nocomp")

    # Note: ef100 testing available starting from onload-8.0 branch
    if host in params["ef100_host"]:
        # EF100 NICs do not have such firmware variants
        remove_silent(ools, "fw_full_featured")
        remove_silent(ools, "fw_low_latency")
        # EF100 NIC has only one port and trc-tag hwport2 is a bit confusing
        remove_silent(ools, "hwport2")
        # ON-13343: temporarily disable rss:active:passive mode
        remove_silent(ools, "scalable_active_passive")
        # ON-14439: problems with configuring bond/team interfaces
        ools = remove_pattern(ools, "bond")
        ools = remove_pattern(ools, "team")

    if host in params["one_link_host"]:
        remove_silent(ools, "hwport2")
        ools = remove_pattern(ools, "bond")
        ools = remove_pattern(ools, "team")

    if slice_name in ["transparent"]:
        remove_silent(ools, "safe", "scalable_active_passive",
                      "scalable_active", "scalable_passive")
        # Scalable filters are not supported with AF_XDP. ST-2231.
        remove_silent(ools, "af_xdp_no_filters", "af_xdp", "zc_af_xdp")
    # sleep_spin requires epoll3
    if "epoll3" not in ools:
        remove_silent(ools, "sleep_spin")

    # Remove libc_close option for epoll package. ON-12255.
    if "packages" in sl and "epoll" in sl["packages"] or \
       "ex_packages" in sl and "epoll" not in sl["ex_packages"]:
        remove_silent(ools, "libc_close")

    # Make safe_epollN from safe and epollN.
    # epoll2 is in safe profile by default
    if "ip4_testing" in slice_name or "ip6_testing" in slice_name:
        if "epoll2" not in ools and "safe" in ools and "epoll" in ools:
            remove_silent(ools, "safe")
            ools = ["safe_" + x if "epoll" in x else x for x in ools]

    if "epoll0" in ools or "epoll2" in ools:
        remove_silent(ools, "fdtable_strict")
    # Remove scalable_iut and scalable_any if there are no other scalable
    # options
    if len([x for x in ools if "scalable" in x and x not in
            ["scalable_iut", "scalable_any"]]) == 0:
        ools = remove_pattern(ools, "scalable")
    else:
        # Remove in case of scalable testing
        remove_silent(ools, "cplane_server_grace_timeout_zero")

    # cplane_server_grace_timeout_zero is incompatible with reuse_stack and
    # reuse_pco.
    if "reuse_stack" in ools or "no_reuse_pco" not in ools:
        remove_silent(ools, "cplane_server_grace_timeout_zero")

    # AF_XDP is tested with reuse_pco or reuse_stack only.
    # Remove cplane_server_grace_timeout_zero for reasons described above
    if "af_xdp" in ools or "af_xdp_no_filters" in ools:
        remove_silent(ools, "cplane_server_grace_timeout_zero")

    # Note: x3 testing available starting from onload-8.0 branch
    if host in params["x3_host"]:
        # FW variants are not applicable for X3
        x3_deny_list = ["fw_low_latency", "fw_full_featured"]
        # ON-13881: X3 does not support clustering nor rss
        # See also XN-200494-PD-1F/KD-050
        x3_deny_list += ["rss_scalable",
                         "scalable_active_passive",
                         "one_cluster",
                         ]
        x3_deny_list += ["scalable", "scalable_active", "scalable_passive"]
        x3_deny_list += ["scalable_iut", "scalable_any"]
        # Disable temporarily: X3-698/X3-700/X3-701
        x3_deny_list += ["bond1", "bond4", "team1", "team4"]
        # ON-14567: AF_XDP doesn't work on X3
        x3_deny_list += ["af_xdp_no_filters", "af_xdp", "zc_af_xdp"]

        for item in x3_deny_list:
            remove_silent(ools, item)

    if host in params["xf_host"]:
        xf_deny_list = ["fw_low_latency", "fw_full_featured"]

        xf_deny_list += ["rss_scalable",
                         "scalable_active_passive",
                         "one_cluster",
                         ]
        xf_deny_list += ["scalable", "scalable_active", "scalable_passive"]
        xf_deny_list += ["scalable_iut", "scalable_any"]

        xf_deny_list += ["af_xdp_no_filters", "af_xdp", "zc_af_xdp"]

        # ON-16745
        xf_deny_list += ["scooby"]

        for item in xf_deny_list:
            remove_silent(ools, item)

    # Remove params which are broken on some configurations
    if host in bad_ool_host.keys():
        for elem in bad_ool_host[host]:

            if elem == "no_vlan":
                # It's prohibited to test bond and team in case
                # of netns_iut without vlan
                if "netns_iut" in ools:
                    ools = remove_pattern(ools, "bond")
                    ools = remove_pattern(ools, "team")
                remove_silent(ools, "vlan")
                continue

            if elem == "no_ip_options":
                remove_silent(ools, "ip_options")
                continue

            if elem == "no_tiny_spin":
                remove_silent(ools, "tiny_spin")
                continue

            exit(f"Following {elem} an error accured: "
                 "realisation to delete bad ool doesn't exist")

    return ools


def gen_testing_part(rand, part_id, host, branch=None, parts_num_only=False,
                     name_spec=False, af_xdp_strict=False, params_file=None):
    if params_file is None:
        params_file = join(dirname(abspath(__file__)), "gen_onload_part.yaml")

    params_file_schema = join(dirname(abspath(__file__)),
                              "gen_onload_part_schema.yaml")
    if yamale_invalid(params_file, schema=params_file_schema):
        print("Invalid configuration file!")
        exit()

    with open(params_file, "r", encoding="utf-8") as cfg_file:
        test_parts = load_yaml(cfg_file)

    parts = test_parts["parts"]
    if parts_num_only:
        print("Number of parts:", len(parts))
        exit()
    slices = test_parts["slices"]
    params = test_parts["params"]
    bad_ool_host = test_parts["bad_ool_host"]

    ret = []
    part = parts[get_part(part_id, parts, name_spec)]

    # Generate random ool params for testing
    test_ool = gen_ools(rand, "ool_params_freqs.yaml")
    if af_xdp_strict:
        if "af_xdp" not in test_ool and "af_xdp_no_filters" not in test_ool:
            test_ool += ["af_xdp"]
        # We can't remove af_xdp in such case, so let's remove transparent
        # slice
        for i in range(len(part)):
            if part[i] == "transparent":
                del part[i]
                break
    # ON-13881: X3 does not support scalable and transparent testing doesn't
    # work without --ool=scalable, so let's remove transparent slice
    if host in params["x3_host"]:
        for i in range(len(part)):
            if part[i] == "transparent":
                del part[i]
                break

    for i in range(len(part)):
        testing = {}
        sl = slices[part[i]]
        reqs = sl["reqs"]
        ools = [ool for ool in sl["ools"] if ool not in test_ool]
        ools = test_ool + ools
        ools = fix_testing_parms(host, ools, reqs, sl, part[i],
                                 params, branch, bad_ool_host)
        # Shuffle packages
        if "packages" in sl:
            shuffle(sl["packages"])
        testing["part_name"] = part[i]
        testing["reqs"] = reqs
        testing["ools"] = ools
        # Add packages
        if "packages" in sl:
            testing["packages"] = sl["packages"]
        # Or exclude packages
        elif "ex_packages" in sl:
            testing["ex_packages"] = sl["ex_packages"]
        ret.append(testing)
    return ret


if __name__ == "__main__":
    if len(argv) > 1 and "-p" in argv:
        gen_testing_part(0, 0, "", parts_num_only=True)

    parser = argparse.ArgumentParser()
    parser.add_argument("rand_num", help="Number for random", type=int)
    parser.add_argument("part", help="Part number or part name in case "
                                     "of -n option")
    parser.add_argument("iut_host", help="IUT host name")
    parser.add_argument("branch", help="Branch name", nargs="?")
    parser.add_argument("-n", help="Generate parameters for specified part",
                        action="store_true")
    parser.add_argument("-a", help="Add testing part name to the beginning "
                                   "of output",
                        action="store_true")
    parser.add_argument("-p", help="Get real number of parts",
                        action="store_true")
    parser.add_argument("-x", help="Use af_xdp for testing",
                        action="store_true")
    parser.add_argument("-u", "--use-params-file", dest="use_params_file",
                        help="Use the specified file instead of gen_onload_part.yaml")
    args = parser.parse_args()

    gen_parts = gen_testing_part(args.rand_num, args.part, args.iut_host,
                                 args.branch, False, args.n, args.x,
                                 params_file=args.use_params_file)
    output = ""

    for p in gen_parts:
        if output:
            output = output + " "
        if args.a:
            output = output + p["part_name"] + ";"
        # Add packages
        if "packages" in p:
            output = output + ",".join(p["packages"])
        # Or exclude packages
        elif "ex_packages" in p:
            output = output + "-" + ",".join(p["ex_packages"])
        output = output + ";"
        output = output + ",".join(p["reqs"]) + ";"
        output = output + ",".join(p["ools"])
    print(output)
