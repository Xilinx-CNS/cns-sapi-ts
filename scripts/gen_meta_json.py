#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

from json import dump
import argparse

VERSION = 1

parser = argparse.ArgumentParser(
    description="Script converts meta_file.txt into meta_file.json.\n"
                "WARNING! meta_file.json will be overwritten if it "
                "exists!", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("in_txt", help="Name of input txt file")
parser.add_argument("out_json", help="Name for converted json file")
args = parser.parse_args()

json_data = {"version": VERSION, "metas": []}


def add_meta(name, value):
    meta = {}
    ref = ""
    name = name.replace(" ", "_")
    build = ""
    if name == "TSDIR":
        name = "PROJECT"
        value = "onload"
    elif name == "TESTSUITE":
        name = "TS_SUITE"
    elif name == "Status":
        name = "status"
    elif name in ["Branch", "HOST"]:
        return
    elif name == "OSVER":
        name = "OS_VER"
    elif name == "TEREV":
        name = "TE_REV"
    elif name == "TSREV":
        name = "TS_REV"
    elif name == "CONFREV":
        name = "TS_CONF_REV"
    elif name == "V5NDEBUG":
        name = "V5_NDEBUG"
    elif name == "V5DATE":
        name = "V5_DATE"
    elif name == "V5REV":
        data = value.split(" ")
        add_meta("V5_REV", data[0])
        add_meta("V5_BRANCH", data[1])
        return
    elif name == "ef_env":
        efs = value.split(" ")
        while "" in efs:
            efs.remove("")
        for i in efs:
            ef = i.split("=")
            if ef[1] == "build_cloud":
                build = "cloud"
            elif ef[1] == "build_ulhelper":
                build = "ulhelper"
            add_meta(ef[0], ef[1])
        if not build:
            build = "default"
        add_meta("build", build)
        return
    elif name == "LOGS":
        ref = value.split("logs")[0] + "logs"
        value = value.split("logs")[1]
        while value[0] == "/":
            value = value[1:]
    elif name == "Tags":
        name = "product_name"
    elif "Testing_part" in name:
        name = "TS_SET"
    meta["name"] = name
    if ref:
        meta["reference"] = ref
    meta["value"] = value
    if "TIMESTAMP" in name:
        meta["type"] = "timestamp"
    elif "REV" in name:
        meta["type"] = "revision"
    elif "BRANCH" in name:
        meta["type"] = "branch"
    elif name == "LOGS":
        meta["type"] = "logs"
    json_data["metas"].append(meta)


with open(args.in_txt, "r") as f:
    for line in f:
        line = line.replace("\n", "")
        meta = {}
        if ": " in line:
            data = line.split(": ")
            add_meta(data[0], data[1])
        elif line.count(" ") == 1:
            data = line.split(" ")
            add_meta(data[0], data[1])
        elif line.count(":") == 1:
            data = line.split(":")
            add_meta(data[0], data[1])
        elif "MC Firmware version" in line:
            data = line.split(" ")
            add_meta("MC_FIRM_VER", data[-1])
        else:
            data = line.split(" ")
            if "TST OSVER" in line:
                add_meta("TST_OS_VER", " ".join(data[2:]))
            elif "IUT USERLAND" in line:
                add_meta("IUT_USERLAND", data[-1])
            elif "Libc version" in line:
                add_meta("LIBC_VER", " ".join(data[2:]))
            elif "Driver load" in line:
                add_meta("driver_load", data[2])
            elif "Driver unload" in line:
                add_meta("driver_unload", data[2])
            else:
                add_meta(data[0], " ".join(data[1:]))

# Delete metas with empty name and empty value
# Empty entries appear, because in in file could be empty line to be more
# human-readable
i = 0
while i < len(json_data["metas"]):
    m = json_data["metas"][i]
    if not m["name"] and not m["value"]:
        del json_data["metas"][i]
        continue
    i += 1

with open(args.out_json, "w") as f:
    dump(json_data, f, indent=2)
