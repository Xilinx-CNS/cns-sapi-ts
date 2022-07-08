#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
'''
Script to build and install additional modules for night testing
'''

import argparse
from subprocess import run
from subprocess import PIPE
from os import path
from glob import glob
import sys
from socket import gethostname

build_dir = ""


def run_and_log(run_args: list, file_name: str) -> str:
    run_out = run(run_args, stdout=PIPE, stderr=PIPE, check=False)
    with open(build_dir + "/" + file_name + ".log", "w",
              encoding="utf-8") as run_log_f:
        run_log_f.write(run_out.stdout.decode("utf-8"))
    with open(build_dir + "/" + file_name + ".err", "w",
              encoding="utf-8") as run_log_f:
        run_log_f.write(run_out.stderr.decode("utf-8"))
    return run_out.stdout.decode("utf-8")


parser = argparse.ArgumentParser()
parser.add_argument("dir", help="Build directory")
parser.add_argument("remove", help="Remove/clean", nargs="?")
parser.add_argument("--srpm_host", help="Host on which srpm should be built")
args = parser.parse_args()

is_remove = False
is_clean = False
if args.remove:
    if args.remove == "remove":
        is_remove = True
    elif args.remove == "clean":
        is_clean = True
    else:
        print("Incorrect argument:", args.remove)
        sys.exit()

if args.dir:
    build_dir = args.dir
else:
    print("Build dir is not defined")
    sys.exit()

# Build or clean sources
if is_clean:
    out = run(["make", "-C", build_dir, "clean"], check=True)
    sys.exit()
elif not is_remove:
    run_and_log(["make", "-C", build_dir], "build")

out = run(["uname", "-a"], stdout=PIPE, check=True)
kernel = out.stdout.decode("utf-8")
is_debian = False
if "Debian" in kernel or "Ubuntu" in kernel:
    is_debian = True

# Make package according to OS and install or remove it without building
if is_debian:
    # Remove previously installed package for Debian or Ubuntu
    if is_remove:
        srch = glob(build_dir + "/deb/*.deb")
        package = srch[0]
        out = run(["sudo", "dpkg", "--info", package], stdout=PIPE, check=True)
        pack_name = out.stdout.decode("utf-8")
        get_next = False
        for s in pack_name.split(" "):
            if get_next:
                pack_name = s.replace("\n", "")
                break
            if "Package:" in s:
                get_next = True
        run_and_log(["sudo", "apt-get", "-y", "remove", pack_name], "remove")
    # Make deb package and install it for Debian or Ubuntu
    else:
        run_and_log(["make", "-C", build_dir, "deb"], "build_deb")
        srch = glob(build_dir + "/deb/*.deb")
        package = srch[0]
        run_and_log(["sudo", "dpkg", "-i", package], "install")
else:
    # Remove previously installed package for RHEL
    if is_remove:
        srch = glob(build_dir + "/*.rpm")
        for f in srch:
            if ".src.rpm" not in f:
                rpm_file = f
                break
        out = run(["rpm", "-qp", "--queryformat", "%{NAME}", rpm_file],
                  stdout=PIPE,
                  check=True)
        pack_name = out.stdout.decode("utf-8")
        run_and_log(["sudo", "yum", "-y", "remove", pack_name], "remove")
    else:
        # Build srpm on 'srpm_host' and copy to the host on which script is
        # called or build it localy if srpm_host is not defined
        if args.srpm_host:
            remote_dir = "/var/tmp/tmp_build_" + gethostname()
            run(["ssh", args.srpm_host, "mkdir", "-p", remote_dir], check=True)
            run(["scp", "-r", build_dir, args.srpm_host + ":" + remote_dir],
                check=True)
            remote_dir += "/" + path.basename(build_dir)

            run_and_log([
                "ssh", args.srpm_host, "PATH=$PATH:/home/tester-l5/unifdef",
                "make", "-C", remote_dir, "srpm"
            ], "build_srpm")
            run([
                "scp", args.srpm_host + ":" + remote_dir + "/rpm/SRPMS/*",
                build_dir
            ],
                check=True)
            run(["ssh", args.srpm_host, "rm", "-fr", remote_dir], check=True)
        else:
            run_and_log([
                "PATH=$PATH:/home/tester-l5/unifdef", "make", "-C", remote_dir,
                "srpm"
            ], "build_srpm")
            run(["cp", build_dir + "/rpm/SRPMS/*", build_dir], check=True)

        # Install srpm
        srch = glob(build_dir + "/*.src.rpm")
        package = srch[0]
        run_and_log(["rpm", "-i", package], "rpm_i")
        rpmbuild_out = run_and_log(
            ["fakeroot", "rpmbuild", "--rebuild", package], "rpmbuild")
        rpm_path = ""
        for s in rpmbuild_out.split("\n"):
            if "Wrote" in s:
                rpm_path = s.split(" ")[1]
                break
        run(["cp", rpm_path, build_dir], check=True)
        run_and_log(
            ["sudo", "rpm", "-ivh", build_dir + "/" + path.basename(rpm_path)],
            "install")
