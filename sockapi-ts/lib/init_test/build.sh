#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
#
# Helper script to build init_test library.

set -e

test -e build.ninja || meson ${EXT_SOURCES} ${PWD}
which ninja &>/dev/null && NINJA=ninja || NINJA=ninja-build
${NINJA} -v
