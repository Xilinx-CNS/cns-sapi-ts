#! /bin/bash
# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
#
# Helper script to build gpl_tools applications.
#

set -e

meson_args="-Dte_cflags=\"$TE_CPPFLAGS\" -Dte_ldflags=\"$TE_LDFLAGS\""

test -e build.ninja || eval "meson $meson_args ${EXT_SOURCES} ${PWD}"
which ninja &>/dev/null && NINJA=ninja || NINJA=ninja-build
${NINJA} -v
