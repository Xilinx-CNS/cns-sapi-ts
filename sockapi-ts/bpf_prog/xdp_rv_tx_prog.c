/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * XDP programs
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("prog")
int xdp_prog(struct xdp_md *ctx)
{
    return XDP_TX;
}
