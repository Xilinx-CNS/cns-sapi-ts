/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Implementations of common functions for checksum package.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@arknetworks.am>
 */

#include "sockapi-test.h"
#include "tapi_ndn.h"
#include "checksum_lib.h"

/* See description in checksum_lib.h */
const char *
sockts_tcpflags2str(uint8_t flags)
{
    switch (flags)
    {
        case TCP_ACK_FLAG:
            return "ACK";

        case TCP_SYN_FLAG:
            return "SYN";

        case TCP_ACK_FLAG | TCP_SYN_FLAG:
            return "SYN-ACK";

        case TCP_ACK_FLAG | TCP_PSH_FLAG:
            return "PSH-ACK";

        case TCP_ACK_FLAG | TCP_FIN_FLAG:
            return "FIN-ACK";

        case TCP_ACK_FLAG | TCP_FIN_FLAG | TCP_PSH_FLAG:
            return "PSH-FIN-ACK";

        case TCP_ACK_FLAG | TCP_RST_FLAG:
            return "RST-ACK";

        case TCP_RST_FLAG:
            return "RST";

        default:
            return "[undefined]";
    }
}

/* See description in checksum_lib.h */
te_errno
sockts_set_ip_csum(asn_value *tmpl, sockts_csum_val csum)
{
    switch (csum)
    {
        case SOCKTS_CSUM_ZERO:
            return asn_write_int32(tmpl, 0, "pdus.1.#ip4.h-checksum.#plain");

        case SOCKTS_CSUM_BAD:
            return asn_write_string(tmpl, "expr:1",
                                    "pdus.1.#ip4.h-checksum.#script");

        default:
            break;
    }

    return 0;
}

/* See description in checksum_lib.h */
te_errno
sockts_set_tcp_csum(asn_value *tmpl, sockts_csum_val csum)
{
    switch (csum)
    {
        case SOCKTS_CSUM_ZERO:
            return tapi_ndn_tmpl_set_tcp_cksum(tmpl,
                                               TE_IP4_UPPER_LAYER_CSUM_ZERO);

        case SOCKTS_CSUM_BAD:
            return tapi_ndn_tmpl_set_tcp_cksum(tmpl,
                                               TE_IP4_UPPER_LAYER_CSUM_BAD);

        default:
            break;
    }

    return 0;
}

/* See description in checksum_lib.h */
te_errno
sockts_set_hdr_csum(asn_value *tmpl, rpc_socket_proto proto,
                    sockts_csum_val csum)
{
    switch (proto)
    {
        case RPC_IPPROTO_IP:
            return sockts_set_ip_csum(tmpl, csum);

        case RPC_IPPROTO_TCP:
            return sockts_set_tcp_csum(tmpl, csum);

        default:
            return TE_RC(TE_TAPI, TE_EPROTONOSUPPORT);
    }
}
