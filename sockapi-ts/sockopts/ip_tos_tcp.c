/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-ip_tos_tcp Linux-specific IP_TOS option behaviour on TCP socket.
 *
 * @objective Check that linux clears 2 last bits on @c IP_TOS option value.
 * 
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 *
 * @par Test sequence:
 * -# Open a stream socket @p iut_s on @p pco_iut.
 * -# For @p value from 1 up to @c IPTOS_LOWDELAY:
 *     -# Set @c IP_TOS option on @p iut_s to @p value.
 *     -# Get @c IP_TOS option value from @p iut_s.
 *     -# Make sure it equals @p value with cleared two last bits.
 * -# Close @p iut_s.
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_tos_tcp"

#include "sockapi-test.h"
#if HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    int                    iut_s = -1;
    uint32_t               value;
    uint32_t               obtained_value;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    for (value = 1; value <= IPTOS_LOWDELAY; value++)
    {
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_TOS, &value);

        rpc_getsockopt(pco_iut, iut_s, RPC_IP_TOS, &obtained_value);
        if ((value & (~3)) != obtained_value)
        {
            TEST_VERDICT("Obtained value is not value with two cleared bits");
        }
    }

    TEST_SUCCESS;               

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}

