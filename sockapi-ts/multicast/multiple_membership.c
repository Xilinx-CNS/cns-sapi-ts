/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 * 
 * $Id$
 */

/** @page multicast-multiple_membership Multiple membership in multicasting group 
 *
 * @objective The test checks whether it is possible to join a multicast 
 *            group on the same interface many times, and, if so, to leave 
 *            it multiple times.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param iut_if        Name of a network interface on @p pco_iut
 * @param mcast_addr    Multicast IP address
 * @param sock_func     Socket creation function
 *
 * @par Test sequence:
 * -# Open a datagram socket @p iut_s on @p pco_iut.
 * -# Adjoin it two times to multicast group @p mcast_addr.
 * -# Make @p iut_s leave the group two times.
 *    Check that no error occured.
 * -# Try to leave the multicast group once more. Make sure that it fails.
 * -# Close @p pco_iut socket.
 * 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/multiple_membership"

#include "sockapi-test.h"
#include "multicast.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    int                          iut_s = -1;
    const struct if_nameindex   *iut_if = NULL;
    const struct sockaddr       *mcast_addr = NULL;
    int                          i;
    int                          packet_number;
    struct sockaddr_storage      bind_addr;
    tarpc_joining_method         method;
    sockts_socket_func           sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    iut_s = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    memcpy(&bind_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(SA(&bind_addr));
    rpc_bind(pco_iut, iut_s, SA(&bind_addr));

    for (i = 1; i <= packet_number; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, mcast_addr,
                                  iut_if->if_index, method) < 0)
        {
            TEST_VERDICT("Attempt #%d to join multicast group failed", i);
        }
    }

    for (i = 1; i <= packet_number; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_common_mcast_leave(pco_iut, iut_s, mcast_addr, mcast_addr,
                                    iut_if->if_index, method) < 0)
        {
            TEST_VERDICT("Attempt #%d to leave multicast group failed", i);
        }
    }

    /* Try to leave once again */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (mcast_leave(pco_iut, iut_s, mcast_addr, iut_if->if_index) == 0)
    {
        TEST_VERDICT("Group can be left more times than it was joined");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}

