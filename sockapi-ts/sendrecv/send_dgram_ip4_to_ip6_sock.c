/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-send_dgram_ip4_to_ip6_sock Sending a datagram from IPv6 socket to IPv4 address.
 * @objective Check possibility of data transfer from IPv6 socket
 *            to IPv4 address.
 *
 * @type conformance
 *
 * @param pco_iut  PCO on IUT
 * @param pco_tst  PCO on Tester
 * @param iut_s    @c PF_INET6 socket on @p pco_iut
 * @param tst_s    @c PF_INET socket on @p pco_tst
 * @param tst_addr Address on Tester
 *
 * Test scenario:
 *
 * -# Open a datagram socket @p iut_s of @c PF_INET6 family on @p pco_iut.
 * -# Open a datagram socket @p tst_s of @c PF_INET family on @p pco_tst.
 * -# Bind @p tst_s to @p tst_addr.
 * -# Send a datagram from @p iut_s to @p tst_addr.
 * -# Receive it on @p tst_s.
 * -# Verify data. If no error occured, test is passed.
 *  
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_dgram_ip4_to_ip6_sock"
#include "sockapi-test.h"

#define DATA_BULK       1024  /**< Size of data to be sent */

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;
    const struct sockaddr  *tst_addr;
    rpc_sendto_f            func = NULL;
    
    struct sockaddr_storage from_addr;
    socklen_t               from_addrlen = sizeof(from_addr);

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;

    uint8_t *sendbuf = NULL;
    uint8_t *recvbuf = NULL;

    ssize_t sent;

    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SENDTO_FUNC(func);

    iut_s = rpc_socket(pco_iut, RPC_PF_INET6, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s, tst_addr);

    sendbuf = (uint8_t *)te_make_buf_by_len(DATA_BULK);
    CHECK_NOT_NULL(recvbuf = (uint8_t *)malloc(DATA_BULK));

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = func(pco_iut, iut_s, sendbuf, DATA_BULK, 0, tst_addr);
    if (sent < 0)
    {
        TEST_VERDICT("%s() to IPv6 socket and IPv4 destination address "
                     "failed with errno %s", rpc_sendto_func_name(func),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else if (sent != DATA_BULK)
    {
        TEST_VERDICT("%s() to IPv6 socket and IPv4 destination address "
                     "does not send all data", rpc_sendto_func_name(func));
    }
    
    memset(&from_addr, 0, sizeof(from_addr));
    if (rpc_recvfrom(pco_tst, tst_s, recvbuf, DATA_BULK, 0,
                     SA(&from_addr), &from_addrlen) != DATA_BULK)
    {
        TEST_FAIL("Only part of data is received");
    }

    if (memcmp(sendbuf, recvbuf, DATA_BULK) != 0)
    {
        TEST_FAIL("Data verification error");
    }

    TEST_SUCCESS;

cleanup:
    free(sendbuf);
    free(recvbuf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

