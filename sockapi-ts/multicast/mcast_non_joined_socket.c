/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_non_joined_socket IP multicasting with joined and
 *                                          non-joined sockets.
 *
 * @objective Check sockets behavior if one of them is joined to a multicast
 *            group and another is not.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Network interface on @p pco_iut
 * @param tst_if            Network interface on @p pco_tst
 * @param iut_addr          Network address on @p pco_iut
 * @param tst_addr          Network address on @p pco_tst
 * @param mcast_addr        Multicast address
 * @param sock_func         Socket creation function
 *
 * @par Test sequence:
 * -# Create two sockets on IUT, bind them to wildcard address with port
 *    number of @p mcast_addr. Join one of the sockets to the multicast
 *    group.
 * -# Create a socket on TST, bind it to @p tst_addr.
 * -# Send one packet from TST.
 * -# Receive packets on IUT via both sockets. Both sockets should receive
 *    the packet on pure linux. But only joined socket receives the packet
 *    if Onload is enabled.
 *
 * @author Andrey Dmitrov <Andrey.Dmirtov@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/mcast_non_joined_socket"

#include "sockapi-test.h"
#include "multicast.h"

int
main(int argc, char **argv)
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    struct sockaddr             aux_addr;
    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    sockts_socket_func  sock_func;

    int     iut_s1  = -1;
    int     iut_s2  = -1;
    int     tst_s = -1;

    size_t    buf_len = 200;
    size_t    send_len = buf_len / 2;
    void     *snd_buf = NULL;
    void     *rcv_buf = NULL;
    te_bool   readable;
    int       opt_val;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    snd_buf = te_make_buf_by_len(buf_len);
    rcv_buf = te_make_buf_by_len(buf_len);

    memcpy(&aux_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(&aux_addr);

    iut_s1 = sockts_socket(sock_func, pco_iut, RPC_AF_INET,
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s1, RPC_SO_REUSEADDR, &opt_val);
    rpc_bind(pco_iut, iut_s1, &aux_addr);

    iut_s2 = sockts_socket(sock_func, pco_iut, RPC_AF_INET,
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s2, RPC_SO_REUSEADDR, &opt_val);
    rpc_bind(pco_iut, iut_s2, &aux_addr);

    rpc_mcast_join(pco_iut, iut_s1, mcast_addr, iut_if->if_index,
                   TARPC_MCAST_ADD_DROP);

    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_sendto(pco_tst, tst_s, snd_buf, send_len, 0, mcast_addr);

    RPC_GET_READABILITY(readable, pco_iut, iut_s1, 1000);
    if (!readable)
        TEST_VERDICT("Joined IUT socket has not received any packets");
    else
    {
        rc = rpc_recv(pco_iut, iut_s1, rcv_buf, buf_len, 0);
        if (rc != (int)send_len || memcmp(snd_buf, rcv_buf, send_len) != 0)
            TEST_VERDICT("IUT has received a packet but it differs from "
                         "the sent one");
    }

    RPC_GET_READABILITY(readable, pco_iut, iut_s2, 1000);
    if (!readable)
        RING_VERDICT("Non-joined IUT socket has not received any packets");
    else
    {
        memset(rcv_buf, 0, buf_len);
        rc = rpc_recv(pco_iut, iut_s2, rcv_buf, buf_len, 0);
        if (rc != (int)send_len || memcmp(snd_buf, rcv_buf, send_len) != 0)
            TEST_VERDICT("IUT has received a packet but it differs from "
                         "the sent one");
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_MULTICAST_LEAVE(pco_iut, iut_s1, mcast_addr,
                            iut_if->if_index, TARPC_MCAST_ADD_DROP);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);

    free(rcv_buf);
    free(snd_buf);

    TEST_END;
}
