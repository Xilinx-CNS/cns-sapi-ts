/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 *
 * $Id$
 */

/** @page udp-reuseaddr_connect Datagrams spreading with SO_REUSEADDR
 *
 * @objective  Check datagrams spreading between two sockets in dependence
 *             on using wildcard addresses and using connect.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param wcard_first       First socket is bound to INADDR_ANY
 * @param wcard_second      Second socket is bound to INADDR_ANY
 * @param connect_first     Connect the first IUT socket
 * @param connect_second    Connect the second IUT socket
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/reuseaddr_connect"

#include "sockapi-test.h"

#define SOCKETS_NUM 2

#define CHECK_RECV_DGRAM \
do {                                                                     \
    rpc_recvfrom(pco_iut, rcv_s, rcvbuf, len_max, 0, SA(&tst_addr_from), \
                 &addr_len);                                             \
    CHECK_BUFS_EQUAL(rcvbuf, sndbuf, len);                               \
    rpc_sendto(pco_iut, rcv_s, sndbuf, len, 0, CONST_SA(&tst_addr_from));\
    rpc_recv(pco_tst, tst_s, rcvbuf, len_max, 0);                        \
    CHECK_BUFS_EQUAL(rcvbuf, sndbuf, len);                               \
    RPC_AWAIT_IUT_ERROR(pco_iut);                                        \
    rc = rpc_recv(pco_iut, lst_s, rcvbuf, len_max, RPC_MSG_DONTWAIT);    \
    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)                    \
        TEST_VERDICT("The last recv() call had to fail with EAGAIN");    \
} while (0)

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    struct sockaddr            iut_addr_a[SOCKETS_NUM];
    const struct sockaddr     *tst_addr = NULL;
    struct sockaddr           *tst_addr2 = NULL;
    struct sockaddr_storage    tst_addr_from;
    socklen_t                  addr_len = sizeof(tst_addr_from);
    tapi_env_net              *net = NULL;
    te_bool                    wcard_first;
    te_bool                    wcard_second;
    te_bool                    connect_first;
    te_bool                    connect_second;

    char           *sndbuf = NULL;
    char           *rcvbuf = NULL;
    size_t          len_max;
    size_t          len;

    int iut_s[SOCKETS_NUM] = {-1};
    int count[SOCKETS_NUM];
    int tst_s = -1;
    int rcv_s = -1;
    int lst_s = -1;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(wcard_first);
    TEST_GET_BOOL_PARAM(wcard_second);
    TEST_GET_BOOL_PARAM(connect_first);
    TEST_GET_BOOL_PARAM(connect_second);
    TEST_GET_NET(net);

    memset(iut_s, -1, sizeof(iut_s));
    memset(count, 0, sizeof(count));

    sndbuf = sockts_make_buf_dgram(&len_max);
    rcvbuf = te_make_buf_by_len(len_max);

    CHECK_RC(tapi_env_allocate_addr(net,
                                    addr_family_rpc2h(
                                      sockts_domain2family(
                                        rpc_socket_domain_by_addr(iut_addr))),
                                    &tst_addr2, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           tst_addr2, -1, FALSE, NULL));
    TAPI_SET_NEW_PORT(pco_tst, tst_addr2);

    TEST_STEP("Create two IUT sockets: "
              "- set SO_REUSEPORT to the both; "
              "- bind sockets to IUT or wildcard address in dependence on "
              "parameters; "
              "- optionally connect sockets to one of TST address.");
    for (i = 0; i < SOCKETS_NUM; i++)
    {
        memcpy(&iut_addr_a[i], iut_addr, sizeof(iut_addr_a));
        if ((i == 0 && wcard_first) || (i == 1 && wcard_second))
            te_sockaddr_set_wildcard(&iut_addr_a[i]);

        iut_s[i] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                              RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s[i], RPC_SO_REUSEADDR, 1);
        rpc_bind(pco_iut, iut_s[i], iut_addr_a + i);

        if (i == 0)
        {
            if (connect_first)
                rpc_connect(pco_iut, iut_s[i], tst_addr);
        }
        else if (connect_second)
            rpc_connect(pco_iut, iut_s[i], tst_addr2);
    }

    TEST_STEP("Create TST socket and bind it to the first TST address.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Send a datagram from the TST socket.");
    len = rand_range(1, len_max);
    rpc_sendto(pco_tst, tst_s, sndbuf, len, 0, iut_addr);

    rcv_s = iut_s[0];
    lst_s = iut_s[1];

    if ((wcard_first || !wcard_second) && !connect_first && !connect_second)
    {
        rcv_s = iut_s[1];
        lst_s = iut_s[0];
    }

    TEST_STEP("Try to receive sent datagram on both IUT sockets, check that only "
              "one of the sockets receives it.");
    CHECK_RECV_DGRAM;
    RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Create TST socket and bind it to the second TST address.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr2);

    TEST_STEP("Send a datagram from the TST socket.");
    len = rand_range(1, len_max);
    rpc_sendto(pco_tst, tst_s, sndbuf, len, 0, iut_addr);

    addr_len = sizeof(tst_addr_from);

    rcv_s = iut_s[1];
    lst_s = iut_s[0];
    if (wcard_second && !wcard_first && !connect_first && !connect_second)
    {
        rcv_s = iut_s[0];
        lst_s = iut_s[1];
    }

    TEST_STEP("Try to receive sent datagram on both IUT sockets, check that only "
              "one of the sockets receives it.");
    CHECK_RECV_DGRAM;

    TEST_SUCCESS;

cleanup:
    sockts_close_sockets(pco_iut, iut_s, SOCKETS_NUM);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sndbuf);
    free(rcvbuf);
    TEST_END;
}
