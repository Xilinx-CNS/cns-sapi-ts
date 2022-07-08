/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-socket_closing Socket close  after bind or listen and then new sockets
 *
 * @objective  Check that clustered socket closing after bind or listen does
 *             not affect new created sockets.
 *
 * @param pco_iut               PCO on IUT
 * @param pco_tst               PCO on TST
 * @param socket_type           Socket type
 * @param wild                  Bind IUT socket to wildcard address
 * @param close_after_listen    Where IUT socket should be closed, @c TRUE
 *                              value make sense only for TCP
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/socket_closing"

#include "sockapi-test.h"
#include "reuseport.h"
#include "iomux.h"

#define SOCKETS_NUM 2

#define ATTEMPTS_NUM 20

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    struct sockaddr        iut_addr_wcard;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    struct sockaddr       *tst_addr2 = NULL;
    struct sockaddr        tst_addr_rpl;
    tapi_env_net          *net = NULL;
    rpc_socket_type        sock_type;
    te_bool                close_after_listen;
    te_bool                wild;

    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 500000};
    iomux_evt_fd    event[SOCKETS_NUM];
    char           *sndbuf = NULL;
    char           *rcvbuf = NULL;
    size_t          len_max;
    size_t          len;
    socklen_t       addr_len;

    int iut_s[SOCKETS_NUM] = {-1, -1};
    int count[SOCKETS_NUM] = {0, 0};
    int tst_s = -1;
    int iut_s_acc = -1;
    int j;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(close_after_listen);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(wild);
    TEST_GET_NET(net);

    sndbuf = sockts_make_buf_stream(&len_max);
    rcvbuf = te_make_buf_by_len(len_max);

    memcpy(&iut_addr_wcard, iut_addr, sizeof(iut_addr_wcard));
    te_sockaddr_set_wildcard(&iut_addr_wcard);

    CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &tst_addr2, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           tst_addr2, -1, FALSE, NULL));

    TEST_STEP("Creat UDP or TCP socket in dependece on @p sock_type.");
    iut_s[0] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                          sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set SO_REUSEPORT socket option and bind it to @p iut_addr or to "
              "wildcard address in dependence on @p wild.");
    rpc_setsockopt_int(pco_iut, iut_s[0], RPC_SO_REUSEPORT, 1);
    rpc_bind(pco_iut, iut_s[0], wild ? &iut_addr_wcard : iut_addr);

    TEST_STEP("Close the socket here or later in dependence on "
              "@p close_after_listen.");
    if (!close_after_listen)
        RPC_CLOSE(pco_iut, iut_s[0]);

    TEST_STEP("For TCP socket call listen and then call the socket if it was not "
              "closed in the previous step.");
    if (sock_type == RPC_SOCK_STREAM && close_after_listen)
    {
        rpc_listen(pco_iut, iut_s[0], -1);
        RPC_CLOSE(pco_iut, iut_s[0]);
    }

    TEST_STEP("Create two new sockets sharing a one port. For TCP socket call "
              "@b listen().");
    for (i = 0; i < SOCKETS_NUM; i++)
    {
        iut_s[i] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                              sock_type, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s[i], RPC_SO_REUSEPORT, 1);
        rpc_bind(pco_iut, iut_s[i], wild ? &iut_addr_wcard : iut_addr);
        if (sock_type == RPC_SOCK_STREAM)
            rpc_listen(pco_iut, iut_s[i], -1);

        event[i].fd = iut_s[i];
        event[i].events = EVT_RD;
        event[i].revents = 0;
    }

    TEST_STEP("Repeat the following steps until both sockets receive at least "
              "one connection/datagram:");
    for (i = 0; i < ATTEMPTS_NUM; i++)
    {
        TEST_STEP("Create socket on tester, bind it and connect.");
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr2),
                           sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr2);
        rpc_connect(pco_tst, tst_s, iut_addr);

        len = rand_range(1, len_max);

        TEST_STEP("For UDP: transmit a datagram.");
        if (sock_type == RPC_SOCK_DGRAM)
            rpc_send(pco_tst, tst_s, sndbuf, len, 0);

        rc = iomux_call(IC_DEFAULT, pco_iut, event, SOCKETS_NUM, &timeout);
        if (rc != 1)
            TEST_VERDICT("Iomux function returned unexpected code");

        TEST_STEP("Receive the datagram/connection by one of IUT sockets and "
                  "send reply packet.");
        for (j = 0; j < SOCKETS_NUM; j++)
        {
            if (event[j].revents == EVT_RD)
            {
                count[j]++;
                if (sock_type == RPC_SOCK_DGRAM)
                {
                    addr_len = sizeof(tst_addr_rpl);
                    rc = rpc_recvfrom(pco_iut, event[j].fd, rcvbuf, len_max,
                                      0, &tst_addr_rpl, &addr_len);
                    if (rc != (int)len || memcmp(sndbuf, rcvbuf, rc) != 0)
                        TEST_VERDICT("Bad datagram was received");
                    rpc_sendto(pco_iut, event[j].fd, sndbuf, len, 0,
                               &tst_addr_rpl);
                    rc = rpc_recvfrom(pco_tst, tst_s, rcvbuf, len_max,
                                      0, &tst_addr_rpl, &addr_len);
                    if (rc != (int)len || memcmp(sndbuf, rcvbuf, rc) != 0)
                        TEST_VERDICT("Bad datagram (second) was received");

                    if (te_sockaddrcmp(iut_addr, sizeof(*iut_addr), 
                                       &tst_addr_rpl, addr_len) != 0)
                        TEST_VERDICT("Unexpected IUT address was received");
                }
                else
                {
                    iut_s_acc = rpc_accept(pco_iut, iut_s[j], NULL, NULL);
                    sockts_test_connection(pco_iut, iut_s_acc, pco_tst, tst_s);
                }

                break;
            }
        }

        if (j == SOCKETS_NUM)
            TEST_VERDICT("Connection request or datagram was lost!");

        if (count[0] > 0 && count[1] > 0)
            break;

        TEST_STEP("Close tester socket.");
        RPC_CLOSE(pco_tst, tst_s);
        TEST_STEP("If TCP is tested close accepted socket.");
        if (iut_s_acc != -1)
            RPC_CLOSE(pco_iut, iut_s_acc);
        CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_tst->ta,
                                               tst_if->if_name, NULL));
        free(tst_addr2);

        CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &tst_addr2, NULL));
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                               tst_addr2, -1, FALSE, NULL));
    }

    RING("Received datagrams/conections number (max %d): first socket %d, second "
         "socket %d", ATTEMPTS_NUM, count[0], count[1]);

    if (count[0] == 0 || count[1] == 0)
        TEST_VERDICT("One of sockets did not receive datagram/connection");

    TEST_SUCCESS;

cleanup:
    sockts_close_sockets(pco_iut, iut_s, SOCKETS_NUM);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s_acc);

    free(sndbuf);
    free(rcvbuf);
    TEST_END;
}
