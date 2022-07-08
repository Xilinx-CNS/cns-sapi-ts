/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_udp_dst Datagrams delivering with two shared addresses
 *
 * @objective  Check that datagrams are delivered to correct sockets if two
 *             address:port sets are shared with SO_REUSEPORT.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param first_wcard   The first socket is bound to INADDR_ANY
 * @param second_wcard  The second socket is bound to INADDR_ANY
 * @param iomux         I/O multiplexing function type
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_udp_dst"

#include "sockapi-test.h"
#include "reuseport.h"
#include "onload.h"
#include "iomux.h"

#define SOCKETS_NUM 4

#define ATTEMPTS_NUM 200

#define IUT_ADDRS_NUM 2

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    struct sockaddr        iut_addr_wcard;
    const struct sockaddr *iut_addr = NULL;
    struct sockaddr       *iut_addr_a[IUT_ADDRS_NUM];
    struct sockaddr       *addr_bind;
    const struct sockaddr *tst_addr = NULL;
    tapi_env_net          *net = NULL;
    te_bool                first_wcard;
    te_bool                second_wcard;
    iomux_call_type        iomux;

    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 200000};
    iomux_evt_fd    event[SOCKETS_NUM];
    char           *sndbuf = NULL;
    char           *rcvbuf = NULL;
    size_t          len_max;
    size_t          len;
    te_bool         received = FALSE;

    int iut_s[SOCKETS_NUM] = {-1};
    int count[SOCKETS_NUM];
    int tst_s = -1;
    int j;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(first_wcard);
    TEST_GET_BOOL_PARAM(second_wcard);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_NET(net);

    memset(iut_s, -1, sizeof(iut_s));
    memset(count, 0, sizeof(count));

    sndbuf = sockts_make_buf_dgram(&len_max);
    rcvbuf = te_make_buf_by_len(len_max);

    TEST_STEP("Add two more IP addresses to @p iut_if.");
    CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &iut_addr_a[0], NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr_a[0], -1, FALSE, NULL));
    TAPI_SET_NEW_PORT(pco_iut, iut_addr_a[0]);

    CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &iut_addr_a[1], NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr_a[1], -1, FALSE, NULL));
    TAPI_SET_NEW_PORT(pco_iut, iut_addr_a[1]);
    TAPI_WAIT_NETWORK;

    memcpy(&iut_addr_wcard, iut_addr_a[0], sizeof(iut_addr_wcard));
    te_sockaddr_set_wildcard(&iut_addr_wcard);

    if (first_wcard)
        addr_bind = &iut_addr_wcard;
    else
        addr_bind = iut_addr_a[0];

    TEST_STEP("Create two  couples UDP sockets, enable SO_REUSEPORT, bind each "
              "couple to its address:port set. Use INADDR_ANY or specific address in "
              "dependence on test arguments @p first_wcard and @p second_wcard.");
    for (i = 0; i < SOCKETS_NUM; i++)
    {
        if (i == 2)
        {
            addr_bind = iut_addr_a[1];
            if (second_wcard)
            {
                te_sockaddr_set_port(&iut_addr_wcard,
                                     *te_sockaddr_get_port_ptr(addr_bind));
                addr_bind = &iut_addr_wcard;
            }
        }

        iut_s[i] = reuseport_create_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                                addr_bind, TRUE);

        event[i].fd = iut_s[i];
        event[i].events = EVT_RD;
        event[i].revents = 0;
    }

    TEST_STEP("Transmit a few datagrams from tester, count and check how much "
              "datagrams each IUT socket receives. Each datagram is sent from "
              "different source address.");
    for (i = 0; i < ATTEMPTS_NUM; i++)
    {
        tst_s = reuseport_create_tst_udp_sock_any_port(pco_tst, tst_if, net,
                                                       NULL, NULL);

        len = rand_range(1, len_max);
        rpc_sendto(pco_tst, tst_s, sndbuf, len, 0, iut_addr_a[i % 2]);
        RPC_CLOSE(pco_tst, tst_s);

        rc = iomux_call(iomux, pco_iut, event, SOCKETS_NUM, &timeout);
        if (rc != 1)
            TEST_VERDICT("Iomux function returned unexpected code");

        received = FALSE;
        for (j = 0; j < SOCKETS_NUM; j++)
        {
            if (event[j].revents == EVT_RD)
            {
                if (received)
                    TEST_VERDICT("Second event is returned unexpectedly");

                count[j]++;
                rc = rpc_recv(pco_iut, event[j].fd, rcvbuf, len_max, 0);
                if (rc != (int)len || memcmp(sndbuf, rcvbuf, len) != 0)
                    TEST_VERDICT("Bad datagram was received");
                received = TRUE;
            }
        }
        if (!received)
            TEST_VERDICT("None of the sockets received datagram");

        received = TRUE;
        for (j = 0; j < SOCKETS_NUM; j++)
            if (count[j] == 0)
            {
                received = FALSE;
                break;
            }
        if (received)
            break;
    }

    TEST_STEP("Check that all sockets can receive their datagrams.");
    for (i = 0; i < SOCKETS_NUM; i++)
        RING("Socket #%d: %d", i, count[i]);
    for (i = 0; i < SOCKETS_NUM; i++)
    {
        if (count[i] == 0)
            TEST_VERDICT("Socket number #%d(fd %d) did not receive any "
                         "datagrams", i, iut_s[i]);
    }

    TEST_STEP("Send datagrams to third IUT address, to check that other's datagrams "
              "are not received.");
    for (i = 0; i < ATTEMPTS_NUM / 2; i++)
    {
        tst_s = reuseport_create_tst_udp_sock(pco_tst, tst_if, net,
                                              NULL, NULL);
        len = rand_range(1, len_max);
        te_sockaddr_set_port((struct sockaddr *)iut_addr,
                             *te_sockaddr_get_port_ptr(iut_addr_a[i % 2]));
        rpc_sendto(pco_tst, tst_s, sndbuf, len, 0, iut_addr);
        RPC_CLOSE(pco_tst, tst_s);

        rc = iomux_call(iomux, pco_iut, event, SOCKETS_NUM, &timeout);
        if ((first_wcard && i % 2 == 0) || (second_wcard && i % 2 == 1))
        {
            if (rc != 1)
                TEST_VERDICT("Iomux function returned unexpected code");
        }
        else if (rc != 0)
            TEST_VERDICT("Iomux returned non-zero value");

        if (rc != 0)
        {
            received = FALSE;
            for (j = 0; j < SOCKETS_NUM; j++)
            {
                if (event[j].revents == EVT_RD)
                {
                    if (received)
                        TEST_VERDICT("Second event is returned unexpectedly");

                    if ((i % 2 == 0 && j > 1) || (i % 2 == 1 && j < 2))
                        TEST_VERDICT("Wrong socket received datagram");

                    count[j]++;
                    rc = rpc_recv(pco_iut, event[j].fd, rcvbuf, len_max, 0);
                    if (rc != (int)len || memcmp(sndbuf, rcvbuf, len) != 0)
                        TEST_VERDICT("Bad datagram was received");
                    received = TRUE;
                }
            }
            if (!received)
                TEST_VERDICT("None of the sockets received datagram");
        }
    }

    TEST_SUCCESS;

cleanup:
    sockts_close_sockets(pco_iut, iut_s, SOCKETS_NUM);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sndbuf);
    free(rcvbuf);
    TEST_END;
}
