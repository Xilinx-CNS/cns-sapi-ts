/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_udp_wild Datagrams delivering with SO_REUSEPORT and wildcards
 *
 * @objective  Check that datagrams are delivered to correct sockets when
 *             SO_REUSEPORT is used in set with binding to INADDR_ANY.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on TST
 * @param pco_tst2      PCO on TST
 * @param second_wcard  Create two more sockets and bind them to a specific
 *                      IUT addr if @c FALSE.
 * @param third_iut     The last socket is bound to SF interface address or
 *                      to non-SF address
 * @param iomux         I/O multiplexing function type
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_udp_wild"

#include "sockapi-test.h"
#include "reuseport.h"
#include "onload.h"
#include "iomux.h"

#define SOCKETS_NUM 6

#define ATTEMPTS_NUM1 200
#define ATTEMPTS_NUM2 30

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    struct sockaddr        iut_addr_wcard;
    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *iut_addr2 = NULL;
    struct sockaddr       *iut_addr1_2 = NULL;
    struct sockaddr       *iut_addr1_3 = NULL;
    const struct sockaddr *tst1_addr = NULL;
    const struct sockaddr *tst2_addr = NULL;
    tapi_env_net          *net1 = NULL;
    tapi_env_net          *net2 = NULL;
    te_bool                second_wcard;
    te_bool                third_iut;
    iomux_call_type        iomux;

    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 500000};
    iomux_evt_fd    event[SOCKETS_NUM];
    te_bool         received;
    char           *sndbuf = NULL;
    char           *rcvbuf = NULL;
    size_t          len;

    int iut_s[SOCKETS_NUM] = {-1};
    int tst_s = -1;
    int count[SOCKETS_NUM] = {0,};
    int num = 0;
    int j;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_BOOL_PARAM(second_wcard);
    TEST_GET_BOOL_PARAM(third_iut);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_NET(net1);
    TEST_GET_NET(net2);

    memset(iut_s, -1, sizeof(iut_s));

    if (third_iut)
        pco_tst2 = pco_tst1;

    sndbuf = sockts_make_buf_dgram(&len);
    rcvbuf = te_make_buf_by_len(len);

    memcpy(&iut_addr_wcard, iut_addr1, sizeof(iut_addr_wcard));
    te_sockaddr_set_wildcard(&iut_addr_wcard);

    TEST_STEP("Add two more IP addresses to @p iut_if1.");
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr1_2, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if1->if_name,
                                           iut_addr1_2, -1, FALSE, NULL));
    te_sockaddr_set_port(iut_addr1_2, *te_sockaddr_get_port_ptr(iut_addr1));
    te_sockaddr_set_port((struct sockaddr *)iut_addr2,
                         *te_sockaddr_get_port_ptr(iut_addr1));

    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr1_3, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if1->if_name,
                                           iut_addr1_3, -1, FALSE, NULL));
    te_sockaddr_set_port(iut_addr1_3, *te_sockaddr_get_port_ptr(iut_addr1));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create two UDP sockets, enable SO_REUSEADDR and SO_REUSEPORT, bind "
              "the sockets to INADDR_ANY.");
    for (num = 0; num < 2; num++)
    {
        iut_s[num] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                              RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s[num], RPC_SO_REUSEADDR, 1);
        rpc_setsockopt_int(pco_iut, iut_s[num], RPC_SO_REUSEPORT, 1);
        rpc_bind(pco_iut, iut_s[num], &iut_addr_wcard);
    }

    TEST_STEP("Create second couple of UDP socket if @p second_wcard is @c TRUE. "
              "Enable SO_REUSEADDR and SO_REUSEPORT, bind them to a specific IUT "
              "address.");
    if (!second_wcard)
    {
        for (; num < 4; num++)
        {
            iut_s[num] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                                    RPC_SOCK_DGRAM, RPC_PROTO_DEF);
            rpc_setsockopt_int(pco_iut, iut_s[num], RPC_SO_REUSEADDR, 1);
            rpc_setsockopt_int(pco_iut, iut_s[num], RPC_SO_REUSEPORT, 1);
            rpc_bind(pco_iut, iut_s[num], iut_addr1_2);
        }
    }

    TEST_STEP("Create one more UDP socket, enable only SO_REUSEADDR socket option, "
              "bind it to a specific IP address. It can be IP address on @p iut_if1 "
              "or @p iut_if2 in dependence on @p third_iut. IP address is not equal "
              "to address which previously created sockets use.");
    iut_s[num] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s[num], RPC_SO_REUSEADDR, 1);
    rpc_bind(pco_iut, iut_s[num], third_iut ? iut_addr1_3 : iut_addr2);
    num++;

    for (i = 0; i < num; i++)
    {
        event[i].fd = iut_s[i];
        event[i].events = EVT_RD;
        event[i].revents = 0;
    }

    TEST_STEP("Tester sends datagrams to the first two IUT addresses alternately "
              "until all sockets (except the last one) receive at least one "
              "datagram.");
    for (i = 0; i < ATTEMPTS_NUM1; i++)
    {
        received = TRUE;
        for (j = 0; j < num - 1; j++)
            if (count[j] == 0)
            {
                received = FALSE;
                break;
            }

        if (received)
            break;

        tst_s = reuseport_create_tst_udp_sock_any_port(
                    pco_tst1, tst1_if, net1, NULL, NULL);
        rpc_sendto(pco_tst1, tst_s, sndbuf, len, 0,
                   i % 2 == 0 ? iut_addr1 : iut_addr1_2);

        rc = iomux_call(iomux, pco_iut, event, num, &timeout);
        if (rc != 1)
            TEST_VERDICT("Iomux function returned unexpected code");

        received = FALSE;
        for (j = 0; j < num; j++)
        {
            if (event[j].revents == EVT_RD)
            {
                count[j]++;
                rpc_recv(pco_iut, event[j].fd, rcvbuf, len, 0);
                received = TRUE;
                break;
            }
        }
        if (!received)
            TEST_VERDICT("None of the sockets received datagram");

        if (second_wcard)
        {
            if (j > 1)
                TEST_VERDICT("The datagram was received on a wrong socket");
        }
        else
        {
            if (i % 2 == 0)
            {
                if (j > 1)
                    TEST_VERDICT("Sent datagram must be received on the wild sockets");
            }
            else if (j != 2 && j != 3)
                TEST_VERDICT("Sent datagram must be received on the non-wild sockets");
        }

        RPC_CLOSE(pco_tst1, tst_s);
    }

    for (i = 0; i < num - 1; i++)
    {
        RING("Socket #%d (fd %d): %d", i, iut_s[i], count[i]);
        if (count[i] == 0)
            TEST_VERDICT("One of sockets did not receive any datagrams");
    }

    TEST_STEP("The last IUT socket should always receive datagrams which are sent "
              "to its address.");
    for (i = 0; i < ATTEMPTS_NUM2; i++)
    {
        if (third_iut)
        {
            tst_s = reuseport_create_tst_udp_sock_any_port(
                        pco_tst1, tst1_if, net1, NULL, NULL);
            rpc_sendto(pco_tst1, tst_s, sndbuf, len, 0, iut_addr1_3);
        }
        else
        {
            tst_s = reuseport_create_tst_udp_sock_any_port(
                        pco_tst2, tst2_if, net2, NULL, NULL);
            rpc_sendto(pco_tst2, tst_s, sndbuf, len, 0, iut_addr2);
        }

        rc = iomux_call(iomux, pco_iut, event, num, &timeout);
        if (rc != 1)
            TEST_VERDICT("Iomux function returned unexpected code");
        if (event[num - 1].revents != EVT_RD)
            TEST_VERDICT("The last datagram was received by a wrong socket");
        rpc_recv(pco_iut, iut_s[num - 1], rcvbuf, len, 0);

        RPC_CLOSE(third_iut ? pco_tst1 : pco_tst2, tst_s);
    }

    TEST_SUCCESS;

cleanup:
    sockts_close_sockets(pco_iut, iut_s, SOCKETS_NUM);
    CLEANUP_RPC_CLOSE(third_iut ? pco_tst1 : pco_tst2, tst_s);

    free(sndbuf);
    free(rcvbuf);
    TEST_END;
}
