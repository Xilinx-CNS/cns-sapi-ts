/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_vs_bind Behaviour of socket bound to an interface and to an address on other interface simultaneously.
 *
 * @objective Check that if socket is bound to device and to address
 *            on other device, it sends and receives packet only via
 *            the device it is bound to.
 *
 * @type conformance
 *
 * @reference MAN 7 socket, MAN 7 ip
 *
 * @param env           Environment:
 *                      - @ref arg_types_env_two_nets_iut_first
 *                      - @ref arg_types_env_two_nets_iut_second
 *                      - @ref arg_types_env_two_nets_iut_first_ipv6
 *                      - @ref arg_types_env_two_nets_iut_second_ipv6
 * @param mtu_first     MTU to be set on @p iut_if1 and @p tst1_if
 * @param mtu_second    MTU to be set on @p iut_if2 and @p tst2_if
 * @param sock_type     Type of sockets used in the test
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_vs_bind"

#include "sockapi-test.h"
#include "tapi_cfg.h"

int
main(int argc, char *argv[])
{
    rpc_socket_type             sock_type;
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst1 = NULL;
    rcf_rpc_server             *pco_tst2 = NULL;
    int                         iut_s = -1;
    int                         tst1_s = -1;
    int                         tst2_s = -1;
    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct sockaddr      *iut_addr1 = NULL;
    const struct sockaddr      *iut_addr2 = NULL;
    const struct sockaddr      *tst1_addr = NULL;
    const struct sockaddr      *tst2_addr = NULL;
    int                         data_len1;
    int                         data_len2;
    int                         max_len;
    uint8_t                    *sendbuf = NULL;

    int                 mtu_first = -1;
    int                 mtu_second = -1;
    int                 opt_val;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst1_mtus = LIST_HEAD_INITIALIZER(tst1_mtus);
    te_saved_mtus   tst2_mtus = LIST_HEAD_INITIALIZER(tst2_mtus);

    /* Test preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_SOCK_TYPE(sock_type);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        TEST_GET_INT_PARAM(mtu_first);
        TEST_GET_INT_PARAM(mtu_second);

        TEST_STEP("If @p sock_type is @c SOCK_DGRAM:");
        TEST_SUBSTEP("Set MTU to @p mtu_first on @p iut_if1 and "
                     "@p tst1_if. Datagrams to be sent via these "
                     "interfaces will be of 0.9 * @p mtu_first size.");
        TEST_SUBSTEP("Set MTU to @p mtu_second on @p iut_if2 and "
                     "@p tst2_if. Datagrams to be sent via these "
                     "interfaces will be of 0.9 * @p mtu_second size.");

        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if1->if_name,
                                        mtu_first, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst1->ta, tst1_if->if_name,
                                        mtu_first, &tst1_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if2->if_name,
                                        mtu_second, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst2->ta, tst2_if->if_name,
                                        mtu_second, &tst2_mtus));

        data_len1 = mtu_first * 0.9;
        data_len2 = mtu_second * 0.9;
        max_len = data_len1 > data_len2 ? data_len1 : data_len2;
    }

    TEST_STEP("Remove neighbor entries for @p tst1_addr and @p tst2_addr "
              "on IUT interfaces.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if1->if_name,
                                      tst1_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if1->if_name,
                                      tst2_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if2->if_name,
                                      tst1_addr));
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if2->if_name,
                                      tst2_addr));

    TEST_STEP("Add a route to @p iut_addr1 via @p iut_addr2 on "
              "the host with @p pco_tst2.");
    CHECK_RC(tapi_cfg_add_route_via_gw(pco_tst2->ta,
                 iut_addr1->sa_family,
                 te_sockaddr_get_netaddr(iut_addr1),
                 te_netaddr_get_bitsize(iut_addr1->sa_family),
                 te_sockaddr_get_netaddr(iut_addr2)) != 0);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create sockets of @p sock_type type: @b iut_s on "
              "@p pco_iut, @b tst1_s on @b pco_tst1, "
              "@b tst2_s on @p pco_tst2.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       sock_type, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                        sock_type, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr),
                        sock_type, RPC_PROTO_DEF);

    TEST_STEP("@b bind() @b iut_s socket to @p iut_addr1.");
    rpc_bind(pco_iut, iut_s, iut_addr1);

    TEST_STEP("Bind @b iut_s socket to @p iut_if2 interface with "
              "@c SO_BINDTODEVICE socket option.");
    rpc_bind_to_device(pco_iut, iut_s, iut_if2->if_name);

    TEST_STEP("Bind @b tst1_s to @p tst1_addr.");
    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    TEST_STEP("Bind @b tst2_s to @p tst2_addr.");
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    TEST_STEP("If @p sock_type is @c SOCK_STREAM:");
    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_SUBSTEP("Call @b listen() on @b iut_s.");
        rpc_listen(pco_iut, iut_s, 2);

        TEST_SUBSTEP("Try to @b connect() to @p iut_addr1 from @b tst1_s, "
                     "check that it fails with @c ECONNREFUSED errno.");
        RPC_AWAIT_IUT_ERROR(pco_tst1);
        rc = rpc_connect(pco_tst1, tst1_s, iut_addr1);
        if (rc != -1 || RPC_ERRNO(pco_tst1) != RPC_ECONNREFUSED)
        {
            TEST_VERDICT("Unexpected result instead of ECONNREFUSED error");
        }

        TEST_SUBSTEP("Try to @b connect() to @p iut_addr1 from @b tst2_s, "
                     "check that it succeeds.");
        RPC_AWAIT_IUT_ERROR(pco_tst2);
        rc = rpc_connect(pco_tst2, tst2_s, iut_addr1);
        if (rc != 0)
        {
            TEST_VERDICT("Connect of the client via interface the server "
                         "is bound to unexpectedly failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_tst2)));
        }

        TEST_SUCCESS;
    }

    TEST_STEP("Otherwise, if @p sock_type is @c SOCK_DGRAM:");

    sendbuf = te_make_buf_by_len(max_len);

    TEST_SUBSTEP("Set @c IP_MTU_DISCOVER on @b iut_s to "
                 "@c IP_PMTUDISC_DO, so that fragmenting "
                 "of large datagrams will be disabled and "
                 "sending them will result in either sending "
                 "a big frame or failing.");
    opt_val = RPC_IP_PMTUDISC_DO;
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MTU_DISCOVER, &opt_val);

    opt_val = data_len1 + data_len2;
    rpc_setsockopt(pco_tst1, tst1_s, RPC_SO_RCVBUF, &opt_val);
    opt_val = data_len1 + data_len2;
    rpc_setsockopt(pco_tst2, tst2_s, RPC_SO_RCVBUF, &opt_val);

    TEST_SUBSTEP("Try to send a datagram from @b iut_s to @p tst1_addr, "
                 "check whether it succeeds.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, sendbuf, data_len1, 0, tst1_addr);
    if (rc < 0)
    {
        if (mtu_first > mtu_second &&
            RPC_ERRNO(pco_iut) == RPC_EMSGSIZE)
        {
            RING("Impossible to send jumbo frame when a socket "
                 "is bound to an interface with small MTU");
        }
        else
        {
            RING_VERDICT("The first sendto() unexpectedly failed with "
                         "errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    TEST_SUBSTEP("Try to send a datagram from @b iut_s to @p tst2_addr, "
                 "check that it succeeds.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, sendbuf, data_len2, 0, tst2_addr);
    if (rc < 0)
    {
        if (mtu_first < mtu_second &&
            RPC_ERRNO(pco_iut) == RPC_EMSGSIZE)
            TEST_VERDICT("Impossible to send jumbo frame when a socket "
                         "is bound to an address on an interface with "
                         "small MTU");
        else
            TEST_VERDICT("The second sendto() unexpectedly failed with "
                         "errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    SLEEP(5);

    TEST_SUBSTEP("Check that only @b tst2_s becomes readable.");
    RPC_CHECK_READABILITY(pco_tst1, tst1_s, FALSE);
    RPC_CHECK_READABILITY(pco_tst2, tst2_s, TRUE);

    TEST_SUBSTEP("Send a datagram to @b iut_addr1 from @b tst1_s, "
                 "check that @b iut_s does not become readable.");
    rpc_sendto(pco_tst1, tst1_s, sendbuf, data_len1, 0, iut_addr1);
    TAPI_WAIT_NETWORK;
    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

    TEST_SUBSTEP("Send a datagram to @b iut_addr1 from @b tst2_s, "
                 "check that @b iut_s becomes readable.");
    rpc_sendto(pco_tst2, tst2_s, sendbuf, data_len2, 0, iut_addr1);
    TAPI_WAIT_NETWORK;
    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE);

    TEST_SUCCESS;

cleanup:

    if (sock_type == RPC_SOCK_DGRAM)
    {
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst1_mtus));
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst2_mtus));
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    TEST_END;
}
