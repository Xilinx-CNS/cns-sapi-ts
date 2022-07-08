/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_add_addr_after_listen Accept connection to a new IP address using an existing listener socket
 *
 * @objective Check that a new network interface address is taken into
 *            account when listening on the wildcard address.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 * @param sock_type Socket type
 * @param multicast Add multicast address if @c TRUE.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_add_addr_after_listen"

#include "sockapi-test.h"
#include "sockapi-ts_monitor.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;
    const struct sockaddr   *tst_addr = NULL;
    const struct sockaddr   *iut_addr = NULL;
    tapi_env_host           *iut_host;
    tapi_env_host           *tst_host;
    tapi_env_net            *net;
    struct sockaddr         *iut_addr2 = NULL;
    struct sockaddr         *tst_addr2 = NULL;
    struct sockaddr         *iut_addr_wild = NULL;
    rpc_socket_type          sock_type;
    rpc_socket_type          multicast;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    tapi_cfg_net_assigned       net_handle = {CFG_HANDLE_INVALID, NULL};
    sockts_if_monitor           iut_if_monitor = SOCKTS_IF_MONITOR_INIT;
    cfg_handle                  iut_addr_handle = CFG_HANDLE_INVALID;

    int iut_s = -1;
    int tst_s = -1;
    int acc_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_HOST(iut_host);
    TEST_GET_HOST(tst_host);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(multicast);

    TEST_STEP("Create @p sock_type socket and bind it to @c INADDR_ANY.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, sock_type, RPC_PROTO_DEF);

    CHECK_RC(tapi_sockaddr_clone2(iut_addr, &iut_addr_wild));
    te_sockaddr_set_wildcard(iut_addr_wild);
    rpc_bind(pco_iut, iut_s, iut_addr_wild);

    TEST_STEP("Call @b listen() for TCP socket.");
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Add new IP addresses on IUT and tester.");
    CHECK_RC(tapi_cfg_net_assign_ip(AF_INET, net->cfg_net, &net_handle));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net, iut_host, AF_INET,
                                        &net_handle, &iut_addr2, NULL));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net, tst_host, AF_INET,
                                        &net_handle, &tst_addr2, NULL));

    TEST_STEP("If @p multicast is @c TRUE add multicast IP address to IUT "
              "interface.");
    if (multicast)
    {
        struct sockaddr *iut_addr_mcast = NULL;

        CHECK_RC(tapi_sockaddr_clone2(iut_addr, &iut_addr_mcast));
        sockts_set_multicast_addr(iut_addr_mcast);
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                               iut_addr_mcast, net->ip4pfx,
                                               FALSE, &iut_addr_handle));
        free(iut_addr_mcast);
    }
    CFG_WAIT_CHANGES;

    te_sockaddr_set_port(tst_addr2, te_sockaddr_get_port(tst_addr));
    te_sockaddr_set_port(iut_addr2, te_sockaddr_get_port(iut_addr));

    CHECK_RC(sockts_if_monitor_init(&iut_if_monitor, pco_iut->ta,
                                    iut_if->if_name, tst_addr2->sa_family,
                                    sock_type, NULL, tst_addr2,
                                    FALSE, TRUE));

    TEST_STEP("Create tester socket and bind it to new IP.");
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr2);

    TEST_STEP("Connect it to new IUT IP address.");
    rpc_connect(pco_tst, tst_s, iut_addr2);

    TEST_STEP("For TCP: accept connection on IUT.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        RPC_CLOSE(pco_iut, iut_s);
        iut_s = acc_s;
        acc_s = -1;
    }
    else
        rpc_connect(pco_iut, iut_s, tst_addr2);

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Check that traffic is accelerated or not as expected.");
    CHECK_IF_ACCELERATED(&env, &iut_if_monitor, "");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_if_monitor));

    if (iut_addr_handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));

    TEST_END;
}
