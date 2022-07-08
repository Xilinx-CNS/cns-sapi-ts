/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_source_addr_stream Source address selection by TCP socket when a few local addresses are assigned to the interface
 *
 * @objective Check that the correct source address is used (when there are
 *            a few local addresses) in TCP connection in dependence on the
 *            peer address.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 * @param iut_addr  Network address not assigned to any interface
 * @param tst_addr  Network address not assigned to any interface from the
 *                  same subnetwork as @p iut_addr
 * @param bind_to   Bind address type
 * @param passive   Use listener socket on IUT side if @c TRUE, else - connect
 *                  from IUT sockets.
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_source_addr_stream"

#include "sockapi-test.h"

static int iut_s = -1;
static int tst_s = -1;
static int iut_acc_s = -1;
static int tst_acc_s = -1;

/**
 * Test passive connection establishment.
 *
 * @param pco_iut   IUT RPC handle
 * @param pco_tst   Tester RPC handle
 * @param iut_addr  IUT address to connect
 * @param tst_addr  Tester address to bind tester socket
 */
static void
test_passive_iut_source(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                       const struct sockaddr *iut_addr,
                       const struct sockaddr *tst_addr)
{
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_connect(pco_tst, tst_s, iut_addr);
    iut_acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    sockts_test_connection(pco_iut, iut_acc_s, pco_tst, tst_s);

    RPC_CLOSE(pco_tst, tst_s);
    RPC_CLOSE(pco_iut, iut_acc_s);
}

/**
 * Test active connection establishment.
 *
 * @param pco_iut       IUT RPC handle
 * @param pco_tst       Tester RPC handle
 * @param iut_addr_bind IUT address to bind or @c NULL
 * @param tst_addr      Tester address to connect
 * @param iut_addr_exp  Expected IUT source address
 */
static void
test_active_iut_source(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                       const struct sockaddr *iut_addr_bind,
                       const struct sockaddr *tst_addr,
                       const struct sockaddr *iut_addr_exp)
{
    struct sockaddr_storage conn_addr;
    socklen_t               conn_addr_len = sizeof(conn_addr);

    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (iut_addr_bind != NULL)
        rpc_bind(pco_iut, iut_s, iut_addr_bind);

    rpc_connect(pco_iut, iut_s, tst_addr);
    tst_acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    rpc_getpeername(pco_tst, tst_acc_s, SA(&conn_addr), &conn_addr_len);
    if (SIN(&conn_addr)->sin_addr.s_addr !=
        SIN(iut_addr_exp)->sin_addr.s_addr)
    {
        TEST_VERDICT("getpeername() on tester shows unexpected IUT address");
    }

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_acc_s);

    RPC_CLOSE(pco_tst, tst_acc_s);
    /* Make sure that iut_s will not go into the TIME_WAIT state. */
    TAPI_WAIT_NETWORK;
    RPC_CLOSE(pco_iut, iut_s);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    tapi_env_net          *net = NULL;
    tapi_env_host         *iut_host = NULL;
    tapi_env_host         *tst_host = NULL;
    sockts_addr_type       bind_to;
    te_bool                passive;

    struct sockaddr       *iut_addr2 = NULL;
    const struct sockaddr *iut_addr_bind = NULL;
    const struct sockaddr *iut_addr_exp = NULL;
    struct sockaddr       *tst_addr2 = NULL;
    struct sockaddr       *tst_addr_wild = NULL;
    struct sockaddr       *iut_addr_wild = NULL;
    tapi_cfg_net_assigned  net_handle = {CFG_HANDLE_INVALID, NULL};

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_HOST(iut_host);
    TEST_GET_HOST(tst_host);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_ADDR_TYPE(bind_to);
    TEST_GET_BOOL_PARAM(passive);

    TEST_STEP("Assign additional network on IUT and tester interfaces. IUT and "
              "tester have two IP addresses couples now - @b first and @b second.");
    CHECK_RC(tapi_cfg_net_assign_ip(AF_INET, net->cfg_net, &net_handle));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net, iut_host, AF_INET,
                                        &net_handle, &iut_addr2, NULL));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net, tst_host, AF_INET,
                                        &net_handle, &tst_addr2, NULL));
    CFG_WAIT_CHANGES;

    te_sockaddr_set_port(tst_addr2, te_sockaddr_get_port(tst_addr));
    te_sockaddr_set_port(iut_addr2, te_sockaddr_get_port(iut_addr));

    TEST_STEP("Create TCP socket, bind it to the @b second IUT address or "
              "@c INADDRA_ANY or don't bind in dependence on @p bind_to.");
    iut_addr_exp = iut_addr;
    if (bind_to == SOCKTS_ADDR_SPEC)
    {
        iut_addr_bind = iut_addr2;
        iut_addr_exp = iut_addr2;
    }
    else if (bind_to == SOCKTS_ADDR_WILD)
    {
        CHECK_RC(tapi_sockaddr_clone2(iut_addr2, &iut_addr_wild));
        te_sockaddr_set_wildcard(iut_addr_wild);
        iut_addr_bind = iut_addr_wild;
    }

    if (passive)
    {
        TEST_STEP("If @p passive is @c TRUE:");
        TEST_SUBSTEP("Call @c listen().");
        iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut_addr_bind);
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

        TEST_SUBSTEP("Connect tester socket to the second IUT IP address if socket "
                     "was bound to the @b second IP. Else connect to the @b first "
                     "address. Tester socket is bound to the first IP address.");
        test_passive_iut_source(pco_iut, pco_tst, iut_addr_exp, tst_addr);

        TEST_SUBSTEP("Connect tester socket to the second IUT address, tester socket "
                     "is bound to the second IP address.");
         TEST_SUBSTEP("Check data transmission in both directions.");
        test_passive_iut_source(pco_iut, pco_tst, iut_addr2, tst_addr2);
    }
    else
    {
        TEST_STEP("If @p passive is @c FALSE:");
        TEST_SUBSTEP("Create listener socket on tester, bind it to @c INADDR_ANY.");
        tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        CHECK_RC(tapi_sockaddr_clone2(tst_addr, &tst_addr_wild));
        te_sockaddr_set_wildcard(tst_addr_wild);
        rpc_bind(pco_tst, tst_s, tst_addr_wild);
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

        TEST_SUBSTEP("Connect IUT socket to the first tester address.");
        test_active_iut_source(pco_iut, pco_tst, iut_addr_bind, tst_addr,
                               iut_addr_exp);

        /* Linux assumes that IUT socket is closed after call close() if
         * socket does not fall to TIME_WAIT state, so port can be
         * immediately used by any other socket. But Onload does not follow
         * this rule, so the port can stay busy for a while after call
         * close(). See bug 71192 for details. */
        TAPI_WAIT_NETWORK;

        TEST_SUBSTEP("Connect IUT socket to the second tester address.");
        TEST_SUBSTEP("Check data transmission in both directions.");
        test_active_iut_source(pco_iut, pco_tst, iut_addr_bind, tst_addr2,
                               iut_addr2);
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_acc_s);

    TEST_END;
}
