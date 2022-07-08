/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_stream Usage of SO_BINDTODEVICE socket option with socket of type SOCK_STREAM
 *
 * @objective Check that only packets received from particular interface will
 *            be processed if a socket is bound to an interface with
 *            @c SO_BINDTODEVICE socket option.
 *
 * @type conformance
 *
 * @reference MAN 7 socket
 *
 * @param env            Testing environment set:
 *                       - @ref arg_types_env_two_nets_iut_first
 *                       - @ref arg_types_env_two_nets_iut_second
 *                       - Private environment with the first tester
 *                       is on local host, and the second one on the remote
 * @param bind_to_lo     If @c TRUE, bind to "lo" interface, otherwise
 *                       bind to @p iut_if1
 * @param connect_to_lo  If @c TRUE, connect to loopback IP address from
 *                       @b pco_tst1, otherwise connect to non-loopback
 *                       IUT IP address
 *
 * @par Scenario:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_stream"

#include "sockapi-test.h"

/**
 * Establish connection from tester to specified address.
 *
 * @param pco_tst_      Tester RPC server.
 * @param tst_s_        Tester socket.
 * @param conn_addr_    Address to connect to.
 * @param acc_s_        Accepted socket.
 * @param must_pass_    Must the connection establishment succeed.
 * @param msg_          String message to use in verdicts.
 */
#define CHECK_NEW_CONNECTION(pco_tst_, tst_s_, conn_addr_, acc_s_,           \
                             must_pass_, msg_)                               \
    do {                                                                     \
        tst_s_ = rpc_socket(pco_tst_, rpc_socket_domain_by_addr(conn_addr_), \
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);                 \
        RPC_AWAIT_IUT_ERROR(pco_tst_);                                       \
        rc = rpc_connect(pco_tst_, tst_s_, conn_addr_);                      \
        if (must_pass_)                                                      \
        {                                                                    \
            if (rc < 0)                                                      \
            {                                                                \
                TEST_VERDICT("%s: connection establishment failed", msg_);   \
            }                                                                \
            else                                                             \
            {                                                                \
                acc_s_ = rpc_accept(pco_iut, iut_s, NULL, NULL);             \
                CHECK_RC(sockts_test_send(pco_tst_, tst_s_, pco_iut, acc_s_, \
                                          NULL, NULL, RPC_PF_UNSPEC,         \
                                          FALSE, msg_));                     \
                CHECK_RC(sockts_test_send(pco_iut, acc_s_, pco_tst_, tst_s_, \
                                          NULL, NULL, RPC_PF_UNSPEC,         \
                                          FALSE, msg_));                     \
            }                                                                \
        }                                                                    \
        else                                                                 \
        {                                                                    \
            if (rc < 0)                                                      \
            {                                                                \
                CHECK_RPC_ERRNO(pco_tst_, RPC_ECONNREFUSED,                  \
                                "%s: connect() returned -1, but", msg_);     \
            }                                                                \
            else                                                             \
            {                                                                \
                TEST_VERDICT("%s: trying connect through network interface " \
                             "that is not serviced by server returns %d, "   \
                             "instead of -1", msg_, rc);                     \
            }                                                                \
        }                                                                    \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server           *pco_iut;
    rcf_rpc_server           *pco_tst1;
    rcf_rpc_server           *pco_tst2;

    int                       iut_s = -1;
    int                       acc1_s = -1;
    int                       acc2_s = -1;
    int                       tst1_s = -1;
    int                       tst2_s = -1;
    int                       tst1_s1 = -1;
    int                       tst2_s1 = -1;

    const struct if_nameindex *iut_if1;

    const struct sockaddr    *iut_addr1;
    const struct sockaddr    *iut_addr2;

    struct sockaddr          *conn1_addr;
    struct sockaddr          *conn2_addr;

    struct sockaddr_storage   acc_addr;
    socklen_t                 acc_addrlen = sizeof(acc_addr);

    struct sockaddr_storage   tst1_name;
    struct sockaddr_storage   tst2_name;
    socklen_t                 name1len = sizeof(tst1_name);
    socklen_t                 name2len = sizeof(tst2_name);

    int                       i;
    char                      opt_val[IFNAMSIZ];
    te_bool                   bind_to_lo;
    te_bool                   connect_to_lo;
    te_bool                   conn1_must_pass = TRUE;
    te_bool                   conn2_must_pass = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_IF(iut_if1);
    TEST_GET_BOOL_PARAM(bind_to_lo);
    TEST_GET_BOOL_PARAM(connect_to_lo);

    if ((bind_to_lo && !connect_to_lo) ||
        (!bind_to_lo && connect_to_lo))
    {
        conn1_must_pass = FALSE;
    }

    strncpy(opt_val, bind_to_lo ? "lo" : iut_if1->if_name, IFNAMSIZ);
    RING("NAMES: if1 %s", opt_val);

    TEST_STEP("Prepare @b conn2_addr - copy it from @p iut_addr2.");
    CHECK_RC(tapi_sockaddr_clone2(iut_addr2, &conn2_addr));
    te_sockaddr_set_port(conn2_addr, te_sockaddr_get_port(iut_addr1));

    TEST_STEP("Prepare @b conn1_addr - copy it from @p iut_addr1.");
    CHECK_RC(tapi_sockaddr_clone2(iut_addr1, &conn1_addr));

    TEST_STEP("If @p connect_to_lo is @c TRUE - make it loopback");
    if (connect_to_lo)
        te_sockaddr_set_loopback(conn1_addr);

    TEST_STEP("Create a wildcard listener @c SOCK_STREAM socket on IUT.");
    iut_s = rpc_stream_server(pco_iut, RPC_IPPROTO_TCP, TRUE, iut_addr1);
    if (iut_s == -1)
        TEST_VERDICT("Fail to create server socket");

    TEST_STEP("Connect to @b iut_s from both interfaces and accept "
              "connections.");
    tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(iut_addr1),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst1, tst1_s, conn1_addr);
    acc1_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(iut_addr2),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_connect(pco_tst2, tst2_s, conn2_addr);
    acc2_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    TEST_STEP("Connect to @b iut_s from both interfaces again and "
              "do not accept connections.");
    tst1_s1 = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(iut_addr1),
                         RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst2_s1 = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(iut_addr2),
                         RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_connect(pco_tst1, tst1_s1, conn1_addr);
    rpc_connect(pco_tst2, tst2_s1, conn2_addr);

    TEST_STEP("Bind @b iut_s socket to @b iut_if1 interface, "
              "or to \"lo\" interface in case of @p bind_to_lo is @c TRUE.");
    TAPI_WAIT_NETWORK;
    rpc_bind_to_device(pco_iut, iut_s, opt_val);

    TEST_STEP("Check that both accepted connections can send/receive data. "
              "Close them.");
    sockts_test_connection(pco_tst1, tst1_s, pco_iut, acc1_s);
    sockts_test_connection(pco_tst2, tst2_s, pco_iut, acc2_s);

    RPC_CLOSE(pco_tst1, tst1_s);
    RPC_CLOSE(pco_iut, acc1_s);
    RPC_CLOSE(pco_tst2, tst2_s);
    RPC_CLOSE(pco_iut, acc2_s);

    rpc_getsockname(pco_tst1, tst1_s1, SA(&tst1_name), &name1len);
    rpc_getsockname(pco_tst2, tst2_s1, SA(&tst2_name), &name2len);

    TEST_STEP("Accept connections from backlog queue on IUT, check that "
              "only connection to the interface, which IUT is bound to, "
              "can be accepted.");
    for (i = 0; i < 2; i++)
    {
        int     acc_s;
        te_bool readable;
        RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
        if (readable)
        {
            acc_s = rpc_accept(pco_iut, iut_s, SA(&acc_addr), &acc_addrlen);

            if (tapi_sockaddr_cmp(CONST_SA(&acc_addr),
                                  CONST_SA(&tst1_name)) == 0)
            {
                acc1_s = acc_s;
                sockts_test_connection(pco_tst1, tst1_s1, pco_iut, acc1_s);
            }

            if (tapi_sockaddr_cmp(CONST_SA(&acc_addr),
                                  CONST_SA(&tst2_name)) == 0)
            {
                acc2_s = acc_s;
                sockts_test_connection(pco_tst2, tst2_s1, pco_iut, acc2_s);
            }
        }
    }

    if (acc1_s == -1 && acc2_s == -1 &&
        (conn1_must_pass || conn2_must_pass))
    {
        RING_VERDICT("Socket can't be accepted from backlog queue after "
                     "binding listener to an interface");
    }

    if (acc1_s != -1 && acc2_s != -1 &&
        (!conn1_must_pass || !conn2_must_pass))
    {
        RING_VERDICT("Accepted two connections from different interfaces "
                     "after binding listener to the single interface");
    }

    if (acc1_s > 0)
        RPC_CLOSE(pco_iut, acc1_s);
    if (acc2_s > 0)
        RPC_CLOSE(pco_iut, acc2_s);

    TEST_STEP("Connect to @b conn1_addr from @b pco_tst1 and check "
              "that connection passes if the address belongs to "
              "the listener interface.");
    CHECK_NEW_CONNECTION(pco_tst1, tst1_s, conn1_addr, acc1_s, conn1_must_pass,
                         "Tester 1 connection");

    TEST_STEP("Connect to @b conn2_addr from @b pco_tst2 and check "
              "that connection fails with ECONNREFUSED.");
    CHECK_NEW_CONNECTION(pco_tst2, tst2_s, conn2_addr, acc2_s, conn2_must_pass,
                         "Tester 2 connection");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc1_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc2_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s1);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s1);

    free(conn1_addr);
    free(conn2_addr);

    TEST_END;
}
