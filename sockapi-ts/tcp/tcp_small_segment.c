/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page tcp-tcp_small_segment Small segment receiving
 *
 * @objective Check that after receiving too many 1-byte packets on one
 *            connection new connection can be created and works properly.
 *
 * @type Conformance, compatibility
 *
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param passive       does IUT perform passive open?
 * @param cache_socket  If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 * -# Create @c SOCK_STREAM connection according to @p passive parameter
 *    between @p pco_iut and @p pco_tst. If @p with_holes is @c TRUE, use
 *    TSA engine on the TST side.
 * -# Set small @c SO_RCVBUF socket option value on the socket on IUT side.
 * -# Send 1-byte packets from Tester using @b send( @c MSG_DONTWAIT)
 *    for some time.  If @p with_holes is @c TRUE, arrange these packets to
 *    have 1-byte holes between them.
 * -# If @p with_holes is @c FALSE, sleep for some time and then read all
 *    the available data from IUT side. Repeat it @p recv_loops times.
 * -# If @p with_holes is @c FALSE, read all the data we've sent.
 * -# Create one more connection.
 * -# Check that connection works properly.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tcp_small_segment"

#include <net/ethernet.h>
#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "ndn.h"
#include "tcp_test_macros.h"

/** TCP listener socket. */
static int s_listener = -1;

/**
 * Establish TCP connection, print verdicts if connect() or accept()
 * fails.
 *
 * @param rpcs1           The first RPC server.
 * @param addr1           The first IP address.
 * @param rpcs2           The second RPC server.
 * @param addr2           The second IP address.
 * @param active          If @c TRUE, connection will be initiated from
 *                        the first RPC server, otherwise - from the
 *                        second one.
 * @param s1              Where to save connected socket created on
 *                        the first RPC server.
 * @param s2              Where to save connected socket created on
 *                        the second RPC server.
 * @param err_msg         String to print in verdicts.
 * @param cache_socket    If @c TRUE, create cached socket to be reused.
 */
static void
establish_tcp_conn(rcf_rpc_server *rpcs1, const struct sockaddr *addr1,
                   rcf_rpc_server *rpcs2, const struct sockaddr *addr2,
                   te_bool active, int *s1, int *s2,
                   const char *err_msg, te_bool cache_socket)
{
    rcf_rpc_server          *rpcs_a = NULL;
    rcf_rpc_server          *rpcs_p = NULL;
    const struct sockaddr   *addr_a = NULL;
    const struct sockaddr   *addr_p = NULL;
    int                     *s_a = NULL;
    int                     *s_p = NULL;
    int                      rc = 0;

    if (active)
    {
        rpcs_a = rpcs1;
        addr_a = addr1;
        s_a = s1;
        rpcs_p = rpcs2;
        addr_p = addr2;
        s_p = s2;
    }
    else
    {
        rpcs_a = rpcs2;
        addr_a = addr2;
        s_a = s2;
        rpcs_p = rpcs1;
        addr_p = addr1;
        s_p= s1;
    }

    if (active)
    {
        sockts_create_cached_socket(rpcs_p, rpcs_a, addr_p, addr_a,
                                    -1, TRUE, cache_socket);
    }

    s_listener = rpc_socket(rpcs_p,
                            rpc_socket_domain_by_addr(addr_p),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(rpcs_p, s_listener, addr_p);
    rpc_listen(rpcs_p, s_listener, SOCKTS_BACKLOG_DEF);

    if (!active)
    {
        sockts_create_cached_socket(rpcs_p, rpcs_a, addr_p, addr_a,
                                    s_listener, FALSE, cache_socket);
    }

    *s_a = rpc_socket(rpcs_a, rpc_socket_domain_by_addr(addr_a),
                      RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(rpcs_a, *s_a, addr_a);

    RPC_AWAIT_ERROR(rpcs_a);
    rc = rpc_connect(rpcs_a, *s_a, addr_p);
    if (rc < 0)
        TEST_VERDICT("%s: connect() failed with errno %r",
                     err_msg, RPC_ERRNO(rpcs_a));

    RPC_AWAIT_ERROR(rpcs_p);
    *s_p = rpc_accept(rpcs_p, s_listener, NULL, NULL);
    if (*s_p < 0)
        TEST_VERDICT("%s: accept() failed with errno %r",
                     err_msg, RPC_ERRNO(rpcs_p));

    RPC_CLOSE(rpcs_p, s_listener);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    rcf_rpc_server             *pco_gw = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *gw_iut_addr = NULL;
    const struct sockaddr      *gw_tst_addr = NULL;
    const struct sockaddr      *alien_link_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *gw_iut_if = NULL;
    const struct if_nameindex  *gw_tst_if = NULL;

    int             iut_s = -1;
    int             aux_s = -1;
    int             tst_s = -1;
    int             iut_s1 = -1;
    int             tst_s1 = -1;
    te_bool         active = FALSE;
    int             recv_loops;
    te_bool         with_holes = FALSE;
    te_bool         cache_socket;

    struct sockaddr_storage iut_addr_aux;
    struct sockaddr_storage tst_addr_aux;
    int                     rcvbuf_size = 100000;
    int                     opt_val = 1;

    static tapi_tcp_handler_t     tcp_conn = 0;

    tsa_session ss = TSA_SESSION_INITIALIZER;
    static char buf[1024];
    asn_value  *pkt = NULL;
    int         num;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_INT_PARAM(recv_loops);
    TEST_GET_BOOL_PARAM(with_holes);
    TEST_GET_BOOL_PARAM(cache_socket);
    if (with_holes)
    {
        TEST_GET_PCO(pco_gw);
        TEST_GET_ADDR(pco_gw, gw_iut_addr);
        TEST_GET_ADDR(pco_gw, gw_tst_addr);
        TEST_GET_LINK_ADDR(alien_link_addr);
        TEST_GET_IF(gw_iut_if);
        TEST_GET_IF(gw_tst_if);
    }

    TEST_STEP("If @p cache_socket is @c TRUE and @p opening is @c OL_ACTIVE - create "
              "cached socket.");
    if (with_holes)
    {
        if (tsa_state_init(&ss, TSA_TST_GW_CSAP) != 0)
            TEST_FAIL("Unable to initialize TSA");

        CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
        CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr, NULL));
        tsa_gw_preconf(&ss, TRUE);
        CHECK_RC(tsa_gw_set(&ss, pco_gw, gw_iut_addr, gw_tst_addr,
                            gw_iut_if, gw_tst_if,
                            alien_link_addr->sa_data));
        CFG_WAIT_CHANGES;

        if (active)
        {
            sockts_create_cached_socket(pco_iut, pco_gw, iut_addr, gw_iut_addr,
                                        -1, TRUE, cache_socket);
        }

        /* Create a tcp socket on IUT and CSAP on tester. */
        tsa_create_session(&ss, 0);
        TAPI_WAIT_NETWORK;

        /* Move IUT socket and the CSAP to @c ESTABLISHED TCP state. */
        tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED,
                          active ? OL_ACTIVE : OL_PASSIVE_OPEN,
                          active ? FALSE : cache_socket);
        iut_s = ss.state.iut_s;
    }
    else
    {
        establish_tcp_conn(pco_iut, iut_addr, pco_tst, tst_addr,
                           active, &iut_s, &tst_s, "First connection",
                           cache_socket);
    }

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &rcvbuf_size);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &opt_val);
    RING("SO_RCVBUF on %s was set to %d, getting value %d",
         pco_iut->name, rcvbuf_size, opt_val);

    if (with_holes)
    {
        int loglevel = 0;
        tcp_conn = tsa_tst_sock(&ss);
        sprintf(buf,
             "{ arg-sets { simple-for:{begin 0,end %"TE_PRINTF_SIZE_T"d} }, "
             "  pdus  { tcp:{flags plain:24,                        "
             "               seqn script:\"expr:(%u + ($0 * 2))\",  "
             "               ackn plain:%u},                        "
             "          ip%d:{}, eth:{}},                            "
             "  payload length:1 }                                  ",
             tapi_tcp_last_win_got(tcp_conn), tapi_tcp_next_seqn(tcp_conn),
             tapi_tcp_next_ackn(tcp_conn),
             iut_addr->sa_family == AF_INET6 ? 6 : 4);
        CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt,
                                      &num));
        TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);
        tapi_tcp_send_template(tcp_conn, pkt, RCF_MODE_BLOCKING);
        TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);
    }
    else
    {
        int received = 0;
        int sent;
        int duration = TAPI_WAIT_NETWORK_DELAY * (recv_loops + 2) / 1000;
        char recvbuf[102400];

        opt_val = 1;
        rpc_setsockopt(pco_tst, tst_s, RPC_TCP_NODELAY, &opt_val);
        rpc_getsockopt(pco_tst, tst_s, RPC_TCP_NODELAY, &opt_val);
        if (opt_val != 1)
            TEST_FAIL("Cannot enable TCP_NODELAY option");

        /* Send 1-byte messages until send call fails with @c EAGAIN.
         * Overfilling send and receive buffers with such packets can take
         * rather long time. */
        pco_tst->op = RCF_RPC_CALL;
        rpc_send_one_byte_many(pco_tst, tst_s, duration);

        while (recv_loops-- > 0)
        {
            int rc;

            MSLEEP(TAPI_WAIT_NETWORK_DELAY);
            do {
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = rpc_recv(pco_iut, iut_s, recvbuf, sizeof(recvbuf),
                              RPC_MSG_DONTWAIT);
                if (rc < 0)
                    break;
                received += rc;
            } while(1);
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "The only expected error is EAGAIN");
        }

        pco_tst->timeout = pco_tst->def_timeout +
                           TAPI_WAIT_NETWORK_DELAY * 2;
        RPC_AWAIT_ERROR(pco_tst);
        sent = rpc_send_one_byte_many(pco_tst, tst_s, duration);
        if (sent < 0)
            TEST_VERDICT("rpc_send_one_byte_many() failed with errno %r",
                         RPC_ERRNO(pco_tst));

        /* Ensure that all sent data can be read */
        while( received < sent )
        {
            int rc = rpc_recv(pco_iut, iut_s, recvbuf, sizeof(recvbuf), 0);
            received += rc;
        }
    }

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_aux));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr_aux));

    if (with_holes)
    {
        /* Delay to make sure the network activity is finished - to avoid
         * ARP reconfiguring problems on the gateway. */
        TAPI_WAIT_NETWORK;
        CHECK_RC(tsa_repair_iut_tst_conn(&ss));
        CFG_WAIT_CHANGES;
    }

    establish_tcp_conn(pco_iut, SA(&iut_addr_aux),
                       pco_tst, SA(&tst_addr_aux),
                       active, &iut_s1, &tst_s1, "Second connection", FALSE);

    sockts_test_connection(pco_iut, iut_s1, pco_tst, tst_s1);

    TEST_SUCCESS;

cleanup:
    if (tcp_conn != 0)
        tsa_destroy_session(&ss);
    else
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE((active ? pco_tst : pco_iut), s_listener);

    TEST_END;
}
