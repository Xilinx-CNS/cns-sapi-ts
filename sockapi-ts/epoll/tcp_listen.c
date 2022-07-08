/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * Test suite on reliability of the @b epoll functions.
 */

/**
 * @page epoll-tcp_listen Epoll event on a listener socket after a connection attempt
 *
 * @objective Check that epoll returns a correct event for a listener
 *            socket when connection attempt fails or succeeds.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "epoll/tcp_listen"

#include "sockapi-test.h"

#include "iomux.h"
#include "epoll_common.h"
#include "onload.h"
#include "tapi_route_gw.h"

/**
 * SYN-ACK retransmission number, to be set to make dropping connection
 * due to timeout faster.
 */
#define SYNACK_RETRIES_NUM 1

/**
 * How long to wait for connection establishment after repairing
 * network connection, in seconds.
 */
#define CONN_WAIT_TIME 5

/**
 * How long to wait for epoll_wait() returning non-zero, in seconds.
 */
#define EPOLL_LOOP_TIMEOUT 130

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;
    rcf_rpc_server *pco_iut_aux = NULL;

    sockts_conn_problem_t   status;
    int                     timeout;

    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter     ctx;

    tarpc_linger            optval;

    int iut_s_listening = -1;
    int iut_s = -1;
    int tst_s = -1;
    int epfd = -1;

    int             error = 0;
    te_bool         done;

    struct rpc_epoll_event event;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ENUM_PARAM(status, SOCKTS_CONN_PROBLEM_MAPPING_LIST);
    TEST_GET_INT_PARAM(timeout);

    TEST_STEP("If @p status is @c timeout, decrease @b tcp_synack_retries.");
    if (status == SOCKTS_CONN_TIMEOUT)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, SYNACK_RETRIES_NUM,
                                         NULL,
                                         "net/ipv4/tcp_synack_retries"));
        rcf_rpc_server_restart(pco_iut);
    }

    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "iut_aux",
                                   &pco_iut_aux));

    TEST_STEP("Configure gateway connecting IUT and Tester.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Configure CSAP listening for packets sent from Tester.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_gw->ta, 0,
                                         gw_iut_if->if_name,
                                         TAD_ETH_RECV_ALL, NULL, NULL,
                                         iut_addr->sa_family,
                                         TAD_SA2ARGS(iut_addr, tst_addr),
                                         &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Create listener TCP socket on IUT.");
    iut_s_listening = rpc_socket(pco_iut,
                                 rpc_socket_domain_by_addr(iut_addr),
                                 RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s_listening, iut_addr);
    rpc_listen(pco_iut, iut_s_listening, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Create a epoll set and add the listener socket with "
              "@c EPOLLIN, @c EPOLLERR and @c EPOLLHUP to it "
              "- use the edge-triggered mode.");
    epfd = rpc_epoll_create(pco_iut, 1);

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                              iut_s_listening,
                              RPC_EPOLLIN | RPC_EPOLLERR |
                              RPC_EPOLLHUP | RPC_EPOLLET);
    if (rc < 0)
        TEST_VERDICT("epoll_ctl() failed with errno %r",
                     RPC_ERRNO(pco_iut));

    TEST_STEP("Create TCP socket on Tester.");
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    /* This is done to free address used by Tester socket faster
     * when closing it. */
    optval.l_onoff = 1;
    optval.l_linger = 0;
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &optval);

    /*
     * epoll_wait() is tested with different timeouts here. Some timeouts
     * are big or infinite, some are small. Connection can be established
     * sooner or later (in case of reuse_stack it is later becase
     * tcp_synack_retries change will not have effect), therefore it is
     * not fully clear which timeout is enough to call epoll_wait() just
     * once (with RCF_RPC_CALL), and which is not. To check all timeouts
     * in a unified way, epoll_wait() is called in a loop until expected
     * event happens.
     */

    TEST_STEP("Call epoll_wait() in a loop on @p pco_iut.");
    pco_iut->op = RCF_RPC_CALL;
    pco_iut->timeout = TE_SEC2MS(EPOLL_LOOP_TIMEOUT);
    rpc_epoll_wait_loop(pco_iut, epfd, &event, timeout);

    TEST_STEP("Break connection from IUT to Tester.");
    tapi_route_gateway_break_gw_tst(&gateway);

    TEST_STEP("Call @b connect() on Tester socket.");
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    RPC_AWAIT_ERROR(pco_tst);
    rpc_connect(pco_tst, tst_s, iut_addr);
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Break connection from Tester to IUT.");
    tapi_route_gateway_break_tst_gw(&gateway);

    TEST_STEP("If @p status is @c refused, close Tester socket.");
    if (status == SOCKTS_CONN_REFUSED)
        RPC_CLOSE(pco_tst, tst_s);

    TEST_STEP("Repair connection from IUT to Tester.");
    tapi_route_gateway_repair_gw_tst(&gateway);

    TEST_STEP("If @p status is not @c 'timeout', repair connection from "
              "Tester to IUT.");
    if (status == SOCKTS_CONN_REFUSED ||
        status == SOCKTS_CONN_DELAYED)
    {
        if (status == SOCKTS_CONN_DELAYED)
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));

        tapi_route_gateway_repair_tst_gw(&gateway);
    }

    TEST_STEP("Wait until connection is either dropped or established, "
              "depending on @p status.");
    if (status != SOCKTS_CONN_DELAYED)
        sockts_wait_cleaned_listenq(pco_iut_aux, iut_addr);
    else
        SLEEP(CONN_WAIT_TIME);

    TEST_STEP("Check that RST arrived from Tester if @p status is @c refused.");

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_stop(pco_gw->ta, 0, csap,
                                tsa_packet_handler, &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    if (status == SOCKTS_CONN_REFUSED)
    {
        if (ctx.rst == 0 && ctx.rst_ack == 0)
            TEST_VERDICT("RST was not received from Tester");
    }
    else
    {
        if (ctx.rst > 0 || ctx.rst_ack > 0)
            TEST_VERDICT("RST was unexpectedly received from Tester");
    }

    TEST_STEP("If @p status is @c timeout, repair connection from Tester "
              "to IUT.");

    if (status == SOCKTS_CONN_TIMEOUT)
        tapi_route_gateway_repair_tst_gw(&gateway);

    if (status != SOCKTS_CONN_DELAYED)
    {
        TEST_STEP("If @p status is not @c delayed, close TCP socket on Tester "
                  "(if it is still open), create a new one and connect it to IUT.");

        if (tst_s >= 0)
            RPC_CLOSE(pco_tst, tst_s);

        tst_s = rpc_socket(pco_tst,
                           rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr);

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));

        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_connect(pco_tst, tst_s, iut_addr);
        if (rc < 0)
            TEST_VERDICT("The second connect() unexpectedly "
                         "failed with errno %r", RPC_ERRNO(pco_tst));

        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Check that epoll_wait() reported EPOLLIN event only after "
              "connection was successfully established.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_epoll_wait_loop(pco_iut, epfd, &event, timeout);
    if (rc < 0)
        TEST_VERDICT("epoll_wait_loop() failed with errno %r",
                     RPC_ERRNO(pco_iut));

    epoll_check_single_event(pco_iut, IC_EPOLL,
                             rc, &event,
                             1, 0, iut_s_listening,
                             RPC_EPOLLIN, "Checking epoll_wait()");

    if (done)
        TEST_VERDICT("epoll_wait() reported event too early");

    TEST_STEP("Accept connection on IUT, check that @c SO_ERROR option value "
              "is zero.");
    iut_s = rpc_accept(pco_iut, iut_s_listening, NULL, NULL);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &error);
    if (error != 0)
        TEST_VERDICT("SO_ERROR is not zero for accepted connection");

    TEST_STEP("If connection was accepted on IUT, check that data can be "
              "transmitted in both directions.");
    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:

    tapi_tad_csap_destroy(pco_gw->ta, 0, csap);

    if (timeout >= 0)
    {
        CLEANUP_RPC_CLOSE(pco_iut, epfd);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s_listening);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    }

    if (pco_iut_aux != NULL)
        rcf_rpc_server_destroy(pco_iut_aux);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
