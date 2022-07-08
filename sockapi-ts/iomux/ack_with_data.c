/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * ACK with data during TCP connection establishing
 */

/**
 * @page iomux-ack_with_data ACK with data during TCP connection establishing
 *
 * @objective Check iomux IN events when connection establishing sequence is
 *            enclosed by ACK with data.
 *
 * @param env             Testing environment:
 *      - @ref arg_types_env_peer2peer_gw
 *      - @ref arg_types_env_peer2peer_tst_gw
 * @param function        Tested iomux or receiving function:
 *      - select
 *      - pselect
 *      - poll
 *      - ppoll
 *      - epoll
 *      - epoll_pwait
 *      - oo_epoll
 *      - recv
 * @param epoll_flags     Set edge-triggered or oneshot epoll flags, iterating
 *                        makes sense only for @p function={epoll,epoll_pwait}:
 *      - et (set @c EPOLLET)
 *      - oneshot (set @c EPOLLONESHOT)
 *      - none
 * @param blocking_func   Tested function should block IUT if @c TRUE.
 * @param blocking_accept If @c TRUE IUT should be blocked in @b accept() call when
 *                        the ACK packet with data is delivered to IUT.
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/ack_with_data"

#include "sockapi-test.h"
#include "iomux.h"
#include "tapi_route_gw.h"

#define BUF_SIZE 512

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    function_type_t    function = FUNCTION_TYPE_NONE;
    epoll_flags_t      epoll_flags = EPOLL_FLAGS_NONE;
    te_bool            blocking_func = false;
    te_bool            blocking_accept = false;
    int                iut_s = -1;
    int                tst_s = -1;
    int                acc_s = -1;

    uint8_t           *tx_buf = (uint8_t *)te_make_buf_by_len(BUF_SIZE);
    uint8_t           *rx_buf = (uint8_t *)te_make_buf_by_len(BUF_SIZE);

    tapi_iomux_evt_fd *evts = NULL;
    tapi_iomux_handle *iomux_handle = NULL;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_FUNCTION_TYPE(function);
    TEST_GET_EPOLL_FLAGS(epoll_flags);
    TEST_GET_BOOL_PARAM(blocking_func);
    TEST_GET_BOOL_PARAM(blocking_accept);

    TEST_STEP("Configure gateway");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create and bind TCP socket on IUT, make it listener.");
    iut_s = rpc_stream_server(pco_iut, RPC_IPPROTO_TCP, false, iut_addr);
    TEST_STEP("If @p blocking_accept = @c TRUE, block IUT process in @b accept() call");
    if (blocking_accept)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_accept(pco_iut, iut_s, NULL, NULL);
        SOCKTS_CALL_IS_BLOCKED(pco_iut, "Accept");
    }
    TEST_STEP("Create and bind TCP socket on tester, make it non-blocking.");
    tst_s = rpc_stream_client(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                              RPC_IPPROTO_TCP, tst_addr);
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    TEST_STEP("Break the channel in the direction IUT->tester using the gateway.");
    tapi_route_gateway_break_gw_tst(&gateway);
    TEST_STEP("Connect from the tester socket.");
    RPC_AWAIT_ERROR(pco_tst);
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Return socket to blocking mode.");
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, 0);

    TEST_STEP("Send a data packet using the same socket.");
    RPC_AWAIT_ERROR(pco_tst);
    pco_tst->op = RCF_RPC_CALL;
    rpc_send(pco_tst, tst_s, tx_buf, BUF_SIZE, 0);

    TAPI_WAIT_NETWORK;

    TEST_STEP("Repair the channel.");
    tapi_route_gateway_repair_gw_tst(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Call @b send() one more time to get the result");
    rpc_send(pco_tst, tst_s, tx_buf, BUF_SIZE, 0);

    TEST_STEP("Accept the connection.");
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    if (function == FUNCTION_TYPE_RECV)
    {
        TEST_STEP("In case when @p function is @b recv(), call @b recv() on accepted "
                  "socket with or without @c MSG_DONTWAIT flag according to "
                  "@p blocking_func parameter.");

        rc = rpc_recv(pco_iut, acc_s, rx_buf, BUF_SIZE,
                      blocking_func ? 0 : RPC_MSG_DONTWAIT);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, BUF_SIZE, rc);
    }
    else
    {
        TEST_STEP("In case when @p function is iomux, add accepted socket to iomux set "
                  "using @p epoll_flags and call the tested @p function with @c 0 timeout "
                  "or @c -1 timeout according to @p blocking_func parameter.");

        iomux_handle = sockts_iomux_create(pco_iut, (tapi_iomux_type)function);
        tapi_iomux_add(iomux_handle, acc_s,
                       EVT_RD | (tapi_iomux_evt)epoll_flags);
        rc = tapi_iomux_call(iomux_handle, blocking_func ? -1 : 0, &evts);
        TEST_SUBSTEP("Check that IN event is returned.");
        SOCKTS_CHECK_IOMUX_EVENTS(rc, 1, evts, EVT_RD, "");
        TEST_SUBSTEP("Call the @p function one more time.");
        rc = tapi_iomux_call(iomux_handle, 0, &evts);
        TEST_SUBSTEP("Check that no events are returned in case @p epoll_flags != none, "
                     "otherwise - the same event is returned.");
        if(epoll_flags != EPOLL_FLAGS_NONE)
            IOMUX_CHECK_ZERO(rc);
        else
            SOCKTS_CHECK_IOMUX_EVENTS(rc, 1, evts, EVT_RD, "");

        TEST_SUBSTEP("Read the data.");
        rc = rpc_recv(pco_iut, acc_s, rx_buf, BUF_SIZE, 0);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, BUF_SIZE, rc);

        /* Destroy a multiplexer */
        tapi_iomux_del(iomux_handle, acc_s);
        tapi_iomux_destroy(iomux_handle);
        iomux_handle = NULL;
    }

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, acc_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    if (iomux_handle != NULL)
    {
        tapi_iomux_del(iomux_handle, acc_s);
        tapi_iomux_destroy(iomux_handle);
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
