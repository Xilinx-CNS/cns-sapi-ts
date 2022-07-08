/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol, such
 * as ICMP and routing table handling, small and zero window, fragmentation
 * of TCP packets, etc.
 */

/**
 * @page tcp-syn_recv_peer_shutdown SYN-RECV -> CLOSE-WAIT transition
 *
 * @objective In human language: http client comes to the server with a short
 *            request. ACK from 3-way handshake is lost. The server must handle
 *            the http request properly, and reply with the html page content.
 *
 * @param shutdown Call shutdown on tester if @c TRUE.
 * @param epoll    Wait for connection acceptance using epoll if @c TRUE.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/syn_recv_peer_shutdown"

#include "sockapi-test.h"
#include "iomux.h"
#include "tapi_route_gw.h"

/* Infinite timeout for iomux. */
#define TIMEOUT -1

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    te_bool shutdown;
    te_bool epoll;

    tapi_iomux_handle *iomux = NULL;
    tapi_iomux_evt_fd *evts =NULL;

    char *sndbuf;
    char *rcvbuf;
    size_t len;
    int tst_s = -1;
    int iut_l = -1;
    int iut_s = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_BOOL_PARAM(shutdown);
    TEST_GET_BOOL_PARAM(epoll);

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);

    sndbuf = sockts_make_buf_stream(&len);
    rcvbuf = te_make_buf_by_len(len);

    TEST_STEP("Create and bind listener socket.");
    iut_l = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_l, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Break channel in the direction iut->tst using gateway.");
    tapi_route_gateway_break_gw_tst(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create epoll set and add the listener socket to the set if @p epoll "
              "is @c TRUE.");
    TEST_STEP("Block in @c epoll_wait() or @c accept() call in dependence on @p epoll.");
    iomux = tapi_iomux_create(pco_iut, TAPI_IOMUX_EPOLL);
    if (epoll)
    {
        tapi_iomux_add(iomux, iut_l, EVT_RD | EVT_HUP | EVT_ERR);
        pco_iut->op = RCF_RPC_CALL;
        tapi_iomux_call(iomux, TIMEOUT, &evts);
    }
    else
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_accept(pco_iut, iut_l, NULL, NULL);
    }

    TEST_STEP("Create socket on tester and connect it to the listener.");
    tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       tst_addr);

    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s, iut_addr);
    if (rc != -1 || RPC_ERRNO(pco_tst) != RPC_EINPROGRESS)
        TEST_FAIL("Tester connect() had to fail with EINPROGRESS");

    TEST_STEP("Break channel in the direction tst->iut using gateway.");
    tapi_route_gateway_break_tst_gw(&gateway);
    /* Delay to make sure configurations are applied, otherwise there is a
     * chance of unexpectedly delivered ACK. */
    CFG_WAIT_CHANGES;

    TEST_STEP("Repair channel iut->tst using gateway.");
    tapi_route_gateway_repair_gw_tst(&gateway);

    TEST_STEP("Finalize @c connect() on tester.");
    rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, 0);
    rpc_connect(pco_tst, tst_s, iut_addr);

    TEST_STEP("Send a data packet from tester.");
    rpc_write(pco_tst, tst_s, sndbuf, len);

    TEST_STEP("If @p shutdown is @c TRUE");
    if (shutdown)
    {
        TEST_SUBSTEP("shutdown(wr) tester socket.");
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);
    }

    TEST_STEP("Repair channel tst->iut using gateway.");
    tapi_route_gateway_repair_tst_gw(&gateway);

    TEST_STEP("Accept connection on IUT");
    if (epoll)
    {
        TEST_SUBSTEP("Check epoll event if @p epoll is @c TRUE.");
        rc = tapi_iomux_call(iomux, TIMEOUT, &evts);
        if (rc != 1 || evts->revents != EVT_RD)
            TEST_VERDICT("The iomux call had to return IN event");
    }
    iut_s = rpc_accept(pco_iut, iut_l, NULL, NULL);

    TEST_STEP("Read and check data on IUT.");
    /* Increase RPC timeout because channel is not repaired immediately. */
    pco_iut->timeout = 2 * pco_iut->def_timeout;
    rc = rpc_read(pco_iut, iut_s, rcvbuf, len);
    SOCKTS_CHECK_RECV(pco_iut, sndbuf, rcvbuf, len, rc);

    TEST_STEP("If @p shutdown is @c TRUE.");
    if (shutdown)
    {
        TEST_SUBSTEP("Call @c recv() one more time - should return @c 0.");
        rc = rpc_read(pco_iut, iut_s, rcvbuf, len);
        if (rc != 0)
            TEST_VERDICT("The second read() call returned non-zero value "
                         "after tester socket shutdown");

        TEST_SUBSTEP("Check iomux result on the accepted connection.");
        tapi_iomux_add(iomux, iut_s, EVT_RD | EVT_HUP | EVT_ERR);
        rc = tapi_iomux_call(iomux, TIMEOUT, &evts);
        if (rc != 1 || evts->revents != EVT_RD)
            TEST_VERDICT("The iomux call had to return IN event");
    }

    TEST_STEP("Send data to tester.");
    te_fill_buf(sndbuf, len);
    rpc_write(pco_iut, iut_s, sndbuf, len);

    TEST_STEP("Read and check data.");
    rc = rpc_read(pco_tst, tst_s, rcvbuf, len);
    SOCKTS_CHECK_RECV(pco_tst, sndbuf, rcvbuf, len, rc);

    if (!shutdown)
    {
        TEST_STEP("If @p shutdown is @c FALSE.");
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);

        TEST_SUBSTEP("Call @c recv() one more time - should return @c 0.");
        rc = rpc_read(pco_iut, iut_s, rcvbuf, len);
        if (rc != 0)
            TEST_VERDICT("The last read() call returned non-zero value "
                         "after tester socket shutdown");
    }

    TEST_SUCCESS;

cleanup:

    tapi_iomux_destroy(iomux);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
