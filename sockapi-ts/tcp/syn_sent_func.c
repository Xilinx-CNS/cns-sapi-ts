/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol,
 * such as ICMP and routing table handling, small and zero window,
 * fragmentation of TCP packets, etc.
 */

/**
 * @page tcp-syn_sent_func Check socket functions behavior in SYN-SENT state
 *
 * @objective Check socket functions behavior in SYN-SENT state.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_gw
 *                      - @ref arg_types_env_peer2peer_gw_ipv6
 * @param test_func     Function to be called in SYN-SENT state:
 *                      - @b send();
 *                      - @b recv();
 *                      - @b getsockname();
 *                      - @b getpeername();
 *                      - @b sendfile();
 *                      - @b shutdown();
 *                      - @b close().
 * @param nonblock      If @c TRUE, call @p test_func in nonblocking mode.
 * @param cache_socket  If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/syn_sent_func"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_route_gw.h"
#include "sendfile_common.h"
#include "tapi_file.h"

/** Functions to be tested. */
typedef enum {
    TEST_FUNC_GETSOCKNAME, /**< getsockname(). */
    TEST_FUNC_GETPEERNAME, /**< getpeername(). */
    TEST_FUNC_RECV,        /**< recv(). */
    TEST_FUNC_SEND,        /**< send(). */
    TEST_FUNC_SENDFILE,    /**< sendfile(). */
    TEST_FUNC_SHUTDOWN,    /**< shutdown(WR). */
    TEST_FUNC_CLOSE,       /**< close(). */
} sockts_test_func;

/** List of functions to be passed to TEST_GET_ENUM_PARAM(). */
#define TEST_FUNCS \
    { "getsockname", TEST_FUNC_GETSOCKNAME },  \
    { "getpeername", TEST_FUNC_GETPEERNAME },  \
    { "recv", TEST_FUNC_RECV },                \
    { "send", TEST_FUNC_SEND },                \
    { "sendfile", TEST_FUNC_SENDFILE },        \
    { "shutdown", TEST_FUNC_SHUTDOWN },        \
    { "close", TEST_FUNC_CLOSE }

/** Packet length used in this test. */
#define PKT_LEN 1024

/**
 * How long to wait for connection establishment
 * after repairing network connection, seconds.
 */
#define CONN_WAIT_TIMEOUT 7

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;

    int tst_s_listening = -1;
    int tst_s = -1;
    int iut_s = -1;
    int iut_s2 = -1;

    struct sockaddr_storage addr;
    socklen_t               addr_len = sizeof(addr);

    te_bool cache_socket;

    char send_data[PKT_LEN];
    char recv_data[PKT_LEN];

    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    tsa_packets_counter     ctx;

    sockts_test_func test_func;
    te_bool          nonblock;
    te_errno         first_rc = 0;

    te_bool failed = FALSE;
    te_bool done = FALSE;
    te_bool is_send_func = FALSE;
    te_bool is_shutdown_close_func = FALSE;
    te_bool is_send_recv_func = FALSE;

    te_string sendfile_fn = TE_STRING_INIT;
    int sendfile_fd = -1;
    te_bool file_created = FALSE;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ENUM_PARAM(test_func, TEST_FUNCS);
    TEST_GET_BOOL_PARAM(nonblock);
    TEST_GET_BOOL_PARAM(cache_socket);

    te_fill_buf(send_data, PKT_LEN);

    if (test_func == TEST_FUNC_SEND || test_func == TEST_FUNC_SENDFILE)
        is_send_func = TRUE;
    if (test_func == TEST_FUNC_SHUTDOWN || test_func == TEST_FUNC_CLOSE)
        is_shutdown_close_func = TRUE;
    if (test_func == TEST_FUNC_RECV || is_send_func)
        is_send_recv_func = TRUE;
    if (test_func == TEST_FUNC_SENDFILE)
    {
        TEST_STEP("If @p test_func is @b sendfile(), create a file "
                  "on IUT to send.");
        tapi_file_make_name(&sendfile_fn);
        RPC_FOPEN_D(sendfile_fd, pco_iut, sendfile_fn.ptr,
                    RPC_O_RDWR | RPC_O_CREAT, 0);
        file_created = TRUE;
        rpc_write(pco_iut, sendfile_fd, send_data, PKT_LEN);
        rpc_lseek(pco_iut, sendfile_fd, 0, RPC_SEEK_SET);
    }

    TEST_STEP("Configure gateway connecting IUT and Tester.");
    TAPI_INIT_ROUTE_GATEWAY(gateway);
    CHECK_RC(tapi_route_gateway_configure(&gateway));
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    TEST_STEP("Configure CSAP on gateway to check what IUT sends.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_gw->ta, 0,
        gw_tst_if->if_name,
        TAD_ETH_RECV_ALL, NULL, NULL,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Break link from Tester to IUT on gateway.");
    tapi_route_gateway_break_tst_gw(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("Create TCP socket on IUT.");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);

    TEST_STEP("Create listener socket on Tester.");
    tst_s_listening = rpc_create_and_bind_socket(
                                       pco_tst, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       tst_addr);
    rpc_listen(pco_tst, tst_s_listening, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Call nonblocking @b connect() on IUT to change IUT "
              "socket state to @c SYN-SENT.");
    rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc >= 0)
    {
        TEST_VERDICT("Nonblocking connect() unexpectedly succeeded");
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EINPROGRESS)
    {
        TEST_VERDICT("Nonblocking connect() failed with unexpected "
                     "errno %r", RPC_ERRNO(pco_iut));
    }

    TEST_STEP("If @p nonblock is @c TRUE, leave IUT socket in "
              "nonblocking mode until @p test_func is called; "
              "otherwise make IUT socket blocking again.");
    if (!nonblock)
        rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, 0);

    TEST_STEP("Call function @p test_func.");

    if (is_send_recv_func && !nonblock)
        pco_iut->op = RCF_RPC_CALL;

    RPC_AWAIT_ERROR(pco_iut);
    switch (test_func)
    {
        case TEST_FUNC_GETSOCKNAME:
            first_rc = rpc_getsockname(pco_iut, iut_s, SA(&addr),
                                       &addr_len);
            break;

        case TEST_FUNC_GETPEERNAME:
            first_rc = rpc_getpeername(pco_iut, iut_s, SA(&addr),
                                       &addr_len);
            break;

        case TEST_FUNC_RECV:
            first_rc = rpc_recv(pco_iut, iut_s, recv_data, PKT_LEN, 0);
            break;

        case TEST_FUNC_SEND:
            first_rc = rpc_send(pco_iut, iut_s, send_data, PKT_LEN, 0);
            break;

        case TEST_FUNC_SENDFILE:
            first_rc = rpc_sendfile(pco_iut, iut_s, sendfile_fd, NULL,
                                    PKT_LEN, FALSE);
            break;

        case TEST_FUNC_SHUTDOWN:
            first_rc = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
            break;

        case TEST_FUNC_CLOSE:
            first_rc = rpc_close(pco_iut, iut_s);
            iut_s = -1;
            break;

        default:
            TEST_FAIL("Unknown test_func");
    }

    TEST_STEP("If @p test_func is a sending or receiving function, check "
              "that it blocks if @p nonblock is @c FALSE and fails with "
              "@c EAGAIN otherwise. If @p test_func is @b shutdown(), "
              "@b close() or getsockname(), check that it succeeds."
              "If @c test_func is @b getpeername() check that it "
              "fails with @c ENOTCONN errno.");
    if (first_rc < 0)
    {
        if (test_func == TEST_FUNC_GETPEERNAME)
        {
            if (RPC_ERRNO(pco_iut) != RPC_ENOTCONN)
            {
                TEST_VERDICT("getpeername() function "
                             "failed with unexpected error " RPC_ERROR_FMT,
                             RPC_ERROR_ARGS(pco_iut));
            }
        }
        else if (!is_send_recv_func || !nonblock)
        {
            TEST_VERDICT("The tested function failed unexpectedly with "
                         "error " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut));
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        {
            TEST_VERDICT("The non-blocking call of the tested function "
                         "failed with unexpected error " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut));
        }
    }
    else if (is_send_recv_func)
    {
        if (nonblock)
        {
            TEST_VERDICT("The non-blocking call of the tested function "
                         "succeeded unexpectedly");
        }
        else
        {
            TAPI_WAIT_NETWORK;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
            if (done)
            {
                ERROR_VERDICT("%s was not blocked in SYN-SENT state",
                              test_func == TEST_FUNC_RECV ? "Receiving" :
                                                            "Sending");
                failed = TRUE;
            }
        }
    }
    else
    {
        if (test_func == TEST_FUNC_GETSOCKNAME)
        {
            if (te_sockaddrcmp(SA(&addr), addr_len, iut_addr,
                               te_sockaddr_get_size(iut_addr)) != 0)
            {
                TEST_VERDICT("Invalid address returned by getsockname()");
            }
        }
        else if (test_func == TEST_FUNC_GETPEERNAME)
        {
            TEST_VERDICT("getpeername() function unexpectedly succeeded");
        }
        else
        {
            TEST_STEP("If @b shutdown() or @b close() is tested, check "
                      "that RST is not sent after the call.");

            TAPI_WAIT_NETWORK;
            memset(&ctx, 0, sizeof(ctx));
            CHECK_RC(rcf_ta_trrecv_get(pco_gw->ta, 0, csap,
                                       tsa_packet_handler, &ctx, NULL));
            tsa_print_packet_stats(&ctx);
            if (ctx.rst_ack > 0 || ctx.rst > 0)
            {
                ERROR_VERDICT("RST packet is sent after the tested "
                              "function call");
                failed = TRUE;
            }
        }
    }

    TEST_STEP("Repair link from Tester to IUT.");
    CHECK_RC(tapi_route_gateway_repair_tst_gw(&gateway));
    SLEEP(CONN_WAIT_TIMEOUT);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_RC(rcf_ta_trrecv_get(pco_gw->ta, 0, csap,
                               tsa_packet_handler, &ctx, NULL));
    tsa_print_packet_stats(&ctx);

    if (is_shutdown_close_func)
    {
        TEST_STEP("If @p test_func is @b shutdown() or @b close(), check "
                  "that @c RST is sent from IUT after @c SYN-ACK arrives "
                  "from Tester.");

        if (ctx.fin_ack > 0 || ctx.push_fin_ack > 0)
        {
            ERROR_VERDICT("FIN was sent from IUT");
            failed = TRUE;
        }

        if (ctx.rst_ack <= 0 && ctx.rst <= 0)
        {
            ERROR_VERDICT("RST was not sent in response to SYN-ACK");
            failed = TRUE;
        }
    }

    if (test_func == TEST_FUNC_RECV)
    {
        TEST_STEP("If @p test_func is @c recv:");
        TEST_SUBSTEP("Call @b accept() on Tester to obtain "
                     "connected socket.");
        tst_s = rpc_accept(pco_tst, tst_s_listening, NULL, NULL);

        if (!nonblock)
        {
            TEST_SUBSTEP("If @p nonblock is @c TRUE call @b send() "
                         "on Tester socket to unblock hanging "
                         "@b recv() call. Check the data.");
            RPC_AWAIT_ERROR(pco_tst);
            RPC_SEND(rc, pco_tst, tst_s, send_data, PKT_LEN, 0);

            pco_iut->op = RCF_RPC_WAIT;
            first_rc = rpc_recv(pco_iut, iut_s, recv_data, PKT_LEN, 0);
            if (first_rc < 0)
            {
                TEST_VERDICT("recv() function unexpectedly failed after "
                             "receiving data from Tester");
            }
            else if (first_rc != rc)
            {
                ERROR("recv() gets %d bytes, but %d bytes was sent",
                      first_rc, rc);
                TEST_VERDICT("recv() gets only part of data");
            }
            else if (memcmp(send_data, recv_data, rc) != 0)
            {
                TEST_VERDICT("Incorrect data were received on IUT");
            }
        }

        TEST_SUBSTEP("Check data transmission in both directions over the "
                     "established connection and terminate the test.");
        sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
        TEST_SUCCESS;
    }

    if (!nonblock && is_send_func)
    {
        TEST_STEP("If @p nonblock is @c FALSE and sending function is "
                  "tested, check that its blocking call finally "
                  "succeeded.");
        RPC_AWAIT_ERROR(pco_iut);
        if (test_func == TEST_FUNC_SEND)
        {
            rc = rpc_send(pco_iut, iut_s, send_data, PKT_LEN, 0);
        }
        else
        {
            rc = rpc_sendfile(pco_iut, iut_s, sendfile_fd, NULL,
                              PKT_LEN, FALSE);
        }

        if (rc < 0)
        {
            TEST_VERDICT("Blocking tested function call failed "
                         "unexpectedly with errno %r",
                         RPC_ERRNO(pco_iut));
        }
        else if (rc != PKT_LEN)
        {
            TEST_VERDICT("Sending function returned unexpected "
                         "value");
        }
    }

    if (is_shutdown_close_func)
    {
        TEST_STEP("If @p test_func is @b shutdown() or @b close():");
        TEST_SUBSTEP("Check that Tester does not accept connection.");
        rpc_fcntl(pco_tst, tst_s_listening, RPC_F_SETFL, RPC_O_NONBLOCK);
        RPC_AWAIT_ERROR(pco_tst);
        tst_s = rpc_accept(pco_tst, tst_s_listening, NULL, NULL);
        if (tst_s != -1)
        {
            TEST_VERDICT("Tester unexpectedly accepted connection");
        }
        else if (RPC_ERRNO(pco_tst) != RPC_EAGAIN)
        {
            TEST_VERDICT("Tester accept() call failed with unexpected "
                         "errno %r", RPC_ERRNO(pco_tst));
        }
        rpc_fcntl(pco_tst, tst_s_listening, RPC_F_SETFL, 0);

        TEST_SUBSTEP("Close IUT socket if not already closed.");
        if (test_func == TEST_FUNC_SHUTDOWN)
            RPC_CLOSE(pco_iut, iut_s);

        TEST_SUBSTEP("Create new TCP socket on IUT and bind it to the same "
                     "address:port.");
        iut_s2 = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                            RPC_PROTO_DEF, FALSE, FALSE,
                                            iut_addr);

        TEST_SUBSTEP("Connect the second IUT socket and check that "
                     "connection was established.");
        rpc_connect(pco_iut, iut_s2, tst_addr);
    }
    else
    {
        TEST_STEP("If sending or getname @p test_func was "
                  "checked, call @b connect() the second time to check "
                  "that connection was established.");
        if (nonblock)
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, 0);
        rpc_connect(pco_iut, iut_s, tst_addr);
    }

    TEST_STEP("Call @b accept() on Tester to obtain connected socket.");
    tst_s = rpc_accept(pco_tst, tst_s_listening, NULL, NULL);

    TEST_STEP("Call @b recv() on Tester socket with @c MSG_DONTWAIT flag "
              "and check what it returns: "
              "- if @p test_func is @b shutdown(), @b close(), "
              "@b getsockname(), @b getpeername() or if "
              "@p test_func call failed, then @b recv() should fail; "
              "- if @p test_func is @b send() or @b sendfile() and its "
              "call was successful, @b recv() should return data sent "
              "previously.");

    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, recv_data, PKT_LEN, RPC_MSG_DONTWAIT);

    switch (test_func)
    {
        case TEST_FUNC_SEND:
        case TEST_FUNC_SENDFILE:
            if (rc < 0)
            {
                if (first_rc > 0)
                {
                    TEST_VERDICT("recv() unexpectedly failed with errno %r",
                                 RPC_ERRNO(pco_tst));
                }
            }
            else if (rc == 0)
            {
                TEST_VERDICT("recv() unexpectedly returned zero");
            }
            else
            {
                if (first_rc < 0)
                {
                    TEST_VERDICT("recv() unexpectedly returned some data "
                                 "after failed sending");
                }
                else if (rc != PKT_LEN ||
                         memcmp(send_data, recv_data, PKT_LEN) != 0)
                {
                    TEST_VERDICT("Received data does not match sent data");
                }
            }
            break;

        case TEST_FUNC_SHUTDOWN:
        case TEST_FUNC_CLOSE:
        case TEST_FUNC_GETSOCKNAME:
        case TEST_FUNC_GETPEERNAME:
            if (rc < 0)
            {
                if (RPC_ERRNO(pco_tst) != RPC_EAGAIN)
                {
                    TEST_VERDICT("recv() failed with unexpected errno %r",
                                 RPC_ERRNO(pco_tst));
                }
            }
            else if (rc == 0)
            {
                TEST_VERDICT("recv() unexpectedly returned zero");
            }
            else if (rc > 0)
            {
                TEST_VERDICT("recv() unexpectedly returned value greater "
                             "than zero");
            }
            break;

        default:
            TEST_FAIL("Unknown test_func");
    }
    TEST_STEP("If @p test_func is @b getsockname or @b getpeername call "
              "it once again and check that it secceeds and returns "
              "correct address.");
    if (test_func == TEST_FUNC_GETSOCKNAME)
    {
        rpc_getsockname(pco_iut, iut_s, SA(&addr),
                        &addr_len);
        if (te_sockaddrcmp(SA(&addr), addr_len, iut_addr,
                           te_sockaddr_get_size(iut_addr)) != 0)
        {
            TEST_VERDICT("Invalid address returned by the second call of "
                         "getsockname()");
        }

    }
    else if (test_func == TEST_FUNC_GETPEERNAME)
    {
        rpc_getpeername(pco_iut, iut_s, SA(&addr),
                        &addr_len);
        if (te_sockaddrcmp(SA(&addr), addr_len, tst_addr,
                           te_sockaddr_get_size(tst_addr)) != 0)
        {
            TEST_VERDICT("Invalid peer address returned by the second "
                         "call of getpeername()");
        }

    }

    TEST_STEP("Check data transmission in both directions over the "
              "established connection.");
    sockts_test_connection(pco_iut,
                           is_shutdown_close_func ? iut_s2 : iut_s,
                           pco_tst, tst_s);

    if (failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, sendfile_fd);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listening);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (file_created)
        REMOVE_REMOTE_FILE(pco_iut->ta, sendfile_fn.ptr);

    TEST_END;
}
