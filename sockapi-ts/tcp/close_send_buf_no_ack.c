/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol, such as ICMP and routing table handling, small and zero window, fragmentation of TCP packets, etc.
 */

/**
 * @page tcp-close_send_buf_no_ack Close socket while there is unacked sent data.
 *
 * @objective Check that socket can be correctly closed despite there is sent
 *            data which is not ACKed.
 *
 * @param sock_type         Socket type:
 *                          - tcp active
 *                          - tcp passive
 * @param close             Close IUT socket or shutdown(wr).
 * @param shut_tst          Shutdown tester socket.
 * @param cache_socket      Create cached socket to be reused.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/close_send_buf_no_ack"

#include "sockapi-test.h"
#include "tapi_route_gw.h"
#include "tcp_test_macros.h"
#include "tapi_proc.h"

/** Maximum waiting time in seconds */
#define TIME_LIMIT 125

/** Minimum send packet data size. */
#define MIN_SEND_BUF 100

/** Maximum send packet data size. */
#define MAX_SEND_BUF 10000

/** MSL timeout, seconds. */
#define MSL_TIMEOUT 5

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gateway;
    sockts_socket_type sock_type;
    te_bool            close;
    te_bool            shut_tst;
    te_bool            cache_socket;

    te_dbuf sent = TE_DBUF_INIT(0);
    char  *sndbuf = NULL;
    char  *rcvbuf = NULL;
    size_t sndbuf_len;
    size_t offt = 0;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(close);
    TEST_GET_BOOL_PARAM(shut_tst);
    TEST_GET_BOOL_PARAM(cache_socket);

    sndbuf = te_make_buf(MIN_SEND_BUF, MAX_SEND_BUF, &sndbuf_len);
    rcvbuf = te_make_buf_by_len(MAX_SEND_BUF);

    TEST_STEP("Set MSL timeout to decrease waiting time in the TIME_WAIT state. "
              "This takes effect only for Onload, useless with reuse_stack.");
    if (!shut_tst && rpc_getenv(pco_iut, "EF_NAME") == NULL)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_TCONST_MSL",
                                     MSL_TIMEOUT, TRUE, TRUE));

    TAPI_INIT_ROUTE_GATEWAY(gateway);
    tapi_route_gateway_configure(&gateway);
    CFG_WAIT_CHANGES;

    TEST_STEP("If @p cache_socket is @c TRUE and  sock_type is "
              "@c SOCKTS_SOCK_TCP_ACTIVE create cached socket.");
    if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
    {
        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                    TRUE, cache_socket);
    }

    TEST_STEP("Establish TCP connection.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Break channel IUT->tester using gateway.");
    tapi_route_gateway_break_gw_tst(&gateway);

    TEST_STEP("Send data from IUT using non-blocking send until the call fails.");
    do {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_send(pco_iut, iut_s, sndbuf, sndbuf_len, RPC_MSG_DONTWAIT);
        if (rc > 0)
            te_dbuf_append(&sent, sndbuf, rc);
    } while (rc > 0);

    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        TEST_VERDICT("send() call had to fail with EAGAIN");

    TEST_STEP("If @p shut_tst is @c TRUE call shutdown(wr) on the tester socket.");
    if (shut_tst)
    {
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Close or shutdown(wr) IUT socket in dependence on @p close.");
    if (close)
        RPC_CLOSE(pco_iut, iut_s);
    else
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);

    TEST_STEP("Repair the channel IUT->tester.");
    tapi_route_gateway_repair_gw_tst(&gateway);

    TEST_STEP("Read data on tester, check the last read call returns zero.");
    TEST_STEP("Check the data for corruption.");
    do {
        rc = rpc_read(pco_tst, tst_s, rcvbuf, MAX_SEND_BUF);
        if (rc > 0)
        {
            if (sent.len < offt + rc)
                TEST_VERDICT("Extra data was received");

            if (memcmp(rcvbuf, sent.ptr + offt,  rc) != 0)
                TEST_VERDICT("Corrupted data was received");
            offt += rc;
        }
    } while (rc != 0);

    if (offt != sent.len)
    {
        RING("Received %"TE_PRINTF_SIZE_T"d, sent %"TE_PRINTF_SIZE_T"d",
             offt, sent.len);
        TEST_VERDICT("Not all data was received");
    }

    TEST_STEP("Close both sockets if they are not closed yet.");
    RPC_CLOSE(pco_tst, tst_s);
    if (iut_s >= 0)
        RPC_CLOSE(pco_iut, iut_s);
    /* Wait a little so all segments reach their destination. */
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create new socket on IUT and bind it to the same address:port");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_SUBSTEP("if @p shut_tst is @c FALSE the address is busy in TIME_WAIT - "
                 "wait and bind later.");
     if (!shut_tst)
        RPC_AWAIT_IUT_ERROR(pco_iut);
     rc = rpc_bind(pco_iut, iut_s, iut_addr);
    if (!shut_tst)
    {
        int i;

        if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
            TEST_VERDICT("IUT address is unexpectedly free");

        for (i = 0; i < TIME_LIMIT; i++)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_bind(pco_iut, iut_s, iut_addr);
            if (rc == 0)
                TEST_SUCCESS;

            if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                TEST_VERDICT("IUT bind had to fail with EADDRINUSE");
            SLEEP(1);
        }
        TEST_VERDICT("IUT address was not free after %d seconds",
                     TIME_LIMIT);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
