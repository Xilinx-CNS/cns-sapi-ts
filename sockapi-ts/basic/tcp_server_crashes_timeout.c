/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-tcp_server_crashes_timeout TCP client returns with timeout when TCP server crashes
 *
 * @objective Check that TCP client returns with timeout if TCP server crashes
 *            and there was not other notifaication about TCP server crash.
 *
 * @type conformance
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_gw
 *              - @ref arg_types_env_peer2peer_gw_ipv6
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# @b bind() both @p iut_s socket and @p tst_s socket to the appropriate
 *    local addresses.
 * -# Call @b listen() on @p tst_s socket.
 * -# Call @b connect() on @p iut_s socket.
 * -# Call @b accept() on @p tst_s to get @p accepted socket.
 * -# Imitate crashing of the server host.
 * -# @b send() some data through @p iut_s.
 * -# Call blocking @b recv() on @p iut_s.
 * -# Check that @b recv() on @p iut_s returns -1 and @b errno set
 *    to the @c ETIMEDOUT.
 * -# Close all involved sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/tcp_server_crashes_timeout"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

#define TST_BUF_LEN           4096

/* Timeout in milliseconds before to complete recv() by means of TE */
#define TST_RECV_TIMEOUT       60 * 60 * 1000


int
main(int argc, char *argv[])
{
    tapi_route_gateway     gw;
    int                    iut_s = -1;
    int                    tst_s = -1;
    unsigned char          tst_buf[TST_BUF_LEN];

    rpc_socket_domain domain;

    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TAPI_INIT_ROUTE_GATEWAY(gw);
    
    domain = rpc_socket_domain_by_addr(iut_addr);

    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_connect(pco_iut, iut_s, tst_addr);


    /*
     * Imitate crashing.
     */
    CHECK_RC(tapi_route_gateway_break_tst_gw(&gw));


    RPC_SEND(rc, pco_iut, iut_s, tst_buf, 1, 0);

    /*
     * Check that after retransmissions caused by previous send()
     * blocking recv returns -1 and errno set to ETIMEDOUT.
     */
    pco_iut->timeout = TST_RECV_TIMEOUT;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, tst_buf, TST_BUF_LEN, 0);
    if (rc != -1)
    {
        TEST_FAIL("Unexpected behavior, recv() should return -1 instead of %d",
                  rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT, "recv() socket returns -1, but");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
