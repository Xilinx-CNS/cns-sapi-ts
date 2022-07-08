/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-threads_shutdown_listening Shutdown on listening socket shared by many threads
 *
 * @objective Check the behavior in the case if shutdown() or close()
 *            being called on the listening socket that is shared between
 *            several threads while blocking on this socket in another
 *            thread.
 *
 * @type Conformance, compatibility
 *
 * @param env   Private environment set but very similar to
 *              @ref arg_types_env_twothr2peer and
 *              @ref arg_types_env_twothr2peer_ipv6.
 * @param accept_before Do accept a connection before close/shutdown?
 * @param do_close      Call close() instead of shutdown() if @c TRUE.
 * @param func          Function to block (accept or io-multiplexer
 *                      such as poll).
 *
 * @par Scenario:
 *
 * -# Create a listening socket @p iut_s on @p pco_iut1.
 * -# If @p accept_before, connect to it from @p pco_tst and accept the
 *    connetion.
 * -# Block on @p func in @p pco_iut1.
 * -# In @p pco_iut2, close or shutdown @p iut_s depending on @p do_close.
 * -# Check that @p func unblocks and returns correct results.
 * -# Check that new connection from @p pco_tst fails.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/threads_shutdown_listening"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut1 = NULL;
    rcf_rpc_server  *pco_iut2 = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    rpc_socket_domain       domain;

    const char      *func;
    iomux_call_type iomux;
    iomux_evt_fd    event;

    te_bool     do_close;
    te_bool     accept_before;

    int iut_s = -1;
    int tst_s1 = -1;
    int tst_s2 = -1;
    int acc_s = -1;

    te_bool done;
    te_bool is_accept = FALSE;

    /* Test preambule */
    TEST_START;
    TEST_GET_STRING_PARAM(func);
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_BOOL_PARAM(do_close);
    TEST_GET_BOOL_PARAM(accept_before);

    /* Create listening socket */
    domain = rpc_socket_domain_by_addr(iut_addr);
    iut_s = rpc_socket(pco_iut1, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut1, iut_s, iut_addr);
    rpc_listen(pco_iut1, iut_s, SOCKTS_BACKLOG_DEF);

    /* If @p accept_before, accept one connection */
    if (accept_before)
    {
        tst_s1 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_connect(pco_tst, tst_s1, iut_addr);
        acc_s = rpc_accept(pco_iut1, iut_s, RPC_NULL, RPC_NULL);
    }

    /* Block in @p pco_iut1 */
    pco_iut1->op = RCF_RPC_CALL;
    if (strcmp(func, "accept") == 0)
    {
        rpc_accept(pco_iut1, iut_s, RPC_NULL, RPC_NULL);
        is_accept = TRUE;
    }
    else
    {
        iomux = iomux_call_str2en(func);
        event.fd = iut_s;
        event.events = EVT_RD;
        iomux_call(iomux, pco_iut1, &event, 1, RPC_NULL);
    }
    TAPI_WAIT_NETWORK;

    /* Close or shutdown */
    if (do_close)
        rpc_close(pco_iut2, iut_s);
    else
        rpc_shutdown(pco_iut2, iut_s, RPC_SHUT_RD);
    TAPI_WAIT_NETWORK;

    /* Check we've unblocked */
    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut1, &done));
    if (do_close == done)
      TEST_VERDICT("function is incorrectly unblocked");

    /* Check new connection fails */
    tst_s2 = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_connect(pco_tst, tst_s2, iut_addr);
    if (do_close)
    {
        if (rc != 0)
            TEST_VERDICT("Closed socket should accept connection");
    }
    else
    {
        if (rc == 0)
            TEST_VERDICT("Socket is listening after shutdown");
        CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED,
                        "listening socket is shut down, but");
    }

    /* Get the @p func result */
    RPC_AWAIT_IUT_ERROR(pco_iut1);
    pco_iut1->op = RCF_RPC_WAIT;
    if (is_accept)
      rc = rpc_accept(pco_iut1, iut_s, RPC_NULL, RPC_NULL);
    else
      rc = iomux_call(iomux, pco_iut1, &event, 1, RPC_NULL);

    /* Check the @p func result */
    /* XXX incorrect in case do_close=TRUE */
    if (is_accept)
    {
        if (rc != -1)
            TEST_VERDICT("Unexpected accept() result");
        CHECK_RPC_ERRNO(pco_iut1, RPC_EINVAL, "accept() returned -1, but");
    }
    else
    {
        if (rc != 1 ||
          (IOMUX_IS_SELECT_LIKE(iomux) && event.revents != EVT_RD) ||
          (IOMUX_IS_POLL_LIKE(iomux) && event.revents != (EVT_HUP | EVT_EXC)))
            TEST_VERDICT("Unexpected iomux result");
    }

    if (do_close)
        iut_s = -1;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut1, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    TEST_END;
}
    
