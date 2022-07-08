/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-peer_close Calling iomux function when peer close connection
 *
 * @objective Check that calling of iomux functions on connected TCP socket
 *            with closed peer socket doesn't lead to failures.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Auxiliary PCO
 * @param passive       Passive or active TCP connection
 * @param iomux         iomux function used in the test
 * @param timeout       Timeout for @p iomux function
 * @param call_shutdown Call or do not call @b shutdown() before @b close()
 *
 * @par Scenario:
 * -# Create TCP connection between @p pco_iut and @p pco_tst according to
 *    @p passive parameter. @p iut_s and @p tst_s sockets will be appeared.
 * -# If @p call_shutdown is @c TRUE call @b shutdown(@c SHUT_RDWR) with @p
 *    iut_s socket.
 * -# Call @b close() on @p tst_s socket.
 * -# Call @p iomux function with @p iut_s socket.
 * -# Check retruned events.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/peer_close"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    te_bool                 passive;
    tarpc_timeval           iomux_to = { 0, 0 };
    int                     timeout;

    iomux_evt_fd            sock_fd;

    te_bool                 call_shutdown;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(passive);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(call_shutdown);

    if (passive)
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s, &tst_s);
    else
        GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       tst_addr, iut_addr, &tst_s, &iut_s);

    iomux_to.tv_sec = timeout;
    sock_fd.fd = iut_s;
    sock_fd.events = EVT_RDWR;
    sock_fd.revents = 0;

    if (call_shutdown)
    {
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
        TAPI_WAIT_NETWORK;
    }
    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;

    rc = iomux_call(iomux, pco_iut, &sock_fd, 1, &iomux_to);

    if ((IOMUX_IS_POLL_LIKE(iomux) && rc != 1) ||
        (IOMUX_IS_SELECT_LIKE(iomux) && rc != 2))
        TEST_VERDICT("iomux() returns incorrect value");
    else
    {
        if (IOMUX_IS_POLL_LIKE(iomux))
        {
            if ((!call_shutdown && sock_fd.revents != EVT_RDWR) ||
                (call_shutdown &&
                 sock_fd.revents != (EVT_RDWR | EVT_HUP | EVT_EXC)))
                TEST_VERDICT("iomux() returns incorrect events");
        }
        else
        {
            if (sock_fd.revents != EVT_RDWR)
                TEST_VERDICT("iomux() returns incorrect events");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
