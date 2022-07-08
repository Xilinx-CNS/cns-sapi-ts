/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-error_rst Function getsockopt(SO_ERROR) after RST received
 * 
 * @objective Check behaviour of @b getsockopt(@c SO_ERROR) function on
 *            socket after RST was received on it.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 *
 * @par Test sequence:
 * -# Create @p iut_s socket and @p tst_s socket on @p pco_iut and @p
 *    pco_tst respectivly;
 * -# Establish connetion between @p iut_s socket and @p tst_s socket of @c
 *    SOCK_STREAM type;
 * -# Send some data from @p iut_s socket to @p tst_s socket;
 * -# Close @p tst_s socket;
 * -# Sleep for @c 10ms to delivery RST;
 * -# Call @b getsockopt(@c SO_ERROR) and check that it sets @p opt_val to
 *    @c ECONNRESET;
 * -# Call @b getsockopt(@c SO_ERROR) once again and check that it sets @p
 *    opt_val to @c 0;
 * -# Close @p iut_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_rst"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                    opt_val;

    void                  *buf = NULL;
    size_t                 buf_len;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    CHECK_NOT_NULL(buf = sockts_make_buf_dgram(&buf_len));
    RPC_SEND(rc, pco_iut, iut_s, buf, buf_len, 0);
    if (rc != (int)buf_len)
        TEST_FAIL("send() returned %d instead %d", rc, buf_len);

    TAPI_WAIT_NETWORK;
    RPC_CLOSE(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != RPC_ECONNRESET)
    {
        TEST_VERDICT("Unexpected error %s occured on 'iut_s' socket, "
                     "but expected ECONNRESET",
                     errno_rpc2str(opt_val));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
    {
        TEST_FAIL("Unexpected error %s occured on 'iut_s' socket, "
                  "but expected 0",
                  errno_rpc2str(opt_val));
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(buf);

    TEST_END;
}
