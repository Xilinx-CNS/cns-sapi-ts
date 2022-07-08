/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-dgram_iov_recv I/O vector receive operations with stream sockets
 *
 * @objective Check support of I/O vector receive operations with STREAM sockets.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 13.4
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Datagram socket on @p tx
 * @param pco_tst   Tester PCO
 * @param tst_s     Datagram socket on @p rx
 * @param func      Receiving function to check:
 *                  - @ref arg_types_recv_func_with_iov_sys
 *
 * @pre Sockets @p tst_s and @p iut_s are connected.
 *
 * -# Send a datagram from @p tst_s.
 * -# Receive data via @p func on iut_s. Check that received part of data
 *    match to sent data.
 * -# The test should be repeated for different number of vectors
 *    (1, 2, 4) and different elements lengths (1, 100).
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "sendrecv/stream_iov_recv"

#include "sockapi-test.h"
#include "rpc_iovec.h"

/** Patterns for vectors to send during tests (both first and second send) */
struct pattern {
    int  len;           /**< Vector length */
    int  pattern[10];   /**< Vector */
    int  cnt;           /**< Vector length to be passed to the readv() */
    int  snd_len;       /**< Length of data to be sent */
} patterns[] = {
    { 2, { 100, 50 }, 2, 50 },
    { 2, { 100, 50 }, 2, 100 },
    { 2, { 100, 50 }, 2, 150 },
    { 4, { 10, 20, 30, 50 }, 4, 5 },
    { 4, { 10, 20, 30, 50 }, 4, 10 },
    { 4, { 10, 20, 30, 50 }, 4, 15 },
    { 4, { 10, 20, 30, 50 }, 4, 30 },
    { 4, { 10, 20, 30, 50 }, 4, 31 },
    { 4, { 10, 20, 30, 50 }, 4, 60 },
    { 4, { 10, 20, 30, 50 }, 4, 61 },
    { 9, { 0, 0, 0, 30, 0, 20, 50, 10, 30 }, 9, 111 },
    { 9, { 70, 10, 30, 0, 0, 0, 50, 0, 30 }, 9, 175 },
    { 9, { 70, 10, 30, 10, 0, 0, 50, 0, 0 }, 9, 160 },
};

static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_tst = NULL;

static char tx_buf[1024];

static int iut_s = -1;
static int tst_s = -1;

/**
 * Perform the test procedure for the pattern and specified
 * traffic direction.
 *
 * @param n         Pattern number
 * @param func      @p func, parameter passed to the test
 *                  (see test description)
 */
static void
execute_pattern(int n, rpc_scatter_read_f func)
{
    rpc_iovec *rx = NULL;
    int        size;
    int        len4zc = 1500;
    int        cnt;

    VERB("Exetute pattern %d", n);
    if (strcmp(rpc_scatter_read_func_name(func), "onload_zc_recv") == 0)
    {
        if (iovec_create(&len4zc, 1, &rx) < 0)
            TEST_STOP;
        cnt = 1;
    }
    else
    {
        if (iovec_create(patterns[n].pattern, patterns[n].len, &rx) < 0)
            TEST_STOP;
        cnt = patterns[n].cnt;
    }

    te_fill_buf(tx_buf, patterns[n].snd_len);
    if (rpc_write(pco_tst, tst_s, tx_buf, patterns[n].snd_len) !=
        patterns[n].snd_len)
    {
        TEST_FAIL("Cannot send a datagram from TST");
    }

    RPC_AWAIT_ERROR(pco_iut);
    size = func(pco_iut, iut_s, rx, cnt);
    if (size < 0)
    {
        TEST_VERDICT("Receiving function failed with errno %r",
                     RPC_ERRNO(pco_iut));
    }

    if (size != patterns[n].snd_len)
    {
        ERROR("Value returned by readv() on IUT does not match to expected");
        ERROR("%d instead %d", size, patterns[n].snd_len);
        TEST_STOP;
    }

    if (iovec_check(rx, cnt, tx_buf, patterns[n].snd_len) < 0)
    {
        TEST_FAIL("Data sent from the TST do not match to data "
                  "received on the IUT");
    }
}

int
main(int argc, char *argv[])
{
    int             i;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_scatter_read_f      func = NULL;

    TEST_START;
    
    /* Prepare sockets */
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SCATTER_READ_FUNC(func);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    for (i = 0; i < (int)(sizeof(patterns)/sizeof(struct pattern)); i++)
        execute_pattern(i, func);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
