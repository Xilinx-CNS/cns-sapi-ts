/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-dgram_iov_send I/O vector send operations with datagram sockets
 *
 * @objective Check support of I/O operations with DGRAM sockets.
 *            One call to I/O vector transmit operation 
 *            must send one datagram.
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
 * @param func      @b writev(), libc @b writev(), @b sendmsg(),
 *                  @b sendmmsg()
 *
 * @pre Sockets @p tst_s and @p iut_s are connected.
 *
 * -# Send data divided into several I/O vector elements
 *    from @p tst_s using @p func.
 * -# Send additional data with non-zero length in the same way.
 * -# Receive data via @p iut_s socket using read(), check that
 *    received data are the same as sent ones (if first vector contained
 *    zero-length data only one datagram should be received).
 * -# The test should be repeated for different number of vectors
 *    (0, 1, 2, 4) and different elements lengths (0, 1, 100).
 *
 * @post Sockets @p iut_s and @p tst_s are kept connected.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/dgram_iov_send"

#include "sockapi-test.h"
#include "rpc_iovec.h"

/* Patterns for vectors to send during tests (both first and second send) */
struct pattern {
    int len1;    /**< Length of the first piece of data to be sent */
    int pattern1[8]; 
                 /**< Vector pattern for the first piece of data to be sent */
    int len2;    /**< Length of the second piece of data to be sent */
    int pattern2[8]; 
                 /**< Vector pattern for the second piece of data to be sent */
} patterns[] = {
    { 1, { 1 }, 1, { 2 } },
    { 2, { 1, 0 }, 3, { 1, 0, 0 } },
    { 2, { 0, 1 }, 3, { 1, 0, 1 } },
    { 1, { 100 }, 3, { 10, 20, 30 } },
    { 2, { 50, 60 }, 1, { 1 } },
    { 4, { 10, 20, 30, 40 }, 1, { 30 } },
    { 5, { 1, 1, 1, 1, 1 }, 1, { 1 } }, 
    { 5, { 0, 0, 0, 13, 5 }, 6, { 11, 3, 0, 3, 0, 0 } },
    { 6, { 2, 27, 0, 0, 0, 9 }, 6, { 0, 3, 0, 3, 0, 21 } },
};

static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_tst = NULL;

static char rx_buf[1024];

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
execute_pattern(int n, rpc_gather_write_f func)
{
    rpc_iovec *tx1 = NULL;
    rpc_iovec *tx2 = NULL;
    
    int size1;
    int size2;
    int size;
    
    VERB("Exetute pattern %d", n);
    
    if ((size1 = iovec_create(patterns[n].pattern1, 
                              patterns[n].len1, &tx1)) < 0)
        TEST_STOP;

    if ((size2 = iovec_create(patterns[n].pattern2, 
                              patterns[n].len2, &tx2)) < 0)
    {
        TEST_STOP;
    }

    RPC_AWAIT_ERROR(pco_iut);
    if ((size = func(pco_iut, iut_s, tx1, patterns[n].len1)) != size1)
    {
        ERROR("Tested function on IUT returned incorrect value");
        INFO("%d instead of %d", size, size1);
        if (size < 0)
        {
            TEST_VERDICT("The first call of the tested function failed "
                         "with errno " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut));
        }
        TEST_STOP;
    }

    RPC_AWAIT_ERROR(pco_iut);
    if ((size = func(pco_iut, iut_s, tx2, patterns[n].len2)) != size2)
    {
        ERROR("Tested function on IUT returned incorrect value");
        INFO("%d instead of %d", size, size2);
        if (size < 0)
        {
            TEST_VERDICT("The second call of the tested function failed "
                         "with errno " RPC_ERROR_FMT,
                         RPC_ERROR_ARGS(pco_iut));
        }
        TEST_STOP;
    }

    size = rpc_read(pco_tst, tst_s, rx_buf, sizeof(rx_buf));
    
    if (size != size1)
    {
        ERROR("Value returned by read() on TST does not match to expected");
        INFO("%d instead %d", size, size1);
        TEST_STOP;
    }
    if (iovec_check(tx1, patterns[n].len1, rx_buf, size1) < 0)
    {
        ERROR("Data received on the TST do not match to data "
              "send from the IUT"); 
        TEST_STOP;
    }

    size = rpc_read(pco_tst, tst_s, rx_buf, sizeof(rx_buf));
    
    if (size != size2)
    {
        ERROR("Value returned by read() on TST does not match to expected");
        INFO("%d instead %d", size, size2);
        TEST_STOP;
    }
    if (iovec_check(tx2, patterns[n].len2, rx_buf, size2) < 0)
    {
        ERROR("Data received on the TST do not match to data "
              "send from the IUT"); 
        TEST_STOP;
    }
}

int
main(int argc, char *argv[])
{
    int             i;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    rpc_gather_write_f      func;

    TEST_START;
    
    /* Prepare sockets */
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_GATHER_WRITE_FUNC(func);

    if (strcmp(rpc_gather_write_func_name(func), "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    for (i = 0; i < (int)(sizeof(patterns)/sizeof(struct pattern)); i++)
        execute_pattern(i, func);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
