/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-stream_iov I/O vector transmit operations with stream sockets
 *
 * @objective Check support of I/O vector transmit operations with @c SOCK_STREAM
 *            sockets.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 13.4
 *
 * @param pco_tx    PCO to be used as transmitter (IUT)
 * @param tx_s      Stream socket on @p pco_tx
 * @param pco_rx    PCO to be used as receiver
 * @param rx_s      Stream socket on @p pco_rx
 * @param func      @b writev(), libc @b writev(), @b sendmsg(),
 *                  @b sendmmsg()
 *
 * @pre Sockets @p tx_s and @p rx_s are connected.
 *
 * -# Send data divided into several I/O vector elements (0, 1, 2, 4) to 
 *    @p tx_s using @p func. 
 * -# Send another data divided into several I/O vector elements (0, 1, 2, 4)
 *    to @p tx_s using @p func.
 * -# Receive the first portion of data from @p rx_s socket using 
 *    @b read() function with the buffer sufficient to get 
 *    both sent portions.  It's expected that all sent data are 
 *    received, however it's not guaranteed.  Warning should be 
 *    generated, if not all data are received from the first attempt.
 *
 * @post Sockets @p tx_s and @p rx_s are kept connected.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/stream_iov_send"

#include "sockapi-test.h"
#include "rpc_iovec.h"

/*
 * Number of patterns to be used with onload_zc_send() or od_send_iov_raw().
 * These functions performs only limited checks on arguments
 * validity, iov_base = NULL / iov_len = 0 should not be passed
 * to it.
 */
#define ZC_ITER_NUM 5

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
        if (size < 0)
        {
            TEST_VERDICT("Function unexpectedly failed with errno "
                         RPC_ERROR_FMT
                         " trying to send the first part of %d pattern",
                         RPC_ERROR_ARGS(pco_iut), n);
        }
        else if (strcmp(rpc_gather_write_func_name(func),
                       "template_send") != 0)
        {
            ERROR("Value returned by writev() on IUT does not "
                  "match to expected");
            INFO("%d instead %d", size, size1);
            TEST_STOP;
        }
    }

    RPC_AWAIT_ERROR(pco_iut);
    if ((size = func(pco_iut, iut_s, tx2, patterns[n].len2)) != size2)
    {
        if (size < 0)
        {
            TEST_VERDICT("Function unexpectedly failed with errno "
                         RPC_ERROR_FMT
                         " trying to send the second part of %d pattern",
                         RPC_ERROR_ARGS(pco_iut), n);
        }
        else if (strcmp(rpc_gather_write_func_name(func),
                       "template_send") != 0)
        {
            ERROR("Value returned by writev() on IUT does not "
                  "match to expected");
            INFO("%d instead %d", size, size2);
            TEST_STOP;
        }
    }

    size = rpc_read(pco_tst, tst_s, rx_buf, sizeof(rx_buf));
    
    if (size < size1 + size2)
    {
        int len;

        WARN("Not all data are received");
        TAPI_WAIT_NETWORK;
        len = rpc_read(pco_tst, tst_s, rx_buf + size, sizeof(rx_buf) - size);
        if (len < 0)
        {
            ERROR("Failed to receive rest of data sent from IUT");
            TEST_STOP;
        }
        size += len;
        if (size != size1 + size2)
        {
            RING("%d bytes received instead of %d", size, size1 + size2);
            TEST_VERDICT("Length of data received on the TST does not match to"
                         " length of data sent from IUT");
        }
    }
    if (iovec_check(tx1, patterns[n].len1, rx_buf, size) < 0)
    {
        ERROR("Data received on the TST do not match to data "
              "send from the IUT"); 
        TEST_STOP;
    }
    if (iovec_check(tx2, patterns[n].len2, rx_buf + size1, size2) < 0)
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
    int                     iter_num;
    
    TEST_START;
    
    /* Prepare sockets */
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_GATHER_WRITE_FUNC(func);

    if (strcmp(rpc_gather_write_func_name(func), "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    if (func == rpc_gather_write_func_onload_zc_send ||
        func == rpc_gather_write_func_onload_zc_send_user_buf ||
        func == rpc_gather_write_func_od_send_iov ||
        func == rpc_gather_write_func_od_send_iov_raw)
    {
        iter_num = ZC_ITER_NUM;
    }
    else
    {
        iter_num = TE_ARRAY_LEN(patterns);
    }

    if (strcmp(rpc_gather_write_func_name(func), "template_send") != 0)
        for (i = 0; i < iter_num; i++)
             execute_pattern(i, func);
    else
    /* The array should be without zeroes. */
        for (i = 0; i < iter_num - 2; i++)
             execute_pattern(i, func);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}

