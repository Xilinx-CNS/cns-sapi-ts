/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-rcvlowat_recv The behaviour of receive functions on stream sockets with SO_RCVLOWAT option
 *
 * @objective Check that @c SO_RCVLOWAT option sets the amount of data that 
 *            must be in the socket receive buffer for @b recv() to 
 *            return data.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param sock_type     Socket type used in the test
 * @param rcvlowat      The value of @c SO_RCVLOWAT socket option used 
 *                      in the test
 *
 * @par Test sequence:
 * @todo Test sequence (almost the same as sockopts/rcvlowat)
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvlowat_recv"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    rpc_socket_type        sock_type;
    int                    rcvlowat;
    int                    n1;
    int                    more_data_tx;
    int                    more_data_rx;
    int                    rx_bytes_req;
    int                    rx_bytes_ret;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    opt_val;
    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    size_t                 buf_len;
    int                    ret;

    struct timeval         tv1_1;
    struct timeval         tv1_2;
    struct timeval         tv2_1;
    struct timeval         tv2_2;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(rcvlowat);
    TEST_GET_INT_PARAM(n1);
    TEST_GET_INT_PARAM(more_data_tx);
    TEST_GET_INT_PARAM(more_data_rx);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (rcvlowat < 1)
    {
        TEST_FAIL("'rcvlowat' parameter should be at least 1");
    }
    if (n1 < 0 || n1 >= rcvlowat)
    {
        TEST_FAIL("'n1' should be in (0, rcvlowat) interval");
    }

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    buf_len = rcvlowat + 
              ((more_data_rx > more_data_tx) ? more_data_rx : more_data_tx);
    rx_bytes_req = rcvlowat + more_data_rx;
    rx_bytes_ret = rcvlowat + 
                   ((more_data_rx > more_data_tx) ? 
                        more_data_tx : more_data_rx);
    
    CHECK_NOT_NULL(tx_buf = malloc(buf_len));
    CHECK_NOT_NULL(rx_buf = malloc(buf_len));
    memset(tx_buf, rand_range(0, 128), buf_len);
    memset(rx_buf, rand_range(0, 128), buf_len);


    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_SOCKET, SO_RCVLOWAT) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    RING("SO_RCVLOWAT socket option is set to %d by default on %s "
         "type of socket", opt_val, socktype_rpc2str(sock_type));

    /* Try to update the value of the option */
    opt_val = rcvlowat;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (opt_val != rcvlowat)
    {
        TEST_FAIL("The value of SO_RCVLOWAT socket option is not updated "
                  "by setsockopt() function");
    }

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, n1, 0);
   
    gettimeofday(&tv1_1, NULL);
    pco_iut->op = RCF_RPC_CALL;
    rpc_recv(pco_iut, iut_s, rx_buf, rx_bytes_req, 0);
    gettimeofday(&tv1_2, NULL);
    
    SLEEP(rand_range(5, 10));
    
    gettimeofday(&tv2_1, NULL);
    /* Send the rest of the data from 'tst_s' socket */
    RPC_SEND(rc, pco_tst, tst_s,
             tx_buf + n1, (rcvlowat - n1) + more_data_tx, 0);
    gettimeofday(&tv2_2, NULL);

    /* Check that the socket is readable now */
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recv(pco_iut, iut_s, rx_buf, rx_bytes_req, 0);

    /* Check that we realy blocked on receing */
    CHECK_CALL_DURATION_INT(pco_iut->duration, TST_TIME_INACCURACY,
                            TST_TIME_INACCURACY_MULTIPLIER,
                            TIMEVAL_SUB(tv2_1, tv1_2),
                            TIMEVAL_SUB(tv2_2, tv1_1));

    if (rc != rx_bytes_ret) 
    {
        TEST_FAIL("Unexpected number of bytes received. "
                  "Expected %d, received %d", rx_bytes_ret, rc);
    }
    
    if (memcmp(tx_buf, rx_buf, rx_bytes_ret) != 0)
    {
        TEST_FAIL("The content of 'tx_buf' and 'rx_buf' buffers "
                  "are different");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}

