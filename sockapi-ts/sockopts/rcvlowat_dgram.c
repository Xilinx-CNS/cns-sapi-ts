/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-rcvlowat_dgram Usage of SO_RCVLOWAT socket option with datagram sockets
 *
 * @objective Check that @c SO_RCVLOWAT option is ignored on datagram
 *            sockets.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param rcvlowat      The value of @c SO_RCVLOWAT socket option used 
 *                      in the test
 * @param send          Number of bytes to send
 *
 * @par Test sequence:
 *
 * -# Create a connection of type @c SOCK_DGRAM between @p pco_iut and 
 *    @p pco_tst. As a result two sockets appear @p iut_s and @p tst_s;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create a buffer @p tx_buf of @p rcvlowat bytes;
 * -# Create a buffer @p rx_buf of @p rcvlowat bytes;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_RCVLOWAT socket
 *    option to get its initial value;
 * -# Call @b setsockopt() on @p iut_s socket with @c SO_RCVLOWAT option 
 *    specifying @p rcvlowat as its value;
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_RCVLOWAT socket;
 * -# Check that the option value is @p rcvlowat;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() first @p send bytes of @p tx_buf buffer from @p tst_s socket;
 * -# Call @b select() waiting for @p iut_s socket becomes readable 
 *    specifying some @p timeout;
 * -# Check that @b select() immediately returns @c 1 and
 *    @b FD_ISSET(@p iut_s, @a readset) is true;
 * -# Check that the content of @p rx_buf is the same as @p tx_buf;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers;
 * -# Close @p tst_s and @p iut_s sockets.
 * 
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvlowat_dgram"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    int                    rcvlowat;
    int                    send;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    opt_val;
    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    size_t                 buf_len;
    int                     ret;


    /* Preambule */
    TEST_START;
    TEST_GET_INT_PARAM(rcvlowat);
    TEST_GET_INT_PARAM(send);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (rcvlowat < 1)
    {
        TEST_FAIL("'rcvlowat' parameter should be at least 1");
    }

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    tx_buf = te_make_buf_by_len(send + 1);
    rx_buf = te_make_buf_by_len(send + 1);
    
    buf_len = send;


    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_SOCKET, SO_RCVLOWAT) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    RING("SO_RCVLOWAT socket option is set to %d by default on SOCK_DGRAM "
         "type of socket", opt_val);

    /* Try to update the value of the option */
    opt_val = rcvlowat;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (rc != 0)
    {
        te_errno err = RPC_ERRNO(pco_iut);

        /*
         * Check if 'SET' operation is not supported for SO_RCVLOWAT
         * socket option.
         */
        if (err == RPC_ENOPROTOOPT)
        {
            WARN("setsockopt(SO_RCVLOWAT) is not supported");
            TEST_SUCCESS;
        }
        TEST_FAIL("setsockopt(SO_RCVLOWAT) returns -1, but sets errno to "
                  "%s not to ENOPROTOOPT", errno_rpc2str(err));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (opt_val != rcvlowat)
    {
        TEST_FAIL("The value of SO_RCVLOWAT socket option is not updated "
                  "by setsockopt() function");
    }

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, send, 0);

    TAPI_WAIT_NETWORK;

    rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);
    if (rc != send)
    {
        TEST_FAIL("Incorrect length of the received datagram: "
                  "expected %d, received %d", send, rc);
    }
    if (memcmp(tx_buf, rx_buf, send) != 0)
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

