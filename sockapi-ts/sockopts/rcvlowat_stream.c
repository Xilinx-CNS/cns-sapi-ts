/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-rcvlowat_stream Usage of SO_RCVLOWAT socket option with stream sockets
 *
 * @objective Check that @c SO_RCVLOWAT option sets the amount of data that 
 *            must be in the socket receive buffer for @b select() to 
 *            return "readable".
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param rcvlowat      The value of @c SO_RCVLOWAT socket option used 
 *                      in the test
 * @param n1            Number of bytes sent first time
 * @param n2            Number of bytes sent second time
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @note @p n1 + @p n2 should be equal to @p rcvlowat
 *
 * @par Test sequence:
 *
 * -# Create a connection of type @c SOCK_STREAM between @p pco_iut and 
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
 * -# @b send() first @p n1 bytes of @p tx_buf buffer from @p tst_s socket;
 * -# If @p n1 is less than @p rcvlowat, check that @p iut_s socket is
 *    readable.  Otherwise (@p n1 equals to @p rcvlowat), check that
 *    socket is not readable;
 * -# @b send() the rest @p n2 bytes of @p tx_buf buffer from @p tst_s socket;
 * -# Check tha @p iut_s socket is readable.
 * -# Call @b recv(@p iut_s, @p rx_buf, @p rcvlowat, 0);
 * -# Check that the content of @p rx_buf is the same as @p tx_buf;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers;
 * -# Close @p tst_s and @p iut_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/rcvlowat_stream"

#include "sockapi-test.h"
#include "iomux.h"


int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    iomux_evt_fd            event;
    tarpc_timeval           timeout = {0, 0};

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    int                    rcvlowat;
    int                    n1;
    int                    n2;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    int                    opt_val;
    void                  *tx_buf = NULL;
    void                  *rx_buf = NULL;
    size_t                 buf_len;
    int                    ret;


    /* Preambule */
    TEST_START;
    TEST_GET_INT_PARAM(rcvlowat);
    TEST_GET_INT_PARAM(n1);
    TEST_GET_INT_PARAM(n2);
    TEST_GET_IOMUX_FUNC(iomux);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (rcvlowat < 1)
    {
        TEST_FAIL("'rcvlowat' parameter should be at least 1");
    }
    if (n1 < 0 || n2 < 0 || (n1 + n2) != rcvlowat)
    {
        TEST_FAIL("'n1', 'n2' should be more than zero, "
                  "and 'n1' + 'n2' should be equal to 'rcvlowat'");
    }

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);
    
    CHECK_NOT_NULL(tx_buf = malloc(rcvlowat));
    CHECK_NOT_NULL(rx_buf = malloc(rcvlowat));
    buf_len = rcvlowat;
    memset(tx_buf, rand_range(0, 128), buf_len);
    memset(rx_buf, rand_range(0, 128), buf_len);


    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_SOCKET, SO_RCVLOWAT) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    RING("SO_RCVLOWAT socket option is set to %d by default on SOCK_STREAM "
         "type of socket", opt_val);

    /* Try to update the value of the option */
    opt_val = rcvlowat;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVLOWAT, &opt_val);
    if (rc != 0)
    {
        int err = RPC_ERRNO(pco_iut);

        if (rc != -1)
        {
            TEST_FAIL("setsockopt(SO_RCVLOWAT) returns %d "
                      "instead of -1 or 0", rc);
        }

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

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, n1, 0);
    TAPI_WAIT_NETWORK;
   
    event.fd = iut_s;
    event.events = EVT_RD;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (n1 >= rcvlowat)
    {
        if (rc == 0)
            TEST_FAIL("Socket is not readable when a lot of data is sent");
    }
    else
    {
        if (rc > 0)
            TEST_VERDICT("Socket is readable when too few data is sent");
    }

    /* Send the rest of the data from 'tst_s' socket */
    RPC_SEND(rc, pco_tst, tst_s, tx_buf + n1, n2, 0);
    TAPI_WAIT_NETWORK;

    /* Check that the socket is readable now */
    event.fd = iut_s;
    event.events = EVT_RD;
    rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
    if (rc == 0)
        TEST_FAIL("Socket is not readable when a lot of data is sent");

    rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0);
    if (rc != (int)buf_len)
    {
        TEST_FAIL("Not all the data received on SOCK_STREAM socket");
    }
    if (memcmp(tx_buf, rx_buf, buf_len) != 0)
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

