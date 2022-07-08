/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-sndlowat Usage of SO_SNDLOWAT socket option with connection-oriented sockets
 *
 * @objective Check that the value of @c SO_SNDLOWAT option is interpreted as
 *            the amount of available space that must exist in the socket
 *            send buffer for @b iomux_call() to return "writable".
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 7.5
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 *
 * @par Test sequence:
 *
 * -# Create @p pco_iut socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p pco_tst socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Call @b getsockopt() on @p pco_iut socket with @c SO_SNDLOWAT option
 *    and log the initial value of this option @p sndlowat_init.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p pco_tst with @c SO_RCVBUF option to set
 *    a new value of socket receive buffer - @p M.
 *    See @ref sockopts_sndlowat_1 "note 1".
 * -# Call @b setsockopt() on @p pco_iut with @c SO_SNDBUF option to set
 *    a new value of socket send buffer - @p N.
 *    See @ref sockopts_sndlowat_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p pco_iut socket with @c SO_SNDLOWAT option
 *    to set a new value of low-water mark - @p K (@p K should be less
 *    than @p N).
 * -# Call @b getsockopt() on @p pco_iut socket with @c SO_SNDLOWAT option
 *    and check that it is updated to @p K.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b bind() @p pco_tst socket to a local address.
 * -# Call @b listen() on @p pco_tst socket.
 * -# @b connect() @p pco_iut socket to @p pco_tst socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create a buffer @p tx_buf of size 1 byte.
 * -# Call @b iomux_call() with @p timeout waiting for @p pco_iut socket
 *    becomes "writable".
 * -# If @b iomux_call() returns @c -1, stop the test and report an error. \n
 *    If @b iomux_call() returns @c 1, send @p tx_buf from @p pco_iut socket
 *    and repeat the previous step, otherwise go to the next step (it
 *    returns @c 0, which means @b iomux_call() completes by timeout).
 * -# Check that the total number of bytes sent is
 *    (@p M @c + @p N @c - @p K @c + @c 1), otherwise report an error.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete @p tx_buf buffer.
 * -# Close @p pco_iut and @p pco_tst sockets.
 *
 * @note
 * -# @anchor sockopts_sndlowat_1
 *    Some implementations do not allow this option to have an arbitrary
 *    value, as a result some implementations may round the value up.
 *    So that it is better to get a new value just after @b setsockopt()
 *    and use actually assigned value in the test.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/sndlowat"

#include "sockapi-test.h"
#include "iomux.h"


#define TST_OPT_M     1000
#define TST_OPT_N     500
#define TST_OPT_K     250
#define TST_EXPECTED  (TST_OPT_M + TST_OPT_N - TST_OPT_K + 1)

    
int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr  *tst_addr;
    char                    tx_buf[1] = { 0, };
    int                     sndlowat_init;
    int                     sent_bytes = 0;
    int                     optval;
    int                     sent;
    int                     ret;
    iomux_evt               revt = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDLOWAT, &sndlowat_init);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SO_SNDLOWAT) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    optval = TST_OPT_M;
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &optval);

    optval = TST_OPT_K;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDLOWAT, &optval);
    if (rc == -1)
    {
        TEST_VERDICT("Failed to set SNDLOWAT option for 'iut_s' socket, "
                     "errno is set to %s", 
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    optval = TST_OPT_N;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &optval);

    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDLOWAT, &optval);
    if (optval != TST_OPT_K)
    {
        TEST_FAIL("getsockopt() called on a socket retrievs unexpected "
                  "value %d instead of %d", optval, TST_OPT_K);
    }

    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, 1);

    rpc_connect(pco_iut, iut_s, tst_addr);

    do {
        rc = iomux_call_default_simple(pco_iut, iut_s, EVT_WR, &revt,
                                       1000);
        if (rc == 1)
        {
            if (revt != EVT_WR)
            {
                TEST_FAIL("iomux_call() on iut_s doesn't mark the socket "
                          "as writable");
            }
            RPC_SEND(sent, pco_iut, iut_s, tx_buf, sizeof(tx_buf), 0);
            sent_bytes++;
        }
    } while (rc != 0);


    if (sent_bytes != TST_EXPECTED)
    {
         TEST_FAIL("Unexpected total number of bytes sent by iut_s: "
                   "retrieved %d, expected %d", sent_bytes, TST_EXPECTED);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
