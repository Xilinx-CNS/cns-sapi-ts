/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-sock_shut_rdwr Socket was shut down for reading and writing
 *
 * @objective Check I/O multiplexing functions behaviour when socket
 *            was shut down for reading and writing.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @reference @ref STEVENS section 6.3, 6.6, 6.9, 6.10
 *
 * @param sock_type Type of the socket (@c SOCK_DGRAM, @c SOCK_STREAM, etc)
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll())
 *
 * @par Scenario:
 * -# Create connection between @p pco_iut and @p pco_tst using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a sock_type: @p sock_type;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a clnt_addr: @p tst_addr;
 *      - @a srvr_s: stored in @p iut_s;
 *      - @a clnt_s: stored in @p tst_s;
 * -# @b shutdown(@p iut_s, @c SHUT_RDWR) IUT socket for reading and writing;
 * -# Wait for @e read and @e write events on the socket using @b iomux
 *    function with zero timeout;
 * -# Check that @p iomux function return @c 2 for @b select() and
 *    @b pselect() calls or @c 1 for @b poll() call. @e read and @e write
 *    events must be returned;
 * -# If @e read event is returned, try to read using @b recv() function
 *    and check that attempt returns @c 0;
 * -# If @e write event is returned, try to write using @b send() function
 *    and check that attempt returns @c -1 with @c EPIPE @b errno;
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @sa Notes for @ref iomux-sock_shut_rdwr test.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/sock_shut_rdwr"
#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    unsigned int            step_fail = 0;

    rpc_socket_type         type;
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    iomux_evt               event;
    unsigned char           buffer[SOCKTS_BUF_SZ];
    int                     err = -1;

    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    te_bool                 restore_signal_handler = FALSE;
    rpc_sigset_p            received_set = RPC_NULL;

    int                     expected_rc;
    iomux_evt               expected_event;

    
    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(type);
    TEST_GET_IOMUX_FUNC(iomux);


    CHECK_RC(tapi_sigaction_simple(pco_iut, RPC_SIGPIPE,
                                   SIGNAL_REGISTRAR, &old_act));
    restore_signal_handler = TRUE;

    GEN_CONNECTION(pco_iut, pco_tst, type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);

    event = EVT_RDWR;
    err = iomux_common_steps(iomux, pco_iut, iut_s, &event, IOMUX_TIMEOUT_RAND, 
                             FALSE, pco_tst, tst_s, RPC_SHUT_NONE, &rc);
    if (err != 0)
    {
        TEST_FAIL("iomux_common_steps() function failed");
    }   

    if (IOMUX_IS_SELECT_LIKE(iomux))
    {
        expected_rc = 2;
        expected_event = EVT_RDWR;
    }
    else
    {
        expected_rc = 1;
        /* 
         * - SunOS returns EVT_RDWR
         * - Linux returns EVT_RDWR | EVT_EXC | EVT_HUP
         */
        expected_event = EVT_RDWR | EVT_EXC | EVT_HUP;
    }
    if ((rc != expected_rc) || (event != expected_event))
    {
        ERROR_VERDICT("Waiting for read and write event on shut down for "
                      "reading and writing socket using %s() returns %d(%s) "
                      "instead of %d(%s)", iomux_call_en2str(iomux),
                      rc, iomux_event_rpc2str(event),
                      expected_rc, iomux_event_rpc2str(expected_event));
        step_fail++;
    }

    rc = rpc_recv(pco_iut, iut_s, buffer, sizeof(buffer), 0);
    if (rc != 0)
    {
        TEST_FAIL("Not zero was returned on attempt to read from the "
                  "socket shut down for reading");
    }
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, buffer, sizeof(buffer), 0);
    if (rc != -1)
    {
        TEST_FAIL("Data has successfully been sent from the socket shut "
                  "down for reading and writing");
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EPIPE, "send() from the socket shut down "
                    "for reading and writing returns -1, but");

    /* Here we must handle SIGPIPE */
    received_set = rpc_sigreceived(pco_iut);
    rc = rpc_sigismember(pco_iut, received_set, RPC_SIGPIPE);
    if (rc == 0)
    {
        ERROR_VERDICT("No SIGPIPE signal has been recieved");
        step_fail++;
    }

    if (step_fail == 0)
        TEST_SUCCESS;
    else
        TEST_FAIL("%u test step(s) failed", step_fail);

cleanup:
    if (restore_signal_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, RPC_SIGPIPE, &old_act, 
                              SIGNAL_REGISTRAR);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

