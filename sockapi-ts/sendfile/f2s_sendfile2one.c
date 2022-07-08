/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-f2s_sendfile2one Performing 'file to socket' sendfile() operation together with backward TCP traffic to the common socket
 *
 * @objective Check a possibility of copying of the file to the socket
 *            by means of @b sendfile() system call together with backward TCP
 *            traffic returned to the same socket.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param iut_aux       Auxiliary PCO on IUT
 * @param use_fork      Create forked process in test or
 *                      use configuration parameters
 * @param iut_addr      Address/port to be used to connect @p pco_iut
 *                      to the @p pco_tst
 * @param pco_tst       Auxiliary PCO
 * @param tst_addr      Address/port to be used to connect to @p pco_tst1
 * @param time2run      How long run the flooder
 * @param file_length   Length used for file processing
 *
 * @par Scenario:
 *
 * -# Create @p sendfile.pco_iut of @p file_length length on @p pco_iut
 *    side.
 * -# Open @p sendfile.pco_iut on @p pco_iut side and retrieve @p src
 *    file descriptor.
 * -# Create connection between @p pco_iut and @p pco_tst using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a sock_type: @c SOCK_STREAM;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut_addr;
 *      - @a clnt_addr: @p tst_addr;
 *      - @a srvr_s: stored in @p iut_s;
 *      - @a clnt_s: stored in @p tst_s;
 * -# Process @p use_fork and create forked process with handle returned
 *    to the @p iut_aux if @p TRUE or use preconfigured iut_aux handle
 *    if @p FALSE.
 * -# Run @ref lib-simple_receiver on @p pco_iut and @ref iomux-echoer on
 *    @p pco_tst PCO with the following parameters:
 *      - @p pco_iut, { @p iut_s }, @c time2run, @p received;
 *      - @p pco_tst, { @p tst_s }, @c time2run, @b select();
 * -# Call @b sendfile() on @p iut_aux with @p iut_s socket descriptor
 *    as @p out_fd parameter and @p src file descriptor as @p in_fd
 *    parameter.
 * -# Check that the number of bytes received by @ref lib-simple_receiver is
 *    the same as sent by @b sendfile();
 * -# Close files opened on @p pco_iut side and @p pco_tst side.
 * -# Remove files created for test purposes on the all sides.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2s_sendfile2one"

#include "sendfile_common.h"
#include "iomux.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    te_bool                 use_fork = FALSE;
    char                   *file_iut = "sendfile.pco_iut";
    int                     file_length;
    long                    sent;
    long                    time2run;
    int                     src = -1;
    te_bool                 created_iut = FALSE;
    te_bool                 simple_receiver_started = FALSE;
    te_bool                 echoer_started = FALSE;

    uint64_t                received = 0;
    uint64_t                echo_tx = 0;
    uint64_t                echo_rx = 0;

    /* Preambule */
    TEST_START;
    TEST_GET_BOOL_PARAM(use_fork);
    TEST_GET_PCO(pco_iut);
    if (!use_fork)
        TEST_GET_PCO(iut_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_INT_PARAM(file_length);

    /* Scenario */
    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'Y', file_length);
    created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    if (use_fork)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "Child", &iut_aux));
    }

    pco_iut->op = RCF_RPC_CALL;
    if (rpc_simple_receiver(pco_iut, iut_s, time2run, &received) != 0)
    {
        TEST_FAIL("Unexpected rpc_simple_receiver() failure on pco_iut");
    }
    simple_receiver_started = TRUE;

    pco_tst->op = RCF_RPC_CALL;
    if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, IC_DEFAULT,
                         &echo_tx, &echo_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }
    echoer_started = TRUE;

    sent = rpc_sendfile(iut_aux, iut_s, src, NULL, file_length, FALSE);
    if (sent != file_length)
    {
        VERB("rpc_sendfile(): sent bytes:%d, expected:%d", sent, file_length);
        TEST_FAIL("Unexpected number of the sent bytes");
    }

    echoer_started = FALSE;
    pco_tst->op = RCF_RPC_WAIT;
    if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, 1,
                         &echo_tx, &echo_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }

    simple_receiver_started = FALSE;
    pco_iut->op = RCF_RPC_WAIT;
    if (rpc_simple_receiver(pco_iut, iut_s, time2run, &received) != 0)
    {
        TEST_FAIL("Unexpected rpc_simple_receiver() failure on pco_iut");
    }


    if (received != (unsigned long)file_length)
    {
        INFO("Traffic statistics: received=%u, echo_tx=%u, echo_rx=%u",
             (unsigned int)received, (unsigned int)echo_tx, 
             (unsigned int)echo_rx);
        TEST_FAIL("Unexpected send/receive traffic");
    }
    TEST_SUCCESS;

cleanup:
    if (simple_receiver_started && pco_iut != NULL)
    {
        pco_iut->op = RCF_RPC_WAIT;
        if (rpc_simple_receiver(pco_iut, iut_s, time2run, &received) != 0)
        {
            TEST_FAIL("Unexpected rpc_simple_receiver() failure on pco_iut");
            result = EXIT_FAILURE;
        }
    }

    if (echoer_started && pco_tst != NULL)
    {
        pco_tst->op = RCF_RPC_WAIT;
        if (rpc_iomux_echoer(pco_tst, &tst_s, 1, time2run, 1,
                             &echo_tx, &echo_rx) != 0)
        {
            ERROR("Unexpected rpc_iomux_echoer() failure on pco_tst");
            result = EXIT_FAILURE;
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, src);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (use_fork && (iut_aux != NULL) &&
        (rcf_rpc_server_destroy(iut_aux) != 0))
    {
        ERROR("rcf_rpc_server_destroy() failed");
        result = EXIT_FAILURE;
    }

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    TEST_END;
}
