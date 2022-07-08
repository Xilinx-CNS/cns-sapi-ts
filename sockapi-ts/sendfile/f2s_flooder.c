/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-f2s_flooder Performing 'file to socket' sendfile() operations while some TCP traffic exists
 *
 * @objective Check a possibility of reliable copying of the file to socket
 *            by means of @b sendfile() system call while some TCP traffic 
 *            exists.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param iut_aux       Auxiliary PCO on IUT (thread created on IUT)
 * @param iut1_addr     Address/port to be used as connection endpoint
 *                      address on @p pco_iut
 * @param pco_tst1          PCO on tester
 * @param tst1_addr     Address/port to be used as connection endpoint
 *                      address on @p pco_tst1
 * @param pco_tst2          PCO on tester
 * @param tst2_addr     Address/port to be used to connect to @p pco_tst2
 * @param time2run      How long run the flooder and timeout for data waiting
 * @param file_length   Length used for file processing (creation/copying/
 *                      comparison)
 * @param use_fork      Create forked process in test or use configuration
 *                      parameters.
 * @par Scenario:
 * -# Create @p iut2_addr to establish second connection between @p pco_iut
 *    and @p pco_tst2
 * -# Prepare @p orig.tpl file and copy it to the @p pco_iut as @p sendfile.pco_iut.
 * -# Open @p sendfile.pco_iut on @p pco_iut side and retrieve @p src file descriptor.
 * -# Create first connection (for flooder) between @p pco_iut and @p pco_tst1 using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst1;
 *      - @a sock_type: @c SOCK_STREAM;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut1_addr;
 *      - @a clnt_addr: @p tst1_addr;
 *      - @a srvr_s: stored in @p iut1_s;
 *      - @a clnt_s: stored in @p tst1_s;
 * -# Create second connection (for sendfile()) between @p pco_iut and @p pco_tst2 using
 *    @ref lib-gen_connection algorithm with the following parameters:
 *      - @a srvr: @p pco_iut;
 *      - @a clnt: @p pco_tst;
 *      - @a sock_type: @c SOCK_STREAM;
 *      - @a proto: @c 0;
 *      - @a srvr_addr: @p iut2_addr;
 *      - @a clnt_addr: @p tst2_addr;
 *      - @a srvr_s: stored in @p iut2_s;
 *      - @a clnt_s: stored in @p tst2_s;
 * -# Process @p use_fork and create forked process with handle returned to the
 *    @p iut_aux if @p TRUE or use preconfigured iut_aux handle if @p FALSE.
 * -# Run @ref iomux-flooder on @p pco_iut and @ref iomux-echoer on @p pco_tst1
 *    with the following parameters:
 *      - @p pco_iut, { @p iut1_s }, { @p iut1_s }, @c 1000,
 *        @c time2run, @b select();
 *      - @p pco_tst2, { @p tst2_s }, @c time2run, @b select();
 * -# Call @b sendfile() on @p iut_aux with @p iut2_s socket descriptor
 *    as @p out_fd parameter and @p src file descriptor as @p in_fd parameter.
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst2 side to receive
 *    data sent by means of @b sendfile() and write its to the file
 *    @p sendfile.pco_tst.
 * -# Check that contents of the both @p sendfile.pco_tst file and @p orig.tpl file
 *    are the same.
 * -# Close files opened for test purposes.
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2s_flooder"

#include "sendfile_common.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut     = NULL;
    rcf_rpc_server         *iut_aux = NULL;
    rcf_rpc_server         *pco_tst1    = NULL;
    rcf_rpc_server         *pco_tst2    = NULL;
    int                     iut1_s = -1;
    int                     tst1_s = -1;
    int                     iut2_s = -1;
    int                     tst2_s = -1;

    const struct sockaddr  *iut1_addr;

    struct sockaddr_storage addr_aux;
    const struct sockaddr  *iut2_addr = SA(&addr_aux);

    const struct sockaddr  *tst1_addr;
    const struct sockaddr  *tst2_addr;

    te_bool                 use_fork = FALSE;

    const char             *file_tpl = "orig.tpl";
    const char             *file_iut = "sendfile.pco_iut";
    const char             *file_tst = "sendfile.pco_tst";
    const char             *file_ret = "sendfile.ret";
    te_bool                 created_tpl = FALSE;
    te_bool                 created_iut = FALSE;
    te_bool                 created_tst = FALSE;
    te_bool                 created_ret = FALSE;
    int                     file_length;
    long                    sent;
    long                    received;
    long                    time2run;
    int                     src = -1;
    tarpc_off_t             offset = 0;

    uint64_t                flooder_tx = 0;
    uint64_t                flooder_rx = 0;
    uint64_t                echo_tx = 0;
    uint64_t                echo_rx = 0;
    int                     loglevel;

    /* Preambule */
    TEST_START;
    TEST_GET_BOOL_PARAM(use_fork);
    TEST_GET_PCO(pco_iut);
    if (!use_fork)
        TEST_GET_PCO(iut_aux);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_INT_PARAM(file_length);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

    /* Scenario */
    memcpy(&addr_aux, iut1_addr, te_sockaddr_get_size(iut1_addr));
    TAPI_SET_NEW_PORT(pco_iut, &addr_aux);

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'Z', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    GEN_CONNECTION(pco_iut, pco_tst1, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut1_addr, tst1_addr, &iut1_s, &tst1_s);

    GEN_CONNECTION(pco_iut, pco_tst2, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut2_addr, tst2_addr, &iut2_s, &tst2_s);

    if (use_fork)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "Child", &iut_aux));
    }

    pco_iut->op = RCF_RPC_CALL;
    if (rpc_iomux_flooder(pco_iut, &iut1_s, 1, &iut1_s, 1, 1000, time2run, 2,
                          FUNC_POLL, &flooder_tx, &flooder_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    pco_tst1->op = RCF_RPC_CALL;
    if (rpc_iomux_echoer(pco_tst1, &tst1_s, 1, time2run + 1, FUNC_POLL,
                         &echo_tx, &echo_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }

    pco_tst2->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received, pco_tst2, tst2_s, file_tst, time2run);
    created_tst = TRUE;

    sent = rpc_sendfile(iut_aux, iut2_s, src, &offset, file_length, FALSE);
    if (sent != file_length)
    {
        VERB("rpc_sendfile(): sent bytes:%d, expected:%d", sent, file_length);
        TEST_FAIL("Unexpected number of the sent bytes");
    }

    pco_tst2->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received, pco_tst2, tst2_s, file_tst, time2run);
    if (received != sent)
    {
        VERB("rpc_socket_to_file(): received bytes:%d, expected:%d",
             received, sent);
        TEST_FAIL("The number of sent and received bytes is not the same");
    }

    pco_iut->op = RCF_RPC_WAIT;
    if (rpc_iomux_flooder(pco_iut, &iut1_s, 1, &iut1_s, 1, 1000, time2run, 2,
                          FUNC_POLL, &flooder_tx, &flooder_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_flooder() failure on pco_iut");
    }

    pco_tst1->op = RCF_RPC_WAIT;
    if (rpc_iomux_echoer(pco_tst1, &tst1_s, 1, time2run + 1, FUNC_POLL,
                         &echo_tx, &echo_rx) != 0)
    {
        TEST_FAIL("Unexpected rpc_iomux_echoer() failure on pco_tst");
    }

    if ((echo_rx != flooder_tx) || (echo_tx != flooder_rx))
    {
          INFO("Traffic statistics: flooder_tx=%u, flooder_rx=%u, "
               "echo_tx=%u, echo_rx=%u",
               (unsigned int)flooder_tx, (unsigned int)flooder_rx,
               (unsigned int)echo_tx, (unsigned int)echo_rx);
          TEST_FAIL("Unexpected flooder sent/received traffic");
    }

    RPC_CLOSE(pco_iut, src);

    RETRIEVE_REMOTE_FILE(pco_tst2->ta, file_tst, file_ret);
    created_ret = TRUE;

    COMPARE_PROCESSED_FILES(file_tpl, file_ret);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, src);
    CLEANUP_RPC_CLOSE(pco_iut, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut2_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (use_fork && (iut_aux != NULL) &&
        (rcf_rpc_server_destroy(iut_aux) != 0))
    {
        ERROR("rcf_rpc_server_destroy() failed");
        result = EXIT_FAILURE;
    }

    if (created_tpl)
        REMOVE_LOCAL_FILE(file_tpl);
    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst2->ta, file_tst);
    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

    TEST_END;
}
