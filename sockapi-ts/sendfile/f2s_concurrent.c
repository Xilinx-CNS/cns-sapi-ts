/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-f2s_concurrent Usage of sendfile() to preform concurrent copying files to sockets
 *
 * @objective Check a possibility of fast copying of files to the sockets
 *            by means of @b sendfile() called concurrently.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut1      The first PCO on IUT
 * @param pco_iut2      The second PCO on IUT
 * @param use_fork      Create forked process in test or
 *                      use configuration parameters
 * @param pco_tst1      PCO on tester
 * @param pco_tst2      PCO on tester
 * @param iut1_addr     @p pco_iut1 address for first connection creation
 * @param tst1_addr     @p pco_tst1 address for first connection creation
 * @param tst2_addr     @p pco_tst2 address for second connection creation
 * @param time2run      Time for data waiting
 * @param length1       The length used for file processing on the
 *                      first connection (creation/copying/comparison)
 * @param length2       The length used for file processing on the
 *                      second connection (creation/copying/comparison)
 *
 * @par Test sequence:
 * -# Create @p iut2_addr to establish second connection between @p pco_iut1
 *    and @p pco_tst2
 * -# Create first connection between @p pco_iut1 and @p pco_tst1 
 *    with @c SOCK_STREAM type of socket and return 
 *    @p iut1_s and @p tst1_s connection descriptors.
 * -# Create second connection between @p pco_iut1 and @p pco_tst2 with
 *    @c SOCK_STREAM type of socket and return @p iut2_s and @p tst2_s 
 *    connection descriptors.
 * -# Prepare @p orig.tpl{1,2} file and copy it to the @p pco_iut1 as
 *    @p sendfile.pco_iut{1,2}.
 * -# Open @p sendfile.pco_iut{1,2} for reading on @p pco_iut1 and retrieve
 *    @p src{1,2} file descriptor.
 * -# Call at the same time:
 *    - @b sendfile() on @p pco_iut1 with @p iut1_s socket descriptor
 *      as @a out_fd parameter and @p src1 file descriptor as @a in_fd
 *      parameter;
 *    - @b sendfile() on @p pco_iut2 with @p iut2_s socket descriptor
 *      as @a out_fd parameter and @p src2 file descriptor as @a in_fd
 *      parameter
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst1 to receive
 *    data sent by means of @b sendfile() on @p pco_iut1 and write its to
 *    the sendfile.pco_tst1.
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst2 to receive
 *    data sent by means of @b sendfile() on @p pco_iut2 and write its to
 *    the sendfile.pco_tst2.
 * -# Check that contents of the both @p sendfile.pco_tst{1,2} file and
 *    original @p orig.tpl{1,2} file are the same.
 * -# Close files opened on IUT side and TESTER side.
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2s_concurrent"

#include "sendfile_common.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;
    te_bool                 use_fork = FALSE;

    const struct sockaddr  *iut1_addr;

    struct sockaddr_storage addr_aux;
    const struct sockaddr  *iut2_addr;

    const struct sockaddr  *tst1_addr;
    const struct sockaddr  *tst2_addr;

    int                     length1;
    int                     length2;

    long                    time2run;

    int                     iut1_s = -1;
    int                     tst1_s = -1;
    int                     iut2_s = -1;
    int                     tst2_s = -1;

    const char *file_tpl1 = "sendfile.tpl1";
    const char *file_tpl2 = "sendfile.tpl2";

    const char *file_iut1 = "sendfile.pco_iut1";
    const char *file_iut2 = "sendfile.pco_iut2";

    const char *file_tst1 = "sendfile.pco_tst1";
    const char *file_tst2 = "sendfile.pco_tst2";

    const char *file_ret1 = "sendfile.ret1";
    const char *file_ret2 = "sendfile.ret2";

    long            sent1, sent2;
    long            received1, received2;

    te_bool         created_tpl1 = FALSE;
    te_bool         created_tpl2 = FALSE;
    te_bool         created_iut1 = FALSE;
    te_bool         created_iut2 = FALSE;
    te_bool         created_tst1 = FALSE;
    te_bool         created_tst2 = FALSE;
    te_bool         created_ret1 = FALSE;
    te_bool         created_ret2 = FALSE;
    te_bool         use_sendfile = TRUE;

    int             src1 = -1;
    int             src2 = -1;
    tarpc_off_t     offset = 0;
    tarpc_timeval   tv = {0, 0};
    te_bool         reported = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_BOOL_PARAM(use_fork);
    if (!use_fork)
        TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut1, iut1_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_INT_PARAM(length1);
    TEST_GET_INT_PARAM(length2);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_BOOL_PARAM(use_sendfile);

    /* Scenario */
    memcpy(&addr_aux, iut1_addr, sizeof(addr_aux));
    TAPI_SET_NEW_PORT(pco_iut1, &addr_aux);
    iut2_addr = SA(&addr_aux);

    GEN_CONNECTION(pco_iut1, pco_tst1, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut1_addr, tst1_addr, &iut1_s, &tst1_s);
    GEN_CONNECTION(pco_iut1, pco_tst2, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut2_addr, tst2_addr, &iut2_s, &tst2_s);

    PREPARE_REMOTE_FILE(pco_iut1->ta, length1, 'c', file_tpl1, file_iut1);
    created_tpl1 = created_iut1 = TRUE;

    PREPARE_REMOTE_FILE(pco_iut1->ta, length2, 'd', file_tpl2, file_iut2);
    created_tpl2 = created_iut2 = TRUE;

    RPC_FOPEN_D(src1, pco_iut1, file_iut1, RPC_O_RDONLY, 0);
    RPC_FOPEN_D(src2, pco_iut1, file_iut2, RPC_O_RDONLY, 0);

    if (use_fork)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut1, "iutchild", &pco_iut2));
    }

    /* Adjust conditions for running at the same time */
    rpc_gettimeofday(pco_iut1, &tv, NULL);
    pco_iut1->start = pco_iut2->start = pco_tst1->start = pco_tst2->start =
        (tv.tv_sec + 5) * 1000 + tv.tv_usec / 1000;

    pco_tst1->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received1, pco_tst1, tst1_s, file_tst1, time2run);
    created_tst1 = TRUE;

    pco_tst2->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received2, pco_tst2, tst2_s, file_tst2, time2run);
    created_tst2 = TRUE;

    pco_iut1->op = RCF_RPC_CALL;
    if (use_sendfile)
        sent1 = rpc_sendfile(pco_iut1, iut1_s, src1, &offset, length1,
                             FALSE);
    else
        sent1 = rpc_sendfile_via_splice(pco_iut1, iut1_s, src1, &offset,
                                        length1);

    RPC_AWAIT_IUT_ERROR(pco_iut2);
    /*
     * sendfile() call hangs more time on some hosts, so timeout was increased.
     * See ST-2733
     */
    pco_iut2->timeout = (pco_iut2->def_timeout + (length1 + length2) / 10000) * 2;
    if (use_sendfile)
        sent2 = rpc_sendfile(pco_iut2, iut2_s, src2, &offset, length2,
                             FALSE);
    else
        sent2 = rpc_sendfile_via_splice(pco_iut2, iut2_s, src2, &offset,
                                        length2);

    if (sent2 < 0)
    {
        reported = TRUE;
        ERROR_VERDICT("The second sendfile call failed with errno %r",
                      RPC_ERRNO(pco_iut2));
    }
    else if (sent2 != length2)
    {
        VERB("rpc_sendfile() on pco_iut2: sent bytes:%d, expected:%d",
             sent2, length1);
        TEST_FAIL("Unexpected number of the sent bytes on pco_iut2");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut1);
    pco_iut1->op = RCF_RPC_WAIT;
    if (use_sendfile)
        sent1 = rpc_sendfile(pco_iut1, iut1_s, src1, &offset, length1,
                             FALSE);
    else
        sent1 = rpc_sendfile_via_splice(pco_iut1, iut1_s, src1, &offset,
                                        length1);

    if (sent1 < 0)
    {
        if (!reported)
            ERROR_VERDICT("The first sendfile call failed with errno %r",
                          RPC_ERRNO(pco_iut2));
        reported = TRUE;
    }
    else if (sent1 != length1)
    {
        VERB("rpc_sendfile() on pco_iut1: sent bytes:%d, expected:%d",
             sent1, length1);
        TEST_FAIL("Unexpected number of the sent bytes on pco_iut1");
    }

    RPC_AWAIT_IUT_ERROR(pco_tst1);
    pco_tst1->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received1, pco_tst1, tst1_s, file_tst1, time2run);
    if (received1 < 0)
    {
        if (!reported)
            ERROR_VERDICT("The first socket_to_file call failed with "
                          "errno %r", RPC_ERRNO(pco_iut2));
        reported = TRUE;
    }
    else if (received1 != sent1)
    {
        VERB("rpc_socket_to_file() on pco_tst1: received bytes:%d, expected:%d",
             received1, sent1);
        TEST_FAIL("The number of sent and received bytes on first connection "
                  "is not the same");
    }

    pco_tst2->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received2, pco_tst2, tst2_s, file_tst2, time2run);
    if (received2 != sent2)
    {
        VERB("rpc_socket_to_file() on pco_tst2: received bytes:%d, expected:%d",
             received2, sent2);
        TEST_FAIL("The number of sent and received bytes on second connection "
                  "is not the same");
    }

    RETRIEVE_REMOTE_FILE(pco_tst1->ta, file_tst1, file_ret1);
    created_ret1 = TRUE;

    RETRIEVE_REMOTE_FILE(pco_tst2->ta, file_tst2, file_ret2);
    created_ret2 = TRUE;

    COMPARE_PROCESSED_FILES(file_tpl1, file_ret1);
    COMPARE_PROCESSED_FILES(file_tpl2, file_ret2);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut1, src1);
    CLEANUP_RPC_CLOSE(pco_iut2, src2);
    CLEANUP_RPC_CLOSE(pco_iut1, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut2_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (use_fork && (pco_iut2 != NULL) &&
        (rcf_rpc_server_destroy(pco_iut2) != 0))
    {
        pco_iut2 = NULL;
        ERROR("rcf_rpc_server_destroy() failed");
        result = EXIT_FAILURE;
    }

    if (created_tpl1)
        REMOVE_LOCAL_FILE(file_tpl1);
    if (created_tpl2)
        REMOVE_LOCAL_FILE(file_tpl2);

    if (created_iut1)
        REMOVE_REMOTE_FILE(pco_iut1->ta, file_iut1);
    if (created_iut2)
        REMOVE_REMOTE_FILE(pco_iut1->ta, file_iut2);

    if (created_tst1)
        REMOVE_REMOTE_FILE(pco_tst1->ta, file_tst1);
    if (created_tst2)
        REMOVE_REMOTE_FILE(pco_tst2->ta, file_tst2);

    if (created_ret1)
        REMOVE_LOCAL_FILE(file_ret1);
    if (created_ret2)
        REMOVE_LOCAL_FILE(file_ret2);

    TEST_END;
}
