/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-f2s_context Copying two source files to common destination socket
 *
 * @objective Check a possibility of copying of two source files to common
 *            destination socket by means of @b sendfile() called in
 *            different processes/threads.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param iut_aux       Auxiliary (child_process/thread) PCO on IUT
 * @param use_fork      Create forked process in test or
 *                      use configuration parameters.
 * @param pco_tst       PCO on TST
 * @param iut_addr      The address to create connection endpoint on IUT
 * @param tst_addr      The address to create connection endpoint on TST
 * @param file_length   Length used for file processing
 *                      (creation/copying/comparison)
 *
 * @par Test sequence:
 *
 * -# Create @p sendfile.pco_iut1 on the @p pco_iut side.
 * -# Create @p sendfile.pco_iut2 on the @p pco_iut side.
 * -# Create connection between @p pco_iut and @p pco_tst with 
 *    @c SOCK_STREAM type of socket and
 *    retrieve @p iut_s and @p tst_s socket descriptors.
 * -# Process @p use_fork and create forked process with handle returned
 *    to the @p iut_aux if @c TRUE or use preconfigured iut_aux handle
 *    if @c FALSE.
 * -# Open @p sendfile.pco_iut1 on @p pco_iut side and retrieve @p src1
 *    file descriptor.
 * -# Open @p sendfile.pco_iut2 on @p iut_aux and retrieve @p src2 file
 *    descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p iut_s socket descriptor
 *    as @a out_fd parameter and @p src1 file descriptor as @a in_fd
 *    parameter.
 * -# Call @b sendfile() on @p iut_aux with @p iut_s file descriptor as
 *    @a out_fd parameter and @p src2 file descriptor as @a in_fd parameter.
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst side
 *    to receive data sent by means of @b sendfile() and write its to
 *    the file @p sendfile.pco_tst.
 * -# Check that @p sendfile.pco_tst file length is the
 *    (@p file_length * @c 2).
 * -# Close files opened on @p pco_iut side.
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2s_context"

#include "sendfile_common.h"


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

    const char     *file_tpl1 = "sendfile.tpl1";
    const char     *file_tpl2 = "sendfile.tpl2";

    const char     *file_iut1 = "sendfile.pco_iut1";
    const char     *file_iut2 = "sendfile.pco_iut2";

    const char     *file_tst = "sendfile.pco_tst";

    const char     *file_ret = "sendfile.ret";

    int             file_length;
    long            sent1, sent2;
    long            received;
    long            time2run;

    te_bool         created_tpl1 = FALSE;
    te_bool         created_tpl2 = FALSE;
    te_bool         created_iut1 = FALSE;
    te_bool         created_iut2 = FALSE;
    te_bool         created_tst = FALSE;
    te_bool         created_ret = FALSE;

    int             src1 = -1;
    int             src2 = -1;
    tarpc_off_t     offset = 0;
    tarpc_timeval   tv = {0, 0};
    te_bool         use_fork = FALSE;
    struct stat     file_stat;
    te_bool         use_sendfile = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(use_fork);
    if (!use_fork)
        TEST_GET_PCO(iut_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_BOOL_PARAM(use_sendfile);

    /* Scenario */

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'I', file_tpl1, file_iut1);
    created_tpl1 = created_iut1 = TRUE;

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'J', file_tpl2, file_iut2);
    created_tpl2 = created_iut2 = TRUE;

    if (use_fork)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "Child", &iut_aux));
    }

    RPC_FOPEN_D(src1, pco_iut, file_iut1, RPC_O_RDONLY, 0);
    RPC_FOPEN_D(src2, iut_aux, file_iut2, RPC_O_RDONLY, 0);

    pco_tst->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, time2run);
    created_tst = TRUE;

    /* Adjust conditions for running at the same time */
    rpc_gettimeofday(pco_iut, &tv, NULL);
    pco_iut->start = (tv.tv_sec + 2) * 1000 + tv.tv_usec / 1000;
    iut_aux->start = (tv.tv_sec + 2) * 1000 + tv.tv_usec / 1000;

    pco_iut->op = RCF_RPC_CALL;
    if (use_sendfile)
        sent1 = rpc_sendfile(pco_iut, iut_s, src1, &offset, file_length,
                             FALSE);
    else
        sent1 = rpc_sendfile_via_splice(pco_iut, iut_s, src1, &offset,
                                        file_length);

    if (use_sendfile)
        sent2 = rpc_sendfile(iut_aux, iut_s, src2, &offset, file_length,
                             FALSE);
    else
        sent2 = rpc_sendfile_via_splice(iut_aux, iut_s, src2, &offset,
                                        file_length);
    if (sent2 != file_length)
    {
        VERB("rpc_sendfile() on iut_aux: sent bytes:%d, expected:%d",
             sent2, file_length);
        TEST_FAIL("Unexpected number of the sent bytes on iut_aux");
    }

    pco_iut->op = RCF_RPC_WAIT;
    if (use_sendfile)
        sent1 = rpc_sendfile(pco_iut, iut_s, src1, &offset, file_length,
                             FALSE);
    else
        sent1 = rpc_sendfile_via_splice(pco_iut, iut_s, src1, &offset,
                                        file_length);
    if (sent1 != file_length)
    {
        VERB("rpc_sendfile() on pco_iut: sent bytes:%d, expected:%d",
             sent1, file_length);
        TEST_FAIL("Unexpected number of the sent bytes on pco_iut");
    }

    pco_tst->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, time2run);
    if (received != (sent1 + sent2))
    {
        VERB("rpc_socket_to_file(): received bytes:%d, expected:%d",
             received, (sent1 + sent2));
        TEST_FAIL("The number of sent and received bytes is not the same");
    }

    RETRIEVE_REMOTE_FILE(pco_tst->ta, file_tst, file_ret);
    created_ret = TRUE;

    RETRIEVE_STAT(file_ret, file_stat);

    if (file_stat.st_size != received)
    {
        TEST_FAIL("Unexpected length of the file gotten as result of the two "
                  "sendfile() operations running at the same time");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, src1);
    CLEANUP_RPC_CLOSE(iut_aux, src2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (use_fork && (iut_aux != NULL) &&
        (rcf_rpc_server_destroy(iut_aux) != 0))
    {
        ERROR("rcf_rpc_server_destroy() failed");
        result = EXIT_FAILURE;
    }

    if (created_tpl1)
        REMOVE_LOCAL_FILE(file_tpl1);
    if (created_tpl2)
        REMOVE_LOCAL_FILE(file_tpl2);

    if (created_iut1)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut1);
    if (created_iut2)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut2);

    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst);

    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    TEST_END;
}
