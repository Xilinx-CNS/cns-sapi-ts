/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-files2file_socket The copying to the file and socket at the same time
 *
 * @objective Check a possibility of copying at the same time by means
 *            of @b sendfile() system call with variants:
 *             - file to file;
 *             - file to socket.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param iut_aux       Auxiliary (thread/process) PCO on IUT
 * @param pco_tst       PCO on tester
 * @param iut_address   The address for connection endpoint on @p pco_iut
 * @param tst_address   The address for connection endpoint on @p pco_tst
 * @param length1       The length used for file_to_file processing
 *                      (creation/copying/comparison)
 * @param length2       The length used for file_to_socket processing
 *                      (creation/copying/comparison)
 * @param time2run      Time for data waiting
 *
 * @par Test sequence:
 *
 * -# Create connection between @p pco_iut and @p pco_tst with 
 *    @c SOCK_STREAM type of socket and retrieve @p iut_s and 
 *    @p tst_s socket descriptors.
 * -# Prepare original @p sendfile.tpl{1,2} file and copy
 *    it to the @p pco_iut as @p sendfile.pco_iut{1,2}.
 * -# Open @p sendfile.pco_iut1 on @p iut_aux side and retrieve @p src1
 *    file descriptor for @e file-to-socket operation.
 * -# Open @p sendfile.cpy on @p pco_iut side and retrieve @p dst_iut
 *    file descriptor.
 * -# Open @p sendfile.pco_iut2 on @p pco_iut side and retrieve @p src2
 *    file descriptor for @e file-to-file operation.
 * -# Call @b sendfile() at the same time on:
 *     - @p pco_iut with @p iut_s socket descriptor as @a out_fd
 *       parameter and @p src1 file descriptor as @a in_fd parameter;
 *     - @p iut_aux with @p dst_iut file descriptor as @a out_fd
 *       parameter and @p src2 file descriptor as @a in_fd parameter;
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst side
 *    to receive data sent by means of @b sendfile() and write its to
 *    the file @p sendfile.pco_tst.
 * -# Check that contents of the @p sendfile.pco_tst file and original
 *    @p sendfile.tpl file are the same.
 * -# Check that contents of the @p sendfile.cpy file and original
 *    @p sendfile.tpl file are the same.
 * -# Close files opened for test purposes.
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/files2file_socket"

#include "sendfile_common.h"


int
main(int argc, char *argv[])
{
    int                     length1, length2;
    int                     time2run;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_aux = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const char             *file_tpl1 = "sendfile.tpl1";
    const char             *file_tpl2 = "sendfile.tpl2";

    const char             *file_iut1 = "sendfile.pco_iut1";
    const char             *file_iut2 = "sendfile.pco_iut2";

    const char             *file_tst1 = "sendfile.pco_tst1";
    const char             *file_tst2 = "sendfile.pco_tst2";

    const char             *file_ret1 = "sendfile.ret1";
    const char             *file_ret2 = "sendfile.ret2";

    te_bool                 created_tpl1 = FALSE;
    te_bool                 created_tpl2 = FALSE;
    te_bool                 created_iut1 = FALSE;
    te_bool                 created_iut2 = FALSE;
    te_bool                 created_tst1 = FALSE;
    te_bool                 created_tst2 = FALSE;
    te_bool                 created_ret1 = FALSE;
    te_bool                 created_ret2 = FALSE;

    int                     iut_s = -1;
    int                     tst_s = -1;
    int                     src1 = -1;
    int                     src2 = -1;
    int                     dst2 = -1;

    tarpc_timeval           tv = {0, 0};

    ssize_t                 sent1, sent2;
    ssize_t                 received;


    /* Preambule */
    TEST_START;
    TEST_GET_INT_PARAM(length1);
    TEST_GET_INT_PARAM(length2);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(iut_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    /* Scenario */

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    PREPARE_REMOTE_FILE(pco_iut->ta, length1, 'V', file_tpl1, file_iut1);
    created_tpl1 = created_iut1 = TRUE;

    PREPARE_REMOTE_FILE(pco_iut->ta, length2, 'W', file_tpl2, file_iut2);
    created_tpl2 = created_iut2 = TRUE;

    RPC_FOPEN_D(src1, pco_iut, file_iut1, RPC_O_RDONLY, 0);
    RPC_FOPEN_D(src2, iut_aux, file_iut2, RPC_O_RDONLY, 0);
    RPC_FOPEN_D(dst2, iut_aux, file_tst2, RPC_O_WRONLY | RPC_O_CREAT,
                RPC_S_IRWXU);
    created_tst2 = TRUE;


    /* Adjust conditions for running at the same time */
    rpc_gettimeofday(pco_iut, &tv, NULL);
    pco_iut->start = iut_aux->start = pco_tst->start =
        (tv.tv_sec + 5) * 1000 + tv.tv_usec / 1000;

    
    iut_aux->op = RCF_RPC_CALL;
    sent2 = rpc_sendfile(iut_aux, dst2, src2, NULL, length2, FALSE);

    pco_tst->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst1, time2run);
    created_tst1 = TRUE;

    
    sent1 = rpc_sendfile(pco_iut, iut_s, src1, NULL, length1, FALSE);
    if (sent1 != length1)
    {
        INFO("rpc_sendfile(): sent bytes:%d, expected:%d", sent1, length1);
        TEST_FAIL("Unexpected number of the sent bytes");
    }

    
    pco_tst->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst1, time2run);
    if (received != sent1)
    {
        INFO("rpc_socket_to_file(): received bytes:%d, expected:%d",
             received, sent1);
        TEST_FAIL("The number of sent and received bytes is not the same");
    }

    iut_aux->op = RCF_RPC_WAIT;
    sent2 = rpc_sendfile(iut_aux, dst2, src2, NULL, length2, FALSE);
    if (sent2 != length2)
    {
        VERB("rpc_sendfile(): sent bytes:%d, expected:%d", sent2, length2);
        TEST_FAIL("Unexpected number of the copied bytes");
    }

    
    RETRIEVE_REMOTE_FILE(pco_tst->ta, file_tst1, file_ret1);
    created_ret1 = TRUE;

    RPC_CLOSE(pco_iut, dst2);
    RETRIEVE_REMOTE_FILE(pco_iut->ta, file_tst2, file_ret2);
    created_ret2 = TRUE;

    COMPARE_PROCESSED_FILES(file_tpl1, file_ret1);
    COMPARE_PROCESSED_FILES(file_tpl2, file_ret2);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, src1);
    CLEANUP_RPC_CLOSE(iut_aux, src2);
    CLEANUP_RPC_CLOSE(iut_aux, dst2);

    if (created_tpl1)
        REMOVE_LOCAL_FILE(file_tpl1);
    if (created_tpl2)
        REMOVE_LOCAL_FILE(file_tpl2);

    if (created_iut1)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut1);
    if (created_iut2)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut2);

    if (created_tst1)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst1);
    if (created_tst2)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_tst2);

    if (created_ret1)
        REMOVE_LOCAL_FILE(file_ret1);
    if (created_ret2)
        REMOVE_LOCAL_FILE(file_ret2);

    TEST_END;
}
