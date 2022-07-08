/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-illegal_params sendfile() behavior on using of illegal parameters
 *
 * @objective Check @b sendfile() behavior in case of passing an illegal
 *            input/output file descriptors.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut           PCO on IUT
 * @param file_length   The length used for file processing
 *                      (creation/copying/comparison)
 *
 * @par Test sequence:
 *
 * -# Prepare original @p sendfile.tpl file and copy it to the @p pco_iut
 *    as @p sendfile.pco_iut (filled in with 'A').
 * -# Create @p sendfile.pco_tst on the @p pco_iut (filled in with '0').
 * -# Open @p sendfile.pco_iut for reading on @p pco_iut and retrieve
 *    @p src file descriptor.
 * -# Open @p sendfile.pco_tst for writing on @p pco_iut and retrieve
 *    @p dst file descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p dst file descriptor as @a out_fd
 *    parameter and @c -1 as @a in_fd parameter.
 * -# Check that @b sendfile() returns @c -1 and @b errno is set to @c EBADF.
 * -# Call @b sendfile() on @p pco_iut with @c -1 as @a out_fd parameter and
 *    @p src file descriptor as @a in_fd parameter.
 * -# Check that @b sendfile() returns @c -1 and @b errno is set to @c EBADF.
 * -# Call @b sendfile() on @p pco_iut with @p dst file descriptor as @a out_fd
 *    parameter, @p src file descriptor as @a in_fd parameter , @a offset 
 *    as @c 0 and @a count as @p file_length.
 * -# Check that @b sendfile() performs file copy without errors.
 * -# Check that contents of the both @p sendfile.pco_tst file and original
 *    @p sendfile.tpl file are the same.
 * -# Close files opened on @p pco_iut.
 * -# Remove all files created for test purposes.
 *
 * @note @p sendfile.pco_tst and @p sendfile.pco_iut have the same @p file_length
 *       length but different content. Old content of @p sendfile.pco_tst should
 *       be lost and @b sendfile() should copy @p sendfile.pco_iut content to
 *       the @p sendfile.pco_tst.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/illegal_params"

#include "sendfile_common.h"


int
main(int argc, char *argv[])
{

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    const char     *file_tpl = "sendfile.tpl";
    const char     *file_iut = "sendfile.pco_iut";
    const char     *file_tst = "sendfile.pco_tst";
    const char     *file_ret = "sendfile.ret";

    te_bool         created_tpl = FALSE;
    te_bool         created_iut = FALSE;
    te_bool         created_tst = FALSE;
    te_bool         created_ret = FALSE;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int             src = -1;
    int             iut_s = -1;
    int             tst_s = -1;

    ssize_t         sent;
    ssize_t         received;
    tarpc_off_t     offset = 0;;
    int             file_length;

    UNUSED(received);

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(file_length);

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'A', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;


    CREATE_REMOTE_FILE(pco_iut->ta, file_tst, '\0', file_length);
    created_tst = TRUE;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_sendfile(pco_iut, iut_s, -1, &offset, file_length, FALSE);
    if (sent != -1)
    {
        TEST_FAIL("sendfail() called with invalid in_fd parameter "
                  "returned %d instead of -1", sent);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "sendfail() called with invalid in_fd "
                    "parameter returns -1");

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_sendfile(pco_iut, -1, src, &offset, file_length, FALSE);
    if (sent != -1)
    {
        TEST_FAIL("sendfail() called with invalid out_fd parameter "
                  "returned %d instead of -1", sent);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EBADF, "sendfail() called with invalid out_fd "
                    "parameter returns -1");

    pco_tst->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, 3);
    created_tst = TRUE;

    offset = 0;
    sent = rpc_sendfile(pco_iut, iut_s, src, &offset, file_length, FALSE);

    pco_tst->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, 3);

    RETRIEVE_REMOTE_FILE(pco_tst->ta, file_tst, file_ret);
    created_ret = TRUE;

    COMPARE_PROCESSED_FILES(file_tpl, file_ret);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, src);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (created_tpl)
        REMOVE_LOCAL_FILE(file_tpl);

    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst);

    TEST_END;
}
