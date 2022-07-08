/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-file2file Usage of sendfile() to perform one file to another copy
 *
 * @objective Check a possibility of fast copying of ordinary files (no sockets
 *            used) by means of @b sendfile() system call.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut           PCO on IUT
 * @param file_length   Length used for file processing
 *                      (creation/copying/comparison)
 *
 * @par Test sequence:
 *
 * -# Prepare original @p sendfile.tpl file and copy
 *    it to the @p pco_iut as @p sendfile.pco_iut (filled in with 'A').
 * -# Create @p sendfile.pco_tst on the @p pco_iut (filled in with '0').
 * -# Open @p sendfile.pco_iut on @p pco_iut and retrieve @p src file descriptor.
 * -# Open @p sendfile.pco_tst on @p pco_iut and retrieve @p dst file descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p dst file descriptor as @a out_fd
 *    parameter and @p src file descriptor as @a in_fd parameter.
 * -# Check that contents of the both @p sendfile.pco_tst file and original
 *    @p sendfile.tpl file are the same.
 * -# Close files opened for test purposes.
 * -# Remove files created for test purposes.
 *
 * @note @p sendfile.pco_tst and @p sendfile.pco_iut have the same @p file_length
 *       length but different content. Old content of @p sendfile.pco_tst should
 *       be lost and @b sendfile() should copy @p sendfile.pco_iut content to
 *       the @p sendfile.pco_tst.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/file2file"

#include "sendfile_common.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             file_length;

    const char     *file_tpl = "sendfile.tpl";
    const char     *file_iut = "sendfile.pco_iut";
    const char     *file_tst = "sendfile.pco_tst";
    const char     *file_ret = "sendfile.ret";

    te_bool         created_tpl = FALSE;
    te_bool         created_iut = FALSE;
    te_bool         created_tst = FALSE;
    te_bool         created_ret = FALSE;

    int             src = -1;
    int             dst = -1;

    tarpc_off_t     offset;
    te_bool         use_sendfile = FALSE;


    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_BOOL_PARAM(use_sendfile);

    /* Scenario */

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'A', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;

    CREATE_REMOTE_FILE(pco_iut->ta, file_tst, '\0', file_length);
    created_tst = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);
    RPC_FOPEN_D(dst, pco_iut, file_tst,
                RPC_O_WRONLY | RPC_O_CREAT, RPC_S_IRWXU);

    offset = 0;
    if (use_sendfile)
        rpc_sendfile(pco_iut, dst, src, &offset, file_length, FALSE);
    else
        rpc_sendfile_via_splice(pco_iut, dst, src, &offset, file_length);

    RPC_CLOSE(pco_iut, dst);

    RETRIEVE_REMOTE_FILE(pco_iut->ta, file_tst, file_ret);
    created_ret = TRUE;

    COMPARE_PROCESSED_FILES(file_tpl, file_ret);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, dst);
    CLEANUP_RPC_CLOSE(pco_iut, src);

    if (created_tpl)
        REMOVE_LOCAL_FILE(file_tpl);

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    if (created_tst)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_tst);

    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    TEST_END;
}
