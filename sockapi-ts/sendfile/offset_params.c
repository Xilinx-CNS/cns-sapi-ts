/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-offset_params sendfile() behavior on using of illegal offset parameter
 *
 * @objective Check @b sendfile() behavior in case of passing an illegal
 *            offset parameter.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut           PCO on IUT
 * @param ofs           The value used as @b sendfile() @a offset parameter
 * @param file_length   The length used for file processing
 *                      (creation/copying/comparison)
 *
 * @par Test sequence:
 *
 * -# Create connection between @p pco_iut and @p pco_tst with 
 *    @c SOCK_STREAM type of socket.
 * -# Prepare original @p sendfile.tpl file and copy
 *    it to the @p pco_iut as @p sendfile.pco_iut (filled in with 'A').
 * -# Open @p sendfile.pco_iut on @p pco_iut and retrieve @p src file
 *    descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p iut_s file descriptor as
 *    @a out_fd parameter, @p src file descriptor as @a in_fd parameter,
 *    @p file_length as @a count parameter and @p ofs as @a offset parameter.
 * -# Check that @b sendfile():
 *      - performs processing without errors, but destination file has
 *        @c 0 length if @p ofs is negative;
 *      - performs processing without errors, but destination file has
 *        @p file_length length if @p ofs is @c 0;
 *      - performs processing without errors, but destination file has
 *        @p file_length - @p ofs length if @p ofs is ]@c 0 .. @p file_length[;
 *      - performs processing without errors, but destination file has
 *        @c 0 length if @p ofs > @p file_length;
 * -# Close files opened for test purposes.
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/offset_params"

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
    UNUSED(received);

    int             offset;
    tarpc_off_t     cur_off;
    tarpc_off_t     orig_off;
    int             file_length;
    int             to_send;
    struct stat     file_stat;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(offset);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_INT_PARAM(to_send);
    orig_off = cur_off = offset;

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'Q', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    pco_tst->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, 3);
    created_tst = TRUE;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_sendfile(pco_iut, iut_s, src, &cur_off, to_send, FALSE);

    pco_tst->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, 3);

    RETRIEVE_REMOTE_FILE(pco_tst->ta, file_tst, file_ret);
    created_ret = TRUE;

    RETRIEVE_STAT(file_ret, file_stat);

    if (orig_off < 0)
    {
        if (cur_off != orig_off)
        {
            TEST_FAIL("Initial offset is negative (%d), but sendfile() "
                      "returns %d with errno %s and updates offset "
                      "to %d", (int)orig_off, sent,
                      errno_rpc2str(RPC_ERRNO(pco_iut)), (int)cur_off);
        }

        RING("Initial offset is negative (%d), sendfile() returns "
             "%d with errno %s and does not update offset",
             (int)orig_off, sent, errno_rpc2str(RPC_ERRNO(pco_iut)));

        if (file_stat.st_size != 0)
        {
            TEST_FAIL("Unexpected length of the file gotten as result "
                      "of sendfile() operation with negative value of "
                      "offset parameter");
        }
    }
    else if (orig_off + to_send > file_length && sent == -1)
    {
        RING_VERDICT("sendfile() with offset plus size of data to send "
                     "larger than file size fails with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else if (orig_off + sent != cur_off)
    {
        TEST_FAIL("Initial offset is %d, sent is %d, but returned "
                  "offset(%d) is not equal to the sum %d",
                  (int)orig_off, sent, (int)cur_off,
                  (int)(orig_off + sent));
    }
    else
    {
        if (orig_off < file_length)
        {
            if (file_stat.st_size != MIN(to_send, file_length - orig_off))
            {
                TEST_FAIL("Unexpected length of the file gotten as result "
                          "of sendfile() operation with value of offset "
                          "parameter in range [0..src_file_length)");
            }
        }
        else
        {
            if (file_stat.st_size != 0)
            {
                TEST_FAIL("Unexpected length of the file gotten as result "
                          "of sendfile() operation with value of "
                          "offset parameter more than src file length");
            }
            if (sent != 0)
            {
                TEST_FAIL("Initial offset is greater or equal to file length, "
                          "but sendfile() returns non zero (%d) bytes sent",
                          sent);
            }
        }
        COMPARE_PROCESSED_WITH_TMPL(file_tpl, orig_off,
                                    MIN(file_length - orig_off, sent),
                                    file_ret);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, src);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (created_tpl)
        REMOVE_LOCAL_FILE(file_tpl);
    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst);
    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    TEST_END;
}
