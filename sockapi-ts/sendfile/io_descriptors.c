/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-io_descriptors sendfile() behavior on using of the in/out descriptors for files opened in inappropriate modes
 *
 * @objective Check @b sendfile() behavior in case of passing the in/out
 *            descriptors for files opened with inappropriate for @b sendfile()
 *            parameters modes.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut           PCO on IUT
 * @param dev_name      The device name (for example: "/dev/null")
 * @param file_length   The length used for file processing
 *                      (creation/copying/comparison)
 *
 * @par Test sequence:
 *
 * -# Create connection between @p pco_iut and @p pco_tst with 
 *    @c SOCK_STREAM type of socket.
 * -# Prepare original @p sendfile.tpl file and copy
 *    it to the @p pco_iut as @p sendfile.pco_iut (filled in with 'A').
 * -# Create @p sendfile.pco_tst on the @p pco_iut (filled in with '0'),
 *    See @ref io_descriptors_1 "note 1".
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Open @p sendfile.pco_iut for reading on @p pco_iut (legal) and
 *    retrieve @p src file descriptor.
 * -# Open @p sendfile.pco_tst for writing on @p pco_iut (legal) and
 *    retrieve @p dst file descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p dst file descriptor as @a out_fd
 *    parameter, @p src file descriptor as @a in_fd parameter, @a offset equal
 *    to @c 0 and @a count as @p file_length.
 * -# Check that @b sendfile() return @c -1 as return code and errno set to
 *    @c EINVAL.
 * -# Close @p src, @p dst file descriptors.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Open @p sendfile.pco_iut for writing on @p pco_iut (illegal) and
 *    retrieve @p src file descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p iut_s socket descriptor as
 *    @a out_fd parameter, @p src file descriptor as @a in_fd parameter,
 *    @a offset equal to @c 0 and @a count as @p file_length.
 * -# Check that @b sendfile() return @c -1 as return code and errno set to
 *    @c EACCES or @c EBADF.
 * -# Close @p src file descriptor.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Open @p dev_name for reading on @p pco_iut side
 *    (See @ref io_descriptors_1 "note 2")
 *    and retrieve @p src file descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p iut_s socket descriptor as
 *    @a out_fd parameter, @p src file descriptor as @a in_fd parameter,
 *    @a offset equal to @c 0 and @a count as @p file_length.
 * -# Check that @b sendfile() return @c -1 as return code and errno set to
 *    @c EINVAL.
 * -# Close @p src, @p dst file descriptors.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# open @p sendfile.pco_iut for reading on @p pco_iut (legal) and
 *    retrieve @p src file descriptor.
 * -# call @b sendfile() on @p pco_iut with @p iut_s socket descriptor as
 *    @a out_fd parameter, @p src file descriptor as @a in_fd parameter,
 *    @a offset equal to @c 0 and @a count as @p file_length.
 * -# Check that @b sendfile() performs file copy without errors.
 * -# Check that contents of the both @p sendfile.pco_tst file and original
 *    @p sendfile.tpl file are the same.
 * -# Close files opened on @p pco_iut.
 * -# Remove all files created for test purposes.
 *
 * @note 
 * -# @anchor io_descriptors_1
 *       @p sendfile.pco_tst and @p sendfile.pco_iut have the same @p file_length
 *       length but different content. Old content of @p sendfile.pco_tst should
 *       be lost and @b sendfile() should copy @p sendfile.pco_iut content to
 *       the @p sendfile.pco_tst.
 * -# @anchor io_descriptors_2
 *       In Linux implementation presently the descriptor from which data
 *       is read cannot correspond to a socket, it must correspond to a file
 *       which supports mmap()-like  operations.   It cannot be a socket or
 *       pipe, or live on a filesystem such as tmpfs or procfs that does not
 *       support mmap.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/io_descriptors"

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
    const char     *dev_name;
    int             file_length;

    te_bool         created_tpl = FALSE;
    te_bool         created_iut = FALSE;
    te_bool         created_iut1 = FALSE;
    te_bool         created_tst = FALSE;
    te_bool         created_ret = FALSE;
    te_bool         dst_opened_iut = FALSE;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int             src = -1;
    int             dst = -1;
    int             iut_s = -1;
    int             tst_s = -1;
    tarpc_off_t     offset = 0;

    ssize_t         sent;
    ssize_t         received;
    UNUSED(received);

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_STRING_PARAM(dev_name);

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    /* Create and open on 'pco_iut' two files for next sendto() operation */
    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'A', file_length);
    created_iut = TRUE;
    CREATE_REMOTE_FILE(pco_iut->ta, file_tst, 'B', file_length);
    created_iut1 = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);
    RPC_FOPEN_D(dst, pco_iut, file_tst, RPC_O_WRONLY | RPC_O_CREAT,
                RPC_S_IRWXU);
    dst_opened_iut = TRUE;

    /* Check that two file can't be copied by sendfile */
    offset = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_sendfile(pco_iut, dst, src, &offset, file_length, FALSE);

#ifdef LINUX_2_6_KERNEL
    if (sent != -1)
    {
        TEST_FAIL("sendfail() called with both file descriptors "
                  "(not supported) returns %d instead of -1", sent);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "sendfail() called with both file "
                    "descriptors returns -1, but");
#else
    {
        rpc_errno err = RPC_ERRNO(pco_iut);
        RING("if both 'src' and 'dst' are opened file sendfile() returns "
             "%d and errno is set to %s", sent, errno_rpc2str(err));
    }
#endif

    RPC_CLOSE(pco_iut, src);
    RPC_CLOSE(pco_iut, dst);
    dst_opened_iut = FALSE;
    if (created_iut1 == TRUE)
    {
        created_iut1 = FALSE;
        REMOVE_REMOTE_FILE(pco_iut->ta, file_tst);
    }

    if (created_iut == TRUE)
    {
        created_iut = FALSE;
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    }

    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'A', file_length);
    created_iut = TRUE;
    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_WRONLY | RPC_O_CREAT,
                RPC_S_IRWXU);
    /*
     * Check that file opened for writing can't be used in 
     * sendfile() operation as source.
     */
    offset = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_sendfile(pco_iut, iut_s, src, &offset, file_length, FALSE);
    if (sent != -1)
    {
        TEST_FAIL("sendfail() called with 'src' file descriptor opened for "
                  "writing returned %d instead of -1", sent);
    }
    if (RPC_ERRNO(pco_iut) == RPC_EBADF)
        RING_VERDICT("sendfail() called with 'src' file descriptor opened "
                     "for writing returns -1 with errno EBADF");
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EACCES, "sendfail() called with "
                        "'src' file descriptor opened for writing "
                        "returns -1");

    RPC_CLOSE(pco_iut, src);
    if (created_iut == TRUE)
    {
        created_iut = FALSE;
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    }

    src = rpc_open(pco_iut, dev_name, RPC_O_RDONLY, 0);

    /*
     * Check that serial device opened for reading can't be used as 'src'
     */
    offset = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_sendfile(pco_iut, iut_s, src, &offset, file_length, FALSE);

#ifdef LINUX_2_6_KERNEL
    if (sent != -1)
    {
        TEST_FAIL("sendfail() called with serial device file descriptor "
                  "opened for reading as in_fd parameter returned %d instead "
                  "of -1", sent);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,"sendfail() called with serial device "
                    "file descriptor opened for reading as in_fd parameter "
                    "returns -1");
#else
    {
        rpc_errno err = RPC_ERRNO(pco_iut);
        RING("if serial device opened to use as  'src' sendfile() returns "
         "%d and errno is set to %s", sent, errno_rpc2str(err));
    }
#endif
    RPC_CLOSE(pco_iut, src);

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'A', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

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

    if (dst_opened_iut == TRUE)
        CLEANUP_RPC_CLOSE(pco_iut, dst);
    CLEANUP_RPC_CLOSE(pco_iut, src);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (created_tpl)
        REMOVE_LOCAL_FILE(file_tpl);
    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    if (created_iut1)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_tst);
    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst);
    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    TEST_END;
}
