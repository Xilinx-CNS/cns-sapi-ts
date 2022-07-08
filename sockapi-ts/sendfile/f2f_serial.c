/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-f2f_serial sendfile() behavior on using of the serial device as out file
 *
 * @objective Check @b sendfile() behavior in case of passing the file
 *            descriptor of the opened serial device ("/dev/mouse" or
 *            "/dev/null", for example) as @b out_fd parameters.
 *
 * @type conformance
 *
 * @reference  MAN 2 sendfile
 *
 * @param pco_iut           PCO on IUT
 * @param dev_name      The name of serial device (for example: "/dev/null")
 * @param exp_errno     Expected @b errno value
 *
 * @par Test sequence:
 *
 * -# Create @p sendfile.pco_iut on @p pco_iut.
 * -# Open @p sendfile.pco_iut for reading on @p pco_iut and retrieve @p src file
 *    descriptor.
 * -# Open @p dev_name for writing on @p pco_iut and retrieve @p dst file
 *    descriptor.
 * -# Call @b sendfile() on @p pco_iut with @p dst file descriptor as @a out_fd
 *    parameter and @p src file descriptor as @a in_fd parameter.
 * -# If @p exp_errno is 0, then check that @b sendfile() returns no errors,
 *    else check that @c -1 is returned and @b errno is set to @p exp_errno.
 * -# Close @p src, @p dst file descriptors.
 * -# Close files opened for test purposes.
 * -# Remove file created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2f_serial"

#include "sendfile_common.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char     *dev_name = NULL;
    rpc_errno       exp_errno;
    int             file_length;

    const char     *file_iut = "sendfile.pco_iut";
    te_bool         created_iut = FALSE;
    int             src = -1;
    int             dst = -1;
    int             sent;
    tarpc_off_t     offset;
    te_bool         use_sendfile = FALSE;


    /* Preambule */
    TEST_START;
    TEST_GET_STRING_PARAM(dev_name);
    TEST_GET_ERRNO_PARAM(exp_errno);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_BOOL_PARAM(use_sendfile);
    TEST_GET_PCO(pco_iut);

    /* Scenario */
    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'M', file_length);
    created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    dst = rpc_open(pco_iut, dev_name, RPC_O_WRONLY, 0);
    if (dst < 0)
    {
        TEST_VERDICT("open(%s, O_WRONLY, 0) failed with errno %s",
                     dev_name, errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    offset = 0;
    if (use_sendfile)
        sent = rpc_sendfile(pco_iut, dst, src, &offset, file_length, FALSE);
    else
        sent = rpc_sendfile_via_splice(pco_iut, dst, src, &offset,
                                       file_length);
    if (exp_errno == 0)
    {
        if (sent == -1)
        {
            TEST_VERDICT("sendfile() to %s failed with errno %s",
                         dev_name, errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }
    else
    {
        if (sent != -1)
        {
            TEST_VERDICT("sendfile() returned %d instead of expected -1",
                         sent);
        }
        CHECK_RPC_ERRNO(pco_iut, exp_errno,
                        "sendfile() to %s returns -1, but", dev_name);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, dst);
    CLEANUP_RPC_CLOSE(pco_iut, src);

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    TEST_END;
}
