/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-file2socket Usage of sendfile() to preform file to socket copy
 *
 * @objective Check a possibility of fast copying of a file to a socket
 *            by means of @b sendfile() system call.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on tester
 * @param timeout       Timeout for data waiting
 * @param file_length   Length used for file processing
 *                      (creation/copying/comparison)
 * @param offset        Offset in the file to start sending
 * @param send_length   Length of the data to be sent (@c -1 stands for 
 *                      all remaining in the file after @p offset)
 *
 * @par Test sequence:
 *
 * -# Create connection between @p pco_iut and @p pco_tst with 
 *    @c SOCK_STREAM type of socket;
 * -# Prepare original @p sendfile.tpl file and copy it to the @p pco_iut 
 *    as @p sendfile.pco_iut;
 * -# Open @p sendfile.pco_iut on @p pco_iut and retrieve @p src file
 *    descriptor;
 * -# Call @b sendfile() on @p pco_iut with @p iut_s socket descriptor as 
 *    @a out_fd parameter, @p src file descriptor as @a in_fd parameter,
 *    @p offset as @a offset parameter and @p send_length as @a size
 *    parameter;
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst to
 *    receive data sent by means of @b sendfile() and write its to
 *    the file @p sendfile.pco_tst;
 * -# Check that contents of the both @p sendfile.pco_tst file and part
 *    of the @p sendfile.tpl file in accordance with @p offset and 
 *    @p send_length parameters are the same;
 * -# Check that the sendfile() has updated file offset pointer correctly;
 * -# Check by lseek() call that the file offset of file descriptor
 *    is not changed by sendfile();
 * -# Close files opened for the test purposes;
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/file2socket"

#define _GNU_SOURCE     1
#include "sendfile_common.h"

#if HAVE_MATH_H
#include <math.h>
#endif


int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    te_bool                 performance;
    int                     file_length;
    int                     offset;
    int                     send_length;
    int                     timeout;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     src = -1;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const char             *file_tpl = "sendfile.tpl";
    const char             *file_iut = "sendfile.pco_iut";
    const char             *file_tst = "sendfile.pco_tst";
    const char             *file_ret = "sendfile.ret";

    te_bool                 created_tpl = FALSE;
    te_bool                 created_iut = FALSE;
    te_bool                 created_tst = FALSE;
    te_bool                 created_ret = FALSE;

    te_bool                 nb_receiver_started = FALSE;

    tarpc_off_t             off;
    tarpc_off_t             off_lseek;

    ssize_t                 sent;
    ssize_t                 received;
    uint64_t                received64;
    uint64_t                duration;
    te_errno                err;
    te_bool                 use_sendfile = FALSE;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(file_length);
    TEST_GET_INT_PARAM(offset);
    TEST_GET_INT_PARAM(send_length);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(performance);
    TEST_GET_BOOL_PARAM(use_sendfile);

    if (send_length == -1)
        send_length = file_length - offset;
    else if (send_length < 0)
        TEST_FAIL("Invalid value of send_length parameter: %d",
                  send_length);

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    PREPARE_REMOTE_FILE(pco_iut->ta, file_length, 'A', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    pco_tst->op = RCF_RPC_CALL;
    if (performance)
    {
        rpc_simple_receiver(pco_tst, tst_s, timeout, &received64);
    }
    else
    {
        RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, timeout);
        created_tst = TRUE;
    }
    nb_receiver_started = TRUE;

    /* It is assumed here that speed is at least 100Mbits/sec */
    pco_iut->timeout = pco_iut->def_timeout + send_length / 10000;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    off = offset;
    if (use_sendfile)
        sent = rpc_sendfile(pco_iut, iut_s, src, &off, send_length, FALSE);
    else
        sent = rpc_sendfile_via_splice(pco_iut, iut_s, src, &off,
                                       send_length);
    duration = pco_iut->duration;
    err = RPC_ERRNO(pco_iut);

    /*
     * Check that sendfile does not change the offset
     * of source file descriptor
     */
    off_lseek = rpc_lseek(pco_iut, src, 0, RPC_SEEK_CUR);
    if (off_lseek != 0)
    {
        WARN("lseek() returned offset %lld instead of %d",
             (long long)off_lseek, 0);
        TEST_VERDICT("lseek() reports that sendfile() changed "
                     "source file offset");
    }

    if (sent > 0)
    {
        TE_LOG_RING("Performance",
                    "Sent %lu bytes, during %llu us => %lld bits/sec",
                    (unsigned long)sent, (unsigned long long)duration,
                    llround((((double)sent * 8.0) * 1e6) /
                            (double)duration));

        if (offset + send_length <= file_length)
        {
            if (send_length != sent)
            {
                RING("sendfile() sent %d bytes instead of %d", 
                     sent, send_length);
                RING_VERDICT("sendfile() sent different amount of data "
                             "than requested");
            }
        }
        else
        {
            if (file_length - offset != sent)
            {
                RING("sendfile() sent %d bytes instead of %d", 
                     sent, file_length - offset);
                RING_VERDICT("sendfile() sent different amount of data "
                             "than expected");
            }
        }
        
        if (off != offset + sent)
        {
            ERROR("sendfile() returns offset %lld instead of %lld",
                  (long long)off, (long long)(offset + sent));
            TEST_VERDICT("sendfile() did not update offset properly");
        }
    }
    else if (sent == 0)
    {
        if (off != offset)
        {
            TEST_VERDICT("sendfile() returned 0 but changed offset");
        }
    }
    else if (offset + send_length > file_length)
    {
        RING_VERDICT("sendfile() with too big length to be sent in "
                     "comparison with source file length failed with "
                     "errno %s", errno_rpc2str(err));

        /* Try to receive some data anyway  */
        nb_receiver_started = FALSE;
        pco_tst->op = RCF_RPC_WAIT;
        if (performance)
        {
            rpc_simple_receiver(pco_tst, tst_s, timeout, &received64);
            received = (ssize_t)received64;
        }
        else
        {
            RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, timeout);
        }

        if (received > 0)
        {
            RING_VERDICT("Data was sent and received(%d) bytes", received);
            if (!performance)
            {
                RETRIEVE_REMOTE_FILE(pco_tst->ta, file_tst, file_ret);
                created_ret = TRUE;

                COMPARE_PROCESSED_WITH_TMPL(file_tpl, offset,
                                            MIN(file_length - offset,
                                                send_length),
                                            file_ret);
            }
        }
        else
        {
            RING_VERDICT("Data was not sent, no data received");
        }
        
        TEST_SUCCESS;
    }
    else
    {
        TEST_VERDICT("sendfile() for %s destination socket failed with "
                     "errno %s", socktype_rpc2str(sock_type),
                     errno_rpc2str(err));
    }

    nb_receiver_started = FALSE;
    pco_tst->op = RCF_RPC_WAIT;
    if (performance)
    {
        rpc_simple_receiver(pco_tst, tst_s, timeout, &received64);
        received = (ssize_t)received64;
    }
    else
    {
        RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, timeout);
    }
    if (received != sent)
    {
        TEST_FAIL("The number of sent (%d) and received (%d) bytes "
                  "is not the same", sent, received);
    }
    
    if (sent != MIN(file_length - offset, send_length))
    {
        TEST_FAIL("Unexpected number of the sent bytes: "
                  "sent %d expected:%d", sent, file_length);
    }
    if (off != offset + sent)
    {
        TEST_VERDICT("sendfile() offset parameter updated incorrectly");
    }

    if (!performance)
    {
        RETRIEVE_REMOTE_FILE(pco_tst->ta, file_tst, file_ret);
        created_ret = TRUE;

        COMPARE_PROCESSED_WITH_TMPL(file_tpl, offset,
                                    MIN(file_length - offset, send_length),
                                    file_ret);
    }

    TEST_SUCCESS;

cleanup:
    if (nb_receiver_started)
    {
        nb_receiver_started = FALSE;
        pco_tst->op = RCF_RPC_WAIT;
        if (performance)
        {
            rpc_simple_receiver(pco_tst, tst_s, timeout, &received64);
            if (received64 != 0)
            {
                TEST_FAIL("simple_receiver() received %u bytes of data "
                          "when sendfile() fails", (unsigned int)received64);
            }
        }
        else
        {
            RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, timeout);
            if (received != 0)
            {
                TEST_FAIL("socket_to_file() received %d bytes of data "
                          "when sendfile() fails", received);
            }
        }
    }

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
