/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id: $
 */

/** @page sendfile-largefile2socket Usage of sendfile() to perform large file (file size > 2Gb, 4Gb) to socket copy
 *
 * @objective Check a possibility of fast copying of a file from
 *            high offsets (offset > 2Gb, 4Gb) to a socket
 *            by means of @b sendfile() system call.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on tester
 * @param timeout        Timeout for data waiting
 * @param sparse_offset  Offset used for sparse file creation
 *                       (lseek to that offset and then write some data there)
 * @param payload_length Length of data to write to the sparse file
 * @param send_offset    Sendfile offset to be added to @a sparse_offset
 * @param send_length    Length of the data to be sent (@c -1 stands for 
 *                       all remaining in the file after @p offset)
 *
 * @par Test sequence:
 *
 * -# Create connection between @p pco_iut and @p pco_tst with 
 *    @c SOCK_STREAM type of socket;
 * -# Prepare remotely @p sendfile.pco_iut file on the @p pco_iut,
 *    using @p sparse_offset and @p payload_length parameters;
 * -# Open @p sendfile.pco_iut on @p pco_iut and retrieve @p src file
 *    descriptor;
 * -# Call @b sendfile() on @p pco_iut with @p iut_s socket descriptor as 
 *    @a out_fd parameter, @p src file descriptor as @a in_fd parameter,
 *    @p offset = ( @a sparse_offset + @a send_offset ) parameter
 *    and @p send_length parameter;
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst to
 *    receive data sent by means of @b sendfile() and write its to
 *    the file @p sendfile.pco_tst;
 * -# Check that contents of the both @p sendfile.pco_tst file and part
 *    of the @p sendfile.pco_iut file in accordance with @p offset and 
 *    @p send_length parameters are the same;
 * -# Check that the sendfile() has updated file offset pointer correctly;
 * -# Check by lseek() call that the file offset of file descriptor
 *    is not changed by sendfile();
 * -# Close files opened for the test purposes;
 * -# Remove files created for test purposes.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/largefile2socket"

#include <stdlib.h>

#define _GNU_SOURCE     1
#include "sendfile_common.h"

#if HAVE_MATH_H
#include <math.h>
#endif

#include <stdlib.h>

int
main(int argc, char *argv[])
{
    rpc_socket_type         sock_type;
    te_bool                 performance;

    long long int           sparse_offset;
    long long int           payload_length;
    int64_t                 send_offset;
    int64_t                 send_length;

    int64_t                 file_length;
    int64_t                 offset;

    int                     timeout;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    int                     src = -1;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const char             *file_iut = "sendfile.pco_iut";
    const char             *file_tst = "sendfile.pco_tst";
    const char             *file_cmp = "sendfile.pco_tst_cmp";

    te_bool                 created_iut = FALSE;
    te_bool                 created_tst = FALSE;
    te_bool                 created_cmp = FALSE;

    te_bool                 nb_receiver_started = FALSE;

    tarpc_off_t             off;
    tarpc_off_t             off_lseek;

    ssize_t                 sent;
    ssize_t                 received;
    uint64_t                received64;
    uint64_t                duration;
    te_errno                err;


    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(timeout);

    TEST_GET_INT64_PARAM(sparse_offset);
    TEST_GET_INT64_PARAM(payload_length);
    TEST_GET_INT64_PARAM(send_offset);
    TEST_GET_INT64_PARAM(send_length);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(performance);

    file_length = sparse_offset + payload_length;
    offset = sparse_offset + send_offset;

    if (send_length == -1)
        send_length = file_length - send_offset - sparse_offset;
    else if (send_length < 0)
        TEST_FAIL("Invalid value of send_length parameter: %lld",
                  send_length);

    RING("Use file_length=%lld, offset=%lld, send_length=%lld",
         file_length, offset, send_length);

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    /* Prepare file on the IUT side for sending */
    CHECK_RC(create_remote_sparse_file(pco_iut->ta, file_iut,
                                       sparse_offset, payload_length, 'A'));
    created_iut = TRUE;

    /* Prepare reaper file on the TST side for comparison */
    CHECK_RC(create_remote_sparse_file(pco_tst->ta, file_cmp,
                                       (send_offset < 0) ? -send_offset : 0,
                                       payload_length, 'A'));
    created_cmp = TRUE;

    /* Open file on the IUT side for sending */
    {
        /*
         * Workaround the solaris tmpfs filesystem,
         * which does not support sparse files
         */

        char *pos = NULL;
        char  src_path_name[RCF_MAX_PATH];

        rc = rcf_ta_get_var(pco_iut->ta, 0, "ta_tmp_path",
                            RCF_STRING, RCF_MAX_PATH, src_path_name);
        if (rc != 0)
        {
            ERROR("%s(): failed to get ta_tmp_path variable, rc=%r",
                  __FUNCTION__, rc);
            strncpy(src_path_name, TA_TMP_PATH, RCF_MAX_PATH);
        }
        
        pos = src_path_name + strlen(src_path_name);
        strncpy(pos, file_iut, sizeof(src_path_name) - strlen(src_path_name));

        RPC_AWAIT_IUT_ERROR(pco_iut);
        src = rpc_open(pco_iut, src_path_name,
                       RPC_O_RDONLY | RPC_O_LARGEFILE, 0);
        if (src < 0)
        {
            RING("open64 call failed, trying to use open()");
            src = rpc_open64(pco_iut, src_path_name,
                           RPC_O_RDONLY | RPC_O_LARGEFILE, 0);
        }

        VERB("file %s opened with descriptor %d", src_path_name, src);  \
    }

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

    /*
     * It is assumed here that speed is at least 100Mbits/sec
     * Double the timeout to account for connection problems that rarely occur
     * See ST-2733.
     */
    pco_iut->timeout = (pco_iut->def_timeout + send_length / 10000) * 2;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    off = offset;
    sent = rpc_sendfile(pco_iut, iut_s, src, &off, send_length, TRUE);
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
            ERROR("sendfile() returns offset %d instead of %d",
                  off, offset + sent);
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
            created_tst = TRUE;
        }

        if (received > 0)
        {
            if (!performance)
            {
                if (compare_remote_files(pco_tst->ta, file_tst, 0, file_cmp, 0,
                                         MIN(file_length - offset,
                                             send_length)) != 0)
                {
                    TEST_VERDICT("Received part file doesn't match "
                                 "the original one");
                }
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
        created_tst = TRUE;
    }
    if (received != sent)
    {
        TEST_FAIL("The number of sent (%d) and received (%d) bytes "
                  "is not the same", sent, received);
    }
    
    if (sent != MIN(file_length - offset, send_length))
    {
        TEST_FAIL("Unexpected number of the sent bytes: "
                  "sent %d expected:%d",
                  sent, MIN(file_length - offset, send_length));
    }
    if (off != offset + sent)
    {
        TEST_VERDICT("sendfile() offset parameter updated incorrectly");
    }

    if (!performance)
    {
        if (!performance)
        {
            if (compare_remote_files(pco_tst->ta, file_tst, 0, file_cmp, 0,
                                     MIN(file_length - offset,
                                         send_length)) != 0)
            {
                TEST_VERDICT("Received part file doesn't match "
                             "the original one");
            }
        }
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

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst);
    if (created_cmp)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_cmp);

    TEST_END;
}
