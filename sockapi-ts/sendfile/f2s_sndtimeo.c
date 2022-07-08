/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sendfile-f2s_sndtimeo Behaviour of sendfile() if SO_SNDTIMEO option set on socket
 *
 * @objective Check that when @c SO_SNDTIMEO option is set for a TCP
 *            socket @b sendfile() completes processing on.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 * @param sndtimeo  Timeout to be set on socket (milliseconds)
 *
 * @par Test sequence:
 *
 * -# Create @c SOCK_STREAM connection between @p pco_iut and @p pco_tst. 
 *    As a result two sockets appear @p iut_s and @p tst_s;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p iut_s socket with @c SO_SNDBUF option
 *    to get its default value;
 * -# Call @b getsockopt() on @p tst_s socket with @c SO_RCVBUF option
 *    to get its default value;
 * -# Create file on @c IUT side with length more than total sum of
 *    receive and send buffers on @p tst_s and @p iut_s accordingly;
 * -# Set @p sndtimeo on @p iut_s by means of SO_SNDTIMEO socket option;
 * -# Call @b sendfile() with opened file descriptor of created file as
 *    @p in_fd and @p iut_s as out_fd while it returns -1 and @b errno
 *    set to @c EAGAIN.
 * -# Check that @b sendfile() operation duration has tolerable deviation
 *    with @p sndtimeo value set on @p iut_s;
 * -# Close created sockets and remove created file.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2s_sndtimeo"

#include "sockapi-test.h"
#include "sendfile_common.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    src   = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    int                    rcv_buflen;
    int                    snd_buflen;

    te_bool                created_iut = FALSE;
    const char            *file_iut = "sendfile.pco_iut";
    int                    file_length = 0;

    tarpc_timeval          tv;
    int                    sndtimeo = 0;
    int                    sent;
    tarpc_off_t            offset = 0;
    tarpc_off_t            save_offset;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(sndtimeo);

    /* Scenario */
    tv.tv_sec = sndtimeo / 1000;
    tv.tv_usec = (sndtimeo % 1000) * 1000;

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    sent = rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &tv);
    if (sent != 0)
    {
        TEST_VERDICT("setsockopt(SOL_SOCKET, SO_SNDTIMEO) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &snd_buflen);

    RING("The length of 'iut_s' send buffer is %d", snd_buflen);

    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &rcv_buflen);

    RING("The length of 'tst_s' receive buffer is %d", rcv_buflen);

    file_length = (snd_buflen + rcv_buflen) * 2;

    RING("The length of file to be sent is %d", file_length);

    CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'D', file_length);
    created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    do {
        save_offset = offset;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = rpc_sendfile(pco_iut, iut_s, src, &offset,
                            file_length - offset, FALSE);

        RING("sendfile() blocks within %d microseconds", pco_iut->duration);
        if (abs(sndtimeo - pco_iut->duration / 1000) > 1)
            WARN("Duration of sendfile() processing is not within "
                 "requested interval in msec: requested=%d, actually=%d",
                 sndtimeo, pco_iut->duration / 1000);
        if (sent < 0)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "sendfile() to a socket with set send "
                            "timeout returns %d, but", sent);
            if (offset != save_offset)
            {
                ERROR_VERDICT("sendfile() returned -1 with "
                              "EAGAIN, but updated offset");
            }
            break;
        }
        else if (sent == 0)
        {
            TEST_FAIL("sendfile() to a socket with set send timeout "
                      "returns 0");
        }
        else
        {
            if (save_offset + sent != offset)
            {
                TEST_FAIL("Previous offset is %d, sent is %d, but "
                          "current offset(%d) is not equal to the "
                          "sum %d", (int)save_offset, sent, (int)offset,
                          (int)(save_offset + sent));
            }
            if (offset > file_length)
            {
                TEST_FAIL("Current offset(%d) is greater than file "
                          "length(%d)", (int)offset, file_length);
            }
        }

        RING("sendfile() sends %d bytes within %d microseconds", 
             sent, pco_iut->duration);
    } while (1);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, src);

    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);

    TEST_END;
}

