/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * sendfile() functionality
 * 
 * $Id$
 */

/** @page sendfile-f2s_nonblocking Usage of sendfile() on socket set to non-blocking mode
 *
 * @objective Check a behavior of @b sendfile() if @p socket descriptor
 *            is used as out_fd parameter and socket set to the non-blocking
 *            mode.
 *
 * @type conformance
 *
 * @reference MAN 2 sendfile
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on tester
 * @param time2run      Timeout for data waiting
 * @param file_length   Length used for file processing
 *                      (creation/copying/comparison)
 *
 * @par Test sequence:
 *
 * -# Create connection between @p pco_iut and @p pco_tst with  
 *    the @c SOCK_STREAM type and retrieve @b iut_s and @b tst_s
 *    socket descriptors.
 * -# Call @b getsockopt(@c SO_SNDBUF) on @b iut_s to get current send
 *    buffer size to @p snd_len.
 * -# Call @b getsockopt(@c SO_SNDLOWAT) on @b iut_s to get current 
 *    option value for informational purposes, ignore errors.
 * -# Call @b getsockopt(@c SO_RCVBUF) on @b tst_s to get current
 *    receive buffer size @p rcv_len.
 * -# Prepare original @p sendfile.tpl file and copy it to the @p pco_iut
 *    as @p sendfile.pco_iut with length (@p snd_len + @p rcv_len) * 2.
 * -# Call @b ioctl(@c FIONBIO) on @b iut_s to enable non-blocking
 *    for socket.
 * -# Open @p sendfile.pco_iut for reading on @p pco_iut and retrieve
 *    @p src file descriptor.
 * -# Call @b sendfile() on @p pco_iut while return code will be @c -1
 *    and @b errno will be @c EAGAIN. @b sendfile() should be called
 *    with @p iut_s socket descriptor as @p out_fd parameter, @p src
 *    file descriptor as @p in_fd parameter and @p file_length as
 *    @p count parameter.
 * -# Call remote @b socket_to_file() procedure on the @b pco_tst side
 *    to receive data sent by means of @b sendfile() and write its to
 *    the file @p sendfile.pco_tst.
 * -# Call @b sendfile() on @p pco_iut to continue file copying.
 *    @b sendfile() should be called with @p iut_s socket descriptor
 *    as @p out_fd parameter, @p src file descriptor as @p in_fd
 *    parameter and @p file_length as @p count parameter.
 * -# Check that contents of the both @p sendfile.pco_tst file and
 *    original @p sendfile.tpl file are the same.
 * -# Close files opened for test purposes.
 * -# Remove files created for test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendfile/f2s_nonblocking"

#include "sendfile_common.h"

/**
 * TCP can increase SO_SNDBUF and SO_RCVBUF while running (see man 7 tcp) so we
 * are using a big enough constant for the file size.
 * For now 16 MiB is enough to fill send and recv buffers.
 */
#define FILE_LENGTH (1<<24)

#define SENDFILE_NONBLOCKING \
    do {                                                                \
        te_bool slept = FALSE;                                          \
                                                                        \
        do {                                                            \
            sent = 0; err = 0;                                          \
            RPC_AWAIT_IUT_ERROR(pco_iut);                               \
            sent = rpc_sendfile(pco_iut, iut_s, src, &offset,           \
                                to_send, FALSE);                        \
            if (sent > 0)                                               \
            {                                                           \
                if (prev_offset + sent != offset)                       \
                {                                                       \
                    TEST_FAIL("sendfile() on IUT incorrectly updated "  \
                              "offset parameter: old=%u, new=%u, "      \
                              "sent=%u", (unsigned)prev_offset,         \
                              (unsigned)offset, (unsigned)sent);        \
                }                                                       \
                prev_offset = offset;                                   \
                total += sent;                                          \
                to_send -= sent;                                        \
                slept = FALSE;                                          \
            }                                                           \
            else if (sent == -1)                                        \
            {                                                           \
                err = RPC_ERRNO(pco_iut);                               \
                if (err != RPC_EAGAIN)                                  \
                {                                                       \
                    TEST_FAIL("RPC sendfile() on IUT failed "           \
                              "RPC_errno=%X", TE_RC_GET_ERROR(err));    \
                }                                                       \
                if (offset != prev_offset)                              \
                {                                                       \
                    if (!verdict_logged)                                \
                    {                                                   \
                        verdict_logged = TRUE;                          \
                        RING_VERDICT("sendfile() returned -1 with "     \
                                     "EAGAIN, but updated offset");     \
                    }                                                   \
                    sent = offset - prev_offset;                        \
                    prev_offset = offset;                               \
                    total += sent;                                      \
                    to_send -= sent;                                    \
                    slept = FALSE;                                      \
                }                                                       \
                if (!slept)                                             \
                {                                                       \
                    MSLEEP(300);                                        \
                    slept = TRUE;                                       \
                    err = 0;                                            \
                }                                                       \
            }                                                           \
            else if (sent == 0)                                         \
            {                                                           \
                TEST_FAIL("sendfile() to a non-blocking socket "        \
                          "returned 0 unexpectedly");                   \
            }                                                           \
            if (to_send == 0)                                           \
                break;                                                  \
        } while (err != RPC_EAGAIN);                                    \
    } while (FALSE)


int
main(int argc, char *argv[])
{
    te_bool                 verdict_logged = FALSE;

    int                     err = 0;
    rcf_rpc_server         *pco_iut    = NULL;
    rcf_rpc_server         *pco_tst    = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    const char             *file_tpl = "orig.tpl";
    const char             *file_iut = "sendfile.pco_iut";
    const char             *file_tst = "sendfile.pco_tst";
    const char             *file_ret = "sendfile.ret";
    te_bool                 created_tpl = FALSE;
    te_bool                 created_iut = FALSE;
    te_bool                 created_tst = FALSE;
    te_bool                 created_ret = FALSE;
    size_t                  to_send;
    long                    sent;
    long                    received;
    long                    total = 0;
    long                    time2run;
    int                     src = -1;
    tarpc_off_t             offset;
    tarpc_off_t             prev_offset = 0;
    int                     snd_len = 0;
    int                     rcv_len = 0;
    int                     lowat_len = -1;
    int                     req_val;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(time2run);

    /* Scenario */
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &snd_len);

    /* If option is not supported, it is not a reason to fail */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_SNDLOWAT, &lowat_len);

    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &rcv_len);

    PREPARE_REMOTE_FILE(pco_iut->ta, FILE_LENGTH, 'X', file_tpl, file_iut);
    created_tpl = created_iut = TRUE;

    RPC_FOPEN_D(src, pco_iut, file_iut, RPC_O_RDONLY, 0);

    req_val = TRUE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    INFO("lowat_len=%d, snd_len=%d, rcv_len=%d, file_length=%d\n",
         lowat_len, snd_len, rcv_len, FILE_LENGTH);

    to_send = FILE_LENGTH;
    offset = 0;
    SENDFILE_NONBLOCKING;

    if (to_send == 0)
    {
        ERROR("The file length is %d bytes", FILE_LENGTH);
        TEST_VERDICT("The file is too small for the test");
    }

    pco_tst->op = RCF_RPC_CALL;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, time2run);
    created_tst = TRUE;

    SENDFILE_NONBLOCKING;

    pco_tst->op = RCF_RPC_WAIT;
    RPC_SOCKET_TO_FILE(received, pco_tst, tst_s, file_tst, time2run);

    if (received != total)
    {
        TEST_FAIL("The number of sent (%d) and received (%d) "
                  "bytes is not the same", total, received);
    }

    RPC_CLOSE(pco_iut, src);

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
    if (created_iut)
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    if (created_tst)
        REMOVE_REMOTE_FILE(pco_tst->ta, file_tst);
    if (created_ret)
        REMOVE_LOCAL_FILE(file_ret);

    TEST_END;
}
