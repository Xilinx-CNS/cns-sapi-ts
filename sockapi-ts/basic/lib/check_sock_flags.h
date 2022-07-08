/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros for tests checking whether socket flags took into
 * effect.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 *
 * $Id$
 */

#include "sockapi-test.h"

/**
 * Check that a socket was closed after exec() actually.
 *
 * @param pco_iut       IUT RPC server
 * @param pco_tst       TESTER RPC server
 * @param iut_s         Socket on IUT
 * @param tst_s         Socket on TESTER
 * @param ebadf_only    Whether to check only EBADF error on
 *                      a socket (used when socket has more than one
 *                      fd opened for it, and not all the fds were
 *                      closed - so it cannot be detected from a
 *                      peer)
 * @param is_failed     Where to store result of checking
 * @param msg           Text with which every error or
 *                      warning message should be prefixed
 */
static inline void check_sock_cloexec(rcf_rpc_server *pco_iut,
                                      rcf_rpc_server *pco_tst,
                                      int iut_s,
                                      int tst_s,
                                      rpc_socket_type sock_type,
                                      te_bool ebadf_only,
                                      te_bool *is_failed,
                                      char *msg)
{
#define FAILED \
    do {                        \
        if (is_failed != NULL)  \
            *is_failed = TRUE;  \
        else                    \
            TEST_STOP;          \
    } while (0)

    void                   *rd_buf = NULL;
    size_t                  rd_buflen;
    void                   *wr_buf = NULL;
    size_t                  wr_buflen;
    int                     sent = 0;
    int                     rc = 0;

    if (sock_type == RPC_SOCK_STREAM)
        wr_buf = sockts_make_buf_stream(&wr_buflen);
    else
        wr_buf = sockts_make_buf_dgram(&wr_buflen);
    rd_buf = te_make_buf_min(wr_buflen, &rd_buflen);

    if (!ebadf_only)
    {
        if (sock_type == RPC_SOCK_DGRAM)
        {
            RPC_SEND(sent, pco_tst, tst_s, wr_buf, wr_buflen, 0);
            TAPI_WAIT_NETWORK;
            RPC_AWAIT_IUT_ERROR(pco_tst);
            sent = rpc_send(pco_tst, tst_s, wr_buf, wr_buflen, 0);
            if (sent != -1)
            {
                ERROR_VERDICT("%ssend() called the second time successed "
                              "instead of -1 (peer should be closed)",
                              msg, sent);
                FAILED;

                TAPI_WAIT_NETWORK;
                RPC_AWAIT_IUT_ERROR(pco_tst);
                sent = rpc_send(pco_tst, tst_s, wr_buf, wr_buflen, 0);
                if (sent != -1)
                    ERROR_VERDICT("%ssend() called the third time "
                                  "successeed instead of -1 (peer "
                                  "should be closed)",
                                  msg, sent);
            }
            if (sent == -1 && RPC_ERRNO(pco_tst) != RPC_ECONNREFUSED)
            {
                ERROR_VERDICT("%sPeer should close socket"
                              " and send() returned -1, but "
                              "errno is %s", msg,
                              errno_rpc2str(RPC_ERRNO(pco_tst)));
                FAILED;
            }
        }
        else if (sock_type == RPC_SOCK_STREAM)
        {
            rc = rpc_recv(pco_tst, tst_s, rd_buf, rd_buflen, 0);
            if (rc != 0)
            {
                ERROR_VERDICT("%sRemote peer should sent FIN on "
                              "'exec' operation, and return 0 "
                              "instead of %d", msg, rc);
                FAILED;
            }

            if (tapi_get_tcp_sock_state(pco_tst, tst_s) !=
                RPC_TCP_CLOSE_WAIT)
            {
                ERROR_VERDICT("%sTCP socket on the peer is not in "
                              "TCP_CLOSE_WAIT state after exec() "
                              "call despite of the fact that "
                              "close-on-exec flag was set for the socket",
                              msg);
                FAILED;
            }
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recv(pco_iut, iut_s, rd_buf, rd_buflen, 0);
    if (rc != -1)
    {
        ERROR_VERDICT("%srecv() returned %d instead of -1 "
                     "(socket should be closed)", msg, rc);
        FAILED;
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EBADF)
    {
        ERROR_VERDICT("%sSocket should be closed"
                      " and send() returned -1, but "
                      "errno is %s", msg,
                      errno_rpc2str(RPC_ERRNO(pco_iut)));
        FAILED;
    }

    free(wr_buf);
    free(rd_buf);

#undef FAILED
}
