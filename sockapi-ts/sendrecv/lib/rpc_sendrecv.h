/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Auxiliary functions for sending and receiving data.
 *
 * @author Elena Vangerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_RPC_SENDRECV_H__
#define __TS_RPC_SENDRECV_H__

#include "sockapi-test.h"

#ifdef __cplusplus
extern "C" {
#endif

static char big_buf[8192 + 10];

/**
 * Receive data with onload_zc_recv(), saving received data
 * in a single buffer.
 *
 * @param rpcs        RPC server handle.
 * @param s           Socket FD.
 * @param rx_buf      Buffer where to save received data.
 * @param len         Length of the buffer.
 * @param msgs_num    Number of messages after which to stop
 *                    processing and return from onload_zc_recv()
 *                    (should not be more than
 *                    @c SOCKTS_RECV_BY_ZC_RECV_MAX_MSGS;
 *                    if negative, the maximum number will be used).
 * @param flags       Flags to pass to the function.
 *
 * @return Number of received bytes on success, negative value
 *         in case of failure.
 */
extern ssize_t sockts_recv_by_zc_recv(rcf_rpc_server *rpcs, int s,
                                      char *rx_buf, int len, int msgs_num,
                                      rpc_send_recv_flags flags);

/** Maximum number of messages supported in sockts_recv_by_zc_recv() */
#define SOCKTS_RECV_BY_ZC_RECV_MAX_MSGS 5

/**
 * Receive data on the IUT using specified function.
 *
 * @param func          Function to be used.
 * @param pco_iut       RPC server handle.
 * @param iut_s         Socket FD.
 * @param sock_type     Socket type (influences only @b onload_zc_recv();
 *                      in case of UDP it will receive the single message
 *                      like other functions).
 * @param rx_buf        Buffer where to save received data.
 * @param len           Buffer length.
 * @param flags         Flags to be passed to the function.
 *
 * @return Result returned by corresponding receive function
 */
static inline ssize_t
recv_by_func_ext(const char *func, rcf_rpc_server *pco_iut, int iut_s,
                 rpc_socket_type sock_type, char *rx_buf, int len,
                 rpc_send_recv_flags flags)
{
    int     rlen = len + 10;
    ssize_t rc = 0;

    assert(rlen <= (int)sizeof(big_buf));

    if (strcmp(func, "read") == 0)
    {
        rc = rpc_read_gen(pco_iut, iut_s, big_buf, len, rlen);
    }
    else if (strcmp(func, "aio_read") == 0)
    {
        rc = rpc_aio_read_blk_gen(pco_iut, iut_s, big_buf, len, 
                                  rand_range(TARPC_AIO_BLK_SUSPEND, 
                                             TARPC_AIO_BLK_CALLBACK),
                                  rlen);
    }
    else if (strcmp(func, "recv") == 0)
    {
        rc = rpc_recv_gen(pco_iut, iut_s, big_buf, len, flags, rlen);
    }
    else if (strcmp(func, "recvfrom") == 0)
    {
        struct sockaddr from;
        socklen_t       fromlen = sizeof(from);

        memset(&from, 0, sizeof(from));
        rc = rpc_recvfrom_gen(pco_iut, iut_s, big_buf, len, flags, 
                              &from, &fromlen, rlen, fromlen);
    }
    else if (strcmp(func, "readv") == 0)
    {
        struct rpc_iovec vector = { big_buf, len, rlen };

        rc = rpc_readv(pco_iut, iut_s, &vector, 1);
    }
    else if (strcmp(func, "recvmsg") == 0 ||
             strcmp(func, "onload_zc_hlrx_recv_zc") == 0 ||
             strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
    {
        rpc_iovec vector = { .iov_base = big_buf,
                             .iov_len = len,
                             .iov_rlen = rlen };

        rpc_msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &vector,
            .msg_iovlen = 1,
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
            .msg_rnamelen = 0,
            .msg_riovlen = 1,
            .msg_cmsghdr_num = 0,
            .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
        };

        if (strcmp(func, "recvmsg") == 0)
        {
            rc = rpc_recvmsg(pco_iut, iut_s, &msg, flags);
        }
        else if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
        {
            rc = rpc_simple_hlrx_recv_zc(pco_iut, iut_s, &msg, flags, TRUE);
        }
        else
        {
            rc = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, &msg,
                                           flags, TRUE);
        }
    }
    else if (strcmp(func, "onload_zc_recv") == 0)
    {
        return sockts_recv_by_zc_recv(pco_iut, iut_s, rx_buf, len,
                                      (sock_type == RPC_SOCK_DGRAM ?
                                            1 : -1),
                                      flags);
    }
    else if (strcmp(func, "recvmmsg") == 0)
    {
        rpc_iovec vector = { .iov_base = big_buf,
                             .iov_len = len,
                             .iov_rlen = rlen };

        struct rpc_mmsghdr mmsg = {
            {
                .msg_name = NULL,
                .msg_namelen = 0,
                .msg_iov = &vector,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0,
                .msg_rnamelen = 0,
                .msg_riovlen = 1,
                .msg_cmsghdr_num = 0,
                .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
            },
            .msg_len = 0
        };

        rc = rpc_recvmmsg_alt(pco_iut, iut_s, &mmsg, 1, flags, NULL);
        if (rc == 1)
            rc = mmsg.msg_len;
        else if (rc > 1)
            TEST_VERDICT("recvmmsg() returned too big number of messages");
    }
    else
        TEST_FAIL("Unsupported function: %s", func);

    if (rc > 0)
        memcpy(rx_buf, big_buf, rc);

    return rc;
}

/**
 * Receive data on the IUT using specified function.
 *
 * @param func          Function to be used.
 * @param pco_iut       RPC server handle.
 * @param iut_s         Socket FD.
 * @param rx_buf        Buffer where to save received data.
 * @param len           Buffer length.
 * @param flags         Flags to be passed to the function.
 *
 * @return Result returned by corresponding receive function.
 */
static inline ssize_t
recv_by_func(const char *func, rcf_rpc_server *pco_iut, int iut_s,
             char *rx_buf, int len, rpc_send_recv_flags flags)
{
    return recv_by_func_ext(func, pco_iut, iut_s, RPC_SOCK_UNKNOWN,
                            rx_buf, len, flags);
}

/**
 * Send data from the IUT using specified function.
 *
 * @param func          function to be used
 * @param pco_iut           IUT TA
 * @param iut_s         socket on the IUT
 * @param tx_buf        location for data
 * @param len           buffer length
 * @param flags         flags to be passed to the function
 * @param to            destination address
 * @param tolen         destination address length
 *
 * @return Result returned by corresponding send function
 */
static inline ssize_t
send_by_func(const char *func, rcf_rpc_server *pco_iut, int iut_s,
             const char *tx_buf, ssize_t len, rpc_send_recv_flags flags, 
             struct sockaddr *to, socklen_t tolen)
{
    if (strcmp(func, "sendto") == 0)
    {
        return rpc_sendto(pco_iut, iut_s, tx_buf, len, flags, to);
    }
    else if (strcmp(func, "sendmsg") == 0)
    {
        rpc_iovec vector = { .iov_base = (void *)tx_buf,
                             .iov_len = len,
                             .iov_rlen = len };

        rpc_msghdr msg = { .msg_name = to,
                           .msg_namelen = tolen,
                           .msg_iov = &vector,
                           .msg_iovlen = 1,
                           .msg_control = NULL,
                           .msg_controllen = 0,
                           .msg_flags = 0,
                           .msg_rnamelen = tolen,
                           .msg_riovlen = 1,
                           .msg_cmsghdr_num = 0,
                           .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK };

        return rpc_sendmsg(pco_iut, iut_s, &msg, flags);
    }
    else
        TEST_FAIL("Incorrect func parameter is specified: %s", func);
        
    return 0;
}


/**
 * Check robustness of Socket API sent/receive functionality
 * when two thread use one socket simultaneously.
 *
 * @param pco_iut   IUT TA
 * @param iut_s     Socket on the IUT
 * @param domain    Socket domain
 * @param pco_tst   Test TA
 * @param tst_s     Socket on the TST
 * @param method    Method of creation of the second thread:
 *                  "thread", "inherit" (fork), "DuplicateSocket" or
 *                  "DuplicateHandle"
 * @param time2run  Time to run in seconds
 *
 * @return 0 (success) or -1 (test fails)
 */
extern int two_threads_stress(rcf_rpc_server *pco_iut, int iut_s, 
                              rpc_socket_domain domain,
                              rcf_rpc_server *pco_tst, int tst_s,
                              const char *method, unsigned int time2run);


#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TS_RPC_SENDRECV_H__ */
