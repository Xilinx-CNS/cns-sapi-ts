/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 *
 * $Id$
 */

/** @page sendrecv-send_more_dgram  Test MSG_MORE flag work with UDP sockets.
 *
 * @objective Check that @c MSG_MORE flag works with UDP sockets and in
 *            case of datagram larger than 64K @c EMSGSIZE is returned.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param send_buf_size Size of single fragment
 * @param max_fragments Quantity of fragments
 * @param use_sendmmsg  If @c TRUE call @b rpc_sendmmsg_as_sendmsg() to send
 *                      data, otherwise call @b rpc_sendmsg()
 *
 * @par Scenario:
 *
 * -# Open @c SOCK_DGRAM sockets @p tst_s on @p pco_tst
 *    and @p iut_s on @p pco_iut; connect them to each other;
 * -# Send @p max_fragments with size equal to @p send_buf_size and
 *    @c MSG_MORE set (except the last fragment) from @p iut_s to @p tst_s;
 * -# Each time:
 *     -# check that the datagram was not received (except last time);
 *     -# if total size of all queued fragments is >(64K - size of UDP
 *        header) and sending function returned @c EMSGSIZE, the test is
 *        passed;
 * -# When datagram is received, verify it.
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_more_dgram"

#include "sockapi-test.h"

#if HAVE_NETINET_UDP_H
#include <netinet/udp.h>
/* Size of UDP header */
#define UDPHDR_SIZE     sizeof(struct udphdr)
#else
/* Size of UDP header */
#define UDPHDR_SIZE     8
#endif

#define MIN_DGRAM_SIZE (0xffff - UDPHDR_SIZE)

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    unsigned int               send_buf_size;
    unsigned int               max_fragments;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *iut_addr = NULL;
    int                        tst_s = -1;
    int                        iut_s = -1;
    struct rpc_msghdr          send_msg_hdr;
    struct rpc_msghdr          recv_msg_hdr;
    uint8_t                   *send_buf = NULL;
    uint8_t                   *recv_buf = NULL;
    struct rpc_iovec           send_buf_iov;
    struct rpc_iovec           recv_buf_iov;
    unsigned int               i;
    int                        received;      /* Number of bytes received */  
    ssize_t                    sent;
    te_bool                    use_sendmmsg = FALSE;

    int total = 0;

    TEST_START;
    TEST_GET_PCO(pco_tst);    
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(send_buf_size);
    TEST_GET_INT_PARAM(max_fragments);
    TEST_GET_BOOL_PARAM(use_sendmmsg);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    send_buf = te_make_buf_by_len(send_buf_size);
    CHECK_NOT_NULL(recv_buf = te_make_buf_by_len(max_fragments *
                                                 send_buf_size));    

    send_buf_iov.iov_base = send_buf;
    send_buf_iov.iov_rlen = send_buf_iov.iov_len = send_buf_size;

    recv_buf_iov.iov_base = recv_buf;
    recv_buf_iov.iov_rlen = recv_buf_iov.iov_len = max_fragments *
                                                   send_buf_size;

    memset(&send_msg_hdr, 0, sizeof(send_msg_hdr));
    send_msg_hdr.msg_iov = &send_buf_iov;
    send_msg_hdr.msg_riovlen = send_msg_hdr.msg_iovlen = 1;

    memset(&recv_msg_hdr, 0, sizeof(recv_msg_hdr));
    recv_msg_hdr.msg_iov = &recv_buf_iov;
    recv_msg_hdr.msg_riovlen = recv_msg_hdr.msg_iovlen = 1;  

    tapi_rpc_provoke_arp_resolution(pco_iut, SA(tst_addr));

    i = 1;
    do {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (i == max_fragments)
        {
            sent = (use_sendmmsg ?
                    rpc_sendmmsg_as_sendmsg : rpc_sendmsg)
                                     (pco_iut, iut_s, &send_msg_hdr, 0);
            TAPI_WAIT_NETWORK;
            rpc_send(pco_iut, iut_s, send_buf, send_buf_size, 0);
            TAPI_WAIT_NETWORK;
        }
        else
        {
            sent = (use_sendmmsg ?
                    rpc_sendmmsg_as_sendmsg : rpc_sendmsg)
                          (pco_iut, iut_s, &send_msg_hdr, RPC_MSG_MORE);
        }
        if (sent < 0)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE,
                            "Failures because of too long datagram "
                            "are expected only");
            RING("Check that queued data amount (%d) + next bunch (%d) is "
                 "greater then %d", total, send_buf_size,
                 MIN_DGRAM_SIZE);

            if (i * send_buf_size >= MIN_DGRAM_SIZE)
                TEST_SUCCESS;
            else
                TEST_VERDICT("Datagram is not too long, but EMSGSIZE received");
        }
        total += sent;
        TAPI_WAIT_NETWORK;
        RPC_AWAIT_IUT_ERROR(pco_tst);
        received = rpc_recvmsg(pco_tst, tst_s, &recv_msg_hdr,
                               RPC_MSG_DONTWAIT);
    } while (received == -1 && RPC_ERRNO(pco_tst) == RPC_EAGAIN &&
             ++i <= max_fragments);

    TAPI_WAIT_NETWORK;
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rpc_recvmsg(pco_tst, tst_s, &recv_msg_hdr, RPC_MSG_DONTWAIT);

    if (i < max_fragments)
        TEST_VERDICT("No fragment without MSG_MORE, but datagram sent");
    if (received < 0)
        TEST_VERDICT("Fragment without MSG_MORE arose, but recvmsg() "
                     "returned %d with %s errno", received,
                      errno_rpc2str(RPC_ERRNO(pco_tst)));

    RING("%d != %d * %d", received, max_fragments, send_buf_size);
    if ((size_t)received != max_fragments * send_buf_size)
        TEST_VERDICT("Wrong data amount was received");

    for (i = 0; i < max_fragments; i++)
    {
        if (memcmp(send_buf, recv_buf + i * send_buf_size,
                   send_buf_size) != 0)
            TEST_FAIL("Data verification error on fragment %d", i);
    }

    TEST_SUCCESS;

cleanup:    
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    free(send_buf);
    free(recv_buf);

    TEST_END;
}
