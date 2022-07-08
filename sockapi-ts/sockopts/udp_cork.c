/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id: udp_cork.c 32368 2006-10-10 12:11:18Z arybchik $
 */

/** @page sockopts-udp_cork  UDP_CORK functionality
 *
 * @objective Checking UDP_CORK functionality providing a coalescing
 *            of the UDP packets.
 *
 * @type Conformance.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param packet_size   Size of packets to send
 * @param sndbuf        @c SO_SNDBUF value for socket on IUT or
 *                      -1 if option should not be changed
 * @param stop_type     Defines the way to interrupt the effect of
 *                      UDP_CORK. May have one of the following values:
 *                        - cork -- end by disabling @c UDP_CORK option
 *                        - close -- end by closing socket
 *                        - linger -- end by closing socket with
 *                          @c SO_LINGER option
 *                        - overflow -- end by trying to send datagram
 *                          larger than 64K or more than @c SO_SNDBUF 
 *                          allows
 *                        - exit -- end by exiting application
 *                        - kill -- end by killing application
 * @param use_sendmmsg  Whether to use @b sendmmsg() instead of @b
 *                      sendmsg()
 *
 * @par Scenario:
 *
 * -# Generate connection of type @c SOCK_DGRAM between IUT and Tester
 *    obtaining @p iut_s and @p tst_s sockets.
 * -# If @p sndbuf parameter is not -1, set @c SO_SNDBUF of @p iut_s
 *    socket to its value.
 * -# Set @p UDP_CORK option of @p iut_s socket. Check if it has set
 *    successfully.
 * -# Prepare data to send. If testing overflow, overall size of data
 *    should be more than 64K.
 * -# Call @b send() several times.
 * -# If send() failed with @c EMSGSIZE, we are testing overflow,
 *    and total size of all queued fragments is >(64K - UDP header size)
 *    test succeed.
 * -# If send() failed with @c ENOBUFS, we are testing overflow,
 *    and @p sndbuf is not -1, test succeed.
 * -# Check that socket on Tester is not readable.
 * -# Interrupt the effect of @p UDP_CORK with action, corresponding to
      @p stop_type param.
 * -# Check if data is received on Tester. If it is, verify it.
 * -# Issue verdicts.
 * -# Close all sockets.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/udp_cork"

#include "sockapi-test.h"

#if HAVE_NETINET_UDP_H
#include <netinet/udp.h>
/* Size of UDP header */
#define UDPHDR_SIZE     sizeof(struct udphdr)
#else
/* Size of UDP header */
#define UDPHDR_SIZE     8
#endif

#define MAX_DATA_TO_SEND 0x1000

void
tst_interrupt_cork(rcf_rpc_server **pco_iut, int *iut_s,
                                            const char *stop_type)
{
    if (strcmp(stop_type, "cork") == 0)
    {
        int optval = 0;
        rpc_setsockopt(*pco_iut, *iut_s, RPC_UDP_CORK, &optval);
        optval = 1;
        rpc_getsockopt(*pco_iut, *iut_s, RPC_UDP_CORK, &optval);
        if (optval != 0)
            TEST_FAIL("UDP_CORK mode on 'iut_s' can not be turned off");
    }
    else if (strcmp(stop_type, "close") == 0)
    {
        RPC_CLOSE(*pco_iut, *iut_s);
    }
    else if (strcmp(stop_type, "linger") == 0)
    {
        tarpc_linger               linger_val;
        linger_val.l_onoff = 1;
        linger_val.l_linger = rand_range(10, 20);
        rpc_setsockopt(*pco_iut, *iut_s, RPC_SO_LINGER, &linger_val);
        RPC_CLOSE(*pco_iut, *iut_s);
    }
    else if (strcmp(stop_type, "overflow") == 0)
    {
        TEST_VERDICT("No overflow occured, though sending more data "
                     "than buffers allow");
    }
    else if (strcmp(stop_type, "exit") == 0)
    {
        CHECK_RC(rcf_rpc_server_dead(*pco_iut));
        CHECK_RC(rcf_rpc_server_destroy(*pco_iut));
        CFG_WAIT_CHANGES;
        *iut_s = -1;
    }
    else if (strcmp(stop_type, "kill") == 0)
    {
        rcf_rpc_server *pco_iut_killer;
        rcf_rpc_server_create((*pco_iut)->ta, "iut_killer",
                                              &pco_iut_killer);
        rpc_kill(pco_iut_killer, rpc_getpid(*pco_iut), RPC_SIGKILL);
        *iut_s = -1;
        CHECK_RC(rcf_rpc_server_dead(pco_iut_killer));
        CHECK_RC(rcf_rpc_server_destroy(pco_iut_killer));
        CFG_WAIT_CHANGES;
    }
    else
        TEST_FAIL("Unexpected value of stop_type variable: %s", stop_type);

    return;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_iut_bak = NULL;
    unsigned int               packet_size;
    unsigned int               max_fragments;
    const char                *stop_type;
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
    int                        optval;
    tarpc_timeval              tv = { 15, 0 };
    int                        ret;
    int                        sndbuf;
    te_bool                    use_sendmmsg = FALSE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_INT_PARAM(packet_size);
    TEST_GET_INT_PARAM(sndbuf);
    TEST_GET_STRING_PARAM(stop_type);
    TEST_GET_BOOL_PARAM(use_sendmmsg);

    /* Scenario */

    if (strcmp(stop_type, "exit") == 0)
        rcf_rpc_server_create(pco_iut->ta, "iut_bak", &pco_iut_bak);

    /* Generate connection */
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* Set RCVTIMEO in oreder to prevent application from failing
     * on blocking recvmsg with no data to read */
    RPC_AWAIT_IUT_ERROR(pco_tst);
    ret = rpc_setsockopt(pco_tst, tst_s, RPC_SO_RCVTIMEO, &tv);
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(SO_RCVTIMEO) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    /* Set SNDBUF socket option of iut_s */
    if (sndbuf > 0)
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDBUF, &sndbuf);

    /* Set UDP_CORK */
    optval = 1;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt(pco_iut, iut_s, RPC_UDP_CORK, &optval);
    if (rc != 0)
    {
        TEST_VERDICT("setsockopt(UDP_CORK) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_UDP_CORK, &optval);
    if (optval != 1)
        TEST_FAIL("UDP_CORK mode on 'iut_s' can not be turned on");

    /* Prepare data to send */
    if (strcmp(stop_type, "overflow") == 0)
        max_fragments = 0xffff / packet_size + 1;
    else
        max_fragments = MAX_DATA_TO_SEND / packet_size;

    send_buf = te_make_buf_by_len(packet_size);
    recv_buf = te_make_buf_by_len(max_fragments * packet_size);

    send_buf_iov.iov_base = send_buf;
    send_buf_iov.iov_rlen = send_buf_iov.iov_len = packet_size;

    recv_buf_iov.iov_base = recv_buf;
    recv_buf_iov.iov_rlen = recv_buf_iov.iov_len = max_fragments *
                                                   packet_size;

    memset(&send_msg_hdr, 0, sizeof(send_msg_hdr));
    send_msg_hdr.msg_iov = &send_buf_iov;
    send_msg_hdr.msg_riovlen = send_msg_hdr.msg_iovlen = 1;

    memset(&recv_msg_hdr, 0, sizeof(recv_msg_hdr));
    recv_msg_hdr.msg_iov = &recv_buf_iov;
    recv_msg_hdr.msg_riovlen = recv_msg_hdr.msg_iovlen = 1;

    /* Send data */
    for (i = 1; i <= max_fragments; i++)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        sent = (use_sendmmsg ?
                    rpc_sendmmsg_as_sendmsg : rpc_sendmsg)
                                    (pco_iut, iut_s, &send_msg_hdr, 0);
        if (sent < 0)
        {
            CHECK_RPC_ERRNO(pco_iut,
                            (sndbuf > 0) ? RPC_ENOBUFS : RPC_EMSGSIZE,
                            "On IUT failures because of too long datagram "
                            "are expected only");
            if ((i * packet_size >= 0xffff - UDPHDR_SIZE) || (sndbuf > 0))
                TEST_SUCCESS;
            else
                TEST_FAIL("Datagram is not too long, but EMSGSIZE "
                          "received");
        }
    }

    TAPI_WAIT_NETWORK;
    RPC_AWAIT_IUT_ERROR(pco_tst);
    received = rpc_recvmsg(pco_tst, tst_s, &recv_msg_hdr,
                           RPC_MSG_DONTWAIT);
    if (received != -1)
        TEST_VERDICT("UDP_CORK doesn't prevent packets from "
                     "being sent");
    CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,
                    "On Tester failures because of no data to read "
                    "are expected only");

    /* Interrupt the effect of UDP_CORK */
    tst_interrupt_cork(&pco_iut, &iut_s, stop_type);

    /* Receive data on Tester */
    RPC_AWAIT_IUT_ERROR(pco_tst);
    pco_tst->timeout = 2 * tv.tv_sec * 1000;
    received = rpc_recvmsg(pco_tst, tst_s, &recv_msg_hdr, 0);
    if (received == -1)
    {
        CHECK_RPC_ERRNO(pco_tst, RPC_EAGAIN,
                        "On Tester failures because of no data to read "
                        "are expected only");
        if (strcmp(stop_type, "cork") == 0)
            TEST_VERDICT("UDP_CORK is not interrupted, no data received");
    }
    else
    {
        if (strcmp(stop_type, "cork") != 0)
            TEST_VERDICT("Data received, though UDP_CORK should not be "
                         "interrupted by stop_type \'%s\'", stop_type);

        /* Verify data */
        if ((size_t)received != max_fragments * packet_size)
            TEST_FAIL("Some data were lost");
        for (i = 0; i < max_fragments; i++)
        {
            if (memcmp(send_buf, recv_buf + i * packet_size,
                       packet_size) != 0)
            {
                TEST_FAIL("Data verification error on fragment %d", i);
            }
        }
    }

    TEST_SUCCESS;

cleanup:
    /* rcf_rpc_server_restart() generates some errors in log,
     * can't be helped without messing with TE */
    if (strcmp(stop_type, "kill") == 0)
        rcf_rpc_server_restart(pco_iut);
    if (strcmp(stop_type, "exit") == 0)
        rcf_rpc_server_create(pco_iut_bak->ta, "pco_iut", &pco_iut);

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(send_buf);
    free(recv_buf);

    TEST_END;
}
