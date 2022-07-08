/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-sendmmsg sendmmsg() operation on a socket
 *
 * @objective Test on reliability of the @b sendmmsg() operation 
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *              - @p sock_type=SOCK_DGRAM:
 *                  - @ref arg_types_env_iut_only
 *                  - @ref arg_types_env_two_nets_iut_second
 *              - @p sock_type=SOCK_STREAM:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 * @param sock_type Socket type:
 *                  - SOCK_DGRAM
 *                  - SOCK_STREAM
 * @param active    Whether connection should be opened actively on IUT
 *                  or not (it makes sense only for @c SOCK_STREAM
 *                  sockets)
 *
 * @par Scenario:
 *
 * -# If @p sock_type is @c SOCK_STREAM, create a pair of @c SOCK_STREAM
 *    type connected sockets - @p iut_s on @p pco_iut and @p tst1_s on
 *    @p pco_tst. Otherwise create a @c SOCK_DGRAM type sockets @p iut_s
 *    on @p pco_iut, @p tst1_s on @p pco_tst1 and @p tst2_s on @p pco_tst2.
 *    Bind sockets to proper addresses.
 * -# Send data from @p iut_s to a peer(s) with help of @p sendmmsg().
 * -# Check return value of @b sendmmsg().
 * -# Receive data on peer(s), check it for correctness.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/sendmmsg"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst1 = NULL;
    rcf_rpc_server     *pco_tst2 = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 tst1_s = -1;
    int                 tst2_s = -1;
    char               *tx_buf1 = NULL;
    size_t              tx_buf1_len;
    char               *tx_buf2 = NULL;
    size_t              tx_buf2_len;
    char               *rx_buf = NULL;
    size_t              rx_buf_len;
    int                 received;

    const struct sockaddr   *iut_addr1;
    const struct sockaddr   *iut_addr2;
    const struct sockaddr   *tst1_addr;
    const struct sockaddr   *tst2_addr;
    const struct sockaddr   *tst_addr;
    const struct sockaddr   *iut_addr;
    struct sockaddr_storage  addr_aux;
    rpc_socket_type          sock_type = RPC_SOCK_UNSPEC;

    struct rpc_iovec iov1;
    struct rpc_iovec iov2;
    struct rpc_mmsghdr msgs[2];

    te_bool active = FALSE;
    te_bool readable = FALSE;
    te_bool is_failed = FALSE;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    if (sock_type == RPC_SOCK_DGRAM)
    {
        TEST_GET_PCO(pco_tst1);
        TEST_GET_PCO(pco_tst2);
        TEST_GET_ADDR(pco_iut, iut_addr1);
        TEST_GET_ADDR(pco_iut, iut_addr2);
        TEST_GET_ADDR(pco_tst1, tst1_addr);
        TEST_GET_ADDR(pco_tst2, tst2_addr);
    }
    else if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
        pco_tst2 = pco_tst1 = pco_tst;
        tst2_addr = tst1_addr = tst_addr;
        iut_addr2 = iut_addr1 = iut_addr;
    }

    TEST_GET_BOOL_PARAM(active);
    TEST_GET_SOCK_TYPE(sock_type);

    tx_buf1 = sockts_make_buf_stream(&tx_buf1_len);
    tx_buf2 = sockts_make_buf_stream(&tx_buf2_len);
    rx_buf_len = tx_buf1_len + tx_buf2_len;
    rx_buf = calloc(1, rx_buf_len);

    if (sock_type == RPC_SOCK_STREAM)
    {
        if (active)
            GEN_CONNECTION(pco_tst, pco_iut, sock_type, RPC_PROTO_DEF,
                           tst_addr, iut_addr, &tst1_s, &iut_s);
        else
            GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                           iut_addr, tst_addr, &iut_s, &tst1_s);
    }
    else if (sock_type == RPC_SOCK_DGRAM)
    {
        tst1_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                            sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_tst1, tst1_s, tst1_addr);
        tst2_s = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst2_addr),
                            sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_tst2, tst2_s, tst2_addr);
        SA(&addr_aux)->sa_family = iut_addr1->sa_family;
        te_sockaddr_set_wildcard(SA(&addr_aux));
        TAPI_SET_NEW_PORT(pco_iut, SA(&addr_aux));
        iut_s = rpc_socket(pco_iut,
                           rpc_socket_domain_by_addr(SA(&addr_aux)),
                           sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, SA(&addr_aux));
    }
    else
        TEST_FAIL("Wrong socket type");

    memset(msgs, 0, sizeof(msgs));

    iov1.iov_base = tx_buf1;
    iov1.iov_len = iov1.iov_rlen = tx_buf1_len;
    iov2.iov_base = tx_buf2;
    iov2.iov_len = iov2.iov_rlen = tx_buf2_len;
    msgs[0].msg_hdr.msg_iov = &iov1;
    msgs[0].msg_hdr.msg_iovlen = msgs[0].msg_hdr.msg_riovlen = 1;
    msgs[0].msg_hdr.msg_name = (void *)tst1_addr;
    msgs[0].msg_hdr.msg_namelen = sizeof(*tst1_addr);
    msgs[1].msg_hdr.msg_iov = &iov2;
    msgs[1].msg_hdr.msg_iovlen = msgs[1].msg_hdr.msg_riovlen = 1;
    msgs[1].msg_hdr.msg_name = (void *)tst2_addr;
    msgs[1].msg_hdr.msg_namelen = sizeof(*tst2_addr);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendmmsg_alt(pco_iut, iut_s, msgs, 2, 0);

    if (rc < 0)
        TEST_VERDICT("sendmmsg() failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    RPC_GET_READABILITY(readable, pco_tst1, tst1_s, 1000);

    if (!readable)
    {
        ERROR_VERDICT("Data didn't arrive on the first socket");
        is_failed = TRUE;
    }
    else
    {
        received = 0;
        while (readable)
        {
            if (received >= (int)rx_buf_len)
                TEST_FAIL("Received more than possible");
            received += rpc_read(pco_tst1, tst1_s, rx_buf + received,
                                 rx_buf_len - received);
            RPC_GET_READABILITY(readable, pco_tst1, tst1_s, 1000);
        }

        if (received != ((sock_type == RPC_SOCK_DGRAM) ?
                         (int)tx_buf1_len : (int)rx_buf_len))
        {
            ERROR_VERDICT("%s data than expected received "
                          "on the first socket",
                          (received > (int)(sock_type == RPC_SOCK_DGRAM ?
                                            tx_buf1_len : rx_buf_len)) ?
                                                "More" : "Less");
            is_failed = TRUE;
        }

        if (memcmp(tx_buf1, rx_buf,
                   (received > (int)tx_buf1_len) ?
                                        (int)tx_buf1_len : received) ||
            (sock_type == RPC_SOCK_STREAM && received > (int)tx_buf1_len &&
             memcmp(tx_buf2, rx_buf + tx_buf1_len,
                    received - tx_buf1_len)))
        {
            ERROR_VERDICT("Invalid data received on the first socket");
            is_failed = TRUE;
        }
    }

    if (sock_type == RPC_SOCK_DGRAM)
    {
        RPC_GET_READABILITY(readable, pco_tst2, tst2_s, 1000);

        if (!readable)
        {
            ERROR_VERDICT("Data didn't arrive on the second socket");
            is_failed = TRUE;
        }
        else
        {
            received = 0;
            while (readable)
            {
                if (received >= (int)rx_buf_len)
                    TEST_FAIL("Received more than possible");
                received += rpc_read(pco_tst2, tst2_s, rx_buf + received,
                                     rx_buf_len - received);
                RPC_GET_READABILITY(readable, pco_tst1, tst1_s, 1000);
            }

            if (received != (int)tx_buf2_len)
            {
                ERROR_VERDICT("%s data than expected received "
                              "on the second socket",
                              received > (int)tx_buf2_len ?
                                                "More" : "Less");
                is_failed = TRUE;
            }

            if (memcmp(tx_buf2, rx_buf, received))
            {
                ERROR_VERDICT("Invalid data received on "
                              "the second socket");
                is_failed = TRUE;
            }
        }
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (sock_type == RPC_SOCK_DGRAM)
    {
        CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
        CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    }
    else
        CLEANUP_RPC_CLOSE(pco_tst, tst1_s);

    free(tx_buf1);
    free(tx_buf2);
    free(rx_buf);

    TEST_END;
}
