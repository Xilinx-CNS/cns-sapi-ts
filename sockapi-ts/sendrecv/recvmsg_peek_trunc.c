/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-recvmsg_peek_trunc Check recvmsg() function with MSG_PEEK flag
 *
 * @objective Check recvmsg() function with @c MSG_PEEK flag to receive unicast or broadcast message.
 *
 * @type conformance, compatibility
 *
 * @reference @ref STEVENS section 13.5
 *
 * @param env        Test environments with unicast and broadcast addresses
 * @param recv_f     Tested readmsg function:
 *                      - readmsg()
 *                      - readmmsg()
 *                      - onload_zc_recv()
 * @param broadcast  If TRUE, then set SO_BROADCAST for the sending socket.
 *
 * @par Test sequence:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/recvmsg_mix_io_flags"
#include "sockapi-test.h"
#include "rpc_sendrecv.h"

#define DATA_BULK       1024
static char rx_buf[DATA_BULK];
static char tx_buf[DATA_BULK];


int
main(int argc, char *argv[])
{
    /* Environment variables */

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_bcast_addr;
    const struct sockaddr  *tst_bcast_addr;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    struct sockaddr_storage dst_addr;

    rpc_msg_read_f recv_f;
    te_bool        broadcast;

    /* Auxiliary variables */
    int        recv_len = DATA_BULK - 1;
    rpc_iovec  vector = { .iov_base = rx_buf,
                          .iov_len = recv_len,
                          .iov_rlen = sizeof(rx_buf) };
    rpc_msghdr msg = { .msg_name = NULL,
                       .msg_namelen = 0,
                       .msg_iov = &vector,
                       .msg_iovlen = 1,
                       .msg_control = NULL,
                       .msg_controllen = 0,
                       .msg_flags = 0,
                       .msg_rnamelen = 0,
                       .msg_riovlen = 1,
                       .msg_cmsghdr_num = 0,
                       .msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK };

    int iut_s = -1;
    int tst_s = -1;
    int len;
    int opt_val = 1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_bcast_addr);
    TEST_GET_ADDR_NO_PORT(tst_bcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR_NO_PORT(tst_addr);
    TEST_GET_MSG_READ_FUNC(recv_f);
    TEST_GET_BOOL_PARAM(broadcast);


    TEST_STEP("Permit sending of broadcast messages from @b tst_s");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_bcast_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_bcast_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    if (broadcast)
    {
        tapi_sockaddr_clone_exact(tst_bcast_addr, &dst_addr);
        te_sockaddr_set_port(SA(&dst_addr),
                             te_sockaddr_get_port(iut_bcast_addr));
        rpc_setsockopt(pco_tst, tst_s, RPC_SO_BROADCAST, &opt_val);
        rpc_bind(pco_iut, iut_s, iut_bcast_addr);
    }
    else
    {
        tapi_sockaddr_clone_exact(iut_addr, &dst_addr);
        rpc_bind(pco_iut, iut_s, iut_addr);
    }

    TEST_STEP("Send message from @b tst_s socket");
    te_fill_buf(tx_buf, DATA_BULK);
    memset(rx_buf, 0, sizeof(rx_buf));
    RPC_AWAIT_IUT_ERROR(pco_tst);
    if (rpc_sendto(pco_tst, tst_s, tx_buf, DATA_BULK, 0, SA(&dst_addr)) !=
            DATA_BULK)
    {
        TEST_VERDICT("Cannot send a datagram from TST");
    }

    TEST_STEP("Receive data from @b iut_s socket using @p recv_f function "
              "with @c MSG_PEEK flag and buffer for data less than size of "
              "sent message. @c MSG_TRUNC flags should be set in @a msg_flags "
              "field of the received message.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_f(pco_iut, iut_s, &msg, RPC_MSG_PEEK);
    if (len < 0)
    {
        TEST_VERDICT("Receive with MSG_PEEK failed with error: %r",
                     RPC_ERRNO(pco_iut));
    }
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, recv_len, len);

    sockts_check_msg_flags(&msg, RPC_MSG_TRUNC);

    TEST_STEP("Receive data from @b iut_s socket using @p recv_f function "
              "with buffer for data equal to size of sent message.");
    vector.iov_len = sizeof(rx_buf);
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_f(pco_iut, iut_s, &msg, 0);
    if (len < 0)
    {
        TEST_VERDICT("Receive without MSG_PEEK failed with error: %r",
                     RPC_ERRNO(pco_iut));
    }
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, len, len);

    sockts_check_msg_flags(&msg, 0);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
