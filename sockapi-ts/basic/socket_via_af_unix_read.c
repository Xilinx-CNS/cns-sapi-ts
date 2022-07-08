/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/**
 * @page basic-socket_via_af_unix_read Pass a socket between proccesses via AF_UNIX socket and read data using it.
 *
 * @objective Check that the read functions work with socket received from
 *            another process via AF_UNIX
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type   Socket type
 *      - @c udp
 *      - @c tcp_active
 *      - @c tcp_passive
 * @param recv_func Function used for receiving data:
 *      - @c read
 *      - @c recv
 *      - @c recvfrom
 *      - @c recvmsg
 *      - @c recvmmsg
 *      - @c onload_zc_recv
 *      - @c onload_zc_hlrx_recv_zc
 *      - @c onload_zc_hlrx_recv_copy
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/socket_via_af_unix_read"

#include "sockapi-test.h"
#include "tapi_file.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *pco_tst = NULL;
    sockts_socket_type sock_type;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    sockts_recv_func recv_func;

    int iut_s = -1;
    int iut_s2 = -1;
    int iut_l = -1;
    int iut1_us = -1;
    int iut2_us = -1;
    int tst_s = -1;

    rpc_msghdr msg_tx;
    rpc_msghdr msg_rx;
    char cmsg_tx_buf[CMSG_SPACE(sizeof(int))];
    char cmsg_rx_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg_tx;
    struct cmsghdr *cmsg_rx;
    struct sockaddr_un us_addr;
    char *us_file_name = NULL;

    void *tx_buf = NULL;
    void *rx_buf = NULL;
    size_t buf_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    SOCKTS_GET_RECV_FUNC_ID(recv_func);

    memset(&msg_tx, 0, sizeof(msg_tx));
    memset(&msg_rx, 0, sizeof(msg_rx));
    memset(&us_addr, 0, sizeof(us_addr));
    memset(&cmsg_tx_buf, 0, sizeof(cmsg_tx_buf));

    switch (sock_type)
    {
        case SOCKTS_SOCK_UDP:
            tx_buf = sockts_make_buf_dgram(&buf_len);
            break;
        case SOCKTS_SOCK_TCP_ACTIVE:
        case SOCKTS_SOCK_TCP_PASSIVE:
            tx_buf = sockts_make_buf_stream(&buf_len);
            break;

        default:
            TEST_FAIL("Invalid socket type");
    }
    rx_buf = TE_ALLOC(buf_len);

    TEST_STEP("Create a new @p pco_iut2 process on IUT");
    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut2", &pco_iut2));

    TEST_STEP("On @p pco_iut create a connection according to @p sock_type");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    TEST_STEP("Create a connection between @p pco_iut and @p pco_iut2 using "
              "@c AF_UNIX socket");
    iut1_us = rpc_socket(pco_iut, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);
    iut2_us = rpc_socket(pco_iut2, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);

    us_addr.sun_family = AF_UNIX;
    us_file_name = tapi_file_generate_name();
    strncpy(us_addr.sun_path, us_file_name, sizeof(us_addr.sun_path));

    rpc_bind(pco_iut2, iut2_us, (struct sockaddr *)&us_addr);

    TEST_STEP("Send the socket from @p pco_iut to @pco_iut2 got "
              "when creating a connection with Tester");
    msg_tx.msg_control = cmsg_tx_buf;
    msg_tx.msg_controllen = sizeof(cmsg_tx_buf);
    msg_tx.msg_iov = NULL;

    cmsg_tx = CMSG_FIRSTHDR(&msg_tx);
    cmsg_tx->cmsg_level = SOL_SOCKET;
    cmsg_tx->cmsg_type = SCM_RIGHTS;
    cmsg_tx->cmsg_len = CMSG_LEN(sizeof(iut_s));
    memcpy(CMSG_DATA(cmsg_tx), &iut_s, sizeof(iut_s));
    msg_tx.msg_cmsghdr_num = 1;

    msg_tx.msg_name = &us_addr;

    rpc_sendmsg(pco_iut, iut1_us, &msg_tx, 0);

    msg_rx.msg_control = cmsg_rx_buf;
    msg_rx.msg_controllen = sizeof(cmsg_rx_buf);

    rpc_recvmsg(pco_iut2, iut2_us, &msg_rx, 0);

    cmsg_rx = CMSG_FIRSTHDR(&msg_rx);

    iut_s2 = *((int*)CMSG_DATA(cmsg_rx));

    TEST_STEP("Check that @p recv_func function receives data from Tester on "
              "@p pco_iut2");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0);

    RPC_AWAIT_ERROR(pco_iut2);
    switch (recv_func)
    {
        case SOCKTS_RECVF_READ:
            rc = rpc_read(pco_iut2, iut_s2, rx_buf, buf_len);
            break;
        case SOCKTS_RECVF_RECV:
            rc = rpc_recv(pco_iut2, iut_s2, rx_buf, buf_len, 0);
            break;
        case SOCKTS_RECVF_RECVFROM:
            rc = rpc_recvfrom(pco_iut2, iut_s2, rx_buf, buf_len, 0,
                              NULL, NULL);
            break;
        case SOCKTS_RECVF_READV:
            rc = rpc_recv_func_readv(pco_iut2, iut_s2, rx_buf, buf_len, 0);
            break;
        case SOCKTS_RECVF_RECVMMSG:
        {
            struct rpc_mmsghdr mmsgs;
            struct rpc_iovec iov;
            rpc_msghdr msg;

            memset(&mmsgs, 0, sizeof(mmsgs));
            memset(&msg, 0, sizeof(msg));

            iov.iov_base = rx_buf;
            iov.iov_len = iov.iov_rlen = buf_len;

            mmsgs.msg_hdr.msg_iov = &iov;
            mmsgs.msg_hdr.msg_riovlen = mmsgs.msg_hdr.msg_iovlen = 1;

            rc = rpc_recvmmsg_alt(pco_iut2, iut_s2, &mmsgs, 1,
                                  0, NULL);
            if (rc != -1)
                rc = mmsgs.msg_len;
            break;
        }
        case SOCKTS_RECVF_RECVMSG:
        case SOCKTS_RECVF_ONLOAD_ZC_RECV:
        case SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_ZC:
        case SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_COPY:
        {
            struct rpc_iovec iov;
            rpc_msghdr msg;

            iov.iov_base = rx_buf;
            iov.iov_len = iov.iov_rlen = buf_len;

            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = &iov;
            msg.msg_riovlen = msg.msg_iovlen = 1;

            if (recv_func == SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_ZC)
            {
                rc = rpc_simple_hlrx_recv_zc(pco_iut2, iut_s2, &msg,
                                             0, TRUE);
            }
            else if (recv_func == SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_COPY)
            {
                rc = rpc_simple_hlrx_recv_copy(pco_iut2, iut_s2, &msg,
                                               0, TRUE);
            }
            else if (recv_func == SOCKTS_RECVF_ONLOAD_ZC_RECV)
            {
                rc = rpc_simple_zc_recv(pco_iut2, iut_s2, &msg, 0);
            }
            else
            {
                rc = rpc_recvmsg(pco_iut2, iut_s2, &msg, 0);
            }
            break;
        }
    }
    if (rc < 0)
    {
        TEST_VERDICT("Failed with unexpected error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut2));
    }

    SOCKTS_CHECK_RECV(pco_iut2, tx_buf, rx_buf, buf_len, rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut, iut1_us);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_us);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
