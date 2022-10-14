/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/**
 * @page basic-socket_via_af_unix_write Pass a socket between proccesses via AF_UNIX socket and send data using it.
 *
 * @objective Check that the write functions work with socket received from
 *            another process via AF_UNIX
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type   Socket type
 *      - @c udp
 *      - @c tcp_active
 *      - @c tcp_passive
 * @param send_func Function used for sending data:
 *      - @c write
 *      - @c send
 *      - @c sendto
 *      - @c sendmsg
 *      - @c sendmmsg
 *      - @c onload_zc_send
 *      - @c onload_zc_send_user_buf
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/socket_via_af_unix_write"

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
    sockts_send_func send_func;

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
    te_string us_file_name = TE_STRING_BUF_INIT(us_addr.sun_path);

    void *tx_buf = NULL;
    void *rx_buf = NULL;
    size_t buf_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    SOCKTS_GET_SEND_FUNC_ID(send_func);

    if (send_func == SOCKTS_SENDF_TEMPLATE_SEND)
    {
        /*
         * Orphaned stacks should be killed before using
         * template_send(), see ST-2357.
         */
        sockts_kill_zombie_stacks(pco_iut);
    }

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

    TEST_STEP("On @p pco_iut create a connection with Tester according "
              "to @p sock_type");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    TEST_STEP("Create @c AF_UNIX socket in each IUT processes. Bind a socket "
              "on @p pco_iut2");
    iut1_us = rpc_socket(pco_iut, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);
    iut2_us = rpc_socket(pco_iut2, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);

    us_addr.sun_family = AF_UNIX;
    tapi_file_make_name(&us_file_name);

    rpc_bind(pco_iut2, iut2_us, (struct sockaddr *)&us_addr);

    TEST_STEP("Send the socket connected to Tester from @p pco_iut  "
              "to @p pco_iut2");
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

    TEST_STEP("Check that @p send_func function sends data from @p pco_iut2 "
              "to Tester");

    RPC_AWAIT_ERROR(pco_iut2);
    switch (send_func)
    {
        case SOCKTS_SENDF_WRITE:
            rc = rpc_write(pco_iut2, iut_s2, tx_buf, buf_len);
            break;
        case SOCKTS_SENDF_WRITEV:
        case SOCKTS_SENDF_TEMPLATE_SEND:
        {
            struct rpc_iovec iov;

            iov.iov_base = tx_buf;
            iov.iov_len = iov.iov_rlen = buf_len;

            if (send_func == SOCKTS_SENDF_WRITEV)
                rc = rpc_writev(pco_iut2, iut_s2, &iov, 1);
            else
                rc = rpc_template_send(pco_iut2, iut_s2, &iov, 1, 1, 0);

            break;
        }
        case SOCKTS_SENDF_SEND:
            rc = rpc_send(pco_iut2, iut_s2, tx_buf, buf_len, 0);
            break;
        case SOCKTS_SENDF_SENDTO:
            rc = rpc_sendto(pco_iut2, iut_s2, tx_buf, buf_len, 0,
                            NULL);
            break;
        case SOCKTS_SENDF_OD_SEND:
            rc = rpc_od_send(pco_iut2, iut_s2, tx_buf, buf_len, 0);
            break;
        case SOCKTS_SENDF_OD_SEND_RAW:
            rc = rpc_od_send_raw(pco_iut2, iut_s2, tx_buf, buf_len, 0);
            break;
        case SOCKTS_SENDF_SENDMSG:
        case SOCKTS_SENDF_SENDMMSG:
        case SOCKTS_SENDF_ONLOAD_ZC_SEND:
        case SOCKTS_SENDF_ONLOAD_ZC_SEND_USER_BUF:
        {
            struct rpc_iovec iov;
            rpc_msghdr msg;
            size_t addr_len;

            memset(&msg, 0, sizeof(msg));

            iov.iov_base = tx_buf;
            iov.iov_len = iov.iov_rlen = buf_len;

            msg.msg_iov = &iov;
            msg.msg_riovlen = msg.msg_iovlen = 1;

            if (send_func == SOCKTS_SENDF_SENDMSG)
            {
                rc = rpc_sendmsg(pco_iut2, iut_s2, &msg, 0);
            }
            else if (send_func == SOCKTS_SENDF_SENDMMSG)
            {
                rc = rpc_sendmmsg_as_sendmsg(pco_iut2, iut_s2, &msg, 0);
            }
            else if (send_func == SOCKTS_SENDF_ONLOAD_ZC_SEND)
            {
                rc = rpc_simple_zc_send(pco_iut2, iut_s2, &msg, 0);
            }
            else
            {
                rc = rpc_simple_zc_send_gen_msg(pco_iut2, iut_s2, &msg, 0, -1,
                                                TRUE);
            }
            free(msg.msg_name);
            break;
        }
        default:
            TEST_FAIL("Unknown @p send_func");
    }
    if (rc < 0)
    {
        TEST_VERDICT("Sending function failed with unexpected error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut2));
    }

    if (rc != buf_len)
        TEST_VERDICT("Sending function sent the wrong number of bytes");

    rc = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0);

    SOCKTS_CHECK_RECV(pco_iut2, tx_buf, rx_buf, buf_len, rc);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut1_us);
    CLEANUP_RPC_CLOSE(pco_iut2, iut2_us);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut2));

    free(rx_buf);
    free(tx_buf);

    TEST_END;
}
