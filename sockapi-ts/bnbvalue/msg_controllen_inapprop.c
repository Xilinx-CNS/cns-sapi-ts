/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-msg_controllen_inapprop NULL msg_control and/or zero msg_controllen
 *
 * @objective Check what happens when @c NULL msg_control and/or zero
 *            msg_controllen are passed to receive functions
 *
 * @type conformance, robustness
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type     Socket type:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 * @param func          Checked function:
 *                      - @b recvmsg
 *                      - @b recvmmsg
 *                      - @b onload_zc_recv
 * @param zero_len      If @c TRUE, msg_controllen is zero.
 * @param null_buf      If @c TRUE, msg_control is @c NULL.
 * @param opt_name      Option to enable so that control message
 *                      is received.
 *
 * @note
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/msg_controllen_inapprop"

#include "sockapi-test.h"
#include "onload.h"

/** Tested receive functions */
typedef enum recvmsg_func {
    RF_RECVMSG = 0,     /**< @b recvmsg() */
    RF_RECVMMSG,        /**< @b recvmmsg() */
    RF_ONLOAD_ZC_RECV,  /**< @b onload_zc_recv() */
} recvmsg_func;

/** List of tested functions to be passed to TEST_GET_ENUM_PARAM() */
#define RECV_FUNC \
    { "recvmsg", RF_RECVMSG },                      \
    { "recvmmsg", RF_RECVMMSG },                    \
    { "onload_zc_recv", RF_ONLOAD_ZC_RECV }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rpc_socket_type        sock_type;
    recvmsg_func           func;
    te_bool                zero_len;
    te_bool                null_buf;
    rpc_sockopt            opt_name;
    rpc_socklevel          opt_level;

    struct rpc_mmsghdr *mmsg = NULL;
    struct rpc_msghdr  *msg = NULL;
    struct cmsghdr     *cmsg = NULL;
    char               *send_buf = NULL;
    size_t              len = 0;
    int                 iut_s = -1;
    int                 tst_s = -1;

    rpc_send_recv_flags exp_msg_flags = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(zero_len);
    TEST_GET_BOOL_PARAM(null_buf);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_ENUM_PARAM(func, RECV_FUNC);

    opt_level = rpc_sockopt2level(opt_name);

    TEST_STEP("Initialize @b rpc_msghdr structure, setting msg_control and "
              "msg_controllen according to @p zero_len and @p null_buf.");

    send_buf = sockts_make_buf_stream(&len);
    init_mmsghdr(1, len, &mmsg);
    msg = &mmsg->msg_hdr;
    msg->msg_cmsghdr_num = 0;
    msg->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    if (zero_len || null_buf)
        exp_msg_flags = RPC_MSG_CTRUNC;

    if (zero_len)
    {
        msg->real_msg_controllen = msg->msg_controllen;
        msg->msg_controllen = 0;
    }

    if (null_buf)
    {
        free(msg->msg_control);
        msg->msg_control = NULL;
    }

    TEST_STEP("Create a pair of connected sockets of type @p sock_type on "
              "IUT and Tester.");

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable socket option @p opt_name on IUT socket, so that control "
              "message for it should be received together with packet.");
    rpc_setsockopt_int(pco_iut, iut_s, opt_name, 1);

    TEST_STEP("Send some data from Tester.");
    rpc_send(pco_tst, tst_s, send_buf, len, 0);

    TEST_STEP("Call @p func on IUT socket, check that it succeeds");

    RPC_AWAIT_ERROR(pco_iut);
    switch (func)
    {
        case RF_RECVMSG:
            rc = rpc_recvmsg(pco_iut, iut_s, msg, 0);
            break;

        case RF_RECVMMSG:
            rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsg, 1, 0, NULL);
            break;

        case RF_ONLOAD_ZC_RECV:
            rc = rpc_simple_zc_recv(pco_iut, iut_s, msg, 0);
            break;

        default:
            TEST_FAIL("Unknown function passed");
    }

    if (rc < 0)
    {
        TEST_VERDICT("The tested function unexpectedly failed with "
                     "errno %r", RPC_ERRNO(pco_iut));
    }

    TEST_STEP("Check that @c MSG_CTRUNC flag is reported if @p zero_len "
              "and/or @p null_buf is @c TRUE.");

    if (msg->msg_flags != exp_msg_flags)
    {
        ERROR("msg_flags are %s instead of %s",
              send_recv_flags_rpc2str(msg->msg_flags),
              send_recv_flags_rpc2str(exp_msg_flags));

        if (msg->msg_flags & ~RPC_MSG_CTRUNC)
        {
            ERROR_VERDICT("Unexpected msg_flags were received");
        }
        else
        {
            ERROR_VERDICT("MSG_CTRUNC flag was %sset unexpectedly",
                          (msg->msg_flags & RPC_MSG_CTRUNC) ? "" : "not ");
        }
        TEST_STOP;
    }

    TEST_STEP("Check that otherwise control message for @p opt_name is "
              "retrieved.");

    if (exp_msg_flags == 0)
    {
        if (msg->msg_cmsghdr_num == 0)
            TEST_VERDICT("No control messages were returned");
        else if (msg->msg_cmsghdr_num != 1)
            TEST_VERDICT("Unexpected number of control messages was returned");

        cmsg = sockts_msg_lookup_control_data(
                   msg, socklevel_rpc2h(opt_level),
                   sockopt_rpc2h(opt_name == RPC_IPV6_RECVPKTINFO ?
                                 RPC_IPV6_PKTINFO : opt_name));
        if (cmsg == NULL)
            TEST_VERDICT("Expected control message was not retrieved");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    cleanup_mmsghdr(mmsg, 1);
    free(send_buf);

    TEST_END;
}
