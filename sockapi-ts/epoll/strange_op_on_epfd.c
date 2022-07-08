/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-strange_op_on_epfd Call functions on epfd which uses fd but not epfd.
 *
 * @objective Check that functions that have fd argument fail correctly
 *            when they are called with epfd.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of sockets using in the test
 * @param func          Function for testing:
 *                      - @b accept()
 *                      - @b bind()
 *                      - @b connect()
 *                      - @b getpeername()
 *                      - @b getsockname()
 *                      - @b listen()
 *                      - @b read()
 *                      - @b readv()
 *                      - @b recv()
 *                      - @b recvfrom()
 *                      - @b recvmsg()
 *                      - @b recvmmsg_alt()
 *                      - @b send()
 *                      - @b sendmsg()
 *                      - @b sendmmsg_alt()
 *                      - @b sendto()
 *                      - @b shutdown()
 *                      - @b write()
 *                      - @b writev()
 *                      - @b onload_zc_send()
 *                      - @b onload_zc_send_user_buf()
 *                      - @b onload_zc_recv()
 *                      - @b onload_zc_hlrx_recv_zc()
 *                      - @b onload_zc_hlrx_recv_copy()
 *                      - @b template_send()
 *                      - @b od_send()
 * @param error         The error which will be reported by @p func
 *                      (@c ENOTSOCK / @c EINVAL)
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type socket @p iut_s on @p pco_iut.
 * -# Create @p epfd with @p iut_s socket and @c EPOLLIN | @c EPOLLOUT
 *    events using @b epoll_create() and @b epoll_ctl(@c EPOLL_CTL_ADD)
 *    functions.
 * -# Call @p func using @p epfd as its file descriptor argument.
 * -# Check that @p func returns @c -1 and sets errno to @p error.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/strange_op_on_epfd"

#include "sockapi-test.h"

#define MAX_BUFF_SIZE 1024
int
main(int argc, char *argv[])
{
    const char             *func;
    rcf_rpc_server         *pco_iut = NULL;

    const struct sockaddr  *iut_addr = NULL;

    struct sockaddr_storage addr;
    socklen_t               addr_len = sizeof(addr);

    int                     iut_s = -1;

    rpc_socket_type         sock_type;

    unsigned char           buffer[MAX_BUFF_SIZE];
    struct rpc_iovec        iov[] = {
        {
            .iov_base = buffer,
            .iov_len = sizeof(buffer),
            .iov_rlen = sizeof(buffer)
        }
    };
    struct rpc_mmsghdr      mmsg = {
        {
            .msg_name = &addr, 
            .msg_namelen = addr_len,
            .msg_iov = iov,
            .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
            .msg_rnamelen = addr_len,
            .msg_riovlen = sizeof(iov) / sizeof(iov[0]),
            .msg_cmsghdr_num = 0,
            .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
        },
        .msg_len = 0
    };
    rpc_msghdr             *msg = &mmsg.msg_hdr;

    int                     epfd = -1;

    rpc_errno               error;
    te_bool                 checked = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ERRNO_PARAM(error);
    TEST_GET_SOCK_TYPE(sock_type);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN | RPC_EPOLLOUT);

    #define CHECK_FUNCTION(func_name_, params_...)                  \
    do {                                                            \
        if (strcmp(func, #func_name_) == 0)                         \
        {                                                           \
            RPC_AWAIT_ERROR(pco_iut);                               \
            rc = rpc_ ## func_name_(pco_iut, params_);              \
            if (rc != -1)                                           \
            {                                                       \
                TEST_FAIL("Function '%s' returns %d, but "          \
                          "expected to return -1",                  \
                          #func_name_, rc);                         \
            }                                                       \
            CHECK_RPC_ERRNO(pco_iut, error,                         \
                            "%s() called with epoll descriptor as " \
                            "socket descriptor returns -1, "        \
                            "but", #func_name_);                    \
            checked = TRUE;                                         \
        }                                                           \
    } while (0)

    te_fill_buf(&addr, sizeof(addr));

    CHECK_FUNCTION(accept, epfd, SA(&addr), &addr_len);
    CHECK_FUNCTION(bind, epfd, iut_addr);
    CHECK_FUNCTION(connect, epfd, iut_addr);
    CHECK_FUNCTION(getpeername, epfd, SA(&addr), &addr_len);
    CHECK_FUNCTION(getsockname, epfd, SA(&addr), &addr_len);
    CHECK_FUNCTION(listen, epfd, SOCKTS_BACKLOG_DEF);

    CHECK_FUNCTION(read, epfd, buffer, sizeof(buffer));
    CHECK_FUNCTION(readv, epfd,
                   iov, sizeof(iov) / sizeof(iov[0]));
    CHECK_FUNCTION(recv, epfd, buffer, sizeof(buffer), 0);
    CHECK_FUNCTION(recvfrom, epfd, buffer, sizeof(buffer), 0,
                   SA(&addr), &addr_len);
    CHECK_FUNCTION(recvmsg, epfd, msg, 0);
    CHECK_FUNCTION(simple_zc_recv, epfd, msg, 0);
    CHECK_FUNCTION(simple_hlrx_recv_zc, epfd, msg, 0, TRUE);
    CHECK_FUNCTION(simple_hlrx_recv_copy, epfd, msg, 0, TRUE);
    CHECK_FUNCTION(recvmmsg_alt, epfd, &mmsg, 1, 0, NULL);

    CHECK_FUNCTION(send, epfd, buffer, sizeof(buffer), 0);
    msg->msg_name = (void *)iut_addr;
    CHECK_FUNCTION(sendmsg, epfd, msg, 0);
    CHECK_FUNCTION(simple_zc_send, epfd, msg, 0);
    CHECK_FUNCTION(simple_zc_send_user_buf, epfd, msg, 0);
    CHECK_FUNCTION(sendmmsg_alt, epfd, &mmsg, 1, 0);
    CHECK_FUNCTION(simple_zc_send_sock, epfd, msg, 0, iut_s);
    CHECK_FUNCTION(simple_zc_send_sock_user_buf, epfd, msg, 0, iut_s);
    CHECK_FUNCTION(sendto, epfd, buffer, sizeof(buffer), 0, iut_addr);
    CHECK_FUNCTION(od_send, epfd, buffer, sizeof(buffer), 0);

    CHECK_FUNCTION(shutdown, epfd, RPC_SHUT_RD);
    CHECK_FUNCTION(write, epfd, buffer, sizeof(buffer));
    CHECK_FUNCTION(writev, epfd,
                   iov, sizeof(iov) / sizeof(iov[0]));
    CHECK_FUNCTION(template_send, epfd, iov, sizeof(iov) / sizeof(iov[0]),
                   sizeof(iov) / sizeof(iov[0]), 0);

    if (!checked)
        TEST_FAIL("Unsupported function");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
