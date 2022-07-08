/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-descr_nonexist Using non existing descriptor in Socket API calls
 *
 * @objective Check that Socket API correctly handles situation with passing
 *            bad socket descriptors - descriptor that is not associated
 *            with any device.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_ucast_ipv6
 * @param func      Socket API @ref bnbvalue_descr_nonexist_func_to_test
 *                  "function" used in test
 *
 * @note
 * - One way to get non-existing descriptor (dull descriptor) is to open
 * some ordinary file with @b open() function and close it just immediately.
 * The descriptor obtained can be thought as non-existing, because it is
 * returned to the pool of free descriptors of the process.
 *
 * @par Scenario:
 * -# Run @p func function on @p pco_iut passing non-existing 
 *    descriptor @p descr.
 * -# Check that function returns @c -1 and @b errno is set to @c EBADF.
 *
 * @par
 * @anchor bnbvalue_descr_nonexist_func_to_test
 * Perform this test for the following functions:
 * - @b accept()
 * - @b bind()
 * - @b close()
 * - @b connect()
 * - @b getpeername()
 * - @b getsockname()
 * - @b getsockopt()
 * - @b ioctl()
 * - @b listen()
 * - @b pselect()
 * - @b read()
 * - @b read_via_splice()
 * - @b readv()
 * - @b recv()
 * - @b recvfrom()
 * - @b recvmsg()
 * - @b simple_zc_send_sock()
 * - @b simple_zc_send_sock_user_buf()
 * - @b simple_zc_recv()
 * - @b simple_hlrx_recv_zc()
 * - @b simple_hlrx_recv_copy()
 * - @b recvmmsg()
 * - @b select()
 * - @b send()
 * - @b sendmsg()
 * - @b sendmmsg()
 * - @b sendto()
 * - @b setsockopt()
 * - @b shutdown()
 * - @b write()
 * - @b write_via_splice()
 * - @b writev()
 * - @b closesocket()
 * - @b od_send()
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/descr_nonexist"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    const char             *func;
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr;

    int                     non_exist_descr;
    int                     aux_s1;
    int                     aux_s2;
    int                     add_sock = -1;

    struct sockaddr_storage addr;
    socklen_t               addr_len = sizeof(addr);

    int                     opt_val = 0;

    int                     ioctl_val = 0;
    te_bool                 checked = FALSE;

#define BUF_SIZE 100
    unsigned char           buf[BUF_SIZE];
    struct rpc_iovec        iov[] = {
        { buf, sizeof(buf), sizeof(buf) }
    };
    struct rpc_mmsghdr mmsghdr[] = {
        {
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
        }
    };
    rpc_msghdr               *msg = &mmsghdr[0].msg_hdr;

    rpc_fd_set_p            readfds = RPC_NULL;
    tarpc_timeval           tv = { 1, 0 };
    struct tarpc_timespec   ts = { 1, 0 };

    int expected_errno;

    /* Preambule */
    TEST_START;
    TEST_GET_STRING_PARAM(func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);

    expected_errno = RPC_EBADF;

    /* Prepare non existing socket descriptor */
    if (strcmp(func, "simple_zc_send_sock") == 0 ||
        strcmp(func, "simple_zc_send_sock_user_buf") == 0)
    {
        non_exist_descr = rpc_socket(pco_iut,
                                     RPC_PF_INET, RPC_SOCK_STREAM,
                                     RPC_PROTO_DEF);

        add_sock = rpc_socket(pco_iut,
                              RPC_PF_INET, RPC_SOCK_STREAM,
                              RPC_PROTO_DEF);

    }
    if (strcmp(func, "read_via_splice") == 0 ||
        strcmp(func, "write_via_splice") == 0)
    {
        aux_s1 = rpc_socket(pco_iut,
                            RPC_PF_INET, RPC_SOCK_STREAM,
                            RPC_PROTO_DEF);
        aux_s2 = rpc_socket(pco_iut,
                            RPC_PF_INET, RPC_SOCK_STREAM,
                            RPC_PROTO_DEF);
        non_exist_descr = rpc_socket(pco_iut,
                                     RPC_PF_INET, RPC_SOCK_STREAM,
                                     RPC_PROTO_DEF);
        rpc_closesocket(pco_iut, aux_s1);
        rpc_closesocket(pco_iut, aux_s2);
    }
    else
        non_exist_descr = rpc_socket(pco_iut,
                                     RPC_PF_INET, RPC_SOCK_DGRAM,
                                     RPC_PROTO_DEF);
    rpc_closesocket(pco_iut, non_exist_descr);

    readfds = rpc_fd_set_new(pco_iut);
    rpc_do_fd_zero(pco_iut, readfds);
    rpc_do_fd_set(pco_iut, non_exist_descr, readfds);


#define CHECK_FUNCTION(func_name_, params_...) \
    do {                                                        \
        if (strcmp(func, #func_name_) == 0)                     \
        {                                                       \
            RPC_AWAIT_ERROR(pco_iut);                           \
            rc = rpc_ ## func_name_(pco_iut, params_);          \
            if (rc >= 0)                                        \
            {                                                   \
                TEST_VERDICT("Tested function unexpectedly "    \
                             "succeeded");                      \
            }                                                   \
            else if (expected_errno != RPC_ERRNO(pco_iut))      \
            {                                                   \
                TEST_VERDICT("Tested function failed with "     \
                             "unexpected error " RPC_ERROR_FMT, \
                             RPC_ERROR_ARGS(pco_iut));          \
            }                                                   \
            checked = TRUE;                                     \
        }                                                       \
    } while (0)

    te_fill_buf(&addr, sizeof(addr));

    CHECK_FUNCTION(accept, non_exist_descr, SA(&addr), &addr_len);
    CHECK_FUNCTION(bind, non_exist_descr, iut_addr);
    CHECK_FUNCTION(close, non_exist_descr);
    CHECK_FUNCTION(closesocket, non_exist_descr);
    CHECK_FUNCTION(connect, non_exist_descr, iut_addr);
    CHECK_FUNCTION(getpeername, non_exist_descr, SA(&addr), &addr_len);
    CHECK_FUNCTION(getsockname, non_exist_descr, SA(&addr), &addr_len);
    CHECK_FUNCTION(getsockopt, non_exist_descr, RPC_SO_BROADCAST, &opt_val);
    CHECK_FUNCTION(ioctl, non_exist_descr, RPC_SIOCATMARK, &ioctl_val);
    CHECK_FUNCTION(listen, non_exist_descr, SOCKTS_BACKLOG_DEF);

    CHECK_FUNCTION(read, non_exist_descr, buf, sizeof(buf));
    CHECK_FUNCTION(read_via_splice, non_exist_descr, buf, sizeof(buf));
    CHECK_FUNCTION(readv, non_exist_descr,
                   iov, sizeof(iov) / sizeof(iov[0]));
    CHECK_FUNCTION(recv, non_exist_descr, buf, sizeof(buf), 0);
    CHECK_FUNCTION(recvfrom, non_exist_descr, buf, sizeof(buf), 0,
                   SA(&addr), &addr_len);
    CHECK_FUNCTION(recvmsg, non_exist_descr, msg, 0);
    CHECK_FUNCTION(simple_zc_recv, non_exist_descr, msg, 0);
    CHECK_FUNCTION(simple_hlrx_recv_zc, non_exist_descr, msg, 0, TRUE);
    CHECK_FUNCTION(simple_hlrx_recv_copy, non_exist_descr, msg, 0, TRUE);
    CHECK_FUNCTION(recvmmsg_alt, non_exist_descr, mmsghdr, 1, 0, &ts);

    CHECK_FUNCTION(send, non_exist_descr, buf, sizeof(buf), 0);
    CHECK_FUNCTION(od_send, non_exist_descr, buf, sizeof(buf), 0);
    CHECK_FUNCTION(od_send_raw, non_exist_descr, buf, sizeof(buf), 0);
    tapi_sockaddr_clone_exact(iut_addr, &addr);
    CHECK_FUNCTION(sendmsg, non_exist_descr, msg, 0);
    CHECK_FUNCTION(sendmmsg_alt, non_exist_descr, mmsghdr, 1, 0);
    CHECK_FUNCTION(simple_zc_send_sock, non_exist_descr, msg, 0, add_sock);
    CHECK_FUNCTION(simple_zc_send_sock_user_buf, non_exist_descr, msg,
                   0, add_sock);
    CHECK_FUNCTION(sendto, non_exist_descr, buf, sizeof(buf), 0, iut_addr);

    CHECK_FUNCTION(setsockopt, non_exist_descr, RPC_SO_BROADCAST, &opt_val);
    CHECK_FUNCTION(shutdown, non_exist_descr, RPC_SHUT_RD);
    CHECK_FUNCTION(write, non_exist_descr, buf, sizeof(buf));
    CHECK_FUNCTION(write_via_splice, non_exist_descr, buf, sizeof(buf));
    CHECK_FUNCTION(writev, non_exist_descr,
                   iov, sizeof(iov) / sizeof(iov[0]));


    CHECK_FUNCTION(select, non_exist_descr + 1, readfds, RPC_NULL, RPC_NULL,
                   &tv);
    CHECK_FUNCTION(pselect, non_exist_descr + 1, readfds, RPC_NULL, RPC_NULL,
                   &ts, RPC_NULL);

    if (!checked)
        TEST_FAIL("Unsupported function");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, add_sock);
    rpc_fd_set_delete(pco_iut, readfds);

    TEST_END;
}
