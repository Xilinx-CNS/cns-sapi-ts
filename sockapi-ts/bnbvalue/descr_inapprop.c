/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-descr_inapprop Using inappropriate descriptor in Socket API calls
 *
 * @objective Check that Socket API correctly handles situation with passing
 *            descriptor for which some socket operations cannot be applied,
 *            for example it might be an ordinary file descriptor.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_ucast_ipv6
 * @param func      Socket API @ref bnbvalue_descr_inapprop_func_to_test
 *                  "function" used in test
 *
 * @note
 * - Standard file descriptors can be used in the test:
 *     - @c 0: @c stdin
 *     - @c 1: @c stdout
 *     - @c 2: @c stderr
 *     .
 * Or it can be a descriptor of any opened file.
 * .
 *
 * @par Scenario:
 * -# Run @p func function on @p pco_iut passing non-socket descriptor
 *    @p descr.
 * -# Check that function returns @c -1 and @b errno is set to
 *    @c ENOTSOCK.
 *
 * @par
 * @anchor bnbvalue_descr_inapprop_func_to_test
 * Perform this test for the following functions:
 * - @b accept()
 * - @b bind()
 * - @b connect()
 * - @b getpeername()
 * - @b getsockname()
 * - @b getsockopt()
 * - @b ioctl()
 * - @b listen()
 * - @b recv()
 * - @b recvfrom()
 * - @b recvmsg()
 * - @b simple_zc_recv()
 * - @b simple_hlrx_recv_zc()
 * - @b simple_hlrx_recv_copy()
 * - @b recvmmsg()
 * - @b simple_zc_send_sock()
 * - @b simple_zc_send_sock_user_buf()
 * - @b send()
 * - @b sendmsg()
 * - @b sendmmsg()
 * - @b sendto()
 * - @b setsockopt()
 * - @b shutdown()
 * - @b onload_msg_template_alloc()
 * - @b od_send()
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/descr_inapprop"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    const char             *func;
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr;

    int                     inapprop_descr = -1;

    struct sockaddr_storage addr;
    socklen_t               addr_len = sizeof(addr);

    int                     opt_val = 0;

    rpc_ioctl_code          ioctl_code = RPC_SIOCATMARK;
    int                     ioctl_val;
    te_bool                 func_found = FALSE;
    struct rpc_iovec        vector;

    int expected_errno;

    int                      add_sock = -1;

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

    struct tarpc_timespec    timeout ={ 1, 0 };
    rpc_onload_template_handle handle = 0;

    /* Preambule */
    TEST_START;
    TEST_GET_STRING_PARAM(func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);

    inapprop_descr = rpc_open(pco_iut, "/dev/null", RPC_O_RDWR, 0);

    if (strcmp(func, "simple_zc_send_sock") == 0 ||
        strcmp(func, "simple_zc_send_sock_user_buf") == 0)
    {
        add_sock = rpc_socket(pco_iut,
                              RPC_PF_INET, RPC_SOCK_STREAM,
                              RPC_PROTO_DEF);
    }

    if (strcmp(func, "AcceptEx") == 0 || strcmp(func, "ConnectEx") == 0)
    {
        expected_errno = RPC_EINVAL;
    }
    else
        expected_errno = RPC_ENOTSOCK;

#define CHECK_FUNCTION(func_name_, params_...) \
    do {                                                            \
        if (strcmp(func, #func_name_) == 0)                         \
        {                                                           \
            func_found = TRUE;                                      \
            RPC_AWAIT_ERROR(pco_iut);                               \
            rc = rpc_ ## func_name_(pco_iut, params_);              \
            if (rc >= 0)                                            \
            {                                                       \
                TEST_VERDICT("Tested function unexpectedly "        \
                             "succeeded");                          \
            }                                                       \
            else if (expected_errno != RPC_ERRNO(pco_iut))          \
            {                                                       \
                TEST_VERDICT("Tested function failed with "         \
                             "unexpected error " RPC_ERROR_FMT      \
                             " instead of %r",                      \
                             RPC_ERROR_ARGS(pco_iut),               \
                             expected_errno);                       \
            }                                                       \
        }                                                           \
    } while (0)

    CHECK_FUNCTION(accept, inapprop_descr, NULL, NULL);
    CHECK_FUNCTION(bind, inapprop_descr, iut_addr);
    CHECK_FUNCTION(connect, inapprop_descr, iut_addr);
    CHECK_FUNCTION(getpeername, inapprop_descr, SA(&addr), &addr_len);
    CHECK_FUNCTION(getsockname, inapprop_descr, SA(&addr), &addr_len);
    CHECK_FUNCTION(getsockopt, inapprop_descr, RPC_SO_BROADCAST, &opt_val);
    CHECK_FUNCTION(listen, inapprop_descr, SOCKTS_BACKLOG_DEF);

    CHECK_FUNCTION(recv, inapprop_descr, buf, sizeof(buf), 0);
    CHECK_FUNCTION(recvfrom, inapprop_descr, buf, sizeof(buf), 0,
                   SA(&addr), &addr_len);
    CHECK_FUNCTION(recvmsg, inapprop_descr, msg, 0);
    CHECK_FUNCTION(simple_zc_recv, inapprop_descr, msg, 0);
    CHECK_FUNCTION(simple_hlrx_recv_zc, inapprop_descr, msg, 0, TRUE);
    CHECK_FUNCTION(simple_hlrx_recv_copy, inapprop_descr, msg, 0, TRUE);
    CHECK_FUNCTION(recvmmsg_alt, inapprop_descr, mmsghdr, 1, 0, &timeout);

    CHECK_FUNCTION(send, inapprop_descr, buf, sizeof(buf), 0);
    CHECK_FUNCTION(od_send, inapprop_descr, buf, sizeof(buf), 0);
    CHECK_FUNCTION(od_send_raw, inapprop_descr, buf, sizeof(buf), 0);
    msg->msg_name = (void *)iut_addr;
    CHECK_FUNCTION(simple_zc_send_sock, inapprop_descr, msg, 0, add_sock);
    CHECK_FUNCTION(simple_zc_send_sock_user_buf, inapprop_descr, msg,
                   0, add_sock);
    CHECK_FUNCTION(sendmsg, inapprop_descr, msg, 0);
    CHECK_FUNCTION(sendmmsg_alt, inapprop_descr, mmsghdr, 1, 0);
    CHECK_FUNCTION(sendto, inapprop_descr, buf, sizeof(buf), 0, iut_addr);

    CHECK_FUNCTION(setsockopt, inapprop_descr, RPC_SO_BROADCAST, &opt_val);
    CHECK_FUNCTION(shutdown, inapprop_descr, RPC_SHUT_RD);

    vector.iov_base = buf;
    vector.iov_len = sizeof(buf);
    vector.iov_rlen = sizeof(buf);

    CHECK_FUNCTION(onload_msg_template_alloc, inapprop_descr, &vector, 1, &handle, 0);

    if (strcmp(func, "ioctl") == 0)
    {
        func_found = TRUE;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_ioctl(pco_iut, inapprop_descr, ioctl_code, &ioctl_val);
        if (rc != -1)
        {
            TEST_FAIL("Function 'ioctl' returns %d, but "
                      "expected to return -1", rc);
        }
        if (RPC_ERRNO(pco_iut) == RPC_ENOTSOCK ||
            RPC_ERRNO(pco_iut) == RPC_ENOTTY ||
            RPC_ERRNO(pco_iut) == RPC_ENXIO)
        {
            RING_VERDICT("ioctl(%s) for not socket file descriptor "
                         "failed with errno %s",
                         ioctl_rpc2str(ioctl_code),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        else
        {
            TEST_VERDICT("ioctl(%s) for not socket file descriptor "
                         "failed with unexpected errno",
                         ioctl_rpc2str(ioctl_code));
        }
    }

    if (!func_found)
    {
        TEST_FAIL("'%s' value of 'func' parameter is not supported "
                  "by the test", func);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, inapprop_descr);
    CLEANUP_RPC_CLOSE(pco_iut, add_sock);

    TEST_END;
}
