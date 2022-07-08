/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_epoll_ctl_bad_fd_type Using epoll_ctl() function with bad fd type
 *
 * @objective Check that @b epoll_ctl() function correctly reports
 *            an error when it is called with bad fd type.
 *
 * @type conformance, robustness
 *
 * @param pco_iut   PCO on IUT
 *
 * @par Scenario:
 * -# Create a socket @p iut_s on @p pco_iut.
 * -# Call @b epoll_create() to create @p epfd.
 * -# Open a temporary file, /dev/null and /dev/zero.
 * -# Try to pass obtained fds to @b epoll_ctl() and check return
 *    values and errno.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_epoll_ctl_bad_fd_type"

#include "sockapi-test.h"

#define CHECK_EPOLL_CTL(fd_, msg_) \
    do {                                                            \
        event.data.fd = (fd_);                                      \
        RPC_AWAIT_IUT_ERROR(pco_iut);                               \
        rc = rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD,        \
                           (fd_), &event);                          \
        if (rc >= 0)                                                \
        {                                                           \
            ERROR_VERDICT("epoll_ctl() successeed adding %s",       \
                          (msg_));                                  \
            is_failed = TRUE;                                       \
        }                                                           \
        else if (RPC_ERRNO(pco_iut) != RPC_EPERM)                   \
        {                                                           \
            ERROR_VERDICT("epoll_ctl() returned strange errno "     \
                          "adding %s", (msg_));                     \
            is_failed = TRUE;                                       \
        }                                                           \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;
    int                     epfd = -1;
    struct rpc_epoll_event  event;

    int tmp_file_fd = -1;
    int dev_null_fd = -1;
    int dev_zero_fd = -1;

    char    tmp_file_name[100];
    te_bool is_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    event.events = RPC_EPOLLIN;
    epfd = rpc_epoll_create(pco_iut, 1);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    dev_null_fd = rpc_open(pco_iut, "/dev/null",
                           RPC_O_WRONLY, 0);
    if (dev_null_fd == -1)
    {
        ERROR_VERDICT("Failed to open /dev/null");
        is_failed = TRUE;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    dev_zero_fd = rpc_open(pco_iut, "/dev/zero",
                           RPC_O_RDONLY, 0);
    if (dev_zero_fd == -1)
    {
        ERROR_VERDICT("Failed to open /dev/zero");
        is_failed = TRUE;
    }

    snprintf(tmp_file_name, sizeof(tmp_file_name), 
             "/tmp/te_tmp_file_%d", 
             rand_range(0, 100000));

    tmp_file_fd = rpc_open(pco_iut, tmp_file_name,
                           RPC_O_RDWR | RPC_O_CREAT | RPC_O_EXCL,
                           RPC_S_IRWXU);
    if (tmp_file_fd == -1)
    {
        ERROR_VERDICT("Failed to open temporary file");
        is_failed = TRUE;
    }

    if (dev_null_fd >= 0)
        CHECK_EPOLL_CTL(dev_null_fd, "/dev/null");
    if (dev_zero_fd >= 0)
        CHECK_EPOLL_CTL(dev_zero_fd, "/dev/zero");
    if (tmp_file_fd >= 0)
        CHECK_EPOLL_CTL(tmp_file_fd, "temporary file");

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (tmp_file_fd >= 0)
    {
        int rc2;

        rc2 = rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc,
                          1 /* argc */, FALSE,
                          RCF_STRING, tmp_file_name);

        if ((rc2 != 0) || (rc != 0))
        {
            ERROR("Failed to unlink file '%s' of TA '%s': rc=%r",
                  tmp_file_name, pco_iut->ta, (rc2 != 0) ? rc2 : rc);
            result = EXIT_FAILURE;
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, dev_null_fd);
    CLEANUP_RPC_CLOSE(pco_iut, dev_zero_fd);
    CLEANUP_RPC_CLOSE(pco_iut, tmp_file_fd);

    TEST_END;
}
