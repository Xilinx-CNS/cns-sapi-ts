/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-ioctl_on_epfd Epoll file descriptor in ioctl function.
 *
 * @objective Check that ioctl() called with epfd correctly reports
 *            the appropriate error.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of sockets using in the test
 * @param evts          One of @c in, @c out or @c inout
 * @param exp_ret       The value that @b ioctl() function should return
 *                      (see table below)
 * @param error         Expected error (see table below)
 * @param req           Type of ioctl request. The table of request values
 *                      with expected error in brackets and the value that
 *                      @b ioctl() should return in square brackets:
 *                      - @c FIONBIO        [@c 0]  (do not check errno)
 *                      - @c FIONREAD       [@c -1] (@c ENOTTY)
 *                      - @c SIOCATMARK     [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFNETMASK [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFADDR    [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFBRDADDR [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFFLAGS   [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFMTU     [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFDSTADDR [@c -1] (@c ENOTTY)
 *                      - @c SIOCGIFHWADDR  [@c -1] (@c ENOTTY)
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type socket @p iut_s.
 * -# Create @p epfd with @p iut_s socket and with the events according
 *    to @p evts parameter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# Call @b ioctl(@p epfd, @p req).
 * -# If @p exp_ret is @c 0 check that @b ioctl() returns @p exp_ret in
 *    other cases check that @b ioctl() returns @p exp_ret and sets errno
 *    to @p error.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/ioctl_on_epfd"

#include "sockapi-test.h"
#include "epoll_common.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    const struct if_nameindex *iut_if = NULL;

    const struct sockaddr  *iut_addr = NULL;

    int                     iut_s = -1;

    rpc_socket_type         sock_type;

    const char             *evts;

    int                     epfd = -1;
    uint32_t                event;

    rpc_ioctl_code          req;
    rpc_errno               error;
    int                     exp_ret;

    struct ifreq            ifreq_var;
    int                     req_val;

    TEST_START;
    TEST_GET_IOCTL_REQ(req);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ERRNO_PARAM(error);
    TEST_GET_INT_PARAM(exp_ret);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_IF(iut_if);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    PARSE_EVTS(evts, event, event);

    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, event);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (req == RPC_SIOCATMARK || req == RPC_FIONBIO || req == RPC_FIONREAD)
    {
        rc = rpc_ioctl(pco_iut, epfd, req, &req_val);
    }
    else
    {
        memset(&ifreq_var, 0, sizeof(ifreq_var));
        strncpy(ifreq_var.ifr_name, iut_if->if_name,
                sizeof(ifreq_var.ifr_name));
        rc = rpc_ioctl(pco_iut, epfd, req, &ifreq_var);
    }

    if (rc != exp_ret)
        TEST_VERDICT("ioctl(%s) called on epoll descriptor returned %d "
                     "instead %d.", ioctl_rpc2str(req), rc, exp_ret);

    if (exp_ret == -1)
        CHECK_RPC_ERRNO(pco_iut, error, "ioctl(%s) returns %d",
                        ioctl_rpc2str(req), rc);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
