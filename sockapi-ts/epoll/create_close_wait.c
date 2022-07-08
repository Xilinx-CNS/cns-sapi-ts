/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-create_close_wait Call epoll_wait() with epfd with closed socket.
 *
 * @objective Check that epoll_wait() ignores closed socket in epfd.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type1    Type of sockets in the first connection
 *                      (@c SOCK_STREAM or @c SOCK_DGRAM)
 * @param sock_type2    Type of sockets in the second connection
 *                      (@c SOCK_STREAM or @c SOCK_DGRAM)
 * @param timeout       Timeout for @b epoll_wait() function
 *                      If it is 0 the non-blocking call should be used
 * @param data_size     The amount of data to be sent
 * @param duplication   Type of descriptor duplication to use
 *                      none - no duplication
 *                      dup  - duplication via @b dup() function
 *                      fork - duplication via @b fork() function
 * @param non_blocking  Test blocking or non-blocking call of @b epoll_wait()
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type1 connection between @p pco_iut and @p pco_tst. Two
 *    connected sockets @p iut_s1 and @p tst_s1 would appear.
 * -# Create @p sock_type2 connection between @p pco_iut and @p pco_tst. Two
 *    connected sockets @p iut_s2 and @p tst_s2 would appear.
 * -# Create @p epfd with @p iut_s1 and @p iut_s2 sockets with @c EPOLLIN
 *    event using @b epoll_create() and @b epoll_ctl(@c EPOLL_CTL_ADD)
 *    functions.
 * -# If duplication is required create duplicated socket of @p iut_s1
 *    by corresponding function.
 * -# Close @p iut_s1 socket.
 * -# If testing blocking @b epoll_wait(), call @b epoll_wait() with 
 *    @p epfd and @p timeout.
 * -# Send @p data_size bytes of data from @p tst_s1 socket to @p iut_s1.
 * -# If testing blocking @b epoll_wait() or duplication was performed send 
 *    @p data_size bytes of data from @p tst_s2 socket to @p iut_s2.
 * -# If duplication was performed check that @p epoll_wait() function
 *    returns @c 1 with @c EPOLLIN event for iut_s1 socket.
 * -# Else check that @p epoll_wait() function returns @c 1 with @c EPOLLIN 
 *    event for iut_s2 socket.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/create_close_wait"

#include "sockapi-test.h"
#include "iomux.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 1024

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *iut_child = NULL;

    rpc_socket_type         sock_type1;
    rpc_socket_type         sock_type2;

    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *iut_addr2 = NULL;
    const struct sockaddr  *tst_addr1 = NULL;
    const struct sockaddr  *tst_addr2 = NULL;

    int                     iut_s1 = -1;
    int                     tst_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s2 = -1;
    int                     dup_s = -1;

    int                     epfd = -1;
    struct rpc_epoll_event  events[3];
    int                     maxevents = 3;
    int                     timeout;
    const char             *duplication;
    te_bool                 create_dup;
    te_bool                 use_fork;
    te_bool                 non_blocking;
    te_bool                 early_ctl;

    unsigned char           buffer[MAX_BUFF_SIZE];
    int                     data_size;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_ADDR(pco_tst, tst_addr2);
    TEST_GET_SOCK_TYPE(sock_type1);
    TEST_GET_SOCK_TYPE(sock_type2);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_STRING_PARAM(duplication);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(early_ctl);

    if (strcmp(duplication, "none") == 0)
    {
        create_dup = FALSE;
        use_fork = FALSE;
    }
    else if(strcmp(duplication, "dup") == 0)
    {
        create_dup = TRUE;
        use_fork = FALSE;
    }
    else if(strcmp(duplication, "fork") == 0)
    {
        create_dup = TRUE;
        use_fork = TRUE;
    }
    else
    {
        TEST_FAIL("Unexpected value of duplication parameter: %s",
                                                        duplication);
    }

    if (non_blocking)
        timeout = 0;

    memset(events, 0, sizeof(events));

    /* Scenario */
    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, FALSE, sock_type1,
                           iut_addr1, tst_addr1, iut_s1, tst_s1,
                           TRUE, TRUE, epfd, early_ctl, RPC_EPOLLIN);
    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, FALSE, sock_type2,
                           iut_addr2, tst_addr2, iut_s2, tst_s2,
                           TRUE, TRUE, epfd, early_ctl, RPC_EPOLLIN);

    if (create_dup)
    {
        if (use_fork)
        {
            CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child",
                                                    &iut_child));
        }
        else
        {
            dup_s = rpc_dup(pco_iut, iut_s1);
        }
    }

    rpc_close(pco_iut, iut_s1);

    pco_iut->op = RCF_RPC_CALL;
    if (!non_blocking)
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                              maxevents, timeout);

    RPC_WRITE(rc, pco_tst, tst_s1, buffer, data_size);
    if ((!non_blocking) || (!create_dup))
    {
        TAPI_WAIT_NETWORK;
        RPC_WRITE(rc, pco_tst, tst_s2, buffer, data_size);
    }

    TAPI_WAIT_NETWORK;

    pco_iut->op = (!non_blocking) ? RCF_RPC_WAIT : RCF_RPC_CALL_WAIT;
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, timeout);
    if (rc != 1)
    {
        TEST_VERDICT("epoll waiting function returned %d instead of 1", rc);
    }
    else if (events[0].events != RPC_EPOLLIN)
    {
        TEST_FAIL("epoll waiting function returned incorrect events");
    }
    else if ((create_dup && events[0].data.fd != iut_s1) ||
             (!create_dup && events[0].data.fd != iut_s2))
    {
        TEST_VERDICT("epoll waiting function returned incorrect socket");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, dup_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    (void)rcf_rpc_server_destroy(iut_child);

    TEST_END;
}
