/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id: epoll_reused_descriptor.c 65452 2010-08-02 09:08:26Z sasha $
 */

/** @page epoll-epoll_reused_descriptor Check that reused file descriptor is properly handled by epoll.
 *
 * @objective Check that reused file descriptor is properly handled by epoll.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of sockets in the connection
 *                      (@c SOCK_STREAM ot @c SOCK_DGRAM)
 * @param timeout       Timeout for @b epoll_wait() function
 * @param duplication   Type of descriptor duplication to use
 *                      none - no duplication
 *                      dup  - duplication via @b dup() function
 *                      fork - duplication via @b fork() function
 * @param fast_reopen   Whether to use @b rpc_close_and_socket() call or not
 * @param iomux         Type of epoll function
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type socket @p iut_s on IUT.
 * -# Create @p epfd with @p iut_s socket with @c EPOLLOUT
 *    event using @b epoll_create() and @b epoll_ctl(@c EPOLL_CTL_ADD)
 *    functions.
 * -# Check that epoll_wait() returns 1 for epfd.
 * -# If @p duplication is not "none" create duplicated socket of @p iut_s
 *    by corresponding function.
 * -# Close and reopen @p iut_s socket. If @p fast_reopen is TRUE use
 *    @b rpc_close_and_socket() rpc call.
 * -# If @p duplication is not "none" add this socket to epfd as well.
 * -# Check that epoll_wait() returns right value for epfd. It should be
 *    0 if @p duplication is "none" and 2 otherwise.
 * -# @b close() all sockets.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_reused_descriptor"

#include "sockapi-test.h"
#include "iomux.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *iut_child = NULL;

    rpc_socket_type         sock_type;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     tst_s = -1;
    int                     tst_aux_s = -1;
    int                     iut_s = -1;
    int                     dup_s = -1;
    int                     tmp_sock;
    int                     tmp_sock1;

    int                     epfd = -1;
    struct rpc_epoll_event  events[3];
    int                     maxevents = 3;
    rpc_onload_ordered_epoll_event  oo_events[maxevents];

    int                     timeout;
    const char             *duplication;
    te_bool                 create_dup;
    te_bool                 use_fork;
    te_bool                 fast_reopen;
    uint32_t                ev_flags = RPC_EPOLLOUT | RPC_EPOLLIN;
    te_bool                 add_to_set;
    const char             *operation;
    int                     exp;
    int                     i;

    void                   *tx_buf = NULL;
    size_t                  tx_buf_len;
    iomux_call_type         iomux;
    rpc_socket_domain       domain;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_STRING_PARAM(duplication);
    TEST_GET_BOOL_PARAM(fast_reopen);
    TEST_GET_BOOL_PARAM(add_to_set);
    TEST_GET_STRING_PARAM(operation);
    TEST_GET_IOMUX_FUNC(iomux);

    domain = rpc_socket_domain_by_addr(iut_addr);

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

    memset(events, 0, sizeof(events));

    tx_buf = sockts_make_buf_stream(&tx_buf_len);

    /* Scenario */

    /* Create socket */
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    /* Create epfd */
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         ev_flags);

    tmp_sock = iut_s;

    if (create_dup)
    {
        if (use_fork)
        {
            CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", 
                                                    &iut_child));  
        }
        else
        {
            dup_s = rpc_dup(pco_iut, iut_s);
        }
    }

    /* Check epoll_wait */
    if (iomux == IC_OO_EPOLL)
        rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                           maxevents, timeout);
    else
        rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
    {
        TEST_VERDICT("epoll_wait returned %d instead of 1", rc);
    }
    else if (events[0].data.fd != iut_s)
    {
        TEST_FAIL("epoll_wait returned incorrect socket, %d",
                                            events[0].data.fd);
    }
    else if ((events[0].events & RPC_EPOLLOUT) == 0)
    {
        TEST_FAIL("epoll_wait returned incorrect events");
    }

    /* Recreate socket */
    if (fast_reopen)
    {
        rpc_close_and_socket(pco_iut, iut_s,
                             domain, sock_type, RPC_PROTO_DEF);
    }
    else
    {
        RPC_CLOSE(pco_iut, iut_s);
        iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
                   
        if (iut_s != tmp_sock)
        {
            /* If fd doesn't match try to move it with dup2() function*/
            RING("Wrong descriptor returned, moving.");
            tmp_sock1 = iut_s;
            iut_s = rpc_dup2(pco_iut, iut_s, tmp_sock);
            if (iut_s != tmp_sock)
            {
                RPC_CLOSE(pco_iut, tmp_sock1);
                TEST_VERDICT("Failed to move descriptor");
            }
            RPC_CLOSE(pco_iut, tmp_sock1);
        }
    }

    if (add_to_set)
    {
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                             ev_flags);
    }

    if (strcmp(operation, "none") != 0)
    {
        tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);

        if (sock_type == RPC_SOCK_DGRAM)
        {
            if (strcmp(operation, "wrtie") == 0)
                rpc_sendto(pco_iut, iut_s, tx_buf, tx_buf_len, 0, tst_addr);
            else
                rpc_sendto(pco_tst, tst_s, tx_buf, tx_buf_len, 0, iut_addr);
        }
        else
        {
            rpc_bind(pco_tst, tst_s, tst_addr);
            rpc_bind(pco_iut, iut_s, iut_addr);

            rpc_listen(pco_tst, tst_s, 1);
            pco_tst->op = RCF_RPC_CALL;
            tst_aux_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
            TAPI_WAIT_NETWORK;
            rpc_connect(pco_iut, iut_s, tst_addr);

            pco_tst->op = RCF_RPC_WAIT;
            tst_aux_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

            if (strcmp(operation, "wrtie") == 0)
                rpc_send(pco_iut, iut_s, tx_buf, tx_buf_len, 0);
            else
                rpc_send(pco_tst, tst_aux_s, tx_buf, tx_buf_len, 0);
        }
        TAPI_WAIT_NETWORK;
    }

    /* Check epoll_wait again */
    if (iomux == IC_OO_EPOLL)
        rc = rpc_onload_ordered_epoll_wait(pco_iut, epfd, events, oo_events,
                                           maxevents, timeout);
    else
        rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    exp = 0;
    if (create_dup)
        exp++;
    if (add_to_set)
        exp++;

    if (rc != exp)
        TEST_VERDICT("epoll_wait returned %d instead of %d", rc, exp);

    for (i = 0; i < exp; i++)
        RING_VERDICT("event[%d] %s", i,
                     epoll_event_rpc2str(events[i].events));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, dup_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_aux_s);

    (void)rcf_rpc_server_destroy(iut_child);

    free(tx_buf);

    TEST_END;
}
