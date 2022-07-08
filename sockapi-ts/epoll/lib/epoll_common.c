/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common functions for epoll tests 
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "epoll_common.h"

/* Description in epoll_common.h */
int
rpc_stream_conn_early_epfd_add(rcf_rpc_server *srvr, rcf_rpc_server *clnt,
                               const struct sockaddr *srvr_addr,
                               const struct sockaddr *clnt_addr,
                               int *srvr_s, int *clnt_s,
                               int *epfds, int epfds_num,
                               uint32_t evts)
{
    int result        = EXIT_SUCCESS;
    int srvr_sock     = -1;
    int clnt_sock     = -1;
    int accepted_sock = -1;
    int i;

    if (epfds_num <= 0)
    {
        ERROR("%s(): incorrect number of epfds_num",
              __FUNCTION__);
        return -1;
    }

    if ((srvr_sock = rpc_stream_server(srvr,
                                       RPC_PROTO_DEF, FALSE,
                                       srvr_addr)) < 0)
    {
        ERROR("%s(): Cannot create server socket of type SOCK_STREAM",
              __FUNCTION__);
        return -1;
    }

    clnt_sock = rpc_socket(clnt, rpc_socket_domain_by_addr(clnt_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

    for (i = 0; i < epfds_num; i++)
    {
        if (epfds[i] == -1)
            epfds[i] = rpc_epoll_create(clnt, 1);
        rpc_epoll_ctl_simple(clnt, epfds[i], RPC_EPOLL_CTL_ADD, clnt_sock,
                             evts);
    }

    rpc_bind(clnt, clnt_sock, clnt_addr);
    rpc_connect(clnt, clnt_sock, srvr_addr);

    accepted_sock = rpc_accept(srvr, srvr_sock, NULL, NULL);

    /*
     * We should close server socket anyway because we've already had a
     * connection "clnt_sock" <-> "accepted_sock"
     */
    CLEANUP_RPC_CLOSE(srvr, srvr_sock);

    if (result == EXIT_FAILURE)
    {
        CLEANUP_RPC_CLOSE(srvr, accepted_sock);
        CLEANUP_RPC_CLOSE(clnt, clnt_sock);
        for (i = 0; i < epfds_num; i++)
            if (epfds[i] == -1)
                CLEANUP_RPC_CLOSE(clnt, epfds[i]);
    }
    else
    {
        *srvr_s = accepted_sock;
        *clnt_s = clnt_sock;
    }

    return ((result == EXIT_SUCCESS) ? 0 : -1);
}

/* See description in epoll_common.h */
void
epoll_check_single_event(rcf_rpc_server *rpcs,
                         iomux_call_type iomux,
                         int rc, struct rpc_epoll_event *event,
                         int exp_rc, te_errno exp_errno,
                         int exp_fd, uint32_t exp_events,
                         const char *err_msg)
{
#define MAX_EVTS_STR_LEN 1000

    if (rc < 0)
    {
        if (exp_rc < 0)
        {
            if (RPC_ERRNO(rpcs) != exp_errno && exp_errno != RPC_EUNKNOWN)
                TEST_VERDICT("%s: %s() failed with unexpected errno %r",
                             err_msg, iomux_call_en2str(iomux),
                             RPC_ERRNO(rpcs));
        }
        else
        {
            TEST_VERDICT("%s: %s() failed unexpectedly with errno %r",
                         err_msg, iomux_call_en2str(iomux),
                         RPC_ERRNO(rpcs));
        }
    }
    else if (rc > 1)
    {
        TEST_VERDICT("%s: %s() returned too big value",
                     err_msg, iomux_call_en2str(iomux));
    }
    else if (rc == 0)
    {
        if (exp_rc < 0)
            TEST_VERDICT("%s: %s() unexpectedly succeeded "
                         "returning no events",
                         err_msg, iomux_call_en2str(iomux));
        else if (exp_rc > 0)
            TEST_VERDICT("%s: %s() unexpectedly returned no events "
                         "instead of '%s'",
                         err_msg, iomux_call_en2str(iomux),
                         epoll_event_rpc2str(exp_events));
    }
    else
    {
        if (event->data.fd != exp_fd)
        {
            TEST_VERDICT("%s: %s() returned events for "
                         "unexpected descriptor",
                         err_msg, iomux_call_en2str(iomux));
        }
        else if (exp_rc < 0)
        {
            TEST_VERDICT("%s: %s() unexpectedly succeeded "
                         "returned events '%s'",
                         err_msg, iomux_call_en2str(iomux),
                         epoll_event_rpc2str(event->events));
        }
        else if (exp_rc == 0)
        {
            TEST_VERDICT("%s: %s() unexpectedly returned events '%s'",
                         err_msg, iomux_call_en2str(iomux),
                         epoll_event_rpc2str(event->events));
        }
        else if (event->events != exp_events)
        {
            char exp_evts_str[MAX_EVTS_STR_LEN] = "";

            snprintf(exp_evts_str, MAX_EVTS_STR_LEN, "%s",
                     epoll_event_rpc2str(exp_events));

            TEST_VERDICT("%s: %s() returned unexpected "
                         "events '%s' instead of '%s'",
                         err_msg, iomux_call_en2str(iomux),
                         epoll_event_rpc2str(event->events),
                         exp_evts_str);
        }
    }
}
