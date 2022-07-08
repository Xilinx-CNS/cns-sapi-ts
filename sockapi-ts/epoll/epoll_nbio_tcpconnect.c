/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * epoll functionality
 * 
 * $Id$
 */

/** @page epoll-epoll_nbio_tcpconnect Fail of non-blocking TCP connection
 *
 * @objective Check epoll functions behavior of failure during non-blocking
 *            TCP connection, socket is reused.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on IUT
 * @param iut_addr  Address/port to be used to connect to @p pco_iut
 * @param pco_tst   Auxiliary PCO
 * @param tst_addr  Address/port to be used to connect to @p pco_tst
 * @param timeout   Timeout value for epoll wait
 * @param sock_type Socket type (@c SOCK_STREM or @c SOCK_DGRAM)
 *
 * @par Scenario:
 * -# create a new epoll set @p epfd;
 * -# create socket @p iut_s at @p pco_iut with type in dependence
 *    on @p sock_type;
 * -# add the socket to the epoll set;
 * -# call epoll_wait for @p epfd with timeout @p timeout;
 * -# delete socket @p iut_s from epoll set @p epfd;
 * -# close and re-create socket @p iut_s at @p pco_iut;
 * -# apply option @c FIONBIO to @p iut_s;
 * -# call connect() for socket @p iut_s with address @p tst_addr,
 *    handle error;
 * -# add the socket to the epoll set;
 * -# call epoll_wait with timeout @p timeout, expect event @c EPOLLERR;
 * -# delete socket @p iut_s from epoll set @p epfd,
 *    removing should be successfully.
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_nbio_tcpconnect"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    int timeout;
    int req_val;
    int iut_s = -1;
    int epfd = -1;
    int maxevents = 10;

    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;
    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;
    struct rpc_epoll_event   events[maxevents];
    uint32_t                 ev = RPC_EPOLLOUT;
    rpc_socket_type          sock_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_SOCK_TYPE(sock_type);

    epfd = rpc_epoll_create(pco_iut, maxevents);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN);
    rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s,
                         RPC_EPOLLIN);
    RPC_CLOSE(pco_iut, iut_s);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    req_val = TRUE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    TAPI_CALL_CHECK_RC(pco_iut, connect, -1, RPC_EINPROGRESS,
                       iut_s, tst_addr);

    TAPI_WAIT_NETWORK;

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, ev);
    memset(events, 0, sizeof(events));
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);
    if (rc != 1)
        TEST_FAIL("epoll_wait returned unexpected value %d instead 1", rc);
    if ((events->events & RPC_EPOLLERR) == 0)
        TEST_FAIL("epoll events %s, but RPC_EPOLLERR was expected",
                  epoll_event_rpc2str(events->events));

    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL, iut_s, ev);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    TEST_END;
}
