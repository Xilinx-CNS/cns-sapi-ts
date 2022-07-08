/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 *
 * $Id$
 */

/** @page iomux-read_write_nbio Check that iomux functions works correctly in case of receiving 1-bytes packets
 *
 * @objective Check that iomux functions works correctly in case of
 *            receiving 1-bytes packets.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iut_addr      Address/port to connect to @p pco_iut
 * @param sock_type     Socket type: @c SOCK_DGRAM or @c SOCK_STREAM
 * @param iomux         I/O multiplexing function to be tested
 * @param add_flags     Auxiliary flags to indecate that @c EPOLLET mode
 *                      should be used
 *
 * @par Scenario:
 * -# Create socket @p iut_s on @p pco_iut and socket @p tst_s
 *    on @p pco_tst;
 * -# Apply option @c FIONBIO via RPC call @b ioctl() to @p iut_s;
 * -# Attempt to call @b accept() on @p iut_s, handle error;
 * -# Add socket @a iut_s to descriptors list of @p iomux;
 * -# If @p sock_type is @c SOCK_STREAM make connection:
 *      - Call @p iomux to wait connection;
 *      - Call @b connect() on the @p tst_s with address @p iut_addr;
 *      - Call @p accept on the @p iut_s to establish connection,
 *        obtained new socket @p aux_s;
 *      - Add the socket @p aux_s to descriptors list of @p iomux;
 *      - Apply option @c FIONBIO via RPC call @b ioctl() to @p aux_s;
 * -# If @p sock_type is @c SOCK_DGRAM:
 *      - Call @b connect() on the @p tst_s with address @p iut_addr;
 *      - Socket @p aux_s is equal to the @a iut_s;
 * -# Send data packet from the TST host via the @a tst_sock;
 * -# Receive data on the IUT host using the socket @p aux_s;
 * -# Verify the received packet size and contents;
 * -# Attempt to call @b accept() on @p iut_s, handle error;
 * -# Call the @p iomux function with timeout @c 0;
 * -# Attempt to call @b recv() on @p iut_s, handle error;
 * -# Call the @p iomux function with indefinitely timeout;
 * -# Send data packet from the TST host via the @a tst_sock;
 * -# Receive data on the IUT host using the socket @p aux_s;
 * -# Verify the received packet size and contents;
 * 
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/read_write_nbio"

#include "sockapi-test.h"
#include "iomux.h"

/* Maximum number of possible events */
#define TEST_MAXEVENTS 2

/**
 * File descriptors to use in iomux functions
 */
typedef struct test_fds_ctx_t {
    uint32_t                event;
    struct rpc_epoll_event  events[TEST_MAXEVENTS];
    struct rpc_pollfd       fds[TEST_MAXEVENTS];
    int                     epfd;
    int                     maxfd;
    rpc_fd_set_p            read_fds;
    rpc_fd_set_p            write_fds;
    rpc_fd_set_p            exc_fds;
    int                     idx;
    iomux_call_type         iomux;
} test_fds_ctx_t;

/**
 * Add socket to appropriate set of descriptos.
 * 
 * @param rpcs      RPC server handle
 * @param fdctx     Context with file descriptors
 * @param sock      Socket which should be added
 */
static void
test_fds_add(rcf_rpc_server *rpcs, test_fds_ctx_t *fdctx, int sock)
{
    if (fdctx->iomux == IC_EPOLL || fdctx->iomux == IC_EPOLL_PWAIT ||
        fdctx->iomux == IC_OO_EPOLL)
        rpc_epoll_ctl_simple(rpcs, fdctx->epfd, RPC_EPOLL_CTL_ADD, sock,
                             fdctx->event);
    else if (fdctx->iomux == IC_POLL || fdctx->iomux == IC_PPOLL)
    {
        fdctx->fds[fdctx->idx].fd = sock;
        fdctx->fds[fdctx->idx].events = RPC_POLLIN | RPC_POLLOUT;
    }
    else
    {
        rpc_do_fd_set(rpcs, sock, fdctx->read_fds);
        rpc_do_fd_set(rpcs, sock, fdctx->write_fds);
        rpc_do_fd_set(rpcs, sock, fdctx->exc_fds);
        fdctx->maxfd = sock + 1;
    }

    fdctx->idx++;
}

/**
 * Initilize file descriptors for iomux calls and add socket @a sock to the
 * fd lists.
 * 
 * @param rpcs      RPC server handle
 * @param iomux     Type of iomux function
 * @param add_flags Auxiliary flags
 * @param fdctx     Context with file descriptors
 */
static void
test_init_fds(rcf_rpc_server *rpcs, iomux_call_type iomux,
              const char *add_flags, test_fds_ctx_t *fdctx)
{
    fdctx->iomux = iomux;
    if (iomux == IC_EPOLL || iomux == IC_EPOLL_PWAIT ||
        iomux == IC_OO_EPOLL)
    {
        fdctx->epfd = rpc_epoll_create(rpcs, 1);
        fdctx->event = RPC_EPOLLIN | RPC_EPOLLOUT;
        if (strcmp(add_flags, "epollet") == 0)
            fdctx->event |= RPC_EPOLLET;
    }
    else if (iomux == IC_POLL || iomux == IC_PPOLL)
    {
        fdctx->fds[0].fd = -1;
        fdctx->fds[1].fd = -1;
    }
    else
    {
        fdctx->read_fds = rpc_fd_set_new(rpcs);
        rpc_do_fd_zero(rpcs, fdctx->read_fds);
        fdctx->write_fds = rpc_fd_set_new(rpcs);
        rpc_do_fd_zero(rpcs, fdctx->write_fds);
        fdctx->exc_fds = rpc_fd_set_new(rpcs);
        rpc_do_fd_zero(rpcs, fdctx->exc_fds);
    }
}

/**
 * Perform call of iomux function
 * 
 * @param rpcs      RPC server handle
 * @param iomux     Type of iomux function
 * @param fdctx     Context with file descriptors
 * @param timeout   Maximum blocking time or @c -1 to block indefinitely
 */
static void
test_iomux_call(rcf_rpc_server *rpcs, iomux_call_type iomux,
                test_fds_ctx_t *fdctx, int timeout)
{
    switch (iomux)
    {
        case IC_EPOLL:
            memset(fdctx->events, 0, sizeof(fdctx->events));
            rpc_epoll_wait(rpcs, fdctx->epfd, fdctx->events, 10,
                           timeout);
            break;

        case IC_EPOLL_PWAIT:
            memset(fdctx->events, 0, sizeof(fdctx->events));
            rpc_epoll_pwait(rpcs, fdctx->epfd, fdctx->events,
                            TEST_MAXEVENTS, timeout, RPC_NULL);
            break;

        case IC_OO_EPOLL:
        {
            rpc_onload_ordered_epoll_event oo_ev[TEST_MAXEVENTS];

            memset(fdctx->events, 0, sizeof(fdctx->events));
            RPC_AWAIT_IUT_ERROR(rpcs);
            if (rpc_onload_ordered_epoll_wait(rpcs, fdctx->epfd,
                                              fdctx->events, oo_ev,
                                              TEST_MAXEVENTS, timeout) < 0)
                    TEST_VERDICT("oo_epoll() failed with %s",
                                 errno_rpc2str(RPC_ERRNO(rpcs)));
            break;
        }


        case IC_POLL:
            rpc_poll(rpcs, fdctx->fds, fdctx->idx, timeout);
            break;

        case IC_PPOLL:
            rpc_ppoll(rpcs, fdctx->fds, fdctx->idx,
                      timeout == -1 ? NULL :
                      &((struct tarpc_timespec){timeout/1000,
                                                timeout * 1000000}),
                      RPC_NULL);
            break;

        case IC_SELECT:
            rpc_select(rpcs, fdctx->maxfd, fdctx->read_fds,
                       fdctx->write_fds, fdctx->exc_fds,
                       timeout == -1 ? NULL :
                       &((struct tarpc_timeval){timeout/1000,
                                                timeout * 1000}));
            break;

        case IC_PSELECT:
            rpc_pselect(rpcs, fdctx->maxfd, fdctx->read_fds,
                        fdctx->write_fds, fdctx->exc_fds,
                        timeout == -1 ? NULL :
                        &((struct tarpc_timespec){timeout/1000,
                                                  timeout * 1000000}),
                        RPC_NULL);
            break;

        default:
         TEST_FAIL("Unknow iomux %s", iomux_call_en2str(iomux));
     }
}

int
main(int argc, char *argv[])
{
    rpc_socket_type          sock_type;
    iomux_call_type          iomux;

    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;

    const struct sockaddr   *iut_addr = NULL;
    struct sockaddr_storage  iut_wildcard_addr;

    int                      aux_s = -1;
    int                      iut_s = -1;
    int                      tst_s = -1;
    int                      req_val;

    test_fds_ctx_t           fdctx;

    const char              *add_flags;
    void                    *tx_buf = NULL;
    size_t                   tx_buf_len;
    void                    *rx_buf = NULL;
    size_t                   rx_buf_len;
    ssize_t                  res;

    rpc_socket_domain domain;

    const struct if_nameindex *tst_if = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(add_flags);

    tx_buf_len = rx_buf_len = 1;
    tx_buf = malloc(tx_buf_len);
    rx_buf = malloc(tx_buf_len);

    domain = rpc_socket_domain_by_addr(iut_addr);

    iut_wildcard_addr.ss_family = domain_rpc2h(domain);
    te_sockaddr_set_port(SA(&iut_wildcard_addr),
                         te_sockaddr_get_port(iut_addr));
    te_sockaddr_set_wildcard(SA(&iut_wildcard_addr));

    memset(&fdctx, 0, sizeof(fdctx));
    test_init_fds(pco_iut, iomux, add_flags, &fdctx);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, SA(&iut_wildcard_addr));
    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    test_fds_add(pco_iut, &fdctx, iut_s);

    req_val = TRUE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    if (sock_type == RPC_SOCK_STREAM)
    {

        RPC_AWAIT_IUT_ERROR(pco_iut);
        aux_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (aux_s == -1)
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "accept() returns -1, but");
        else
            TEST_FAIL("RPC accept() should fail with errno EAGAIN");
        RPC_DONT_AWAIT_IUT_ERROR(pco_iut);

        pco_iut->op = RCF_RPC_CALL;
        test_iomux_call(pco_iut, iomux, &fdctx, -1);

        rpc_connect(pco_tst, tst_s, iut_addr);

        pco_iut->op = RCF_RPC_WAIT;
        test_iomux_call(pco_iut, iomux, &fdctx, -1);
        aux_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

        test_fds_add(pco_iut, &fdctx, aux_s);
        req_val = TRUE;
        rpc_ioctl(pco_iut, aux_s, RPC_FIONBIO, &req_val);
    }
    else
    {
        rpc_connect(pco_tst, tst_s, iut_addr);
        aux_s = iut_s;
    }

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    TAPI_WAIT_NETWORK;
    pco_iut->op = RCF_RPC_CALL_WAIT;

#define RECV_AND_CHECK_BUF \
do {                                                                       \
    res = rpc_recv_gen(pco_iut, aux_s, rx_buf, tx_buf_len, 0, rx_buf_len); \
    if (res != (ssize_t)tx_buf_len)                                        \
        TEST_FAIL("Only part of data received");                           \
    if (memcmp(tx_buf, rx_buf, tx_buf_len))                                \
        TEST_FAIL("Invalid data received");                                \
} while(0)

    RECV_AND_CHECK_BUF;

    if (sock_type == RPC_SOCK_STREAM)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_accept(pco_iut, iut_s, NULL, NULL);
        if (rc == -1)
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
                            "accept() returns -1, but");
        else
            TEST_FAIL("RPC accept() should fail with errno EAGAIN");
    }

    test_iomux_call(pco_iut, iomux, &fdctx, 0);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    res = rpc_recv_gen(pco_iut, aux_s, rx_buf, tx_buf_len, 0, rx_buf_len);
    if (res == -1)
        CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "recv_gen() returns -1, but");
    else
        TEST_FAIL("RPC recv_gen() should fail with errno EAGAIN");
    RPC_DONT_AWAIT_IUT_ERROR(pco_iut);

    pco_iut->op = RCF_RPC_CALL;
    test_iomux_call(pco_iut, iomux, &fdctx, -1);

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0);
    TAPI_WAIT_NETWORK;

    pco_iut->op = RCF_RPC_WAIT;
    test_iomux_call(pco_iut, iomux, &fdctx, -1);
    memset(rx_buf, 0, rx_buf_len);

    RECV_AND_CHECK_BUF;

    TEST_SUCCESS;

cleanup:
    if (fdctx.iomux == IC_EPOLL || fdctx.iomux == IC_EPOLL_PWAIT ||
        fdctx.iomux == IC_OO_EPOLL)
    {
        CLEANUP_RPC_CLOSE(pco_iut, fdctx.epfd);
    }
    if (sock_type == RPC_SOCK_STREAM)
        CLEANUP_RPC_CLOSE(pco_iut, aux_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    TEST_END;
}
