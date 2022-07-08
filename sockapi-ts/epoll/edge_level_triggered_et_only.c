/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-edge_level_triggered_et_only File descriptors in ET and LT mode in one epfd with events only for the ET descriptor
 *
 * @objective Check that epoll functions correctly handle epoll descriptor
 *            with fds in edge and level-triggered modes when only
 *            the fd in edge-triggered mode has events.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param is_pipe       Whether we test a pipe or a pair of connected
 *                      sockets
 * @param sock_type     Type of sockets used in the test
 * @param evts          One of @c in, @c out or @c inout
 * @param data_size     The amount of data to be sent
 * @param et_first      Determine the sequence in which fds in edge
 *                      and level-triggered mode should be added to epoll
 *                      descriptor
 * @param timeout       Timeout for @b epoll_wait() function
 * @param non_blocking  Test blocking or non-blocking call of
 *                      @b epoll_wait()
 * @param read_between  Whether we should to read data sent between
 *                      the first and the second @b epoll_wait()
 *                      calls to edge-triggered fd or not (can be @c TRUE
 *                      only if we test @c in event)
 * @param zf            Zetaferno specific iteration if @c TRUE
 *
 * @par Test sequence:
 *
 * -# Create two pairs of connected fds (i.e. pairs of pipe ends or
 *    connected sockets) - (@p iut_fd1, @p tst_fd1) and
 *    (@p iut_fd2, @p tst_fd2).
 * -# Create @p epfd using @b epoll_create() function.
 * -# Add fds to @p epfd according to @p et_first parameter:
 *    - If @p et_first is @c TRUE add @p iut_fd1 in edge-triggered
 *      mode and after that @p iut_fd2 in level-triggered mode, both
 *      with the events according to @p evts parameter
 *    - If @p et_first is @c FALSE add @p iut_fd1 in level-triggered
 *      mode and after that @p iut_fd2 in edge-triggered mode, both
 *      with the events according to @p evts parameter
 * -# Produce events only for the fd in edge-triggered mode.
 *    In case of @c out and @c inout events call @b overfill_buffers() on
 *    the fd in level-triggered mode. In case of @c in event send
 *    @p data_size bytes of data to the fd in edge-triggered mode.
 * -# Call @b epoll_wait() on @p epfd with @p timeout according to
 *    @p non_blocking parameter.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for the fd in edge-triggered mode.
 * -# Call @b epoll_wait() on @p epfd with zero timeout once again to
 *    check that edge-triggered mode works correctly i.e. there are no
 *    events for the fd in edge-triggered mode.
 * -# Check that @b epoll_wait() returns @c 0.
 * -# Produce events for the fd in edge-triggered mode:
 *      - If @p evts is @c in event send @p data_size bytes of data
 *        to the fd in edge-triggered mode.
 *      - If @p evts is @c out event send @p data_size bytes of data
 *        from the fd in edge-triggered mode.
 * -# Call @b epoll_wait() on @p epfd with @p timeout according to
 *    @p non_blocking parameter.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for the fd in edge-triggered mode.
 * -# Call @b epoll_wait() on @p epfd with zero timeout once again to
 *    check that edge-triggered mode works correctly i.e. there are no
 *    events for the fd in edge-triggered mode.
 * -# Check that @b epoll_wait() returns @c 1 with the events according to
 *    @p evts parameter for the fd in level-triggered mode.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/edge_level_triggered_et_only"

#include "sockapi-test.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 10240
int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr        *iut_addr2 = NULL;
    struct sockaddr        *tst_addr2 = NULL;

    tapi_env_net                *net;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    cfg_handle  iut_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle  tst_addr_handle = CFG_HANDLE_INVALID;

    int                     iut_fd1 = -1;
    int                     tst_fd1 = -1;
    int                     iut_fd2 = -1;
    int                     tst_fd2 = -1;

    rpc_socket_type         sock_type = RPC_SOCK_UNKNOWN;

    const char             *evts;

    int                     data_size;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[3];
    uint32_t                event1;
    uint32_t                event2;
    int                     maxevents = 3;

    uint32_t                exp_ev;
    uint64_t                total_bytes;
    int                     timeout;
    te_bool                 et_first;
    te_bool                 non_blocking;
    te_bool                 read_between;
    te_bool                 is_pipe;
    te_bool                 is_failed = FALSE;
    te_bool                 early_ctl;
    te_bool                 first_active;
    te_bool                 zf;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(et_first);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_BOOL_PARAM(read_between);
    TEST_GET_BOOL_PARAM(is_pipe);
    TEST_GET_BOOL_PARAM(early_ctl);
    TEST_GET_BOOL_PARAM(zf);
    if (!is_pipe)
    {
        int prefix;

        TEST_GET_NET(net);
        TEST_GET_IF(iut_if);
        TEST_GET_IF(tst_if);
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_iut, iut_addr);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_SOCK_TYPE(sock_type);

        prefix = iut_addr->sa_family == AF_INET ? net->ip4pfx : net->ip6pfx;

        /* Add new IP addresses on IUT/Tester interfaces. */
        CHECK_RC(tapi_env_allocate_addr(net, iut_addr->sa_family,
                                        &iut_addr2, NULL));
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                               iut_addr2, prefix,
                                               FALSE, &iut_addr_handle));

        /* Check if loopback environment is used. */
        if (te_sockaddrcmp_no_ports(iut_addr,
                                    te_sockaddr_get_size(iut_addr),
                                    tst_addr,
                                    te_sockaddr_get_size(tst_addr)) == 0)
        {
            CHECK_RC(tapi_sockaddr_clone2(iut_addr2, &tst_addr2));
        }
        else
        {
            CHECK_RC(tapi_env_allocate_addr(net, tst_addr->sa_family,
                                            &tst_addr2, NULL));
            CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta,
                                                   tst_if->if_name,
                                                   tst_addr2, prefix,
                                                   FALSE, &tst_addr_handle));
        }

        CFG_WAIT_CHANGES;
        CHECK_RC(tapi_allocate_set_port(pco_iut, iut_addr2));
        CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr2));
    }

    if (non_blocking)
        timeout = 0;

    PARSE_EVTS(evts, event1, exp_ev);
    event2 = event1;
    if (et_first)
        event1 |= RPC_EPOLLET;
    else
        event2 |= RPC_EPOLLET;

    first_active = is_pipe ? ((exp_ev & RPC_EPOLLOUT) ? TRUE : FALSE) : TRUE;

    /* Hack for ZF shim testing: we can't add one socket to 2 epoll sets,
     * so epoll_ctl() must be called after overfill_buffers().
     * I.e. GET_CONNECTED_ADD_EPFD() does not do the right thing for us. */
    if (!zf)
    {
        GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, is_pipe, sock_type,
                               iut_addr, tst_addr, iut_fd1, tst_fd1,
                               first_active, TRUE, epfd, early_ctl, event1);

        GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, is_pipe, sock_type,
                               iut_addr2, tst_addr2, iut_fd2, tst_fd2,
                               first_active, TRUE, epfd, early_ctl, event2);
    }
    else
    {
        GET_CONNECTED_FDS(pco_iut, pco_tst, is_pipe, sock_type,
                          iut_addr, tst_addr, iut_fd1, tst_fd1,
                          first_active, TRUE);

        GET_CONNECTED_FDS(pco_iut, pco_tst, is_pipe, sock_type,
                          iut_addr2, tst_addr2, iut_fd2, tst_fd2,
                          first_active, TRUE);
    }


    GET_FD2_PCO(pco_iut, pco_tst, pco_tst, is_pipe, iut_fd1, tst_fd1);
    GET_FD2_PCO(pco_iut, pco_tst, pco_tst, is_pipe, iut_fd2, tst_fd2);

    if (exp_ev == RPC_EPOLLIN)
    {
        RPC_WRITE(rc, pco_tst, (et_first) ? tst_fd1 : tst_fd2, buffer,
                  data_size);
        TAPI_WAIT_NETWORK;
    }
    else if (sock_type == RPC_SOCK_STREAM || is_pipe)
    {
        if (is_pipe)
            rpc_overfill_fd(pco_iut,
                            (et_first) ? iut_fd2 : iut_fd1,
                            &total_bytes);
        else
            rpc_overfill_buffers_gen(pco_iut,
                                     (et_first) ? iut_fd2 : iut_fd1,
                                     &total_bytes, FUNC_EPOLL);
    }

    /* Hack for ZF shim testing: we can't add one socket to 2 epoll sets,
     * so epoll_ctl() must be called after overfill_buffers(). */
    if (zf)
    {
        epfd = rpc_epoll_create(pco_iut, 1);
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_fd1,
                             event1);
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_fd2,
                             event2);
    }

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
    {
        RING_VERDICT("The first epoll_wait() call returned %d "
                     "instead of 1", rc);
        is_failed = TRUE;
    }
    else if (!((events[0].data.fd == iut_fd1 && et_first) ||
               (events[0].data.fd == iut_fd2 && !et_first)))
    {
        TEST_FAIL("epoll_wait returned incorrect fd %d instead of %d",
                  events[0].data.fd,  (et_first)? iut_fd1 : iut_fd2);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    if (read_between)
    {
        if (rpc_read(pco_iut, (et_first) ? iut_fd1 : iut_fd2, buffer,
                     MAX_BUFF_SIZE) != data_size)
            TEST_FAIL("Incorrect amount of data on iut_fd%s fd.",
                      (et_first) ? "1" : "2");
    }
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (rc != 0)
    {
        RING_VERDICT("The second epoll_wait() call returned %d "
                     "instead of 0", rc);
        is_failed = TRUE;
    }

    if (exp_ev == RPC_EPOLLIN) {
        TAPI_WAIT_NETWORK;
        RPC_WRITE(rc, pco_tst, (et_first) ? tst_fd1 : tst_fd2, buffer,
                  data_size);
    }
    else
    {
        if (sock_type == RPC_SOCK_STREAM || is_pipe)
        {
            if (is_pipe)
                rpc_overfill_fd(pco_iut,
                                (et_first) ? iut_fd1 : iut_fd2,
                                &total_bytes);
            else
            {
                /* Hack for ZF shim testing: we can't add one socket to
                 * 2 epoll sets, so delete file descriptors from the set
                 * and add them back after overfill_buffers(). */
                if (zf)
                {
                    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL,
                                         iut_fd1, event1);
                    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL,
                                         iut_fd2, event2);
                }

                rpc_overfill_buffers(pco_iut,
                                     (et_first) ? iut_fd1 : iut_fd2,
                                     &total_bytes);

                if (zf)
                {
                    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                                         iut_fd1, event1);
                    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                                         iut_fd2, event2);
                }
            }
            SLEEP(1);
            do {
                rc = rpc_read(pco_tst,
                              (et_first) ? tst_fd1 : tst_fd2, buffer,
                              MAX_BUFF_SIZE);
                total_bytes -= rc;
            } while (total_bytes != 0);
        }
        else
            RPC_WRITE(rc, pco_iut, (et_first) ? iut_fd1 : iut_fd2, buffer,
                      data_size);
    }

    TAPI_WAIT_NETWORK;
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    if (rc != 1)
    {
        RING_VERDICT("The third epoll_wait() call returned %d "
                     "instead of 1", rc);
        is_failed = TRUE;
    }
    else if (!((events[0].data.fd == iut_fd1 && et_first) ||
               (events[0].data.fd == iut_fd2 && !et_first)))
    {
        TEST_FAIL("epoll_wait returned incorrect fd %d instead of %d",
                  events[0].data.fd,  (et_first)? iut_fd1 : iut_fd2);
    }
    else if (events[0].events != exp_ev)
        TEST_FAIL("epoll_wait returned incorrect events");

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (rc != 0)
    {
        RING_VERDICT("The fourth epoll_wait() call returned %d "
                     "instead of 0", rc);
        is_failed = TRUE;
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd2);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }
    if (tst_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(tst_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }

    if (is_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    TEST_END;
}
