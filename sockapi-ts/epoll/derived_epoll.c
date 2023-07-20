/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-derived_epoll Exec/fork/dup robustness for epoll sockets
 *
 * @objective Check that epfd is inherited during
 *            execve() / fork() / dup() calls.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           Tester PCO
 * @param sock_type         Type of sockets used in the test
 * @param evts              One of @c in, @c out or @c inout
 * @param func              The function to get another epoll descriptor
 *                          instance. The value can be @c fork, @c dup,
 *                          @c execve and @c fork_exec. Last one is for the
 *                          sequence of @b fork() and execve() functions.
 * @param data_size         The amount of data to be sent
 * @param timeout           Timeout for @b epoll_wait() function
 * @param gen_ev_before     Generate or do not generate the event on the
 *                          socket before the first @b epoll_wait() call
 * @param gen_ev_between    Generate or do not generate the event on the
 *                          socket before @p func call and after the first
 *                          @b epoll_wait() call
 * @param gen_ev_after      Generate or do not generate the event on the
 *                          socket just after @b func
 * @param call_wait_before  Call or do not call @b epoll_wait() before
 *                          @p func
 * @param non_blocking      Test blocking or non-blocking call of
 *                          @b epoll_wait()
 *
 * @par Test sequence:
 *
 * -# Create @p sock_type connection between @p pco_iut and @p pco_tst. Two
 *    connected sockets @p iut_s and @p tst_s would appear.
 * -# Create @p epfd with @p iut_s socket and with the events according to
 *    @p evts paramter using @b epoll_create() and
 *    @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# If @p gen_ev_before is @c FALSE, @p evts is @c out or @c inout and
 *    @p sock_type is @c SOCK_STREAM call @b rpc_overfill_buffers() on
 *    @b iut_s socket.
 * -# If @p gen_ev_before is @c TRUE and @p evts is @c in send @p data_size
 *    bytes of data from @p tst_s socket to @p iut_s socket.
 * -# If @p call_wait_before is @c TRUE call @b epoll_wait() on @p epfd
 *    with @p timeout (in case of non-blocking @b epoll_wait() with zero
 *    timeout).
 * -# If @p get_ev_between is @c TRUE produce events for @p iut_s socket:
 *      - In case of @c in event send @p data_size bytes of data from
 *        @p tst_s socket to @p iut_s.
 *      - In case of @c out or @c inout events and @c SOCK_STREAM sockets
 *        read @p data_size bytes of data on @p iut_s socket.
 * -# Check that @b epoll_wait() exits with correct events set.
 * -# Create a process or duplicated epoll descriptor as defined by
 *    @p func parameter. @p child_pco and @p child_epfd would appear.
 *    In case of @b fork(), @b execve() and @b fork() + @b execve()
 *    @p child_epfd will be equal to @p epfd. In case of @b dup() and
 *    @b execve() @p child_pco will be equal to @p pco_iut.
 * -# If @p get_ev_after is @c TRUE produce events for @p iut_s socket:
 *      - In case of @c in event send @p data_size bytes of data from
 *        @p tst_s socket to @p iut_s.
 *      - In case of @c out or @c inout events and @c SOCK_STREAM sockets
 *        read @p data_size bytes of data on @p iut_s socket
 * -# Call @b epoll_wait() on @p child_pco and @p child_epfd with
 *    @p timeout (in case of non-blocking @b epoll_wait() with zero
 *    timeout).
 * -# Check that @b epoll_wait() exits with correct events set.
 * -# @b close() all sockets.
 *
 * @note
 * -# Only one form gen_ev_before, send_data_between and send_data_after
 *    parameters should have @c TRUE value.
 * -# In case of @c SOCK_DGRAM socket and @c inout or @c out events the
 *    socket always has write event, so there is only one case how event
 *    should be generated (when @p gen_ev_before is @c TRUE).
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/derived_epoll"
#include "sockapi-test.h"
#include "derived_instances.h"
#include "iomux.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 10240

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;

    rpc_socket_domain      domain;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    rpc_socket_type         sock_type;

    const char             *evts;

    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    int                     maxevents = 2;
    int                     timeout;
    int                     data_size;

    int                     inst_num = 0;
    derived_test_instance  *instances = NULL;
    const char             *func;

    uint64_t                total_bytes;

    te_bool                 gen_ev_before;
    te_bool                 gen_ev_between;
    te_bool                 gen_ev_after;
    te_bool                 call_wait_before;
    te_bool                 non_blocking;
    te_bool                 early_ctl;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    domain = rpc_socket_domain_by_addr(iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_BOOL_PARAM(gen_ev_before);
    TEST_GET_BOOL_PARAM(gen_ev_between);
    TEST_GET_BOOL_PARAM(gen_ev_after);
    TEST_GET_BOOL_PARAM(call_wait_before);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_BOOL_PARAM(early_ctl);
    TEST_GET_IOMUX_FUNC(iomux);

    PARSE_EVTS(evts, event, event);
    GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, FALSE, sock_type,
                           iut_addr, tst_addr, iut_s, tst_s,
                           TRUE, TRUE, epfd, early_ctl, event);

    if (non_blocking)
        timeout = 0;

    if ((event & RPC_EPOLLOUT) != 0 &&
        (sock_type == RPC_SOCK_STREAM) && !gen_ev_before)
        rpc_overfill_buffers_gen(pco_iut, iut_s, &total_bytes, iomux);
    if (event == RPC_EPOLLIN && gen_ev_before)
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);

    /* Wait for incoming packet in case of non-blocking epoll_wait() */
    if (non_blocking)
        TAPI_WAIT_NETWORK;
    if (call_wait_before)
    {
        pco_iut->op = RCF_RPC_CALL;
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                              maxevents, timeout);
        MSLEEP(200);
    }

    if (gen_ev_between)
    {
        if (strcmp(evts, "in") == 0)
            RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        else
        {
            if (sock_type == RPC_SOCK_STREAM)
            {
                do {
                    rc = rpc_read(pco_tst, tst_s, buffer, MAX_BUFF_SIZE);
                    total_bytes -= rc;
                } while (total_bytes != 0);
            }
        }
        TAPI_WAIT_NETWORK;
    }

    if (call_wait_before)
    {
        pco_iut->op = RCF_RPC_WAIT;
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events,
                              maxevents, timeout);
        if (gen_ev_after || (non_blocking && !gen_ev_before))
        {
            if (rc != 0)
            {
                TEST_FAIL("%s() returned %d instead of 0",
                          iomux_call_en2str(iomux), rc);
            }
        }
        else if (rc != 1)
        {
            TEST_FAIL("%s() returned %d instead of 1",
                      iomux_call_en2str(iomux), rc);
        }
        else if (events[0].data.fd != iut_s)
        {
            TEST_FAIL("%s() retured incorrect socket %d instead of "
                      "%d iut_s", iomux_call_en2str(iomux),
                      events[0].data.fd, iut_s);
        }
        else if (!(((strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0)
                    && events[0].events == RPC_EPOLLOUT) ||
                    (strcmp(evts, "in") == 0 &&
                    events[0].events == RPC_EPOLLIN)))
            TEST_FAIL("%s() returned incorrect events",
                      iomux_call_en2str(iomux));
    }

    if (strcmp(func, "fork_exec") == 0)
    {
        if ((instances = create_instances("inherit", "fork", pco_iut, epfd,
                                          &inst_num, domain,
                                          sock_type)) == NULL)
            TEST_FAIL("Cannot create test instnaces");

        CHECK_RC(rcf_rpc_server_exec(instances[1].rpcs));
    }
    else
    {
            if ((instances = create_instances("inherit", func, pco_iut,
                                              epfd, &inst_num, domain,
                                              sock_type)) == NULL)
                TEST_FAIL("Cannot create test instnaces");
    }

    if (gen_ev_after)
    {
        if (strcmp(evts, "in") == 0)
            RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        else
        {
            if (sock_type == RPC_SOCK_STREAM)
            {
                do {
                    rc = rpc_read(pco_tst, tst_s, buffer, MAX_BUFF_SIZE);
                    total_bytes -= rc;
                } while (total_bytes != 0);
            }
        }
    }

    /* Wait for incoming packet in case of non-blocking epoll_wait() */
    if (non_blocking)
        TAPI_WAIT_NETWORK;
    rc = iomux_epoll_call(iomux, instances[inst_num - 1].rpcs,
                          instances[inst_num - 1].s, events, maxevents,
                          timeout);
    if (rc != 1)
    {
        TEST_FAIL("%s() returned %d instead of 1",
                  iomux_call_en2str(iomux), rc);
    }
    else if (events[0].data.fd != iut_s)
    {
        TEST_FAIL("%s() retured incorrect socket %d instead of "
                  "%d iut_s", iomux_call_en2str(iomux), events[0].data.fd,
                  iut_s);
    }
    else if (!(((strcmp(evts, "out") == 0 || strcmp(evts, "inout") == 0) 
                && events[0].events == RPC_EPOLLOUT) ||
              (strcmp(evts, "in") == 0 &&
               events[0].events == RPC_EPOLLIN)))
        TEST_FAIL("%s() returned incorrect events",
                  iomux_call_en2str(iomux));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (inst_num == 2)
    {
        CLEANUP_RPC_CLOSE(instances[inst_num - 1].rpcs,
                          instances[inst_num - 1].s);
    }

    if (inst_num != 0 && instances[inst_num - 1].rpcs != pco_iut)
        rcf_rpc_server_destroy(instances[inst_num - 1].rpcs);

    free(instances);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
