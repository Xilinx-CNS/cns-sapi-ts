/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-multiple_same_epfd Multiple epoll_wait() calls with the same epfds.
 *
 * @objective Check that multiple epoll_wait() calls running simultaneously
 *            with the same epfd (with one epfd or epfds with the same
 *            content) work correctly.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param evts          One of @c in, @c out or @c inout
 * @param epfd_num      Number of created epoll descriptors
 * @param call_num      Number of epoll_wait() calls to be run
 * @param timeout       Timeout for @b epoll_wait() function
 * @param data_size     The amount of data to be sent or read
 * @param send_data     Send or do not send any data
 *
 * @par Test sequence:
 *
 * -# Create @c SOCK_STREAM connection between @p pco_iut @p iut_s socket
 *    and @p pco_tst @p tst_s socket.
 * -# Create @p epfd_num number of epoll descriptors with @p iut_s socket
 *    and @p evts using @b epoll_create() and @b epoll_ctl(@c EPOLL_CTL_ADD)
 *    functions.
 * -# If @p send_data is @c TRUE and evts is @c out or @c inout call
 *    @b rpc_overfill_buffers() on @b iut_s socket.
 * -# Call @p call_num number of @b epoll_wait() functions simultaneously.
 *    Call first @p epfd_num functions each with different epoll descriptor
 *    and last @p call_num - @p epfd_num functions each with randomly chosen
 *    epoll descriptor.
 * -# In case of @c TRUE @p send_data and @c in @p evts call @b send()
 *    function on tst_s to write @p data_size bytes of data.
 * -# In case of @c TRUE @p send_data and @c inout or @c out @p evts call
 *    @b recv() function on tst_s to read @p data_size bytes of data.
 * -# In case of @c FALSE @p send_data and @c in @p evts check that
 *    all @b epoll_wait() calls return @c 0. In all other cases check that
 *    all epoll_wait() calls return @c 1 with appropriate and equal events.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/multiple_same_epfd"

#include "sockapi-test.h"
#include "epoll_common.h"
#include "iomux.h"

#define MAX_BUFF_SIZE  10240
#define MAX_EPFD_NUM   10
#define MAX_THREAD_NUM 10

/**
 * Structure to be passed to pthread_create() function.
 */
struct epoll_wait_args
{
    rcf_rpc_server         *pco;
    int                     epfd;
    int                     maxevents;
    struct rpc_epoll_event *events;
    int                     timeout;
    iomux_call_type         iomux;
    rpc_sigset_p            sigmask;
};

/*
 * Function to be passed to pthread_create()
 */
static void *
launch_epoll_wait(void *args)
{
    long int  rc;

    struct epoll_wait_args *epw_args =
        (struct epoll_wait_args *)args;
    rcf_rpc_server         *pco = epw_args->pco;
    int                     epfd = epw_args->epfd;
    struct rpc_epoll_event *events = epw_args->events;
    int                     maxevents = epw_args->maxevents;
    int                     timeout = epw_args->timeout;
    rpc_sigset_p            sigmask = epw_args->sigmask;

    if (epw_args->iomux == IC_OO_EPOLL)
    {
        rpc_onload_ordered_epoll_event  oo_events[maxevents];

        rc = rpc_onload_ordered_epoll_wait(pco, epfd, events, oo_events,
                                           maxevents, timeout);
    }
    else if (epw_args->iomux == IC_EPOLL)
    {
        rc = rpc_epoll_wait(pco, epfd, events, maxevents, timeout);
    }
    else
    {
        rc = rpc_epoll_pwait(pco, epfd, events, maxevents, timeout,
                             sigmask);
    }

    return (void *)rc;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_arr[MAX_THREAD_NUM] = { NULL, };
    char                    pco_name[64] = { 0, };

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    struct epoll_wait_args  epw_args;

    const char             *evts;

    int                     data_size;
    int                     epfd_num;
    int                     call_num;
    int                     close_num;
    int                     num;
    int                     timeout;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd_arr[MAX_EPFD_NUM];
    rpc_sigset_p            sigmask_arr[MAX_EPFD_NUM];
    struct rpc_epoll_event  events[MAX_THREAD_NUM][2];
    uint32_t                event;
    int                     maxevents = 2;

    uint32_t                exp_ev;
    uint64_t                total_bytes;

    pthread_t               thread_arr[MAX_THREAD_NUM];
    te_bool                 send_data;
    te_bool                 tmp_send_data;
    te_bool                 early_ctl;
    int                     i;
    iomux_call_type         iomux;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(epfd_num);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(call_num);
    TEST_GET_BOOL_PARAM(send_data);
    TEST_GET_INT_PARAM(close_num);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(early_ctl);

    tmp_send_data = send_data;
    memset(events, 0, sizeof(events));
    PARSE_EVTS(evts, event, exp_ev);

    for (i = 0; i < epfd_num; i++)
    {
        epfd_arr[i] = -1;
        sigmask_arr[i] = RPC_NULL;
    }

    if (early_ctl)
        CHECK_RC(rpc_stream_conn_early_epfd_add(pco_tst, pco_iut,
                                                tst_addr, iut_addr,
                                                &tst_s, &iut_s,
                                                epfd_arr, epfd_num,
                                                event));
    else
    {
        GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &iut_s, &tst_s);

        for (i = 0; i < epfd_num; i++)
        {
            epfd_arr[i] = rpc_epoll_create(pco_iut, 1);
            rpc_epoll_ctl_simple(pco_iut, epfd_arr[i], RPC_EPOLL_CTL_ADD,
                                 iut_s, event);
        }
    }

    if ((event & RPC_EPOLLOUT) != 0 && send_data)
        rpc_overfill_buffers_gen(pco_iut, iut_s, &total_bytes, FUNC_EPOLL);

    for (i = 0; i < call_num; i++)
    {
        sprintf(pco_name, "child_thread_%d", i);
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, pco_name,
                                              &pco_arr[i]));
        epw_args.pco = pco_arr[i];
        if (i < epfd_num)
            epw_args.epfd = epfd_arr[i];
        else
            epw_args.epfd = epfd_arr[rand_range(0, epfd_num - 1)];
        epw_args.maxevents = maxevents;
        epw_args.events = events[i];
        epw_args.timeout = timeout;
        epw_args.iomux = iomux;
        if (epw_args.iomux == IC_EPOLL_PWAIT)
        {
            sigmask_arr[i] = rpc_sigset_new(pco_arr[i]);
            epw_args.sigmask = sigmask_arr[i];
            rpc_sigemptyset(pco_arr[i], epw_args.sigmask);
            rpc_sigaddset(pco_arr[i], epw_args.sigmask, RPC_SIGUSR1);
        }

        if (pthread_create(&thread_arr[i], NULL, launch_epoll_wait,
                           (void *)&epw_args) < 0)
        {
            rc = errno;
            TEST_FAIL("Failed to create thread");
        }
        MSLEEP(100);
    }

    i = 0;
    for (i = 0; i < close_num; i++)
    {
        while (epfd_arr[(num = rand_range(0, epfd_num - 1))] == -1);
        RPC_CLOSE(pco_iut, epfd_arr[num]);
    }

    if (send_data)
    {
        if (strcmp(evts, "in") == 0)
        {
            exp_ev = RPC_EPOLLIN;
            RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        }
        else
        {
            exp_ev = RPC_EPOLLOUT;
            do {
                rc = rpc_read(pco_tst, tst_s, buffer, MAX_BUFF_SIZE);
                total_bytes -= rc;
            } while (total_bytes != 0);
        }
    }

    for (i = 0; i < call_num; i++)
    {
        pthread_join(thread_arr[i], (void **)&rc);
        if ((!tmp_send_data) && (strcmp(evts, "in") == 0))
        {
            if (rc != 0)
                TEST_VERDICT("epoll_wait returned %d instead of 0", rc);
        }
        else if (rc != 1)
            TEST_VERDICT("epoll_wait returned %d instead of 1", rc);
        else if (events[i][0].data.fd != iut_s)
        {
            TEST_VERDICT("epoll_wait retured incorrect socket %d instead "
                         "of %d", events[i][0].data.fd, iut_s);
        }
        else if (events[i][0].events != exp_ev)
            TEST_FAIL("epoll_wait returned incorrect events");
    }

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < epfd_num; i++)
    {
        if (epw_args.iomux == IC_EPOLL_PWAIT)
            rpc_sigset_delete(pco_arr[i], sigmask_arr[i]);
        CLEANUP_RPC_CLOSE(pco_iut, epfd_arr[i]);
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    for (i = 0; i < call_num; i++)
        if (pco_arr[i] != NULL)
            CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_arr[i]));
        else
            break;
    TEST_END;
}
