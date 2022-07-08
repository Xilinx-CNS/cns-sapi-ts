/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 */

/** @page epoll-maxevents_two_stacks maxevents and mixed epoll set
 *
 * @objective Check what happens when epoll set contains sockets from
 *            different Onload stacks and number of events is more than
 *            @p maxevents.
 *
 * @type conformance
 *
 * @param env                   Testing environment:
 *                              - @ref arg_types_env_peer2peer
 *                              - @ref arg_types_env_peer2peer_ipv6
 * @param iomux                 Which iomux function to test:
 *                              - @b epoll_wait()
 *                              - @b epoll_pwait()
 * @param maxevents             Value of maxevents parameter:
 *                              - @c 5
 * @param first_group           Share of connections established via
 *                              the first IUT listener:
 *                              - @c less (than via the second listener)
 *                              - @c equal (to the number of connections
 *                                established via the second listener)
 *                              - @c more (than via the second listener)
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/maxevents_two_stacks"

#include "sockapi-test.h"
#include "onload.h"
#include "epoll_common.h"

/** Name of the second Onload stack */
#define OTHER_STACK_NAME "stack1"

/** Description of the single TCP connection */
typedef struct test_conn {
    int iut_s;              /**< Connected socket on IUT */
    int tst_s;              /**< Connected socket on Tester */
    te_bool received_evt;   /**< Set to TRUE when EPOLLIN is reported
                                 the first time */

    char sent_data[SOCKTS_MSG_STREAM_MAX]; /**< Data sent from Tester */
    int sent_len;                          /**< Sent data length */
} test_conn;

/** Share of connections established via the first IUT listener */
enum {
    FIRST_GROUP_LESS,    /**< Less than via the second one */
    FIRST_GROUP_EQUAL,   /**< Same number as via the second one */
    FIRST_GROUP_MORE,    /**< More than via the second one */
};

/** List of values of "first_group" parameter */
#define FIRST_GROUP \
    { "less", FIRST_GROUP_LESS },      \
    { "equal", FIRST_GROUP_EQUAL },    \
    { "more", FIRST_GROUP_MORE }

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int first_group_num;
    int sockets_num;
    int i;
    int j;
    int fd;

    int iut_l1 = -1;
    int iut_l2 = -1;

    int epfd = -1;
    struct rpc_epoll_event *evts = NULL;
    struct rpc_epoll_event event;

    test_conn *conns = NULL;
    test_conn **conns_p = NULL;
    test_conn *conn = NULL;
    test_conn *exp_conn = NULL;

    char recv_data[SOCKTS_MSG_STREAM_MAX];

    const struct sockaddr *conn_addr1 = NULL;
    const struct sockaddr *conn_addr2 = NULL;
    struct sockaddr_storage iut_addr2;

    iomux_call_type iomux;
    int maxevents;
    int first_group;

    te_bool onload_run = FALSE;
    te_bool restore_stack = FALSE;
    te_bool new_fd = FALSE;
    te_bool wrong_order = FALSE;
    int readable_fds = 0;
    int calls_count = 0;
    const char *iomux_name = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(maxevents);
    TEST_GET_ENUM_PARAM(first_group, FIRST_GROUP);

    iomux_name = sockts_iomux_call_en2str(iomux);

    sockets_num = 2 * maxevents;
    if (first_group == FIRST_GROUP_LESS)
        first_group_num = rand_range(1, maxevents - 1);
    else if (first_group == FIRST_GROUP_MORE)
        first_group_num = rand_range(maxevents + 1, sockets_num - 1);
    else
        first_group_num = maxevents;

    conns = tapi_calloc(sockets_num, sizeof(*conns));
    for (i = 0; i < sockets_num; i++)
    {
        conns[i].iut_s = -1;
        conns[i].tst_s = -1;
    }

    conns_p = tapi_calloc(sockets_num, sizeof(*conns_p));
    evts = tapi_calloc(maxevents, sizeof(*evts));

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr2));
    conn_addr1 = iut_addr;
    conn_addr2 = SA(&iut_addr2);

    onload_run = tapi_onload_run();

    TEST_STEP("Open epoll FD with @b epoll_create() on IUT.");
    epfd = rpc_epoll_create(pco_iut, maxevents);

    TEST_STEP("Create the first listener socket on IUT.");
    iut_l1 = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                        RPC_PROTO_DEF, FALSE, FALSE,
                                        conn_addr1);
    rpc_listen(pco_iut, iut_l1, -1);

    if (onload_run)
    {
        TEST_STEP("If the test is run on Onload, use "
                  "@b onload_set_stackname() to set a different Onload "
                  "stack name for the second listener on IUT.");

        rpc_onload_stackname_save(pco_iut);
        rpc_onload_set_stackname(pco_iut,
                                 ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL,
                                 OTHER_STACK_NAME);
        restore_stack = TRUE;
    }

    TEST_STEP("Create the second listener socket on IUT.");
    iut_l2 = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                        RPC_PROTO_DEF, FALSE, FALSE,
                                        conn_addr2);
    rpc_listen(pco_iut, iut_l2, -1);

    TEST_STEP("Establish 2 * @p maxevents connections from Tester, "
              "some of them (chosen according to @p first_group) - to "
              "the first IUT listener, others - to the second IUT "
              "listener. Accept them on IUT. Add to the epoll set "
              "every accepted IUT socket.");

    for (i = 0; i < sockets_num; i++)
    {
        conns_p[i] = &conns[i];

        conns[i].tst_s = rpc_socket(pco_tst,
                                    rpc_socket_domain_by_addr(tst_addr),
                                    RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_connect(pco_tst, conns[i].tst_s,
                    (i < first_group_num ? conn_addr1 : conn_addr2));
        conns[i].iut_s = rpc_accept(pco_iut,
                                    (i < first_group_num ? iut_l1 : iut_l2),
                                    NULL, NULL);

        event.events = RPC_EPOLLIN;
        event.data.fd = conns[i].iut_s;
        rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD, conns[i].iut_s,
                      &event);
    }

    for (i = sockets_num - 1; i > 0; i--)
    {
        j = rand_range(0, i);
        if (j == i)
            continue;

        conn = conns_p[j];
        conns_p[j] = conns_p[i];
        conns_p[i] = conn;
    }

    TEST_STEP("In random order send a packet from every Tester socket.");
    for (i = 0; i < sockets_num; i++)
    {
        conn = conns_p[i];
        conn->sent_len = rand_range(1, SOCKTS_MSG_STREAM_MAX);
        te_fill_buf(conn->sent_data, conn->sent_len);

        RPC_SEND(rc, pco_tst, conn->tst_s, conn->sent_data,
                 conn->sent_len, 0);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @p iomux on IUT in a loop until it reports EPOLLIN "
              "event for each connected IUT socket or until it stops "
              "reporting events for new sockets. Check that it reports "
              "@p maxevents events every time it is called.");

    while (TRUE)
    {
        calls_count++;

        RPC_AWAIT_ERROR(pco_iut);
        rc = iomux_epoll_call(iomux, pco_iut, epfd, evts, maxevents, 0);
        if (rc < 0)
        {
            TEST_VERDICT("%s() failed with error %r",
                         iomux_name, RPC_ERRNO(pco_iut));
        }
        else if (rc != maxevents)
        {
            TEST_VERDICT("%s() returned %s events than expected",
                         iomux_name,
                         (rc < maxevents ? "less" : "more"));
        }

        new_fd = FALSE;
        for (i = 0; i < maxevents; i++)
        {
            fd = evts[i].data.fd;
            conn = NULL;
            for (j = 0; j < sockets_num; j++)
            {
                if (conns[j].iut_s == fd)
                {
                    conn = &conns[j];
                    break;
                }
            }

            if (conn == NULL)
            {
                ERROR("Unknown FD %d in event data", fd);
                TEST_VERDICT("%s() returned unknown FD in event data",
                             iomux_name);
            }

            if (!wrong_order)
            {
                exp_conn = conns_p[readable_fds];
                if (conn != exp_conn)
                {
                    WARN("Event is reported for IUT socket %d (peer %d) "
                         "while in the order of receiving it should be "
                         "IUT socket %d (peer %d)", conn->iut_s,
                         conn->tst_s, exp_conn->iut_s, exp_conn->tst_s);

                    wrong_order = TRUE;
                }
            }

            if (evts[i].events != RPC_EPOLLIN)
            {
                TEST_VERDICT("%s() returned unexpected events %s instead "
                             "of EPOLLIN", iomux_name,
                             epoll_event_rpc2str(evts[i].events));
            }

            if (conn->received_evt)
                continue;

            new_fd = TRUE;
            conn->received_evt = TRUE;
            readable_fds++;
        }

        if (!new_fd || readable_fds == sockets_num)
            break;
    }

    TEST_STEP("Check that EPOLLIN event was reported for every "
              "connected IUT socket.");

    if (readable_fds < sockets_num)
    {
        for (i = 0; i < sockets_num; i++)
        {
            if (!conns[i].received_evt)
            {
                ERROR("EPOLLIN was not reported for IUT socket %d "
                      "(connection %d, the %s group)",
                      conns[i].iut_s, i,
                      (i < first_group_num ? "first" : "second"));
            }
        }

        TEST_VERDICT("%s() did not return events for some IUT sockets",
                     iomux_name);
    }

    if (calls_count > 2)
    {
        WARN_VERDICT("More than two %s() calls were required to get "
                     "events for all IUT sockets", iomux_name);
    }

    if (wrong_order)
    {
        WARN_VERDICT("Events are reported not in order of receiving "
                     "data on the related sockets");
    }

    TEST_STEP("Read and check data for every connected IUT socket.");

    for (i = 0; i < sockets_num; i++)
    {
        conn = &conns[i];

        rc = rpc_recv(pco_iut, conn->iut_s, recv_data,
                      sizeof(recv_data), 0);
        SOCKTS_CHECK_RECV(pco_iut, conn->sent_data, recv_data,
                          conn->sent_len, rc);
    }

    TEST_SUCCESS;

cleanup:

    if (restore_stack)
        rpc_onload_stackname_restore(pco_iut);

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l2);

    if (conns != NULL)
    {
        for (i = 0; i < sockets_num; i++)
        {
            CLEANUP_RPC_CLOSE(pco_iut, conns[i].iut_s);
            CLEANUP_RPC_CLOSE(pco_tst, conns[i].tst_s);
        }
    }

    free(conns);
    free(conns_p);
    free(evts);

    TEST_END;
}
