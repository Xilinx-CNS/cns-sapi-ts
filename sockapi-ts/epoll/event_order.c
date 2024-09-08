/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 */

/** @page epoll-event_order maxevents and epoll set order
 *
 * @objective Check that epoll reports events in right order.
 *
 * @type conformance
 *
 * @param env                   Testing environment:
 *                              - @ref arg_types_env_peer2peer
 *                              - @ref arg_types_env_peer2peer_ipv6
 * @param iomux                 Which iomux function to test:
 *                              - @b epoll_wait()
 *                              - @b epoll_pwait()
 *                              - @b epoll_pwait2()
 * @param maxevents             Value of maxevents parameter:
 *                              - @c 1
 *                              - @c 2
 * @param with_delay            Whether to sleep between sends or not
 *
 * @par Test sequence:
 *
 * @author Vasilij Ivanov <Vasilij.Ivanov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/event_order"

#include "sockapi-test.h"
#include "onload.h"
#include "epoll_common.h"

#define SOCKTS_NUM 2
#define DATA_BULK 200

/** Description of the single TCP connection */
typedef struct test_conn {
    int iut_s;              /**< Connected socket on IUT */
    int tst_s;              /**< Connected socket on Tester */
    te_bool reported;       /**< Was event reported on IUT socket */
} test_conn;

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    int i;
    int j;
    int fd;

    int iut_l = -1;

    int epfd = -1;
    struct rpc_epoll_event *evts = NULL;
    struct rpc_epoll_event event;

    test_conn conns[SOCKTS_NUM];
    test_conn *conns_p[SOCKTS_NUM];
    test_conn *conn = NULL;
    test_conn *exp_conn = NULL;

    iomux_call_type iomux;
    int maxevents;
    int reported_events = 0;

    te_bool wrong_order = FALSE;
    te_bool with_delay = FALSE;
    int readable_fds = 0;
    const char *iomux_name = NULL;

    char sent_data[DATA_BULK];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(maxevents);
    TEST_GET_BOOL_PARAM(with_delay);

    iomux_name = sockts_iomux_call_en2str(iomux);

    te_fill_buf(sent_data, DATA_BULK);

    evts = tapi_calloc(maxevents, sizeof(*evts));

    TEST_STEP("Open epoll FD with @b epoll_create() on IUT.");
    epfd = rpc_epoll_create(pco_iut, maxevents);

    TEST_STEP("Create listener socket on IUT.");
    iut_l = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                       RPC_PROTO_DEF, FALSE, FALSE,
                                       iut_addr);
    rpc_listen(pco_iut, iut_l, -1);

    TEST_STEP("Establish 2 connections from Tester to IUT. "
              "Accept them on IUT. Add to the epoll set "
              "every accepted IUT socket.");
    for (i = 0; i < SOCKTS_NUM; i++)
    {
        conns_p[i] = &conns[i];

        conns[i].tst_s = rpc_socket(pco_tst,
                                    rpc_socket_domain_by_addr(tst_addr),
                                    RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_connect(pco_tst, conns[i].tst_s,
                    iut_addr);
        conns[i].iut_s = rpc_accept(pco_iut,
                                    iut_l,
                                    NULL, NULL);

        conns[i].reported = FALSE;

        event.events = RPC_EPOLLIN;
        event.data.fd = conns[i].iut_s;
        rpc_epoll_ctl(pco_iut, epfd, RPC_EPOLL_CTL_ADD, conns[i].iut_s,
                      &event);
    }

    TAPI_WAIT_NETWORK;

    for (i = SOCKTS_NUM - 1; i > 0; i--)
    {
        j = rand_range(0, i);
        if (j == i)
            continue;

        conn = conns_p[j];
        conns_p[j] = conns_p[i];
        conns_p[i] = conn;
    }

    TEST_STEP("In random order send a packet from every Tester socket.");
    for (i = 0; i < SOCKTS_NUM; i++)
    {
        conn = conns_p[i];

	if (with_delay)
        {
            TEST_STEP("If @p with_delay is @c TRUE, then sleep between sends.");
            TAPI_WAIT_NETWORK;
        }

        RPC_SEND(rc, pco_tst, conn->tst_s, sent_data,
                 DATA_BULK, 0);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @p iomux on IUT in a loop until it reports "
              "@c 2 events in total, check that events were "
              "reported in right order.");
    while (reported_events < SOCKTS_NUM)
    {
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

        reported_events += rc;

        for (i = 0; i < maxevents; i++)
        {
            fd = evts[i].data.fd;
            conn = NULL;
            for (j = 0; j < SOCKTS_NUM; j++)
            {
                if (conns[j].iut_s == fd)
                {
                    conn = &conns[j];
                    if (conn->reported)
                    {
                        ERROR("Event on FD %d was reported more than once",
                              fd);
                        TEST_VERDICT("Event on one of sockets was reported "
                                     "more than once");
                    }
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

            conn->reported = TRUE;
            readable_fds++;
        }
    }

    if (reported_events != SOCKTS_NUM)
    {
        TEST_VERDICT("More than two events were reported");
    }

    if (wrong_order)
    {
        TEST_VERDICT("Events are reported not in order of receiving "
                     "data on the related sockets");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);

    for (i = 0; i < SOCKTS_NUM; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, conns[i].iut_s);
        CLEANUP_RPC_CLOSE(pco_tst, conns[i].tst_s);
    }

    free(evts);

    TEST_END;
}
