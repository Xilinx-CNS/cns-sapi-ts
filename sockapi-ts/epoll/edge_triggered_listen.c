/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-edge_triggered_listen Listen and connected sockets with ET flag in one epfd
 *
 * @objective Check that SOCK_STREAM sockets in connected and listen states
 *            in one epoll descriptor all in edge-triggered mode correctly
 *            handle by @b epoll_wait().
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param group_num     Number of socket groups
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/edge_triggered_listen"

#include "sockapi-test.h"

#define MAX_BUFF_SIZE 1024
#define MAX_PAIR_NUM 20

/* Action types to make with sockets group */
enum actions {
    ACT_NONE = 0,
    ACT_CONNECT = 1,
    ACT_DOUBLE_CONNECT = 2,
    ACT_SEND
};

/* Structure for the group of sockets */
typedef struct sock_and_act {
    int      iut_s;
    int      aux_tst_s;
    int      tst_s;
    int      acc_s;
    int      aux_acc_s;
    int      act;
    uint16_t port;
} sock_and_act;

/* Check that socket is in epoll events */
static int
is_in_epfd_ev(int sock, struct rpc_epoll_event *evts, int ev_num)
{
    int i;

    for (i = 0; i < ev_num; i++)
        if (sock == evts[i].data.fd)
            return 1;
    return 0;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr_storage bind_addr;

    int domain;

    sock_and_act            sock_act[MAX_PAIR_NUM];

    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[MAX_PAIR_NUM * 2];
    int                     maxevents = MAX_PAIR_NUM * 2;

    int                     group_num;
    int                     send_num = 0;
    int                     conn_num = 0;
    int                     double_conn_num = 0;

    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(group_num);
    domain = rpc_socket_domain_by_addr(iut_addr);

    /* Set all sockets as invalid at the beginning */
    for (i = 0; i < group_num; i++)
    {
        sock_act[i].iut_s = -1;
        sock_act[i].acc_s = -1;
        sock_act[i].aux_acc_s = -1;
        sock_act[i].tst_s = -1;
        sock_act[i].aux_tst_s = -1;
    }

    /* Create epoll file descriptor */
    epfd = rpc_epoll_create(pco_iut, 1);

    /* Create all needed sockets */
    for (i = 0; i < group_num; i++)
    {
        int fd;

        /* Search for free ports on pco_iut and pco_tst */
        TAPI_SET_NEW_PORT(pco_iut, iut_addr);
        TAPI_SET_NEW_PORT(pco_tst, tst_addr);

        /* Choose the type of sockets (connected or in listen state) */
        if (rand_range(0, 1) == 0)
        {
            /* Generate connection */
            GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                           iut_addr, tst_addr, &(sock_act[i].acc_s),
                           &(sock_act[i].tst_s));
            /* Choose the action for the group of sockets */
            sock_act[i].act = (rand_range(0, 1) == 0) ? ACT_SEND : ACT_NONE;

            /* This socket should be added to the epoll file descriptor */
            fd = sock_act[i].acc_s;
        }
        else
        {
            /* Choose the action for the group of sockets */
            sock_act[i].act = rand_range(ACT_NONE, ACT_DOUBLE_CONNECT);

            /* Create sockets on pco_iut and pco_tst */
            sock_act[i].iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM,
                                           RPC_PROTO_DEF);
            sock_act[i].tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM,
                                           RPC_PROTO_DEF);
            /* Create auxiliary socket on pco_iut in case of DOUBLE_CONNECT
             * action
             */
            if (sock_act[i].act == ACT_DOUBLE_CONNECT)
                sock_act[i].aux_tst_s = rpc_socket(pco_tst, domain,
                                                   RPC_SOCK_STREAM,
                                                   RPC_PROTO_DEF);
            /* Bind just created sockts */
            memcpy(&bind_addr, iut_addr, te_sockaddr_get_size(iut_addr));
            te_sockaddr_set_wildcard(SA(&bind_addr));
            rpc_bind(pco_iut, sock_act[i].iut_s, SA(&bind_addr));
            rpc_bind(pco_tst, sock_act[i].tst_s, SA(tst_addr));
            if (sock_act[i].act == ACT_DOUBLE_CONNECT)
            {
                TAPI_SET_NEW_PORT(pco_tst, tst_addr);
                rpc_bind(pco_tst, sock_act[i].aux_tst_s, SA(tst_addr));
            }
            /* Store the port for the futher connect() */
            sock_act[i].port = SIN(iut_addr)->sin_port;
            /* Call listen on socket on pco_iut */
            rpc_listen(pco_iut, sock_act[i].iut_s, 1);

            /* This socket should be added to the epoll file descriptor */
            fd = sock_act[i].iut_s;
        }

        /* Determine the total number of events */
        if (sock_act[i].act == ACT_SEND)
            send_num++;
        else if (sock_act[i].act == ACT_CONNECT)
            conn_num++;
        else if (sock_act[i].act == ACT_DOUBLE_CONNECT)
            double_conn_num++;

        /* Add the socket from pco_iut to the epoll file descriptor. This
         * socket can be in listen or connected state */
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, fd,
                             RPC_EPOLLIN | RPC_EPOLLET);
    }

    /* Generate events */
    for (i = 0; i < group_num; i++)
    {
        if (sock_act[i].act == ACT_SEND)
        {
            RPC_SEND(rc, pco_tst, sock_act[i].tst_s, buffer,
                     MAX_BUFF_SIZE, 0);
        }
        else if (sock_act[i].act != ACT_NONE)
        {
            SIN(iut_addr)->sin_port = sock_act[i].port;
            rpc_connect(pco_tst, sock_act[i].tst_s, SA(iut_addr));
        }
    }

    /* Call epoll_wait() for the first time and check that listening sockets
     * and connected sockets with events have been reported
     */
    TAPI_WAIT_NETWORK;
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);
    if (rc != send_num + conn_num + double_conn_num)
    {
        if (rc == conn_num + double_conn_num)
            TEST_VERDICT("epoll_wait() doesn't return events for connected "
                         "sockets at the first call");
        else if (rc == send_num)
            TEST_VERDICT("epoll_wait() doen't returns events for "
                         "listening sockets with pending connect");
        else
            TEST_FAIL("epoll_wait() returned %d instead of %d",
                      rc, send_num + conn_num + double_conn_num);
    }

    send_num = conn_num + double_conn_num;
    conn_num = double_conn_num;
    double_conn_num = 0;
    /* Check returned events, accept pending connections and call connect
     * once again in case of DOUBLE_CONNECT action */
    for (i = 0; i < group_num; i++)
    {
        if (sock_act[i].act == ACT_SEND)
        {
            if (is_in_epfd_ev(sock_act[i].acc_s, events, rc) == 0)
                TEST_VERDICT("Connected socket %d has not been returned "
                             "in events from epoll_wait()",
                             sock_act[i].acc_s);
        }
        else if (sock_act[i].act != ACT_NONE)
        {
            if (is_in_epfd_ev(sock_act[i].iut_s, events, rc) == 0)
                TEST_VERDICT("Listening socket %d has not been returned "
                             "in events from epoll_wait()",
                             sock_act[i].iut_s);
            sock_act[i].acc_s = rpc_accept(pco_iut, sock_act[i].iut_s, NULL,
                                           NULL);
            rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                                 sock_act[i].acc_s,
                                 RPC_EPOLLIN | RPC_EPOLLET);
            if (sock_act[i].act == ACT_DOUBLE_CONNECT)
            {
                SIN(iut_addr)->sin_port = sock_act[i].port;
                rpc_connect(pco_tst, sock_act[i].aux_tst_s, SA(iut_addr));
            }
            RPC_SEND(rc, pco_tst, sock_act[i].tst_s, buffer,
                     MAX_BUFF_SIZE, 0);
        }
    }

    /* Call epoll_wait() for the second time. Check that it doesn't returns
     * events for connected sockets which don't recieve any data between
     * the first epoll_wait() call and the second one. */
    TAPI_WAIT_NETWORK;
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);
    if (rc != send_num + conn_num)
    {
        if (rc == send_num)
        {
            TEST_VERDICT("epoll_wait() doesn't return events for listening "
                         "sockets");
        }
        else
            TEST_FAIL("epoll_wait() returned %d instead of %d",
                      rc, send_num + conn_num);
    }

    send_num = conn_num;
    conn_num = 0;
    for (i = 0; i < group_num; i++)
    {
        if (sock_act[i].act == ACT_CONNECT ||
            sock_act[i].act == ACT_DOUBLE_CONNECT)
        {
            if (is_in_epfd_ev(sock_act[i].acc_s, events, rc) == 0)
            {
                TEST_VERDICT("Connected socket %d has not been returned "
                             "in events from epoll_wait()",
                             sock_act[i].acc_s);
            }
            if (sock_act[i].act == ACT_DOUBLE_CONNECT)
            {
                sock_act[i].aux_acc_s = rpc_accept(pco_iut,
                                                   sock_act[i].iut_s,
                                                   NULL, NULL);
                RPC_SEND(rc, pco_tst, sock_act[i].aux_tst_s, buffer,
                         MAX_BUFF_SIZE, 0);
                rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                                     sock_act[i].aux_acc_s,
                                     RPC_EPOLLIN | RPC_EPOLLET);
            }
        }
    }

    /* Call epoll_wait() for the third time and check that it reports
     * events only for the aux_acc_s socket. Check the data on all
     * connected sockets
     */
    TAPI_WAIT_NETWORK;
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);
    if (rc != send_num)
    {
        TEST_FAIL("epoll_wait() returned %d instead of %d",
                  rc, send_num);
    }

    for (i = 0; i < group_num; i++)
    {
        if (sock_act[i].act != ACT_NONE)
        {
            if (rpc_read(pco_iut, sock_act[i].acc_s, buffer, MAX_BUFF_SIZE)
                != MAX_BUFF_SIZE)
            {
                TEST_VERDICT("Incorrect amount of data of %d socket",
                             sock_act[i].acc_s);
            }
            if (sock_act[i].act == ACT_DOUBLE_CONNECT)
            {
                if (is_in_epfd_ev(sock_act[i].aux_acc_s, events,
                                  rc) == 0)
                {
                    TEST_VERDICT("Connected socket %d has not been "
                                 "returned in events from epoll_wait()",
                                 sock_act[i].aux_acc_s);
                }
                if (rpc_read(pco_iut, sock_act[i].aux_acc_s, buffer,
                             MAX_BUFF_SIZE) != MAX_BUFF_SIZE)
                {
                    TEST_VERDICT("Incorrect amount of data of %d socket",
                                 sock_act[i].aux_acc_s);
                }
            }
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    for (i = 0; i < group_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, sock_act[i].iut_s);
        CLEANUP_RPC_CLOSE(pco_iut, sock_act[i].acc_s);
        CLEANUP_RPC_CLOSE(pco_iut, sock_act[i].aux_acc_s);
        CLEANUP_RPC_CLOSE(pco_tst, sock_act[i].tst_s);
        CLEANUP_RPC_CLOSE(pco_tst, sock_act[i].aux_tst_s);
    }

    TEST_END;
}
