/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_evnt_queue Epoll event queue.
 *
 * @objective Check that @b epoll_wait() function correctly handles the
 *            situation when the number of descriptors with events in epoll
 *            descriptor is greater than @p maxevents in @b epoll_wait()
 *            function which is called with this epoll descriptor.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of sockets using in the test
 * @param conn_num      The number of connections for the test
 * @param evt_num       The number of sockets with events
 * @param maxevents     The value of @p maxevents for @b epoll_wait()
 * @param data_size     The amount of data to be sent
 * @param timeout       Timeout for @b epoll_wait() function
 * @param non_blocking  Test blocking or non-blocking call of
 *                      @b epoll_wait()
 *
 * @par Test sequence:
 *
 * -# Create @p conn_num connections between @p pco_iut and @p pco_tst.
 * -# Create @p epfd with all sockets on @p pco_iut and @c EPOLLIN event
 *    using @b epoll_create() and @b epoll_ctl(@c EPOLL_CTL_ADD) functions.
 * -# Send @p data_size bytes of data from @p evt_num sockets on @p pco_tst
 *    to the sockets on @p pco_iut.
 * -# Call @b epoll_wait(@p epfd) with @p maxevents and @p timeout
 *    according to @p non_blocking parameter.
 * -# Check that @b epoll_wait() returns @p maxevents with @c EPOLLIN event for
 *    some approprite socekts on @p pco_iut.
 * -# Read all data from the sockets on @p pco_iut.
 * -# Call @b epoll_wait(@p epfd) with @p maxevents and zero timeout.
 * -# Check that @b epoll_wait() returns @c 0.
 * -# @b close() all sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_evnt_queue"

#include "sockapi-test.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 1024
#define MAX_EVT       32

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    rpc_socket_type         sock_type;

    int                     data_size;
    unsigned char           buffer[MAX_BUFF_SIZE];

    int                     epfd = -1;
    struct rpc_epoll_event  events[MAX_EVT];
    int                     maxevents;

    int                     tmp_send_num;

    int                     conn_num;
    int                     evt_num;
    int                     timeout;

    int                     i;
    int                     j;

    struct connection {
        int             iut_s;
        int             tst_s;
        int             send;
        int             checked;
    } *conns = NULL;

    te_bool                 non_blocking;
    te_bool                 early_ctl;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(maxevents);
    TEST_GET_INT_PARAM(conn_num);
    TEST_GET_INT_PARAM(evt_num);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(non_blocking);
    TEST_GET_BOOL_PARAM(early_ctl);

    if (non_blocking)
        timeout = 0;

    if ((conns = calloc(conn_num, sizeof(struct connection))) == NULL)
    {
        TEST_FAIL("Out of memory");
    }

    for (i = 0; i < conn_num; i++)
    {
        conns[i].tst_s = -1;
        conns[i].iut_s = -1;
        conns[i].send = 0;
    }

    for (i = 0; i < conn_num; i++)
    {
        TAPI_SET_NEW_PORT(pco_iut, iut_addr);
        TAPI_SET_NEW_PORT(pco_tst, tst_addr);

        GET_CONNECTED_ADD_EPFD(pco_iut, pco_tst, FALSE, sock_type,
                               iut_addr, tst_addr, conns[i].iut_s,
                               conns[i].tst_s, TRUE,
                               TRUE, epfd, early_ctl, RPC_EPOLLIN);
    }

    /* Randomly choose connections for operations */
    tmp_send_num = evt_num;
    i = 0;
    while (tmp_send_num > 0)
    {
        /* Skip already chosen connections */
        while (conns[i].send)
        {
            i++;
            i = i % conn_num;
        }

        if (rand_range(0, 1) == 1)
        {
            RPC_WRITE(rc, pco_tst, conns[i].tst_s, buffer, data_size);
            /* Mark connection as chosen */
            conns[i].send = 1;
            tmp_send_num--;
        }

        /* Go to the next connection */
        i++;
        i = i % conn_num;
    }

    /* Wait for incoming packets */
    TAPI_WAIT_NETWORK;
    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, timeout);

    if (rc != maxevents)
    {
        TEST_FAIL("epoll_wait returned %d instead of %d", rc, maxevents);
    }

    /* Check that epoll_wait() detects events only on connections 
     * with data
     */
    j = 0;
    while (j < maxevents)
    {
        for (i = 0; i < conn_num; i++)
        {
            if (conns[i].iut_s != events[j].data.fd)
                continue;
            if (conns[i].send != 1 || conns[i].checked == 1)
                TEST_FAIL("Events unexpectedly detected for %d socket",
                          conns[i].iut_s);
            conns[i].checked = 1;

            if (events[j].events != RPC_EPOLLIN)
                TEST_FAIL("epoll_wait returned incorrect events for %d "
                          "socket", conns[i].iut_s);
            break;
        }
        j++;
    }

    /* Read all sent data */
    for (i = 0; i < conn_num; i++)
    {
        if (conns[i].send)
        {
            rc = rpc_read(pco_iut, conns[i].iut_s, buffer, data_size);
            if (rc != data_size)
                TEST_FAIL("Incorrect number of bytes was recieved on %d "
                          "socket", conns[i].iut_s);
        }
    }

    rc = rpc_epoll_wait(pco_iut, epfd, events, maxevents, 0);

    if (rc != 0)
    {
        TEST_FAIL("epoll_wait returned %d instead of 0", rc);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    for (i = 0; i < conn_num; i++)
    {
        CLEANUP_RPC_CLOSE(pco_iut, conns[i].iut_s);
        CLEANUP_RPC_CLOSE(pco_tst, conns[i].tst_s);
    }
    free(conns);

    TEST_END;
}
