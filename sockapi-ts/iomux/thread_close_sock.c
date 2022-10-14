/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-thread_close_sock Socket is closed from another thread
 *
 * @objective Check I/O multiplexing functions behaviour when the socket is
 *            closed from another thread.
 *
 * @type conformance, compatibility
 *
 * @requirement REQ-1, REQ-2, REQ-3, REQ-13
 *
 * @param pco_iut1  IUT thread #1
 * @param pco_iut2  IUT thread #2
 * @param pco_tst   Auxiliary PCO
 * @param sock_type Type of sockets using in the test
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll(), @b epoll())
 * @param data_size The amount of data to be sent
 *
 * @par Scenario:
 * -# Create two @p sock_type connections between @p pco_iut and @p pco_tst.
 *    Four sockets @p iut_s1, @p iut_s2, @p tst_s1 and @p tst_s2 would
 *    appear.
 * -# Call @b iomux_call() on @p pco_iut1 with
 *    {{@p iut_s1, @c EVT_RD}, {@p iut_s2, @c EVT_RD}} and with infinite
 *    timeout.
 * -# Call @b close() on @p pco_iut2 to close @p iut_s1 socket.
 * -# Send @p data_size bytes of data from @p tst_s1 socket to @p iut_s1.
 * -# Send @p data_size bytes of data from @p tst_s2 socket to @p iut_s2.
 * -# Check that @b iomux_call() returns @c 1 and in case of @b poll() sets
 *    revents to @c POLLNVAL for @ iut_s1 socket and @c 0 for
 *    @p iut_s2 socket. In case of other iomux functions it should return
 *    only @c EVT_RD event for @p iut_s2 socket.
 * -# Close @b iut_s2 and @b tst_s sockets.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/thread_close_sock"
#include "sockapi-test.h"
#include "iomux.h"

#define MAX_BUFF_SIZE 1024

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    rcf_rpc_server         *pco_iut1 = NULL;
    rcf_rpc_server         *pco_iut2 = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    rpc_socket_type         sock_type;

    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *iut_addr2 = NULL;
    const struct sockaddr  *tst_addr1 = NULL;
    const struct sockaddr  *tst_addr2 = NULL;

    int                     iut_s1 = -1;
    int                     tst_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s2 = -1;

    iomux_evt_fd            events[2];

    unsigned char           buffer[MAX_BUFF_SIZE];
    int                     data_size;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut1, iut_addr1);
    TEST_GET_ADDR(pco_iut2, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_ADDR(pco_tst, tst_addr2);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(data_size);

    memset(events, 0, sizeof(events));

    /* Scenario */
    GEN_CONNECTION(pco_tst, pco_iut1, sock_type, RPC_PROTO_DEF,
                   tst_addr1, iut_addr1, &tst_s1, &iut_s1);
    GEN_CONNECTION(pco_tst, pco_iut1, sock_type, RPC_PROTO_DEF,
                   tst_addr2, iut_addr2, &tst_s2, &iut_s2);

    events[0].fd = iut_s1;
    events[0].events = EVT_RD;
    events[1].fd = iut_s2;
    events[1].events = EVT_RD;

    pco_iut1->op = RCF_RPC_CALL;
    iomux_call(iomux, pco_iut1, events, 2, NULL);
    TAPI_WAIT_NETWORK;

    RPC_CLOSE(pco_iut2, iut_s1);
    TAPI_WAIT_NETWORK;

    RPC_WRITE(rc, pco_tst, tst_s1, buffer, data_size);
    TAPI_WAIT_NETWORK;
    RPC_WRITE(rc, pco_tst, tst_s2, buffer, data_size);

    pco_iut1->op = RCF_RPC_WAIT;
    rc = iomux_call(iomux, pco_iut1, events, 2, NULL);
    if (rc != 1)
    {
        if (rc >= 0)
            TEST_VERDICT("iomux_call() returned %d instead of 1", rc);
        else
            TEST_VERDICT("iomux_call() returned %d instead of 1 "
                         "with errno %s", rc,
                         errno_rpc2str(RPC_ERRNO(pco_iut1)));
    }
    RING("%s() returned %d, revents %x, %x",
         iomux_call_en2str(iomux), rc, events[0].revents,
         events[1].revents);

    if (!(((iomux == IC_POLL || iomux == IC_PPOLL) &&
           events[0].revents == (EVT_EXC | EVT_NVAL) &&
           events[1].revents == 0) ||
          ((iomux != IC_POLL && iomux != IC_PPOLL) &&
           ((events[0].revents == 0 && events[1].revents == EVT_RD) ||
           (events[1].revents == 0 && events[0].revents == EVT_RD)))))
    {
        TEST_FAIL("Incorrect events have been reported.");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    TEST_END;
}
