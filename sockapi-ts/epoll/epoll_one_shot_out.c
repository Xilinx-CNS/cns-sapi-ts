/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 *
 * $Id$
 */

/** @page epoll-epoll_one_shot_out  OUT event with different timeout values and ET mode
 *
 * @objective Test OUT event with different timeout values in the
 *            edge-triggered mode.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param iomux         Multiplexing function
 * @param timeout       Timeout value for the second and further iomux calls
 *
 * @par Test sequence:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epoll_one_shot_out"

#include "sockapi-test.h"
#include "onload.h"
#include "iomux.h"
#include "epoll_common.h"

#define MAX_BUFF_SIZE 10240
#define FIRST_TIMEOUT 5000
#define IOMUX_ATTEMPTS_NUM 3

int
main(int argc, char *argv[])
{
    iomux_call_type         iomux;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    int                     timeout;

    unsigned char           buffer[MAX_BUFF_SIZE];
    struct rpc_epoll_event  events[2];
    uint32_t                event;
    uint64_t                total_bytes;
    uint32_t                exp_ev;

    int maxevents = 2;
    int epfd = -1;
    int iut_s = -1;
    int tst_s = -1;
    int count;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(timeout);

    event = RPC_EPOLLOUT;
    exp_ev = event;
    event |= RPC_EPOLLET;

    TEST_STEP("Create sockets, establish connection.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Overfill buffers for IUT->tester direction.");
    rpc_overfill_buffers_gen(pco_iut, iut_s, &total_bytes,
                             iomux == IC_OO_EPOLL ? IC_EPOLL : iomux);

    TEST_STEP("Create epoll set and add IUT socket to it.");
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s, event);

    TEST_STEP("Call blocking iomux on IUT.");
    pco_iut->op = RCF_RPC_CALL;
    iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, FIRST_TIMEOUT);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Read data on the tester side.");
    do {
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, buffer, MAX_BUFF_SIZE, RPC_MSG_DONTWAIT);
        if (rc < 0)
        {
            if (RPC_ERRNO(pco_tst) != RPC_EAGAIN)
                TEST_VERDICT("Read failed with unexpected errno %r",
                             RPC_ERRNO(pco_tst));
            break;
        }

        total_bytes -= rc;
    } while (total_bytes != 0);

    TEST_STEP("Withdraw called iomux results and check them.");
    pco_iut->op = RCF_RPC_WAIT;
    if ((rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents,
                               FIRST_TIMEOUT)) != 1)
        TEST_VERDICT("First iomux returned unexpected value %d", rc);
    else if (events[0].data.fd != iut_s)
        TEST_FAIL("%s() retured incorrect fd %d instead of %d iut_s",
                  iomux_call_en2str(iomux), events[0].data.fd, iut_s);
    else if (events[0].events != exp_ev)
        TEST_FAIL("%s() returned incorrect events", iomux_call_en2str(iomux));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Call the iomux function a few times to get number how many times "
              "the event is reported.");
    for (i = 0, count = 1; i < IOMUX_ATTEMPTS_NUM; i++, count++)
    {
        rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, timeout);
        if (rc == 0)
            break;
        if (rc != 1)
            TEST_VERDICT("Unexpected events number was returned on "
                         "iteration #%d", i);
        TAPI_WAIT_NETWORK;
    }
    RING("Event was reported %d times", count);

    if (count != 1)
    {
        if (count == 2)
            RING_VERDICT("Event was reported 2 times");
        else
            TEST_VERDICT("Event was reported %d times", count);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
