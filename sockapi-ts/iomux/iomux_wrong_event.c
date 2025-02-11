/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 */

/**
 * @page iomux-iomux_wrong_event Wrong event handling
 *
 * @objective Check that iomux ignores wrong event
 *
 * @param env        Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_lo
 *      - @ref arg_types_env_peer2peer_tst
 * @param sock_type  Type of sockets:
 *      - tcp_passive
 *      - tcp_active
 *      - tcp_passive_close
 *      - udp_notconn
 *      - udp
 * @param iomux      Type of iomux function:
 *      - select
 *      - pselect
 *      - poll
 *      - ppoll
 *      - epoll
 *      - epoll_pwait
 *      - epoll_pwait2
 *      - oo_epoll
 * @param event1     Type of tested event iomux is waiting for:
 *      - EVT_RD
 *      - EVT_HUP
 *      - EVT_WR
 * @param event2     Type of created event iomux must not catch:
 *      - EVT_WR
 *      - EVT_RD
 * @param timeout    If @c TRUE break iomux call by timeout, else by creating
 *                   the desired event:
 *      - TRUE
 *      - FALSE
 * @param before     If @c TRUE create the event before performing iomux call:
 *      - TRUE
 *      - FALSE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/iomux_wrong_event"

#include "sockapi-test.h"
#include "iomux.h"

/*
 * Test uses SOCKTS_SOCK_TCP_PASSIVE to perform
 * "tcp_listen" iteration.
 */
#define SOCK_TCP_LISTEN     SOCKTS_SOCK_TCP_PASSIVE

/* Timeout to use in iomux */
#define TIMEOUT 2000

/*
 * select()/pselect() has no POLLHUP analogue and does not shoot after
 * shutdown() call, however it succesfully catches OUT event when
 * the test performs shutdown().
 * So, we need to wait EVT_WR event instead of EVT_HUP to unblock
 * iomux call.
 */
#define IOMUX_SELECT_WORKAROUND(evt) \
    (((evt) == EVT_HUP && \
    (iomux == TAPI_IOMUX_SELECT || iomux == TAPI_IOMUX_PSELECT) && \
    sock_type_sockts2rpc(sock_type) != RPC_SOCK_DGRAM) ? \
    EVT_WR : (evt))

/*
 * Create iomux event with type @p evt on IUT.
 *
 * @param pco_iut_thread    IUT thread RPC server (for shutdown).
 * @param pco_tst           Tester RPC server.
 * @param iut_s             IUT socket.
 * @param tst_s             Tester socket.
 * @param iut_addr          IUT address.
 * @param sock_type         Type of connection.
 * @param evt               Type of event.
 */
static void
create_iut_event(rcf_rpc_server *pco_iut_thread,
                 rcf_rpc_server *pco_tst,
                 int iut_s, int tst_s,
                 const struct sockaddr *iut_addr,
                 sockts_socket_type sock_type, tapi_iomux_evt evt)
{
    char         buf[SOCKTS_MSG_STREAM_MAX];
    te_bool      connect = FALSE;

    connect = sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL ||
              sock_type == SOCKTS_SOCK_TCP_ACTIVE ||
              sock_type == SOCKTS_SOCK_UDP;

    switch (evt)
    {
        case EVT_RD:
            if (sock_type == SOCK_TCP_LISTEN)
            {
                rpc_connect(pco_tst, tst_s, iut_addr);
            }
            else if (!connect)
            {
                rpc_sendto(pco_tst, tst_s, buf, SOCKTS_MSG_STREAM_MAX,
                           0, iut_addr);
            }
            else
            {
                rpc_send(pco_tst, tst_s, buf, SOCKTS_MSG_STREAM_MAX, 0);
            }
            break;

        case EVT_WR:
            if (sock_type == SOCK_TCP_LISTEN)
            {
                TEST_FAIL("Invalid iteration: cannot create EVT_WR "
                          "event on listening socket.");
            }
            rpc_drain_fd_simple(pco_tst, tst_s, NULL);
            break;

        case EVT_HUP:
            rpc_shutdown(pco_iut_thread, iut_s, RPC_SHUT_RDWR);
            if (sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL ||
                sock_type == SOCKTS_SOCK_TCP_ACTIVE)
            {
                rpc_shutdown(pco_tst, tst_s, RPC_SHUT_RDWR);
            }
            break;

        default:
            TEST_FAIL("Unsupported type of event");
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_iut_thread = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    sockts_socket_type      sock_type;
    te_bool                 timeout;
    te_bool                 before;

    int                     iut_s = -1;
    int                     iut_l = -1;
    int                     tst_s = -1;

    tapi_iomux_evt_fd      *evts = NULL;
    tapi_iomux_handle      *iomux_h = NULL;
    tapi_iomux_evt          event1;
    tapi_iomux_evt          event2;
    tapi_iomux_evt          exp_evt;
    tapi_iomux_type         iomux;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_PCO(pco_tst);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(timeout);
    TEST_GET_BOOL_PARAM(before);
    TEST_GET_ENUM_PARAM(event1, IOMUX_EVENT_MAPPING_LIST);
    TEST_GET_ENUM_PARAM(event2, IOMUX_EVENT_MAPPING_LIST);
    TEST_GET_IOMUX_FUNC(iomux);

    if (event1 == EVT_HUP || event2 == EVT_HUP)
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "iut_thread",
                                              &pco_iut_thread));
    }

    TEST_STEP("Establish @p sock_type connection between IUT and tester.");
    if (sock_type == SOCK_TCP_LISTEN)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_s, iut_addr);
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
    }
    else
    {
        SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                          &iut_s, &tst_s, &iut_l);
    }

    TEST_STEP("For TCP connected socket overfill TX buffer on IUT "
              "in order to discard OUT event.");
    if (sock_type == SOCKTS_SOCK_TCP_ACTIVE ||
        sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
    {
        rpc_overfill_buffers(pco_iut, iut_s, NULL);
    }

    TEST_STEP("Create an iomux set, add IUT socket and @p event1 to the set.");
    iomux_h = sockts_iomux_create(pco_iut, iomux);
    tapi_iomux_add(iomux_h, iut_s, IOMUX_SELECT_WORKAROUND(event1));

    TEST_STEP("If @p before is @c TRUE, create an event with type @p event2.");
    if (before)
    {
        create_iut_event(pco_iut_thread, pco_tst, iut_s, tst_s,
                         iut_addr, sock_type, event2);
        TAPI_WAIT_NETWORK;
    }

    TEST_STEP("Perform iomux call (use non-zero timeout "
              "if @p timeout is @c TRUE).");
    pco_iut->op = RCF_RPC_CALL;
    tapi_iomux_call(iomux_h, timeout ? TIMEOUT : -1 , &evts);

    TEST_STEP("If @p before is @c FALSE, create an event with "
              "type @p event2.");
    if (!before)
    {
        TAPI_WAIT_NETWORK;
        create_iut_event(pco_iut_thread, pco_tst, iut_s, tst_s,
                         iut_addr, sock_type, event2);
    }

    TEST_STEP("Check that iomux does not return any events.");
    if (sockts_is_op_done(pco_iut))
    {
        pco_iut->op = RCF_RPC_WAIT;
        RPC_AWAIT_ERROR(pco_iut);
        tapi_iomux_call(iomux_h, timeout ? TIMEOUT : -1 , &evts);
        TEST_VERDICT("%s call is not blocked", tapi_iomux_call_en2str(iomux));
    }

    if (timeout)
    {
        TEST_STEP("If @p timeout is @c TRUE");
        TEST_SUBSTEP("Check that iomux call exits with timeout.");
        pco_iut->op = RCF_RPC_WAIT;
        IOMUX_CHECK_ZERO(tapi_iomux_call(iomux_h, TIMEOUT, &evts));
    }
    else
    {
        TEST_STEP("If @p timeout is @c FALSE");
        exp_evt = IOMUX_SELECT_WORKAROUND(event1);

        /*
         * IOmux lib adds EVT_EXC to returned events when receives EVT_HUP,
         * so we are expecting it too here.
         */
        if (exp_evt == EVT_HUP)
            exp_evt |= EVT_EXC;

        TEST_SUBSTEP("Create the event with type @p event1.");
        create_iut_event(pco_iut_thread, pco_tst, iut_s, tst_s,
                         iut_addr, sock_type, event1);

        TEST_SUBSTEP("Check that iomux returns required event.");
        pco_iut->op = RCF_RPC_WAIT;
        rc = tapi_iomux_call(iomux_h, -1 , &evts);
        SOCKTS_CHECK_IOMUX_EVENTS(rc, 1, evts, exp_evt, "");
    }

    TEST_SUCCESS;

cleanup:
    tapi_iomux_destroy(iomux_h);
    CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
