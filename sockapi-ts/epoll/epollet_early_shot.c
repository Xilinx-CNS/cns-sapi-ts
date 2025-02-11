/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Edge-triggered epoll discharged before binding
 */

/**
 * @page epoll-epollet_early_shot Edge-triggered epoll discharged before binding
 *
 * @objective Add a socket before bind(), listen() or connect() to epoll set
 *            with EPOLLET flag, discharge event using epoll_wait(). Check that
 *            further events are rised as usual independently on if socket is
 *            handed over or not.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_two_nets_iut_first: the environment provides both
 *        kinds of connections IUT and tst, so all iterations can be implemented
 *        using it.
 *      - @ref arg_types_env_two_nets_iut_first_ipv6
 * @param iomux     A kind of epoll_wait() call (enum @c epoll_wait_calls):
 *      - epoll
 *      - epoll_pwait
 *      - epoll_pwait2
 * @param sock_type Type of sockets:
 *      - SOCK_STREAM
 *      - SOCK_DGRAM
 * @param bind_to   Bind IUT socket to:
 *      - iut (an accelerated interface address (iut_addr1))
 *      - tst (address from tester network (iut_addr2))
 *      - wild (INADDR_ANY)
 *      - lo (localhost (127.0.0.1))
 *      - none (do not bind (applicable only for TCP with @p listening=FALSE))
 * @param peer      Kind of address to connect to/from:
 *      - iut (peer address on accelerated connection (tst1_addr))
 *      - tst (peer address on non-accelerated connection (tst2_addr))
 *      - lo_iut (any IUT address (iut_addr1))
 *      - lo (localhost (127.0.0.1))
 *      - none (do not call connect() (do not iterate for TCP))
 * @param listening Actively or passively establish TCP connection, it does not
 *                  make sense for UDP:
 *      - False (active connection open for IUT socket)
 *      - True (passive connection open for IUT socket (do not iterate for UDP))
 * @param blocking_iomux
 *        If @c TRUE, create aux thread on IUT
 *        and block it in @p iomux call before the event.
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "epoll/epollet_early_shot"

#include "sockapi-test.h"
#include "iomux.h"
#include "tapi_route_gw.h"

#define MAX_EVENTS  1
#define BUF_SIZE    512

/* Enum for @p bind_to */
typedef enum bind_to_e {
    BIND_TO_IUT,
    BIND_TO_TST,
    BIND_TO_WILD,
    BIND_TO_LO,
    BIND_TO_NONE
} bind_to_t;

#define BIND_TO_MAPPING_LIST \
    {"iut", BIND_TO_IUT},    \
    {"tst", BIND_TO_TST},    \
    {"wild", BIND_TO_WILD},  \
    {"lo", BIND_TO_LO},      \
    {"none", BIND_TO_NONE}

/* Enum for @p peer */
typedef enum peer_e {
    PEER_IUT,
    PEER_TST,
    PEER_LO,
    PEER_NONE
} peer_t;

#define PEER_MAPPING_LIST    \
    {"iut", PEER_IUT},       \
    {"tst", PEER_TST},       \
    {"lo", PEER_LO},         \
    {"none", PEER_NONE}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_iut_peer = NULL;
    rcf_rpc_server             *pco_aux = NULL;
    rcf_rpc_server             *pco_tst1 = NULL;
    rcf_rpc_server             *pco_tst2 = NULL;

    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;

    const struct sockaddr      *iut_addr1;
    const struct sockaddr      *iut_addr2;
    const struct sockaddr      *tst1_addr;
    const struct sockaddr      *tst2_addr;

    int                         iut_s = -1;
    int                         tester_s = -1;
    int                         acc_s = -1;

    iomux_call_type             iomux;
    rpc_socket_type             sock_type;
    bind_to_t                   bind_to;
    peer_t                      peer;
    te_bool                     listening;
    te_bool                     blocking_iomux;

    te_bool                     epoll_done;

    struct sockaddr_storage     iut_bind_addr;
    const struct sockaddr      *iut_addr;
    struct sockaddr_storage     peer_addr;
    rcf_rpc_server             *peer_rpc_server;

    int                         epfd = -1;
    struct rpc_epoll_event      events[MAX_EVENTS];

    uint8_t                    *tx_buf;
    uint8_t                    *rx_buf;

    cfg_handle                  rt_handle = CFG_HANDLE_INVALID;
    rpc_socket_domain           domain;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(bind_to, BIND_TO_MAPPING_LIST);
    TEST_GET_ENUM_PARAM(peer, PEER_MAPPING_LIST);
    TEST_GET_BOOL_PARAM(listening);
    TEST_GET_BOOL_PARAM(blocking_iomux);

    tx_buf = (uint8_t *)te_make_buf_by_len(BUF_SIZE);
    rx_buf = (uint8_t *)te_make_buf_by_len(BUF_SIZE);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    TEST_STEP("Create @p sock_type socket.");
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    TEST_STEP("Create new epoll set.");
    epfd = rpc_epoll_create(pco_iut, MAX_EVENTS);
    TEST_STEP("Add the socket to the epoll set with flag EPOLLET and expecting "
              "event @c EPOLLIN.");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s,
                         RPC_EPOLLIN | RPC_EPOLLET);
    TEST_STEP("Call @p iomux, check it returns an expected event.");
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, MAX_EVENTS, 0);
    if (sock_type == RPC_SOCK_STREAM)
    {
        if (rc != 1 || events[0].data.fd != iut_s ||
           events[0].events != RPC_EPOLLHUP)
            TEST_VERDICT("Unexpected epoll result");
    }
    else if (rc != 0)
    {
        TEST_VERDICT("Unexpected epoll result");
    }

    TEST_STEP("Call @p iomux with zero timeout - returns zero.");
    IOMUX_CHECK_ZERO(iomux_epoll_call(iomux, pco_iut, epfd,
                                      events, MAX_EVENTS, 0));

    if (blocking_iomux)
    {
        TEST_STEP("If @p blocking_iomux=TRUE: "
                  "- Create aux thread on IUT. "
                  "- Call @p iomux with timeout @c -1 in the thread.");

        iomux_epoll_call(iomux, pco_iut, epfd, events, MAX_EVENTS, 1);
        IOMUX_CHECK_ZERO(iomux_epoll_call(iomux, pco_iut, epfd,
                                          events, MAX_EVENTS, 1));
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "pco_aux", &pco_aux));
        pco_aux->op = RCF_RPC_CALL;
        iomux_epoll_call(iomux, pco_aux, epfd, events, MAX_EVENTS, -1);
        CHECK_RC(rcf_rpc_server_is_op_done(pco_aux, &epoll_done));
        if (epoll_done)
            TEST_VERDICT("Epoll did not block IUT process thread");
        else
            RING("Epoll blocked IUT process thread");
    }

    TEST_STEP("If @p bind_to is not @c none, perform bind() to address "
              "depending on @p bind_to.");
    TEST_STEP("If @p bind_to is @c iut and @p peer is @c tst or vise versa "
              "@c tst and @c iut accordignly, it is require to add route on "
              "the peer side to deliver packets tst->iut. E.g. a route like "
              "the following - on pco_tst2: ip route add iut_addr1 dev tst2_if");
    switch(bind_to)
    {
        case BIND_TO_IUT:
            iut_addr = iut_addr1;
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr1), &iut_bind_addr);
            rpc_bind(pco_iut, iut_s, CONST_SA(&iut_bind_addr));
            if (peer == PEER_TST)
            {
                CHECK_RC(tapi_cfg_add_route(pco_tst2->ta,
                                            domain_rpc2h(domain),
                                            te_sockaddr_get_netaddr(iut_addr1),
                                            te_netaddr_get_size(iut_addr1->sa_family) * 8,
                                            NULL, tst2_if->if_name, NULL,
                                            0, 0, 0, 0, 0, 0, &rt_handle));
                /*
                 * We need to add IPv6 neighbors entries manually because
                 * there are cases when Linux can not re-resolve FAILED
                 * entries for gateway routes.
                 * See bug 9774.
                 */
                if (domain == RPC_PF_INET6)
                {
                    CHECK_RC(tapi_update_arp(pco_tst2->ta, tst2_if->if_name,
                                             pco_iut->ta, iut_if2->if_name,
                                             iut_addr1, NULL, FALSE));
                    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if2->if_name,
                                             pco_tst2->ta, tst2_if->if_name,
                                             tst2_addr, NULL, FALSE));
                }
                CFG_WAIT_CHANGES;
            }
            break;

        case BIND_TO_TST:
            iut_addr = iut_addr2;
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr2), &iut_bind_addr);
            rpc_bind(pco_iut, iut_s, CONST_SA(&iut_bind_addr));
            if (peer == PEER_IUT)
            {
                CHECK_RC(tapi_cfg_add_route(pco_tst1->ta,
                                            domain_rpc2h(domain),
                                            te_sockaddr_get_netaddr(iut_addr2),
                                            te_netaddr_get_size(iut_addr2->sa_family) * 8,
                                            NULL, tst1_if->if_name, NULL,
                                            0, 0, 0, 0, 0, 0, &rt_handle));
                if (domain == RPC_PF_INET6)
                {
                    CHECK_RC(tapi_update_arp(pco_tst1->ta, tst1_if->if_name,
                                             pco_iut->ta, iut_if1->if_name,
                                             iut_addr2, NULL, FALSE));
                    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if1->if_name,
                                             pco_tst1->ta, tst1_if->if_name,
                                             tst1_addr, NULL, FALSE));
                }
                CFG_WAIT_CHANGES;
            }
            break;

        case BIND_TO_WILD:
            if (peer == PEER_TST)
                iut_addr = iut_addr2;
            else
                iut_addr = iut_addr1;
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr), &iut_bind_addr);
            te_sockaddr_set_wildcard(SA(&iut_bind_addr));
            rpc_bind(pco_iut, iut_s, CONST_SA(&iut_bind_addr));
            break;

        case BIND_TO_LO:
            if (peer == PEER_TST)
                iut_addr = iut_addr2;
            else
                iut_addr = iut_addr1;
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr), &iut_bind_addr);
            te_sockaddr_set_loopback(SA(&iut_bind_addr));
            rpc_bind(pco_iut, iut_s, CONST_SA(&iut_bind_addr));
            iut_addr = SA(&iut_bind_addr);
            break;

        case BIND_TO_NONE:
            break;

    }

    switch(peer)
    {
        case PEER_IUT:
            peer_rpc_server = pco_tst1;
            tapi_sockaddr_clone_exact(CONST_SA(tst1_addr), &peer_addr);
            break;

        case PEER_TST:
            peer_rpc_server = pco_tst2;
            tapi_sockaddr_clone_exact(CONST_SA(tst2_addr), &peer_addr);
            break;

        case PEER_LO:
            CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut_peer", &pco_iut_peer));
            peer_rpc_server = pco_iut_peer;
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr1), &peer_addr);
            tapi_allocate_set_port(peer_rpc_server, CONST_SA(&peer_addr));
            te_sockaddr_set_loopback(SA(&peer_addr));
            break;

        case PEER_NONE:
            if (bind_to == BIND_TO_IUT || bind_to == BIND_TO_WILD)
            {
                peer_rpc_server = pco_tst1;
                tapi_sockaddr_clone_exact(CONST_SA(tst1_addr), &peer_addr);
            }
            else
            {
                peer_rpc_server = pco_tst2;
                tapi_sockaddr_clone_exact(CONST_SA(tst2_addr), &peer_addr);
            }
            break;

    }

    if (bind_to == BIND_TO_LO && peer != PEER_LO)
    {
        CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_iut_peer", &pco_iut_peer));
        peer_rpc_server = pco_iut_peer;
        if (peer == PEER_IUT || peer == PEER_NONE)
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr1), &peer_addr);
        else
            tapi_sockaddr_clone_exact(CONST_SA(iut_addr2), &peer_addr);
        tapi_allocate_set_port(peer_rpc_server, CONST_SA(&peer_addr));
    }

    TEST_STEP("For UDP");
    if (sock_type == RPC_SOCK_DGRAM)
    {
        TEST_SUBSTEP("Connect (or not) the socket to an address in dependence on @p peer.");
        if (peer != PEER_NONE)
            rpc_connect(pco_iut, iut_s, CONST_SA(&peer_addr));
        TEST_SUBSTEP("Create UDP socket on a tester which depends on @p peer.");
        tester_s = rpc_socket(peer_rpc_server, domain, sock_type, RPC_PROTO_DEF);
        rpc_bind(peer_rpc_server, tester_s, CONST_SA(&peer_addr));

        if (!blocking_iomux)
        {
            TEST_SUBSTEP("If @p blocking_iomux=FALSE: "
                         "Block IUT process in @p iomux.");
            pco_iut->op = RCF_RPC_CALL;
            iomux_epoll_call(iomux, pco_iut, epfd, events, MAX_EVENTS, -1);
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &epoll_done));
            if (epoll_done)
                TEST_VERDICT("Epoll did not block IUT process");
        }

        TEST_SUBSTEP("Transmit a datagram from the tester socket.");
        rpc_sendto(peer_rpc_server, tester_s, tx_buf, BUF_SIZE, 0, CONST_SA(iut_addr));
        TEST_SUBSTEP("Check that @p iomux is unblocked and returned the event.");
        rc = iomux_epoll_call(iomux, blocking_iomux ? pco_aux : pco_iut,
                              epfd, events, MAX_EVENTS, -1);
        if (rc != 1 || events[0].data.fd != iut_s || events[0].events != RPC_EPOLLIN)
            TEST_VERDICT("Unexpected epoll result");
        TEST_SUBSTEP("Read and check the datagram.");
        rc = rpc_recv(pco_iut, iut_s, rx_buf, BUF_SIZE, 0);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, BUF_SIZE, rc);
        TEST_SUBSTEP("Call @p iomux one more time - returns zero.");
        IOMUX_CHECK_ZERO(iomux_epoll_call(iomux, blocking_iomux ? pco_aux : pco_iut,
                                          epfd, events, MAX_EVENTS, 0));
        TEST_SUBSTEP("Check data transmission in both directions.");
        sockts_test_udp_sendto_bidir(pco_iut, iut_s, CONST_SA(iut_addr),
                                     peer_rpc_server, tester_s, CONST_SA(&peer_addr));
    }
    else if (!listening)
    {
        TEST_STEP("For TCP active (@p listening=FALSE)");
        TEST_SUBSTEP("Create a listener socket on a tester, which depends on @p peer.");
        tester_s = rpc_socket(peer_rpc_server, domain, sock_type, RPC_PROTO_DEF);
        rpc_bind(peer_rpc_server, tester_s, CONST_SA(&peer_addr));
        rpc_listen(peer_rpc_server, tester_s, SOCKTS_BACKLOG_DEF);
        TEST_SUBSTEP("Connect IUT socket to the tester address.");
        rpc_connect(pco_iut, iut_s, CONST_SA(&peer_addr));

        if (!blocking_iomux)
        {
            TEST_SUBSTEP("If @p blocking_iomux=FALSE: "
                         "Block IUT process in @p iomux.");
            pco_iut->op = RCF_RPC_CALL;
            iomux_epoll_call(iomux, pco_iut, epfd, events, MAX_EVENTS, -1);
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &epoll_done));
            if (epoll_done)
                TEST_VERDICT("Epoll did not block IUT process");
        }
        TEST_SUBSTEP("Transmit a packet from the tester socket.");
        acc_s = rpc_accept(peer_rpc_server, tester_s, NULL, NULL);
        rpc_send(peer_rpc_server, acc_s, tx_buf, BUF_SIZE, 0);
        TEST_SUBSTEP("Check that @p iomux is unblocked and returned the event.");
        rc = iomux_epoll_call(iomux, blocking_iomux ? pco_aux : pco_iut,
                              epfd, events, MAX_EVENTS, -1);
        if (rc != 1 || events[0].data.fd != iut_s || events[0].events != RPC_EPOLLIN)
            TEST_VERDICT("Unexpected epoll result");
        TEST_SUBSTEP("Read and check data.");
        rc = rpc_recv(pco_iut, iut_s, rx_buf, BUF_SIZE, 0);
        SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, BUF_SIZE, rc);
        TEST_SUBSTEP("Call @p iomux one more time - returns zero.");
        IOMUX_CHECK_ZERO(iomux_epoll_call(iomux, blocking_iomux ? pco_aux : pco_iut,
                                          epfd, events, MAX_EVENTS, 0));
        TEST_SUBSTEP("Check data transmission in both directions.");
        sockts_test_connection(pco_iut, iut_s, peer_rpc_server, acc_s);
    }
    else
    {
        TEST_STEP("For TCP passive (@p listening=TRUE)");
        TEST_SUBSTEP("Call listen() on IUT socket.");
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

        if (!blocking_iomux)
        {
            TEST_SUBSTEP("If @p blocking_iomux=FALSE: "
                         "Block IUT process in @p iomux.");
            pco_iut->op = RCF_RPC_CALL;
            iomux_epoll_call(iomux, pco_iut, epfd, events, MAX_EVENTS, -1);
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &epoll_done));
            if (epoll_done)
                TEST_VERDICT("Epoll did not block IUT process");
        }
        TEST_SUBSTEP("Create socket and connect from a tester, which depends on @p peer.");
        tester_s = rpc_socket(peer_rpc_server, domain, sock_type, RPC_PROTO_DEF);
        rpc_bind(peer_rpc_server, tester_s, CONST_SA(&peer_addr));
        rpc_connect(peer_rpc_server, tester_s, CONST_SA(iut_addr));
        TEST_SUBSTEP("Check that @p iomux is unblocked and returned the event.");
        rc = iomux_epoll_call(iomux, blocking_iomux ? pco_aux : pco_iut,
                              epfd, events, MAX_EVENTS, -1);
        if (rc != 1 || events[0].data.fd != iut_s || events[0].events != RPC_EPOLLIN)
            TEST_VERDICT("Unexpected epoll result");
        TEST_SUBSTEP("Accept the connection.");
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

        TEST_SUBSTEP("Call @p iomux one more time - returns zero.");
        IOMUX_CHECK_ZERO(iomux_epoll_call(iomux, blocking_iomux ? pco_aux : pco_iut,
                                          epfd, events, MAX_EVENTS, 0));
        TEST_SUBSTEP("Check data transmission in both directions.");
        sockts_test_connection(pco_iut, acc_s, peer_rpc_server, tester_s);
    }


    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(peer_rpc_server, tester_s);
    CLEANUP_RPC_CLOSE(listening ? pco_iut : peer_rpc_server, acc_s);
    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));
    TEST_END;
}
