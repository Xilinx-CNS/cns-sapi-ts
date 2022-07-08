/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_tcp_wild TCP connections distribution with SO_REUSEPORT and wildcards
 *
 * @objective Check that connection requests are delivered to correct
 *            sockets when SO_REUSEPORT is used together with binding
 *            to INADDR_ANY.
 *
 * @type use case
 *
 * @param first_wild      Use INADDR_ANY to bind the first sockets couple.
 * @param second_wild     Use INADDR_ANY to bind the second sockets couple.
 * @param same_port       Use the same port for all sockets. Value @c TRUE
 *                        is not applicable for iteration when both
 *                        @p first_wild and second_wild are @c TRUE.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_tcp_wild"

#include "sockapi-test.h"
#include "reuseport.h"

/** Number of pairs of listener sockets. */
#define SOCK_PAIRS 2

/** Total number of listener sockets. */
#define SOCK_NUM (SOCK_PAIRS * 2)

/**
 * Maximum number of connect attempts
 * before giving up.
 */
#define MAX_ATTEMPTS (SOCK_NUM * 10)

/** TCP connection establishment timeout, milliseconds. */
#define CONN_TIMEOUT 500

int
main(int argc, char *argv[])
{
    tapi_env_net    *net = NULL;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr *iut_addr2 = NULL;
    cfg_handle       iut_addr2_handle = CFG_HANDLE_INVALID;

    struct sockaddr_storage tst_bind_addr;
    struct sockaddr_storage iut_bind_addrs[SOCK_PAIRS];
    struct sockaddr_storage iut_conn_addrs[SOCK_PAIRS];

    int       tst_s = -1;
    int       iut_acc = -1;
    int       iut_listeners[SOCK_PAIRS][2];
    te_bool   iut_accepted[SOCK_PAIRS][2];
    te_bool   connect_first = FALSE;
    int       listeners_accepted = 0;

    int i;
    int j;
    int k;
    int l;

    struct rpc_pollfd fds[SOCK_NUM];

    te_bool first_wild;
    te_bool second_wild;
    te_bool same_port;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(first_wild);
    TEST_GET_BOOL_PARAM(second_wild);
    TEST_GET_BOOL_PARAM(same_port);

    for (i = 0; i < SOCK_PAIRS; i++)
    {
        for (j = 0; j < 2; j++)
        {
            iut_listeners[i][j] = -1;
            iut_accepted[i][j] = FALSE;
        }
    }

    TEST_STEP("Add iut_addr2 IP address to the IUT interface to "
              "have in sum two IP addresses iut_addr and iut_addr2.");

    CHECK_RC(tapi_env_allocate_addr(net, AF_INET,
                                    &iut_addr2, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr2,
                                           net->ip4pfx,
                                           FALSE, &iut_addr2_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Construct bind_addr1:port1 to bind the first socket pair to: "
              "if @p first_wild is @c TRUE, bind_addr1 here is INADDR_ANY, "
              "otherwise it should be iut_addr.");

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addrs[0]);
    if (first_wild)
        te_sockaddr_set_wildcard(SA(&iut_bind_addrs[0]));

    TEST_STEP("Construct bind_addr2:port2 to bind the second socket pair to: "
              "if @p second_wild is @c TRUE, bind_addr2 should be INADDR_ANY, "
              "otherwise it should be iut_addr2. If @p same_port is @c TRUE, "
              "port2 should be the same as port1; otherwise use another port.");

    tapi_sockaddr_clone_exact(iut_addr2, &iut_bind_addrs[1]);
    if (second_wild)
        te_sockaddr_set_wildcard(SA(&iut_bind_addrs[1]));

    if (same_port)
        te_sockaddr_set_port(SA(&iut_bind_addrs[1]),
                             te_sockaddr_get_port(SA(&iut_bind_addrs[0])));
    else
        CHECK_RC(tapi_allocate_set_port(pco_iut, SA(&iut_bind_addrs[1])));

    tapi_sockaddr_clone_exact(iut_addr, &iut_conn_addrs[0]);
    te_sockaddr_set_port(SA(&iut_conn_addrs[0]),
                         te_sockaddr_get_port(SA(&iut_bind_addrs[0])));

    tapi_sockaddr_clone_exact(iut_addr2, &iut_conn_addrs[1]);
    te_sockaddr_set_port(SA(&iut_conn_addrs[1]),
                         te_sockaddr_get_port(SA(&iut_bind_addrs[1])));

    TEST_STEP("Create two pairs of TCP sockets on IUT. Set @c SO_REUSEPORT "
              "for each socket. Bind sockets from the first pair to "
              "bind_addr1:port1, and sockets from the second pair to "
              "bind_addr2:port2. Call listen() on each of them.");

    k = 0;
    for (i = 0; i < SOCK_PAIRS; i++)
    {
        for (j = 0; j < 2; j++)
        {
            iut_listeners[i][j] = rpc_socket(
                                      pco_iut,
                                      rpc_socket_domain_by_addr(iut_addr),
                                      RPC_SOCK_STREAM,
                                      RPC_PROTO_DEF);
            rpc_setsockopt_int(pco_iut, iut_listeners[i][j],
                               RPC_SO_REUSEPORT, 1);
            rpc_bind(pco_iut, iut_listeners[i][j],
                     SA(&iut_bind_addrs[i]));
            rpc_listen(pco_iut, iut_listeners[i][j],
                       SOCKTS_BACKLOG_DEF);

            fds[k].fd = iut_listeners[i][j];
            fds[k].events = RPC_POLLIN;
            fds[k].revents = 0;
            k++;
        }
    }

    TEST_STEP("In a loop until @c MAX_ATTEMPTS iterations are done "
              "or each listener socket on IUT accepted at least one "
              "connection:");

    for (l = 0; l < MAX_ATTEMPTS; l++)
    {
        TEST_SUBSTEP("Create a socket on Tester.");
        tst_s = rpc_socket(pco_tst,
                           rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM,
                           RPC_PROTO_DEF);
        rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);

        CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_bind_addr));
        rpc_bind(pco_tst, tst_s, SA(&tst_bind_addr));

        TEST_SUBSTEP("Call nonblocking connect() to either iut_addr:port1 "
                     "or iut_addr2:port2 (select these destination in turns "
                     "while iterating this loop).");

        connect_first = !connect_first;

        RPC_AWAIT_ERROR(pco_tst);
        if (connect_first)
            rc = rpc_connect(pco_tst, tst_s,
                             SA(&iut_conn_addrs[0]));
        else
            rc = rpc_connect(pco_tst, tst_s,
                             SA(&iut_conn_addrs[1]));

        if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_EINPROGRESS)
            TEST_VERDICT("Nonblocking connect() on Tester failed with "
                         "unexpected errno %r", RPC_ERRNO(pco_tst));

        TEST_SUBSTEP("Check that if the tester socket connected to "
                     "iut_addr:port1, one of the listeners from the first "
                     "pair accepted connection; and if the tester socket "
                     "connected to iut_addr2:port2, one of the listeners "
                     "from the second pair accepted connection.");

        rc = rpc_poll(pco_iut, fds, SOCK_NUM, CONN_TIMEOUT);
        if (rc == 0)
            TEST_VERDICT("No listener on IUT accepted connection");
        else if (rc > 1)
            TEST_VERDICT("More than one listener on IUT has events");

        for (k = 0; k < SOCK_NUM; k++)
        {
            if (fds[k].revents != 0)
            {
                if (fds[k].revents != RPC_POLLIN)
                    TEST_VERDICT("poll() returned unexpected events %s",
                                 poll_event_rpc2str(fds[k].revents));

                if ((k >= 2 && connect_first) ||
                    (k < 2 && !connect_first))
                    TEST_VERDICT("Listener from the wrong pair "
                                 "accepted connection on IUT");

                break;
            }
        }
        if (k >= SOCK_NUM)
            TEST_FAIL("Failed to find socket "
                      "for which poll() reported events");

        iut_acc = rpc_accept(pco_iut, fds[k].fd, NULL, NULL);

        TEST_SUBSTEP("Check that data can be transmitted in both directions "
                     "over the established connection.");
        rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, 0);
        sockts_test_connection(pco_iut, iut_acc,
                               pco_tst, tst_s);
        RPC_CLOSE(pco_iut, iut_acc);
        RPC_CLOSE(pco_tst, tst_s);

        i = k / 2;
        j = k % 2;
        if (!iut_accepted[i][j])
        {
            iut_accepted[i][j] = TRUE;
            listeners_accepted++;
            if (listeners_accepted == SOCK_NUM)
                break;
        }
    }

    TEST_STEP("Check that every listener accepted at least one "
              "connection.");
    if (listeners_accepted < SOCK_NUM)
        TEST_VERDICT("Not every listener on IUT accepted connection");

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < SOCK_PAIRS; i++)
    {
        for (j = 0; j < 2; j++)
        {
            CLEANUP_RPC_CLOSE(pco_iut, iut_listeners[i][j]);
        }
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(iut_addr2);
    if (iut_addr2_handle != CFG_HANDLE_INVALID)
    {
        CHECK_RC(cfg_del_instance(iut_addr2_handle,
                                  FALSE));
        CFG_WAIT_CHANGES;
    }

    TEST_END;
}
