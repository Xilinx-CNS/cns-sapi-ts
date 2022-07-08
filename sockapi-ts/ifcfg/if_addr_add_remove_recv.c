/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_addr_add_remove_recv Sending or connecting to a newly added or removed address
 *
 * @objective Check what happens when connection request or data is sent
 *            to an address which was added or removed and there is a
 *            socket bound to @c INADDR_ANY before the address was added
 *            the first time.
 *
 * @type conformance
 *
 * @param env             Testing environment:
 *                        - @ref arg_types_env_peer2peer
 *                        - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type       Socket type:
 *                        - @c SOCK_STREAM
 *                        - @c SOCK_DGRAM
 * @param same_net        If @c TRUE, tested address is from the same
 *                        network as existing ones, otherwise it is
 *                        from a different network.
 * @param traffic         If @c TRUE, packets are actively sent from
 *                        Tester to the tested address when it is removed.
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_addr_add_remove_recv"

#include "sockapi-test.h"
#include "sockapi-ts_net_conns.h"
#include "tapi_route_gw.h"

/* Maximum packet length */
#define MAX_PKT_LEN 1024

/* Maximum time to send data from Tester, in seconds */
#define MAX_SEND_TIME MAX(5, TE_MS2SEC(TAPI_WAIT_NETWORK_DELAY * 10) + 1)

/*
 * Maximum time to wait for new data after restoring removed address,
 * in milliseconds.
 */
#define MAX_WAIT_TIME 30000

/**
 * Call connect() in a non-blocking way, expecting that it fails with
 * EINPROGRESS.
 *
 * @param rpcs        RPC server.
 * @param s           Socket FD (should be in non-blocking mode).
 * @param addr        Address to connect to.
 * @param stage       String to start verdicts with.
 */
static void
nonblock_connect(rcf_rpc_server *rpcs, int s, const struct sockaddr *addr,
                 const char *stage)
{
    int rc;

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_connect(rpcs, s, addr);
    if (rc == 0)
    {
        TEST_VERDICT("%s: nonblocking connect() unexpectedly succeeded",
                     stage);
    }
    else if (rc < 0 && RPC_ERRNO(rpcs) != RPC_EINPROGRESS)
    {
        TEST_VERDICT("%s: nonblocking connect() failed with unexpected "
                     "errno %r instead of EINPROGRESS",
                     stage, RPC_ERRNO(rpcs));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    tapi_env_net *net = NULL;
    const struct sockaddr *iut_addr = NULL;
    struct sockaddr *new_addr = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    struct sockaddr_storage bind_addr;

    cfg_handle net_handle = CFG_HANDLE_INVALID;
    cfg_handle new_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle rt_handle = CFG_HANDLE_INVALID;
    unsigned int prefix;

    rpc_socket_type sock_type;
    te_bool same_net;
    te_bool traffic;

    int iut_s = -1;
    int iut_acc = -1;
    int iut_recv_s = -1;
    int tst_s = -1;
    int tst_s2 = -1;
    int iut_acc2 = -1;

    char buf[MAX_PKT_LEN];
    int send_len;
    te_bool readable;

    tapi_pat_sender tst_sender_ctx;
    tapi_pat_receiver iut_receiver_ctx;
    uint64_t total_received = 0;
    te_bool done;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(same_net);
    TEST_GET_BOOL_PARAM(traffic);

    tapi_sockaddr_clone_exact(iut_addr, &bind_addr);
    te_sockaddr_set_wildcard(SA(&bind_addr));

    TEST_STEP("Create a socket of type @p sock_type on IUT, bind it to "
              "a wildcard address.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, SA(&bind_addr));

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If it is TCP socket, call @b listen() on it.");
        rpc_listen(pco_iut, iut_s, -1);
    }

    TEST_STEP("Add a new address @b new_addr on the IUT interface, chosen "
              "according to @p same_net.");

    if (same_net)
    {
        if (iut_addr->sa_family == AF_INET)
        {
            net_handle = net->ip4net;
            prefix = net->ip4pfx;
        }
        else
        {
            net_handle = net->ip6net;
            prefix = net->ip6pfx;
        }
    }
    else
    {
        sockts_allocate_network(&net_handle, &prefix, iut_addr->sa_family);
    }

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &new_addr));
    te_sockaddr_set_port(new_addr, te_sockaddr_get_port(iut_addr));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                 pco_iut->ta, iut_if->if_name, new_addr, prefix,
                 FALSE, &new_addr_handle));

    if (!same_net)
    {
        TEST_STEP("If @p same_net is @c FALSE, add a route to @b new_addr "
                  "on Tester.");
        CHECK_RC(tapi_cfg_add_route(pco_tst->ta, iut_addr->sa_family,
                                    te_sockaddr_get_netaddr(new_addr),
                                    prefix, NULL, tst_if->if_name, NULL,
                                    0, 0, 0, 0, 0, 0, &rt_handle));
    }

    TEST_STEP("Add a permanent neighbor entry for @b new_addr on Tester.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name,
                             pco_iut->ta, iut_if->if_name,
                             new_addr, NULL, TRUE));

    CFG_WAIT_CHANGES;

    TEST_STEP("Create a socket of type @p sock_type on Tester.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If TCP is checked, establish TCP connection from "
                  "the Tester socket to @b new_addr.");

        iut_acc = sockts_tcp_connect(pco_tst, tst_s, pco_iut, iut_s,
                                     NULL, new_addr, RPC_PF_UNKNOWN,
                                     "Connecting after adding an address");
        if (iut_acc < 0)
            TEST_STOP;

        iut_recv_s = iut_acc;
    }
    else
    {
        TEST_STEP("If UDP is checked, send data from the Tester "
                  "socket to @b new_addr. Check that the IUT "
                  "socket receives it.");

        rpc_connect(pco_tst, tst_s, new_addr);
        sockts_test_send(pco_tst, tst_s, pco_iut, iut_s,
                         NULL, NULL, RPC_PF_UNKNOWN, TRUE,
                         "Sending after adding an address");

        iut_recv_s = iut_s;
    }

    if (traffic)
    {
        TEST_STEP("If @p traffic is @c TRUE, start sending data from "
                  "the Tester socket to @b new_addr and receiving it on "
                  "the IUT socket with help of @b rpc_pattern_sender() and "
                  "@b rpc_pattern_receiver().");

        sockts_init_pat_sender_receiver(&tst_sender_ctx, &iut_receiver_ctx,
                                        MAX_PKT_LEN, MAX_PKT_LEN,
                                        MAX_SEND_TIME, MAX_SEND_TIME + 1,
                                        TAPI_WAIT_NETWORK_DELAY);

        pco_iut->timeout = TE_SEC2MS(MAX_SEND_TIME + 1);
        pco_iut->op = RCF_RPC_CALL;
        rpc_pattern_receiver(pco_iut, iut_recv_s, &iut_receiver_ctx);

        pco_tst->timeout = TE_SEC2MS(MAX_SEND_TIME + 1);
        pco_tst->op = RCF_RPC_CALL;
        rpc_pattern_sender(pco_tst, tst_s, &tst_sender_ctx);
    }

    TEST_STEP("Remove @b new_addr on IUT.");
    CHECK_RC(cfg_del_instance(new_addr_handle, FALSE));
    new_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    if (traffic)
    {
        TEST_STEP("If @p traffic is @c TRUE, check that "
                  "@b rpc_pattern_receiver() on IUT stops due to lack of "
                  "new data. Wait until @b rpc_pattern_sender() terminates "
                  "too.");

        MSLEEP(TAPI_WAIT_NETWORK_DELAY * 2);
        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_pattern_receiver(pco_iut, iut_recv_s, &iut_receiver_ctx);
        if (rc < 0)
        {
            ERROR_VERDICT("rpc_pattern_receiver() failed unexpectedly with "
                          "error %r", RPC_ERRNO(pco_iut));
        }
        total_received = iut_receiver_ctx.received;

        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_pattern_sender(pco_tst, tst_s, &tst_sender_ctx);
        if (rc < 0)
        {
            ERROR_VERDICT("rpc_pattern_sender() failed unexpectedly with "
                          "error %r", RPC_ERRNO(pco_tst));
        }

        if (!done)
        {
            TEST_VERDICT("After removing an address on IUT, "
                         "rpc_pattern_receiver() did not stop due to "
                         "absence of new data");
        }
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If TCP sockets are checked, create another socket on "
                  "Tester and try to connect it to @b new_addr.");

        tst_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                            sock_type, RPC_PROTO_DEF);

        rpc_fcntl(pco_tst, tst_s2, RPC_F_SETFL, RPC_O_NONBLOCK);

        nonblock_connect(pco_tst, tst_s2, new_addr,
                         "After address removal");
    }
    else
    {
        TEST_STEP("If UDP sockets are checked, send another packet to "
                  "@b new_addr from the Tester socket.");

        send_len = rand_range(1, sizeof(buf));
        te_fill_buf(buf, send_len);
        RPC_SEND(rc, pco_tst, tst_s, buf, send_len, 0);
    }

    TEST_STEP("Check that the IUT socket bound to wildcard address does "
              "not become readable.");
    RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
    if (readable)
    {
        TEST_VERDICT("IUT socket is readable after removing the "
                     "address and sending a packet or connection request "
                     "to it");
    }

    TEST_STEP("Add @b new_addr again on the IUT interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                 pco_iut->ta, iut_if->if_name, new_addr, prefix,
                 FALSE, &new_addr_handle));
    CFG_WAIT_CHANGES;

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("If TCP sockets are checked, check that now the "
                  "second Tester socket can connect successfully to "
                  "@b new_addr. Accept the new connection on IUT and "
                  "check that data can be sent over the new connection.");

        /*
         * IUT host may have replied with ICMP "destination unreachable"
         * in case when the removed address was from another network and
         * there is no default route for a given protocol. In that
         * case we should start another connection attempt on Tester.
         */
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_connect(pco_tst, tst_s2, new_addr);
        if (rc < 0)
        {
            if (!same_net && RPC_ERRNO(pco_tst) == RPC_ENETUNREACH)
            {
                nonblock_connect(pco_tst, tst_s2, new_addr,
                                 "The second call after restoring address");
            }
            else if (RPC_ERRNO(pco_tst) != RPC_EALREADY)
            {
                TEST_VERDICT("Nonblocking connect() failed with unexpected "
                             "error %r after restoring the address",
                             RPC_ERRNO(pco_tst));
            }
        }

        iut_acc2 = rpc_accept(pco_iut, iut_s, NULL, NULL);
        sockts_test_connection(pco_iut, iut_acc2, pco_tst, tst_s2);

        if (traffic)
        {
            TEST_SUBSTEP("If @p traffic is @c TRUE, check also that all "
                         "the data written to the first Tester socket "
                         "by @b rpc_pattern_sender() eventually arrives "
                         "on IUT.");

            pco_iut->timeout = MAX_WAIT_TIME;
            RPC_GET_READABILITY(readable, pco_iut, iut_recv_s,
                                MAX_WAIT_TIME);
            if (!readable)
            {
                TEST_VERDICT("The first IUT socket did not become readable "
                             "after restoring IUT address");
            }

            rpc_pattern_receiver(pco_iut, iut_recv_s, &iut_receiver_ctx);
            total_received += iut_receiver_ctx.received;
            if (total_received != tst_sender_ctx.sent)
            {
                ERROR("%llu bytes were sent, %llu bytes were received",
                      (long long unsigned int)(tst_sender_ctx.sent),
                      (long long unsigned int)total_received);

                TEST_VERDICT("Number of bytes received over the first "
                             "connection does not match number of bytes "
                             "sent via it.");
            }
        }
    }
    else
    {
        TEST_STEP("If UDP sockets are checked, try to send another packet "
                  "to @b new_addr from the Tester socket. Check that the "
                  "IUT socket can receive it now.");
        sockts_test_send(pco_tst, tst_s, pco_iut, iut_s,
                         NULL, NULL, RPC_PF_UNKNOWN, TRUE,
                         "Sending after adding the address again");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc2);

    if (new_addr_handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(new_addr_handle, FALSE));

    if (rt_handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(rt_handle, FALSE));

    TEST_END;
}
