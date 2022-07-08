/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_after_bind Enable SO_REUSEPORT after bind
 *
 * @objective Check that enabling SO_REUSEPORT after socket
 *            binding does not take effect.
 *
 * @type use case
 *
 * @param sock_type     Socket type.
 * @param wildcard      If @c TRUE, bind sockets on IUT
 *                      to @c INADDR_ANY.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_after_bind"

#include "sockapi-test.h"
#include "reuseport.h"

/**
 * Maximum number of attempts to connect to IUT listeners
 * or to send data to IUT UDP sockets before finishing test.
 */
#define MAX_ATTEPTS 20

/** Number of sockets on IUT. */
#define SOCK_NUM 2

/** Timeout used with poll(), milliseconds. */
#define POLL_TIMEOUT 500

/**
 * Call poll() for sockets, check that it returns POLLIN
 * for one of them.
 *
 * @param rpcs      RPC server handle.
 * @param fds       Array of rpc_pollfd structures.
 * @param nfds      Number if elements in the array.
 * @param timeout   Timeout in milliseconds.
 */
static void
call_check_poll(rcf_rpc_server *rpcs,
                struct rpc_pollfd *fds,
                unsigned int nfds,
                int timeout)
{
    int           rc;
    unsigned int  i;

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_poll(rpcs, fds, nfds, timeout);
    if (rc < 0)
        TEST_VERDICT("poll() failed with errno %r on %s",
                     RPC_ERRNO(rpcs), rpcs->name);
    else if (rc == 0)
        TEST_VERDICT("poll() reported no events on %s",
                     rpcs->name);
    else if (rc > 1)
        TEST_VERDICT("poll() reported events on more than "
                     "one socket on %s", rpcs->name);

    for (i = 0; i < nfds; i++)
    {
        if (fds[i].revents != RPC_POLLIN &&
            fds[i].revents != 0)
            TEST_VERDICT("poll() reported unexpected events on %s",
                         rpcs->name);
    }
}

int
main(int argc, char *argv[])
{
    tapi_env_net    *net = NULL;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr_storage iut_bind_addr;

    cfg_handle tst_addr_handles[MAX_ATTEPTS];

    rpc_socket_type   sock_type;
    te_bool           wildcard;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int iut_acc = -1;
    int tst_s = -1;

    struct rpc_pollfd fds[SOCK_NUM];
    te_bool           sock_received[SOCK_NUM];

    char    snd_buf[SOCKTS_MSG_DGRAM_MAX];
    char    rcv_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t  send_len;

    int i = 0;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(wildcard);

    for (i = 0; i < SOCK_NUM; i++)
        sock_received[i] = FALSE;

    for (i = 0; i < MAX_ATTEPTS; i++)
        tst_addr_handles[i] = CFG_HANDLE_INVALID;

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);
    if (wildcard)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    TEST_STEP("Create two sockets on IUT.");

    iut_s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);

    iut_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);

    TEST_STEP("Bind the first socket.");
    rpc_bind(pco_iut, iut_s1, SA(&iut_bind_addr));

    TEST_STEP("Enable SO_REUSEPORT on the first socket.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_REUSEPORT, 1);
    if (rc < 0)
    {
        RING_VERDICT("setsockopt(SO_REUSEPORT) failed for already "
                     "bound socket with errno %r", RPC_ERRNO(pco_iut));
        TEST_SUCCESS;
    }

    TEST_STEP("Enable SO_REUSEPORT on the second socket.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEPORT, 1);
    if (rc < 0)
        TEST_VERDICT("setsockopt(SO_REUSEPORT) failed for "
                     "the second socket, errno %r", RPC_ERRNO(pco_iut));

    TEST_STEP("Bind the second socket to the same address.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s2, SA(&iut_bind_addr));
    if (rc < 0)
    {
        RING_VERDICT("Failed to bind the second socket "
                     "to the same address and port, errno %r",
                     RPC_ERRNO(pco_iut));
        TEST_SUCCESS;
    }

    TEST_STEP("If @p sock_type is @c SOCK_STREAM, call listen() on TCP sockets.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_listen(pco_iut, iut_s1, SOCKTS_BACKLOG_DEF);
        if (rc < 0)
        {
            RING_VERDICT("listen() failed for the first socket, errno %r",
                         RPC_ERRNO(pco_iut));
            TEST_SUCCESS;
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_listen(pco_iut, iut_s2, SOCKTS_BACKLOG_DEF);
        if (rc < 0)
        {
            RING_VERDICT("listen() failed for the second socket, errno %r",
                         RPC_ERRNO(pco_iut));
            TEST_SUCCESS;
        }
    }

    memset(fds, 0, sizeof(fds));
    fds[0].fd = iut_s1;
    fds[0].events = RPC_POLLIN;
    fds[1].fd = iut_s2;
    fds[1].events = RPC_POLLIN;

    TEST_STEP("In a loop until both sockets accept connection or datagram:");

    for (i = 0; i < MAX_ATTEPTS; i++)
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCK_STREAM, create TCP socket "
                         "on Tester, connect it to IUT, poll the listeners, accept "
                         "connection on one of them, check that data can be "
                         "transmitted in both directions.");
            tst_s = rpc_socket(pco_tst,
                               rpc_socket_domain_by_addr(tst_addr),
                               sock_type, RPC_PROTO_DEF);

            RPC_AWAIT_ERROR(pco_tst);
            rc = rpc_connect(pco_tst, tst_s, iut_addr);
            if (rc < 0)
                TEST_VERDICT("connect() on Tester failed with errno %r",
                             RPC_ERRNO(pco_tst));

            call_check_poll(pco_iut, fds, SOCK_NUM, POLL_TIMEOUT);

            if (fds[0].revents != 0)
            {
                iut_acc = rpc_accept(pco_iut, iut_s1, NULL, NULL);
                sock_received[0] = TRUE;
            }
            else
            {
                iut_acc = rpc_accept(pco_iut, iut_s2, NULL, NULL);
                sock_received[1] = TRUE;
            }

            sockts_test_connection(pco_iut, iut_acc,
                                   pco_tst, tst_s);

            RPC_CLOSE(pco_iut, iut_acc);
        }
        else
        {
            TEST_SUBSTEP("If @p sock_type is @c SOCK_DGRAM, create UDP socket "
                         "on Tester, bind it to a new IP address, send data to "
                         "IUT from it, poll the UDP sockets on IUT, receive "
                         "data on one of them.");

            tst_s = reuseport_create_tst_udp_sock(pco_tst, tst_if, net,
                                                  NULL,
                                                  &tst_addr_handles[i]);

            te_fill_buf(snd_buf, SOCKTS_MSG_DGRAM_MAX);
            send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
            rc = rpc_sendto(pco_tst, tst_s, snd_buf, send_len, 0, iut_addr);
            if (rc != (int)send_len)
                TEST_FAIL("sendto() returned unexpected result on Tester");

            call_check_poll(pco_iut, fds, SOCK_NUM, POLL_TIMEOUT);

            if (fds[0].revents != 0)
            {
                rc = rpc_recv(pco_iut, iut_s1, rcv_buf,
                              SOCKTS_MSG_DGRAM_MAX, 0);
                sock_received[0] = TRUE;
            }
            else
            {
                rc = rpc_recv(pco_iut, iut_s2, rcv_buf,
                              SOCKTS_MSG_DGRAM_MAX, 0);
                sock_received[1] = TRUE;
            }

            if (rc != (int)send_len ||
                memcmp(snd_buf, rcv_buf, send_len) != 0)
                TEST_VERDICT("Wrong data was received on IUT socket");
        }

        RPC_CLOSE(pco_tst, tst_s);

        if (sock_received[0] && sock_received[1])
            break;
    }

    if (!(sock_received[0] && sock_received[1]))
        TEST_VERDICT("Some of the sockets bound to the same IUT "
                     "address have not received anything from peer");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_acc);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    for (i = MAX_ATTEPTS - 1; i >= 0; i--)
    {
        if (tst_addr_handles[i] != CFG_HANDLE_INVALID)
        {
            CHECK_RC(cfg_del_instance(tst_addr_handles[i],
                                      FALSE));
            CFG_WAIT_CHANGES;
        }
    }

    TEST_END;
}
