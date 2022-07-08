/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Bind a socket to zero port with and without SO_REUSEPORT.
 */

/**
 * @page basic-reuseport_bind_zero_port Bind a socket to zero port.
 *
 * @objective Check that bind to zero port works correctly with SO_REUSEPORT
 *            option.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 * @param sock_type Socket type:
 *      - @c SOCK_STREAM
 *      - @c SOCK_DGRAM
 * @param wildcard  Whether to bind to wildcard address or not:
 *      - @c TRUE
 *      - @c FALSE
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/reuseport_bind_zero_port"

#include "sockapi-test.h"

/** Number of repeats for checking connection */
#define NUM_REPEAT 5
/** Number of listener sockets */
#define ONLOAD_CLUSTER_SIZE 2

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut;
    rcf_rpc_server        *pco_tst;
    rpc_socket_type        sock_type;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    te_bool                use_wildcard;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int tst_s = -1;
    int accept_sock = -1;
    int i;
    int init_cluster_sz;

    struct sockaddr_storage iut_listen_addr;
    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage tst_bind_addr;
    struct sockaddr_storage connect_addr;
    socklen_t               iut_listen_addr_len;

    void   *tx_buf = NULL;
    void   *rx_buf = NULL;
    size_t  tx_buf_len;
    size_t  rx_buf_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(use_wildcard);

    switch (sock_type)
    {
        case RPC_SOCK_DGRAM:
            tx_buf = sockts_make_buf_dgram(&tx_buf_len);
            break;

        case RPC_SOCK_STREAM:
            tx_buf = sockts_make_buf_stream(&tx_buf_len);
            break;

        default:
            TEST_FAIL("Incorrect socket type.");
    }
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    TEST_STEP("Set env EF_CLUSTER_SIZE to 2");
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                      ONLOAD_CLUSTER_SIZE,
                                      TRUE, NULL, &init_cluster_sz));

    TEST_STEP("On IUT create socket @b iut_s1 of type @p sock_type, "
              "setting @c SOCK_NONBLOCK flag for it.");
    iut_s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type | RPC_SOCK_NONBLOCK, RPC_PROTO_DEF);

    TEST_STEP("Set @c SO_REUSEPORT for @b iut_s1.");
    rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_REUSEPORT, 1);

    TEST_STEP("On IUT create socket @b iut_s2 of type @p sock_type, "
              "setting @c SOCK_NONBLOCK flag for it.");
    iut_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type | RPC_SOCK_NONBLOCK, RPC_PROTO_DEF);

    TEST_STEP("Set @c SO_REUSEPORT for @b iut_s2.");
    rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEPORT, 1);

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);
    tapi_sockaddr_clone_exact(iut_addr, &connect_addr);
    tapi_sockaddr_clone_exact(tst_addr, &tst_bind_addr);
    te_sockaddr_set_port(SA(&iut_bind_addr), 0);
    if (use_wildcard)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    TEST_STEP("Bind @b iut_s1 to @p iut_addr or wildcard address "
              "(if @p use_wildcard is @c TRUE) with zero port");
    rpc_bind(pco_iut, iut_s1, SA(&iut_bind_addr));

    TEST_STEP("Call @b getsockname() on @b iut_s1 and remember result as @b "
              "iut_listen_addr.");
    iut_listen_addr_len = sizeof(iut_listen_addr);
    rpc_getsockname(pco_iut, iut_s1, SA(&iut_listen_addr),
                    &iut_listen_addr_len);

    TEST_STEP("Bind @b iut_s2 to @b iut_listen_addr.");
    rpc_bind(pco_iut, iut_s2, SA(&iut_listen_addr));

    TEST_STEP("If @p sock_type is @c SOCK_STREAM call @b listen() on @b iut_s1 "
              "and @b iut_s2.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_iut, iut_s1, SOCKTS_BACKLOG_DEF);
        rpc_listen(pco_iut, iut_s2, SOCKTS_BACKLOG_DEF);
    }

    te_sockaddr_set_port(SA(&connect_addr),
                         te_sockaddr_get_port(SA(&iut_listen_addr)));

    TEST_STEP("Check that connection is working correctly 5 times");
    for (i = 0; i < NUM_REPEAT; i++)
    {
        TEST_STEP("Create @b tst_s on @p pco_tst and bind it to @p tst_addr.");
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           sock_type, RPC_PROTO_DEF);
        tapi_allocate_set_port(pco_tst, SA(&tst_bind_addr));
        rpc_bind(pco_tst, tst_s, SA(&tst_bind_addr));

        if (sock_type == RPC_SOCK_STREAM)
        {
            TEST_STEP("If @p sock_type is @c SOCK_STREAM try to establish connection "
                      "for TCP socket");

            TEST_SUBSTEP("Call @b connect() @b tst_s to @p iut_addr with port "
                         "from @b iut_listen_addr.");
            rpc_connect(pco_tst, tst_s, SA(&connect_addr));

            TEST_SUBSTEP("Check that connection can be accepted on @b iut_s1 or @b iut_s2");
            RPC_AWAIT_ERROR(pco_iut);
            accept_sock = rpc_accept4(pco_iut, iut_s1, NULL, NULL, RPC_SOCK_NONBLOCK);

            if (accept_sock == -1)
            {
                if (RPC_ERRNO(pco_iut) != RPC_EAGAIN &&
                    RPC_ERRNO(pco_iut) != RPC_EWOULDBLOCK)
                {
                        TEST_VERDICT("accept() failed with unexpected errno %r",
                                     RPC_ERRNO(pco_iut));
                }

                accept_sock = rpc_accept4(pco_iut, iut_s2, NULL, NULL, RPC_SOCK_NONBLOCK);
                if (accept_sock == -1)
                    TEST_VERDICT("Neither of listeners accepted connection");
            }

            TEST_SUBSTEP("Send and receive packet from @p pco_tst to @p pco_iut.");
            rpc_send(pco_tst, tst_s, tx_buf, tx_buf_len, 0);
            rc = rpc_recv(pco_iut, accept_sock, rx_buf, rx_buf_len, 0);
            SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buf_len, rc);

            RPC_CLOSE(pco_iut, accept_sock);
        }
        else
        {
            TEST_STEP("If @p sock_type is @c SOCK_DGRAM send packet from @b tst_s "
                      "to the address of IUT sockets; check that one of the sockets receives it");
            rpc_sendto(pco_tst, tst_s, tx_buf, tx_buf_len, 0, SA(&connect_addr));
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_recvfrom(pco_iut, iut_s1, rx_buf, rx_buf_len, 0, NULL, NULL);
            if (rc == -1)
            {
                if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                {
                    TEST_VERDICT("recfrom() failed with unexpected errno %r",
                                 RPC_ERRNO(pco_iut));
                }

                rc = rpc_recvfrom(pco_iut, iut_s2, rx_buf, rx_buf_len, 0, NULL, NULL);
                if (rc == -1)
                    TEST_VERDICT("Neither of sockets received data");
            }
            SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_buf_len, rc);
        }
        RPC_CLOSE(pco_tst, tst_s);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, accept_sock);
    free(rx_buf);
    free(tx_buf);
    CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                         init_cluster_sz, TRUE, TRUE));
    TEST_END;
}
