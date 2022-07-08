/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-many_recv_threads Sharing of the one socket by several threads for receive
 *
 * @objective Check that several threads may use a single socket for
 *            receiving.
 *
 * @type stress
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_tst
 *                      - @ref arg_types_env_peer2peer_lo
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_tst_ipv6
 *                      - @ref arg_types_env_peer2peer_lo_ipv6
 * @param func          Function to be used in the test to receive data:
 *                      - @ref arg_types_recv_func_with_flags
 * @param method        How to create a child RPC server:
 *                      - @c thread (create a thread)
 *                      - @c inherit (fork a new process)
 * @param use_wildcard  If @c TRUE, bind IUT socket to the
 *                      wildcard address.
 *
 * @par Scenario:
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/many_recv_threads"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"


#define DATA_BULK       1024  /**< Size of data to be sent */


static char rx_buf[DATA_BULK];


int
main(int argc, char *argv[])
{
    /* Environment variables */
    const char *func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_iut_aux = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const char             *method;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    int     sock_child = -1;
    ssize_t len;
    size_t  len1;
    size_t  len2;

    char *tx_buf1 = NULL;
    char *tx_buf2 = NULL;

    te_bool use_wildcard = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_STRING_PARAM(method);
    TEST_GET_BOOL_PARAM(use_wildcard);

    tx_buf1 = te_make_buf(1, DATA_BULK, &len1);
    tx_buf2 = te_make_buf(1, DATA_BULK, &len2);

    TEST_STEP("Create a pair of UDP sockets on IUT and Tester.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);

    if (strcmp(method, "inherit") == 0)
    {
        TEST_STEP("If @p method is @c inherit, fork a process "
                  "@b pco_iut_aux from @b pco_iut.");
        rpc_create_child_process_socket(method, pco_iut, iut_s,
                                        rpc_socket_domain_by_addr(iut_addr),
                                        RPC_SOCK_DGRAM,
                                        &pco_iut_aux, &sock_child);
    }
    else
    {
        TEST_STEP("If @p method is @c thread, create a thread "
                  "@b pco_iut_aux on @b pco_iut.");
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "IUT_thread",
                                              &pco_iut_aux));
        sock_child = iut_s;
    }

    TEST_STEP("Send two datagrams from the Tester socket.");
    RPC_SEND(rc, pco_tst, tst_s, tx_buf1, len1, 0);
    RPC_SEND(rc, pco_tst, tst_s, tx_buf2, len2, 0);

    TEST_STEP("Receive the first datagram with @p func on @b pco_iut.");
    RPC_AWAIT_ERROR(pco_iut);
    len = recv_by_func_ext(func, pco_iut, iut_s, RPC_SOCK_DGRAM,
                           rx_buf, sizeof(rx_buf), 0);

    SOCKTS_CHECK_RECV_EXT(pco_iut, tx_buf1, rx_buf, len1, len,
                          "Receiving the first datagram");

    memset(rx_buf, 0, sizeof(rx_buf));

    TEST_STEP("Receive the second datagram with @p func on "
              "@b pco_iut_aux.");
    RPC_AWAIT_ERROR(pco_iut_aux);
    len = recv_by_func_ext(func, pco_iut_aux, sock_child, RPC_SOCK_DGRAM,
                           rx_buf, sizeof(rx_buf), 0);
    SOCKTS_CHECK_RECV_EXT(pco_iut_aux, tx_buf2, rx_buf, len2, len,
                          "Receiving the second datagram");

    TEST_SUCCESS;

cleanup:

    if (pco_iut_aux != NULL)
    {
        if (strcmp(method, "thread") != 0)
        {
            /*
             * This will result in cleanup for Onload HLRX state
             * associated with socket.
             */
            CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s);
        }
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_aux));
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf1);
    free(tx_buf2);

    TEST_END;
}

