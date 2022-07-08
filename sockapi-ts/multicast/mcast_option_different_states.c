/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 * 
 * $Id$
 */

/** @page multicast-mcast_option_different_states Setting IP_MULTICAST_* options in different states
 *
 * @objective Check that options @c IP_MULTICAST_IF, @c IP_MULTICAST_TTL and
 *            @c IP_MULTICAST_LOOP can be changed at any socket state
 *            (fresh, binded, joined) in any order.
 *
 * @type conformance
 *
 * @param pco_iut1          PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Interface name/index on IUT
 * @param tst_if            Interface name/index on TESTER
 * @param mcast_addr        Multicast address used in the test
 * @param method            Method to join multicasting group
 * @param state             Socket state, it determines calls sequence
 * @param order             Determines options setting order
 * @param ip_multicast_loop Set IP_MULTICAST_LOOP to 0 if @c FALSE,
 *                          to 1 if it's @c TRUE
 * @param ip_multicast_ttl  Set IP_MULTICAST_TTL to 0 if @c FALSE,
 *                          to 1 if it's @c TRUE
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_option_different_states"

#include "sockapi-test.h"
#include "mcast_lib.h"
#include "multicast.h"

/**
 * Enumeration to determine calls sequence.
 */
typedef enum {
    STATE_FRESH = 0,     /**< Set options immediately after socket
                              creation */
    STATE_BINDED,        /**< Set options after binding */
    STATE_JOINED,        /**< Set options after joining to multicast
                              group */
} socket_state_type;

#define SOCKET_STATE  \
    { "fresh", STATE_FRESH },   \
    { "binded", STATE_BINDED }, \
    { "joined", STATE_JOINED }

/**
 * Enumeration to determine setting options order.
 */
typedef enum {
    ORDER_TTL_FIRST = 0,    /**< Set IP_MULTICAST_TTL option first */
    ORDER_LOOP_FIRST,       /**< Set IP_MULTICAST_LOOP option first */
    ORDER_IF_FIRST,         /**< Set IP_MULTICAST_IF option first */
} options_order_type;

#define OPTIONS_ORDER  \
    { "ttl_first", ORDER_TTL_FIRST },   \
    { "loop_first", ORDER_LOOP_FIRST }, \
    { "if_first", ORDER_IF_FIRST }

/**
 * Set socket options.
 * 
 * @param rpcs               RPC server
 * @param sock               Socket descriptor
 * @param iut_addr           IUT address to determine multicast interface
 * @param order              Determines setting options order
 * @param ip_multicast_loop  IP_MULTICAST_LOOP option value
 * @param ip_multicast_ttl   IP_MULTICAST_TTL option value
 */
static void
test_set_opt(rcf_rpc_server *rpcs, int sock,
             const struct sockaddr *iut_addr, options_order_type order,
             int ip_multicast_loop, int ip_multicast_ttl)
{
    switch (order)
    {
        case ORDER_TTL_FIRST:
            rpc_setsockopt_int(rpcs, sock, RPC_IP_MULTICAST_TTL,
                               ip_multicast_ttl);
            rpc_setsockopt_int(rpcs, sock, RPC_IP_MULTICAST_LOOP,
                               ip_multicast_loop);
            set_ip_multicast_if(rpcs, sock, iut_addr);
            break;

        case ORDER_LOOP_FIRST:
            rpc_setsockopt_int(rpcs, sock, RPC_IP_MULTICAST_LOOP,
                               ip_multicast_loop);
            rpc_setsockopt_int(rpcs, sock, RPC_IP_MULTICAST_TTL,
                               ip_multicast_ttl);
            set_ip_multicast_if(rpcs, sock, iut_addr);
            break;

        case ORDER_IF_FIRST:
            set_ip_multicast_if(rpcs, sock, iut_addr);
            rpc_setsockopt_int(rpcs, sock, RPC_IP_MULTICAST_LOOP,
                               ip_multicast_loop);
            rpc_setsockopt_int(rpcs, sock, RPC_IP_MULTICAST_TTL,
                               ip_multicast_ttl);
            break;

        default:
            TEST_FAIL("Unexpected order value: %d", order);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut1    = NULL;
    rcf_rpc_server            *pco_iut2    = NULL;
    rcf_rpc_server            *pco_tst    = NULL;
    const struct if_nameindex *iut_if     = NULL;
    const struct if_nameindex *tst_if     = NULL;
    const struct sockaddr     *iut_addr   = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    struct sockaddr            wild_addr;
    tarpc_joining_method       method;
    socket_state_type          state;
    options_order_type         order;
    mcast_listener_t           listener  = CSAP_INVALID_HANDLE;    
    cmp_results_type           rx_res[2] = {{FALSE, FALSE}, };
    cmp_results_type           tx_res = {FALSE, FALSE};
    cmp_results_type           tst_res = {FALSE, FALSE};
    te_bool                    ip_multicast_loop = FALSE;
    te_bool                    ip_multicast_ttl = FALSE;
    sockts_socket_func         sock_func;

    int     iut_tx_s;
    int     iut_rx_s1;
    int     iut_rx_s2;
    int     tst_s;
    char   *sendbuf;
    size_t  buflen;
    int     ef_mcast_send = 0;

    TEST_START;

    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_ADDR(pco_iut1, mcast_addr);
    TEST_GET_ADDR(pco_tst, iut_addr);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_ENUM_PARAM(state, SOCKET_STATE);
    TEST_GET_ENUM_PARAM(order, OPTIONS_ORDER);
    TEST_GET_BOOL_PARAM(ip_multicast_loop);
    TEST_GET_BOOL_PARAM(ip_multicast_ttl);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    sendbuf = sockts_make_buf_dgram(&buflen);

    TEST_STEP("Set EF_MCAST_SEND env to enable loopback transmission.");
    rc = tapi_sh_env_get_int(pco_iut1, "EF_MCAST_SEND", &ef_mcast_send);
    if (rc != 0)
        ef_mcast_send = -1;
    CHECK_RC(tapi_sh_env_set_int(pco_iut1, "EF_MCAST_SEND", 3, TRUE, TRUE));

    TEST_STEP("Create socket to transmit multicast packets.");
    iut_tx_s = sockts_socket(sock_func, pco_iut1,
                             rpc_socket_domain_by_addr(mcast_addr),
                             RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    TEST_STEP("If @p state is @c STATE_FRESH set the multicast socket options.");
    if (state == STATE_FRESH)
        test_set_opt(pco_iut1, iut_tx_s, iut_addr, order, ip_multicast_loop,
                     ip_multicast_ttl);

    TEST_STEP("Bind the socket to wildcard address");
    rpc_setsockopt_int(pco_iut1, iut_tx_s, RPC_SO_REUSEADDR, 1);
    memcpy(&wild_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(&wild_addr);
    rpc_bind(pco_iut1, iut_tx_s, &wild_addr);

    TEST_STEP("If @p state is @c STATE_BINDED set the multicast socket options.");
    if (state == STATE_BINDED)
        test_set_opt(pco_iut1, iut_tx_s, iut_addr, order, ip_multicast_loop,
                     ip_multicast_ttl);

    TEST_STEP("Bind the socket to the multicast group.");
    rpc_mcast_join(pco_iut1, iut_tx_s, mcast_addr, iut_if->if_index,
                   method);

    TEST_STEP("If @p state is @c STATE_JOINED set the multicast socket options.");
    if (state == STATE_JOINED)
        test_set_opt(pco_iut1, iut_tx_s, iut_addr, order, ip_multicast_loop,
                     ip_multicast_ttl);

    TEST_STEP("Create one socket on the same IUT process, one on other IUT process "
              "and one on tester, bind them and join to multicast group to receive "
              "packets.");
    iut_rx_s1 = create_joined_socket_ext(sock_func, pco_iut1, iut_if,
                                         mcast_addr, mcast_addr, method);
    iut_rx_s2 = create_joined_socket_ext(sock_func, pco_iut2, iut_if,
                                         mcast_addr, mcast_addr, method);
    tst_s = create_joined_socket(pco_tst, tst_if, mcast_addr, mcast_addr,
                                 method);

    TEST_STEP("Multicast listener to make sure that packets are accelerated.");
    listener = mcast_listener_init(pco_iut1, iut_if, mcast_addr, NULL, 0);
    mcast_listen_start(pco_iut1, listener);

    TEST_STEP("Send multicast packet.");
    rpc_sendto(pco_iut1, iut_tx_s, sendbuf, buflen, 0, mcast_addr);

    TEST_STEP("Check packets readability and read them.");
    tx_res.got = read_check_pkt(pco_iut1, iut_tx_s, sendbuf, buflen);
    rx_res[0].got = read_check_pkt(pco_iut1, iut_rx_s1, sendbuf, buflen);
    rx_res[1].got = read_check_pkt(pco_iut2, iut_rx_s2, sendbuf, buflen);
    tst_res.got = read_check_pkt(pco_tst, tst_s, sendbuf, buflen);

    TEST_STEP("Stop multicast listener, check that no packets received.");
    if (mcast_listen_stop(pco_iut1, listener, NULL) != 0)
        RING_VERDICT("System detects multicast packets, acceleration is "
                     "not achieved");

    TEST_STEP("IUT transmitter process should not receive packets if "
              "IP_MULTICAST_LOOP set to @c 0.");
    if (ip_multicast_loop)
        tx_res.exp = rx_res[0].exp = TRUE;

    TEST_STEP("IUT process @p pco_iut2 transmitter process should not receive "
              "packets if IP_MULTICAST_TTL set to @c 0.");
    if (ip_multicast_ttl)
        rx_res[1].exp = TRUE;

    if (tx_res.got != rx_res[0].got)
        RING_VERDICT("Two sockets, which share stack, have different "
                     "reading results");

    TEST_STEP("Tester should receive packets if ttl > 0");
    if (ip_multicast_ttl)
        tst_res.exp = TRUE;

    TEST_STEP("Compare expected results with actual obtained");
    cmp_exp_results(&tx_res, "Transmitter");
    cmp_exp_results(rx_res, "First receiver");
    cmp_exp_results(rx_res + 1, "Second receiver");
    cmp_exp_results(&tst_res, "Tester receiver");

    TEST_SUCCESS;
cleanup:
    mcast_listener_fini(pco_iut1, listener);

    CLEANUP_RPC_CLOSE(pco_iut1, iut_tx_s);
    CLEANUP_RPC_CLOSE(pco_iut1, iut_rx_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_rx_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (ef_mcast_send != -1)
    {
        CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut1, "EF_MCAST_SEND",
                                             ef_mcast_send, TRUE, TRUE));
    }
    else
    {
        CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut1, "EF_MCAST_SEND", TRUE,
                                           TRUE));
    }

    TEST_END;
}
