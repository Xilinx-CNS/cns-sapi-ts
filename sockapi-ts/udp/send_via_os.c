/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 */

/**
 * @page udp-send_via_os Sending datagrams via OS interface
 *
 * @objective Check sending of UDP packets through the OS interface
 *
 * @param env                   Test environment
 *                              - @ref arg_types_env_two_nets_iut_first
 *                              - @ref arg_types_env_two_nets_iut_first_ipv6
 * @param bind_socket           Bind socket or not
 * @param min_data_buf_len      Minimum size of transmit data buffer
 * @param max_data_buf_len      Maximum size of transmit data buffer
 *
 * @par Scenario:
 *
 * @author Timofey Alekseev <Timofey.Alekseev@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/send_via_os"

#include "sockapi-test.h"

/* Number of send calls to test */
#define TEST_NUM 3

#define SMALL_DGRAM_SIZE 1

static void
send_recv_check(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                int iut_s, int tst_s,
                void **tx_bufs, void **rx_bufs, size_t *buf_lens)
{
    int i;
    size_t rc;
    int received[TEST_NUM];

    /* Send small UDP packet to resolve ARP */
    RPC_SEND(rc, pco_iut, iut_s, tx_bufs[0], SMALL_DGRAM_SIZE, 0);
    rc = rpc_recv(pco_tst, tst_s, rx_bufs[0], SMALL_DGRAM_SIZE, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_bufs[0], rx_bufs[0], SMALL_DGRAM_SIZE, rc);

    for (i = 0; i < TEST_NUM; i++)
        RPC_SEND(rc, pco_iut, iut_s, tx_bufs[i], buf_lens[i], 0);

    for (i = 0; i < TEST_NUM; i++)
        received[i] = rpc_recv(pco_tst, tst_s, rx_bufs[i], buf_lens[i], 0);

    for (i = 0; i < TEST_NUM; i++)
    {
        SOCKTS_CHECK_RECV(pco_tst, tx_bufs[i], rx_bufs[i],
                          buf_lens[i], received[i]);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst1 = NULL;
    rcf_rpc_server            *pco_tst2 = NULL;
    const struct sockaddr     *iut_addr1;
    const struct if_nameindex *iut_if2;
    const struct if_nameindex *tst2_if;
    const struct sockaddr     *tst1_addr;
    const struct sockaddr     *tst2_addr;
    te_bool                    bind_socket;
    size_t                     min_data_buf_len;
    size_t                     max_data_buf_len;

    rpc_socket_domain  domain;
    void              *tx_bufs[TEST_NUM];
    void              *rx_bufs[TEST_NUM];
    size_t             buf_lengths[TEST_NUM];
    cfg_handle         ah = CFG_HANDLE_INVALID;

    int i;
    int iut_s  = -1;
    int tst1_s = -1;
    int tst2_s = -1;

    int so_rbuf;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst2_if);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_BOOL_PARAM(bind_socket);
    TEST_GET_INT_PARAM(min_data_buf_len);
    TEST_GET_INT_PARAM(max_data_buf_len);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    /*
     * Receive buffer size.
     * It must be greater than TEST_NUM maximum packet sizes.
     */
    so_rbuf = TEST_NUM * max_data_buf_len;

    for (i = 0; i < TEST_NUM; i++)
    {
        tx_bufs[i] = te_make_buf(min_data_buf_len, max_data_buf_len,
                                 &(buf_lengths[i]));
        rx_bufs[i] = te_make_buf_by_len(buf_lengths[i]);
    }

    TEST_STEP("Create UDP sockets @b iut_s on IUT, @b tst1_s on Tester1 and "
              "@b tst2_s on Tester2. Bind @b tst1_s to @p tst1_addr.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_create_and_bind_socket(pco_tst1, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                                        FALSE, FALSE, tst1_addr);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /* Setup receive buffer size due to need to receive many data */
    rpc_setsockopt_int(pco_tst1, tst1_s, RPC_SO_RCVBUF, so_rbuf);
    rpc_setsockopt_int(pco_tst2, tst2_s, RPC_SO_RCVBUF, so_rbuf);

    TEST_STEP("Bind @b iut_s to @p iut_addr1 if needed.");
    if (bind_socket)
        rpc_bind(pco_iut, iut_s, iut_addr1);

    TEST_STEP("Connect @b iut_s to @p tst1_addr.");
    rpc_connect(pco_iut, iut_s, tst1_addr);

    TEST_STEP("Send messages from @b iut_s, receive and check them on tst1_s.");
    send_recv_check(pco_iut, pco_tst1, iut_s, tst1_s, tx_bufs,
                       rx_bufs, buf_lengths);

    TEST_STEP("Change address on @p tst2_if to @p tst1_addr. "
              "Setup route to @p tst1_addr through @p iut_if2.");
    CHECK_RC(tapi_cfg_save_del_if_addresses(pco_tst2->ta,
                                            tst2_if->if_name,
                                            tst2_addr, FALSE,
                                            NULL, NULL, NULL, NULL,
                                            domain_rpc2h(domain)));

    /* Add  IP address to interface with /24 (IPv4) of /48 (IPv6) prefix */
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta, tst2_if->if_name,
                                           tst1_addr,
                                           domain == RPC_PF_INET ? 24 : 48,
                                           FALSE, &ah));

    CHECK_RC(tapi_cfg_add_route_simple(
                 pco_iut->ta, tst1_addr,
                 te_netaddr_get_size(tst1_addr->sa_family) * 8,
                 NULL, iut_if2->if_name));

    CFG_WAIT_CHANGES;

    TEST_STEP("Bind @b tst2_s to @p tst1_addr.");
    rpc_bind(pco_tst2, tst2_s, tst1_addr);

    TEST_STEP("Send messages from @b iut_s, receive and check them on tst2_s.");
    send_recv_check(pco_iut, pco_tst2, iut_s, tst2_s, tx_bufs,
                       rx_bufs, buf_lengths);

    TEST_SUCCESS;

cleanup:
    cfg_del_instance(ah, FALSE);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    for(i = 0; i < TEST_NUM; i++)
    {
        free(tx_bufs[i]);
        free(rx_bufs[i]);
    }

    TEST_END;
}
