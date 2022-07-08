/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-recv_wrong_mac Receive a packet with wrong MAC
 *
 * @objective Check that a packet with wrong MAC but correct IP address
 *            is ignored.
 *
 * @type conformance
 *
 * @param env         Testing environment:
 *                    - @ref arg_types_env_peer2peer
 *                    - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type   Tested socket type:
 *                    - @c udp
 *                    - @c tcp_active
 *                    - @c tcp_passive
 *                    - @c tcp_passive_close
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/recv_wrong_mac"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

/* Maximum length of the sent packet */
#define MAX_PKT_LEN 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *alien_link_addr = NULL;
    const struct if_nameindex *tst_if = NULL;

    char send_buf[MAX_PKT_LEN];
    int send_len;
    te_bool readable;
    tarpc_linger opt_linger_val = {0};

    int iut_s = -1;
    int iut_l = -1;
    int tst_s = -1;

    sockts_socket_type sock_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Establish connection of type @p sock_type between IUT "
              "and Tester.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    /*
     * SO_LINGER is set for Tester socket so that it is closed immediately
     * even though sent packet is not acked.
     */
    opt_linger_val.l_onoff = 1;
    opt_linger_val.l_linger = 0;
    rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &opt_linger_val);

    TEST_STEP("Add neighbor entry with an alien MAC for @p iut_addr on "
              "Tester.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, alien_link_addr->sa_data,
                             TRUE));
    CFG_WAIT_CHANGES;

    send_len = rand_range(1, MAX_PKT_LEN);
    te_fill_buf(send_buf, send_len);

    TEST_STEP("Send a packet from Tester to IUT.");
    RPC_SEND(rc, pco_tst, tst_s, send_buf, send_len, 0);

    TEST_STEP("Check that IUT socket does not become readable.");
    RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
    if (readable)
    {
        TEST_VERDICT("IUT socket is readable after receiving packet with a "
                     "wrong Ethernet address");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
