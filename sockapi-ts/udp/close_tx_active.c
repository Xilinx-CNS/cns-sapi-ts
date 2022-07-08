/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Close UDP socket with TX queue is active.
 */

/**
 * @page udp-close_tx_active Close UDP socket with TX queue is active.
 *
 * @objective Perform close() or connect() to non-SFC destination on UDP socket
 *            with non-empty TX queue.
 *
 * @param env            Testing environment:
 *      - @ref arg_types_env_two_nets_iut_first
 * @param msg_num        Number of packets to send:
 *      - @c 10
 * @param disconnect_way How to perform disconnection - close or connect to non-
 *                       SFC destination:
 *      - close
 *      - exit
 *      - disconnect
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/close_tx_active"

#include "sockapi-test.h"
#include "tapi_mem.h"
#include "onload.h"
#include "tapi_route_gw.h"

#define MSG_LEN 60000

#define DISCONN_WAY_MAPPING_LIST \
    {"close", CLOSE},            \
    {"exit", EXIT},              \
    {"disconnect", DISCONNECT}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst1 = NULL;
    rcf_rpc_server              *pco_tst2 = NULL;
    const struct sockaddr       *iut_addr1;
    const struct sockaddr       *tst1_addr;
    const struct sockaddr       *tst2_addr;
    const struct if_nameindex   *tst2_if = NULL;
    const struct if_nameindex   *iut_if2 = NULL;

    int                 iut_s = -1;
    int                 tst1_s = -1;
    int                 tst2_s = -1;
    int                 msg_num = 0;
    tarpc_disconn_way   disconnect_way;
    te_bool             test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(tst2_if);
    TEST_GET_IF(iut_if2);
    TEST_GET_INT_PARAM(msg_num);
    TEST_GET_ENUM_PARAM(disconnect_way, DISCONN_WAY_MAPPING_LIST);

    TEST_STEP("If @p disconnect_way is @c DISCONNECT.");
    if (disconnect_way == DISCONNECT)
    {
        TEST_SUBSTEP("Add a route to deliver packets iut-tst2.");
        CHECK_RC(tapi_cfg_add_route(pco_tst2->ta,
                                    addr_family_rpc2h(
                                        sockts_domain2family(
                                            rpc_socket_domain_by_addr(iut_addr1))),
                                    te_sockaddr_get_netaddr(iut_addr1),
                                    te_netaddr_get_size(iut_addr1->sa_family) * 8,
                                    NULL, tst2_if->if_name, NULL,
                                    0, 0, 0, 0, 0, 0, NULL));
        /* We need to add IPv6 neighbors entries manually. See OL bug 9774. */
        if (iut_addr1->sa_family == AF_INET6)
        {
            CHECK_RC(tapi_update_arp(pco_tst2->ta, tst2_if->if_name,
                                     pco_iut->ta, iut_if2->if_name,
                                     iut_addr1, NULL, FALSE));
        }
        CFG_WAIT_CHANGES;
        TEST_SUBSTEP("Create socket on tst2.");
        if ((tst2_s = rpc_create_and_bind_socket(pco_tst2,
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                            FALSE, FALSE, tst2_addr)) < 0)
            TEST_VERDICT("Cannot create socket on tst2");
    }

    TEST_STEP("Create @c SOCK_DGRAM socket on IUT.");
    TEST_STEP("Connect it to tst1.");
    GEN_CONNECTION(pco_iut, pco_tst1, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr1, tst1_addr, &iut_s, &tst1_s);

    TEST_STEP("Call @ref rpc_sendmmsg_disconnect() to send @p msg_num messages "
              "60 kB each and then disconnect the socket.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendmmsg_disconnect(pco_iut, &iut_s, MSG_LEN, msg_num,
                                 disconnect_way, tst2_addr);

    TEST_STEP("Make sure @ref rpc_sendmmsg_disconnect() returned error.");
    if (rc != -1)
    {
        ERROR_VERDICT("sendmmsg() did not return error");
        test_failed = TRUE;
    }

    TEST_STEP("If @p disconnect_way is @c DISCONNECT");
    if (disconnect_way == DISCONNECT)
    {
        TEST_SUBSTEP("Check data transmission.");
        sockts_test_udp_sendto_bidir(pco_iut, iut_s, iut_addr1,
                                     pco_tst2, tst2_s, tst2_addr);
    }

    if (test_failed)
        TEST_STOP;
    else
        TEST_SUCCESS;

cleanup:
    if (iut_s > 0)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    TEST_END;
}
