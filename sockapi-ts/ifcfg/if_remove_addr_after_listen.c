/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_remove_addr_after_listen Remove IP address while there is a listener socket
 *
 * @objective Check that there are no changes in the socket API return
 *            values if local address is removed, a connection can be
 *            accepted when the address is back.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "ifcfg/if_remove_addr_after_listen"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_hwaddr = NULL;
    tapi_env_net          *net1;
    struct sockaddr       *iut_addr;
    cfg_handle             iut_addr_handle = CFG_HANDLE_INVALID;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    te_bool added_arp = FALSE;
    int iut_s = -1;
    int tst_s = -1;
    int acc_s = -1;
    int req_val;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net1);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(iut_hwaddr);

    TEST_STEP("Add IP address on IUT interface.");
    CHECK_RC(tapi_env_allocate_addr(net1, AF_INET, &iut_addr, NULL));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Add static ARP to IUT interface on tester.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, CVT_HW_ADDR(iut_hwaddr),
                             TRUE));

    TEST_STEP("Create non-blocking TCP listener socket on IUT.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    req_val = TRUE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);
    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    tst_s = rpc_socket(pco_tst, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Delete added address from IUT interface.");
    CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
    iut_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    TEST_STEP("Block tester in connect() call.");
    pco_tst->op = RCF_RPC_CALL;
    rpc_connect(pco_tst, tst_s, iut_addr);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that no connections is accepted on IUT.");
    TAPI_CALL_CHECK_RC(pco_iut, accept, -1, RPC_EAGAIN, iut_s, NULL, NULL);

    TEST_STEP("Add the address back to IUT interface.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           iut_addr, net1->ip4pfx, FALSE,
                                           &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Finish connection establishment.");
    rpc_connect(pco_tst, tst_s, iut_addr);
    req_val = FALSE;
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    TEST_STEP("Accept socket on IUT.");
    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    TEST_STEP("Check data transmission in both directions.");
    sockts_test_connection(pco_iut, acc_s, pco_tst, tst_s);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(iut_addr_handle, FALSE));
        CFG_WAIT_CHANGES;
    }

    if (added_arp)
        CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta,
                                                  tst_if->if_name,
                                                  iut_addr));

    TEST_END;
}
