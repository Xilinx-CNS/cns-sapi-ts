/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-bond_bind_remove Removing bond when there is a socket bound to it
 *
 * @objective Check that removing bonding is handled correctly when there
 *            is a socket bound to an address from bonding interface
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param iut_if1       The first interface on IUT
 * @param iut_if2       The second interface on IUT
 * @param mode          Value of "mode" parameter of
 *                      bonding module
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/bond_bind_remove"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg_aggr.h"
#include "te_ethernet.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    char                       *bond_ifname = NULL;
    struct sockaddr            *bond_addr = NULL;
    cfg_handle                  bond_addr_handle = CFG_HANDLE_INVALID;
    tapi_env_net               *net1 = NULL; 
    const char                 *mode = NULL;

    const struct sockaddr      *iut_addr1 = NULL;

    char            oid[CFG_OID_MAX];
    uint8_t         mac[ETHER_ADDR_LEN];
    int             iut_s = -1;
    te_bool         bond_created = FALSE;
    te_bool         first_added = FALSE;
    te_bool         second_added = FALSE;
    int             sock_created = FALSE;

    int             max_tries;
    te_bool         remove_slave = FALSE;
    te_bool         remove_bond = FALSE;
    const char     *restart_close_sock;

    TEST_START;

    TEST_GET_NET(net1);
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_STRING_PARAM(mode);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_INT_PARAM(max_tries);
    TEST_GET_BOOL_PARAM(remove_slave);
    TEST_GET_BOOL_PARAM(remove_bond);
    TEST_GET_STRING_PARAM(restart_close_sock);

    while((max_tries--) >= 0)
    {
        if (!bond_created)
        {
            CHECK_RC(tapi_cfg_aggr_create_bond(
                            pco_iut->ta, "my_bond", &bond_ifname, mode));
            bond_created = TRUE;

            snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s",
                     pco_iut->ta, iut_if1->if_name);
            CHECK_RC(tapi_cfg_base_if_get_mac(oid, mac));
            snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s",
                     pco_iut->ta, bond_ifname);
            CHECK_RC(tapi_cfg_base_if_set_mac(oid, mac));

            snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s",
                     pco_iut->ta, bond_ifname);
            CHECK_RC(tapi_env_allocate_addr(
                        net1,
                        domain_rpc2h(rpc_socket_domain_by_addr(iut_addr1)),
                        &bond_addr, NULL));
            CHECK_RC(tapi_cfg_base_add_net_addr(oid, bond_addr,
                                                net1->ip4pfx,
                                                TRUE,
                                                &bond_addr_handle));
            CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, bond_ifname));

            CHECK_RC(tapi_cfg_aggr_bond_enslave(pco_iut->ta, "my_bond",
                                                iut_if1->if_name));
            first_added = TRUE;
            CHECK_RC(tapi_cfg_aggr_bond_enslave(pco_iut->ta, "my_bond",
                                                iut_if2->if_name));
            second_added = TRUE;
        }
        else
        {
            CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, bond_ifname));
            TAPI_WAIT_NETWORK;
            if (!first_added)
            {
                CHECK_RC(tapi_cfg_aggr_bond_enslave(pco_iut->ta, "my_bond",
                                                    iut_if1->if_name));
                first_added = TRUE;
            }
        }
        if (!sock_created)
        {
            iut_s = rpc_socket(pco_iut,
                               rpc_socket_domain_by_addr(bond_addr),
                               SOCK_DGRAM, RPC_PROTO_DEF);
            sock_created = TRUE;
            rpc_bind(pco_iut, iut_s, bond_addr);
        }

        if (remove_slave)
        {
            CHECK_RC(tapi_cfg_aggr_bond_free_slave(pco_iut->ta, "my_bond",
                                                   iut_if1->if_name));
            first_added = FALSE;
            CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
            TAPI_WAIT_NETWORK;
        }

    if (remove_bond)
    {
        CLEANUP_CHECK_RC(cfg_del_instance(bond_addr_handle, FALSE));
        bond_addr_handle = CFG_HANDLE_INVALID;

        CLEANUP_CHECK_RC(tapi_cfg_aggr_destroy_bond(pco_iut->ta,
                                                    "my_bond"));
        bond_created = FALSE;
        TAPI_WAIT_NETWORK;
        free(bond_addr);
        free(bond_ifname);
    }
    else
    {
        CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta, bond_ifname));
        TAPI_WAIT_NETWORK;
    }

    if (strcmp(restart_close_sock, "restart") == 0)
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
    if (strcmp(restart_close_sock, "close") == 0)
        RPC_CLOSE(pco_iut, iut_s);
    if (strcmp(restart_close_sock, "none") != 0)
        sock_created = FALSE;
}

    TEST_SUCCESS;

cleanup:

    if (bond_addr_handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(bond_addr_handle, FALSE));
    if (bond_created)
    {
        if (first_added)
        {
            CLEANUP_CHECK_RC(
                    tapi_cfg_aggr_bond_free_slave(pco_iut->ta,
                                                  "my_bond",
                                                  iut_if1->if_name));
            CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta,
                                                 iut_if1->if_name));
        }
        if (second_added)
        {
            CLEANUP_CHECK_RC(
                    tapi_cfg_aggr_bond_free_slave(pco_iut->ta, "my_bond",
                                                  iut_if2->if_name));
            CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta,
                                                 iut_if2->if_name));
        }
        CLEANUP_CHECK_RC(tapi_cfg_aggr_destroy_bond(
                                            pco_iut->ta, "my_bond"));
    }

    TEST_END;
}
