/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page multicast-mcast_bond Checking multicast data receiving via bond interface
 *
 * @objective Check that socket joined multicast group on a bond interface
 *            can receive data only via its slaves
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_if1       The first interface on IUT
 * @param iut_if2       The second interface on IUT
 * @param tst1_addr     Address assigned to the first
 *                      interface on TESTER
 * @param mcast_addr    Multicast address
 * @param mode          Value of "mode" parameter of
 *                      bonding module
 * @param method        Multicast group joining method
 * @param sock_func     Socket creation function
 *
 * @par Test sequence:
 *  -# Create bonding interface enslaving @p iut_if1 and
 *     @p iut_if2.
 *  -# Create @p iut_s socket of @p sock_type type on
 *     IUT, bind it to the wildcard address with the same
 *     port as in @p mcast_addr address and join it to
 *     @p mcast_addr multicast group on this interface.
 *  -# Create @p tst_s socket of @p sock_type type on
 *     TESTER, bind it to @p tst1_addr.
 *  -# Establish a connection between created pair of sockets.
 *  -# Send data from @p tst_s and check that it can be
 *     received from @p iut_s.
 *  -# Delete @p iut_if1 from the bonding interface;
 *     check that we can no longer receive from @p iut_s
 *     socket multicast packets sent from @p tst_s socket.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_bond"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg_aggr.h"
#include "te_ethernet.h"
#include "mcast_lib.h"
#include "multicast.h"

#define MAX_CMD  255
#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct if_nameindex  *tst1_if = NULL;
    int                         bond_ifindex = -1;
    char                       *bond_ifname = NULL;
    struct sockaddr            *bond_addr = NULL;
    cfg_handle                  bond_addr_handle = CFG_HANDLE_INVALID;
    char                       *bond_aux_ifname = NULL;
    struct sockaddr            *bond_aux_addr = NULL;
    cfg_handle                  bond_aux_addr_handle = CFG_HANDLE_INVALID;
    struct sockaddr             bind_addr;
    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *tst1_addr = NULL;
    tapi_env_net               *net1 = NULL; 
    const char                 *mode = NULL;
    tarpc_joining_method        method;
    sockts_socket_func          sock_func;
    struct tarpc_mreqn          mreq;

    char            tx_buf[BUF_SIZE];
    char            rx_buf[BUF_SIZE];
    char            oid[CFG_OID_MAX];
    uint8_t         mac[ETHER_ADDR_LEN];
    int             iut_s = -1;
    int             tst_s = -1;
    socklen_t       namelen = 0;
    te_bool         is_readable = FALSE;
    te_bool         bond_created = FALSE;
    te_bool         bond_aux_created = FALSE;
    te_bool         first_added = FALSE;
    te_bool         second_added = FALSE;
    te_bool         aux_added = FALSE;

    TEST_START;

    TEST_GET_NET(net1);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_STRING_PARAM(mode);
    TEST_GET_MCAST_METHOD(method);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    CHECK_RC(tapi_cfg_aggr_create_bond(
                            pco_iut->ta, "my_bond", &bond_ifname, mode));
    bond_created = TRUE;

    if (strcmp(mode, "team4") == 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_tst);
        CHECK_RC(tapi_cfg_aggr_create_bond(
                                pco_tst->ta, "my_aux_bond",
                                &bond_aux_ifname, mode));
        bond_aux_created = TRUE;

        snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s", pco_tst->ta,
                 tst1_if->if_name);
        CHECK_RC(tapi_cfg_base_if_get_mac(oid, mac));
        snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s", pco_tst->ta,
                 bond_aux_ifname);
        CHECK_RC(tapi_cfg_base_if_set_mac(oid, mac));
        memset(oid, 0, sizeof(oid));
        memset(mac, 0, sizeof(mac));

        snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s", pco_tst->ta,
                 bond_aux_ifname);
        CHECK_RC(tapi_env_allocate_addr(
                        net1,
                        domain_rpc2h(rpc_socket_domain_by_addr(tst1_addr)),
                        &bond_aux_addr, NULL));
        CHECK_RC(tapi_cfg_base_add_net_addr(oid, bond_aux_addr,
                                            net1->ip4pfx,
                                            TRUE,
                                            &bond_aux_addr_handle));
        te_sockaddr_set_port(SA(bond_aux_addr),
                        *(te_sockaddr_get_port_ptr(SA(tst1_addr))));
        CHECK_RC(tapi_cfg_base_if_up(pco_tst->ta, bond_aux_ifname));

        CHECK_RC(tapi_cfg_aggr_bond_enslave(pco_tst->ta, "my_aux_bond",
                                            tst1_if->if_name));
        aux_added = TRUE;
    }

    snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s", pco_iut->ta, 
             iut_if1->if_name);
    CHECK_RC(tapi_cfg_base_if_get_mac(oid, mac));
    snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s", pco_iut->ta, 
             bond_ifname);
    CHECK_RC(tapi_cfg_base_if_set_mac(oid, mac));

    snprintf(oid, CFG_OID_MAX, "/agent:%s/interface:%s", pco_iut->ta, 
            bond_ifname);
    CHECK_RC(tapi_env_allocate_addr(
                        net1,
                        domain_rpc2h(rpc_socket_domain_by_addr(tst1_addr)),
                        &bond_addr, NULL));
    CHECK_RC(tapi_cfg_base_add_net_addr(oid, bond_addr, net1->ip4pfx, 
                                        TRUE, &bond_addr_handle));
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, bond_ifname));

    CHECK_RC(tapi_cfg_aggr_bond_enslave(pco_iut->ta, "my_bond",
                                        iut_if1->if_name));
    first_added = TRUE;
    CHECK_RC(tapi_cfg_aggr_bond_enslave(pco_iut->ta, "my_bond",
                                        iut_if2->if_name));
    second_added = TRUE;

    /* Make sure that all interfaces are up (see ST-2260) */
    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if1->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if2->if_name));
    CHECK_RC(sockts_wait_for_if_up(pco_iut, bond_ifname));

    iut_s = sockts_socket(sock_func, pco_iut,
                          rpc_socket_domain_by_addr(bond_addr), SOCK_DGRAM,
                          RPC_PROTO_DEF);
    memcpy(&bind_addr, mcast_addr, sizeof(bind_addr));
    te_sockaddr_set_wildcard(&bind_addr);
    rpc_bind(pco_iut, iut_s, &bind_addr);
    namelen = sizeof(*bond_addr);
    rpc_getsockname(pco_iut, iut_s, bond_addr, &namelen);

    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst1_addr), SOCK_DGRAM,
                       RPC_PROTO_DEF);
    if (strcmp(mode, "team4") == 0)
        rpc_bind(pco_tst, tst_s, bond_aux_addr);
    else
        rpc_bind(pco_tst, tst_s, tst1_addr);

    bond_ifindex = rpc_if_nametoindex(pco_iut, bond_ifname);
    if (rpc_mcast_join(pco_iut, iut_s,  mcast_addr, bond_ifindex,
                       method) < 0)
        TEST_VERDICT("Socket on IUT cannot join multicast group on "
                     "bond interface");

    memset(&mreq, 0, sizeof(mreq));    
    mreq.type = OPT_MREQN;
    if (strcmp(mode, "team4") == 0)
        mreq.ifindex = rpc_if_nametoindex(pco_tst, bond_aux_ifname);
    else
        mreq.ifindex = tst1_if->if_index;
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    rpc_sendto(pco_tst, tst_s, tx_buf, BUF_SIZE, 0, mcast_addr);
    TAPI_WAIT_NETWORK;
    RPC_GET_READABILITY(is_readable, pco_iut, iut_s, 1);
    if (!is_readable)
        TEST_VERDICT("Data cannot be received from a socket bound to "
                     "the bond interface");
    rc = rpc_recv(pco_iut, iut_s, rx_buf, BUF_SIZE, 0);
    if (rc != BUF_SIZE || memcmp(tx_buf, rx_buf, BUF_SIZE) != 0)
        TEST_VERDICT("Incorrect data was received from a peer");

    CHECK_RC(tapi_cfg_aggr_bond_free_slave(pco_iut->ta, "my_bond",
                                           iut_if1->if_name));
    first_added = FALSE;
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta, iut_if1->if_name));
    TAPI_WAIT_NETWORK;
    rpc_sendto(pco_tst, tst_s, tx_buf, BUF_SIZE, 0, mcast_addr);
    RPC_GET_READABILITY(is_readable, pco_iut, iut_s, 1);
    if (is_readable)
        TEST_VERDICT("Data can still be received on a socket bound "
                     "to the bond interface after removing the first "
                     "interface from it");

    if (rpc_mcast_leave(pco_iut, iut_s,  mcast_addr, bond_ifindex,
                       method) < 0)
        TEST_VERDICT("Socket on IUT cannot leave multicast group on "
                     "bond interface");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (bond_addr_handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(bond_addr_handle, FALSE));
    free(bond_addr);
    free(bond_ifname);

    if (bond_aux_addr_handle != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(cfg_del_instance(bond_aux_addr_handle, FALSE));
    free(bond_aux_addr);
    free(bond_aux_ifname);

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

    if (bond_aux_created)
    {
        if (aux_added)
        {
            CLEANUP_CHECK_RC(
                    tapi_cfg_aggr_bond_free_slave(pco_tst->ta,
                                                  "my_aux_bond",
                                                  tst1_if->if_name));
            CLEANUP_CHECK_RC(tapi_cfg_base_if_up(pco_tst->ta,
                                                 tst1_if->if_name));
        }
        CLEANUP_CHECK_RC(tapi_cfg_aggr_destroy_bond(
                                            pco_tst->ta, "my_aux_bond"));
    }
    TEST_END;
}
