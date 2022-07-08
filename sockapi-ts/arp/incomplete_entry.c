/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 */

/** @page arp-incomplete_entry Incomplete entry in ARP cache
 *
 * @objective Check that ARP cache works fine with incomplete entry
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 * @param sock_type         Socket type
 *
 * @par Scenario:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "arp/incomplete_entry"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    struct sockaddr         tst_link_addr;
    struct sockaddr        *new_addr = NULL;
    cfg_handle              new_addr_handle = CFG_HANDLE_INVALID;
    tapi_env_net           *net = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    int iut_s = -1;
    int tst_s = -1;
    int iut_s_listener = -1;
    int tst_s_listener = -1;

    void  *tx_buf = NULL;
    size_t tx_buflen = 256;

    int        arp_flags = 0;
    te_bool    arp_entry_exist;

    csap_handle_t          arp_handle = CSAP_INVALID_HANDLE;
    unsigned int           arp_reqs;

    sockts_socket_type  sock_type;
    te_dbuf             iut_sent = TE_DBUF_INIT(0);

    /* Preambule */
    TEST_START;

    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    SOCKTS_GET_SOCK_TYPE(sock_type);

    /* Scenario */

    TEST_STEP("Allocate a new IP address @b new_addr from the same network "
              "as @p tst_addr, choosing it so that there is no neighbor "
              "entry on IUT for it yet.");

    sockts_alloc_addr_without_arp_entry(net, pco_iut,
                                        iut_if->if_name, &new_addr);
    CHECK_RC(tapi_allocate_set_port(pco_tst, new_addr));

    TEST_CHECK_ARP_ENTRY_IS_DELETED(pco_iut->ta, iut_if->if_name,
                                    new_addr);

    /* Prepare buffers */
    tx_buf = te_make_buf_by_len(tx_buflen);

    TEST_STEP("Create a socket of type @p sock_type on IUT, send a packet "
              "(or initiate connection) to @b new_addr. "
              "An incomplete ARP entry with address @b new_addr should "
              "appear.");

    iut_s = rpc_socket(pco_iut, RPC_AF_INET,
                       sock_type_sockts2rpc(sock_type), RPC_PROTO_DEF);

    START_ARP_FILTER_WITH_HDR(pco_tst->ta, tst_if->if_name,
                              NULL, NULL,
                              ARPOP_REQUEST,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              CVT_PROTO_ADDR(iut_addr), NULL,
                              NULL,  NULL,
                              0, arp_handle);

    switch (sock_type)
    {
        case SOCKTS_SOCK_UDP:
            rpc_connect(pco_iut, iut_s, new_addr);
            RPC_SEND(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0);
            break;

        case SOCKTS_SOCK_UDP_NOTCONN:
            RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0, new_addr);
            break;

        case SOCKTS_SOCK_TCP_ACTIVE:
            rpc_fcntl(pco_iut, iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, new_addr);
            if (rc >= 0)
                TEST_VERDICT("connect() to unknown address was successful");
            else if (RPC_ERRNO(pco_iut) != RPC_EINPROGRESS)
                TEST_VERDICT("connect() reported unexpected error %r",
                             RPC_ERRNO(pco_iut));
            break;

        default:
            TEST_FAIL("Unexpected socket type");
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Get ARP entry for @b new_addr on IUT - check that it is "
              "incomplete (!(arp_flags & ATF_COM)).");

    TEST_GET_ARP_ENTRY(pco_iut, new_addr, iut_if->if_name,
                       &tst_link_addr, arp_flags, arp_entry_exist);
    if (!arp_entry_exist || (arp_flags & ATF_COM))
    {
        TEST_VERDICT("Test expects to get incomplete ARP entry, "
                     "got %s which is not incomplete",
                     arp_entry_exist? "one" : "none");
    }

    TEST_STEP("Check that ARP request was sent from IUT.");

    STOP_ETH_FILTER(pco_tst->ta, arp_handle, arp_reqs);
    if (arp_reqs == 0)
        TEST_VERDICT("No ARP requests were detected on Tester");

    TEST_STEP("Close the IUT socket.");
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Add @b new_addr on @p tst_if interface on Tester.");
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                           new_addr, net->ip4pfx,
                                           TRUE, &new_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a pair of sockets on IUT and Tester according "
              "to @p sock_type. In case of TCP start nonblocking connection "
              "establishment; in case of UDP call @b send() or @b sendto() "
              "on IUT. Use @b new_addr as destination on IUT.");
    sockts_connection_begin(pco_iut, pco_tst, iut_addr, new_addr,
                            sock_type, &iut_s, &iut_s_listener,
                            &tst_s, &tst_s_listener, &iut_sent);

    TEST_STEP("In case of TCP, finish connection establishment. In case of "
              "UDP, receive a packet on Tester.");
    sockts_connection_end(pco_iut, pco_tst, iut_addr, new_addr,
                          sock_type, &iut_s, &iut_s_listener,
                          &tst_s, &tst_s_listener, &iut_sent);

    TEST_STEP("Get ARP entry for @b new_addr on IUT - check that it "
              "is complete.");

    CFG_WAIT_CHANGES;
    TEST_GET_ARP_ENTRY(pco_iut, new_addr, iut_if->if_name,
                       &tst_link_addr, arp_flags, arp_entry_exist);
    if (!arp_entry_exist || !(arp_flags & ATF_COM))
    {
        TEST_VERDICT("Test expects to get complete ARP entry, "
                     "got %s which is not complete",
                     arp_entry_exist? "one" : "none");
    }

    TEST_SUCCESS;

cleanup:

    /* Avoid TIME_WAIT socket on IUT in case of TCP */
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM)
        TAPI_WAIT_NETWORK;
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_listener);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_listener);
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, arp_handle));
    te_dbuf_free(&iut_sent);
    free(tx_buf);

    CLEANUP_CHECK_RC(cfg_del_instance(new_addr_handle, FALSE));
    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                              new_addr));
    free(new_addr);

    TEST_END;
}
