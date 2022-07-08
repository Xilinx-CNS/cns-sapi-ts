/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * ARP table
 * 
 * $Id$
 */

/** @page arp-invalid_arp_request Invalid arp request shouldn't touch ARP table
 *
 * @objective Check that if sender protocol address in received ARP 
 *            request is broadcast/multicast, then corresponding ARP
 *            entry does not appear in ARP table.
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut         PCO on IUT on @p host1
 * @param pco_tst         PCO on TESTER on @p host2
 * @param host1_addr      host1 unicast address
 * @param bcast_addr      host1 broadcast address
 * @param mcast_addr      host1_multicast address
 * @param isbroad         @c TRUE/ @c FALSE test broadcast/multicast
 *                        
 * @par Test sequence:
 *
 * -# Send invalid ARP request for @p host1_addr, 
 *    use as sender protocol address acording to @p isbroad parameter (if
 *    it's @c TRUE use @p bcast_addr, else @p use mcast_addr).
 * -# Check that there is no ARP entry for @p bcast_addr or for
 *    @p mcast_addr (according to @p isbroad parameter), in @p host1.
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/invalid_arp_request"

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

int
main(int argc, char *argv[])
{
    tapi_env_host   *host1 = NULL;
    
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *mcast_addr = NULL;
    const struct sockaddr  *bcast_addr = NULL;
    const struct sockaddr  *host1_addr = NULL;

    const struct sockaddr  *host1_hwaddr = NULL;
    const struct sockaddr  *fake_hwaddr = NULL;

    const struct if_nameindex  *host1_if = NULL;
    const struct if_nameindex  *host2_if = NULL;

    te_bool                 isbroad;

    csap_handle_t           handle = CSAP_INVALID_HANDLE;
    unsigned int            frames_caught;

    te_bool err_verdict = FALSE;

    /* Preambule */
    TEST_START;
   
    TEST_GET_HOST(host1);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR_NO_PORT(mcast_addr);
    TEST_GET_ADDR_NO_PORT(bcast_addr);
    TEST_GET_ADDR(pco_iut, host1_addr);

    TEST_GET_LINK_ADDR(host1_hwaddr);
    TEST_GET_LINK_ADDR(fake_hwaddr);

    TEST_GET_IF(host1_if);
    TEST_GET_IF(host2_if);

    TEST_GET_BOOL_PARAM(isbroad);

    tapi_cfg_base_if_down(pco_iut->ta, host1_if->if_name);
    CFG_WAIT_CHANGES;
    tapi_cfg_base_if_up(pco_iut->ta, host1_if->if_name);
    CFG_WAIT_CHANGES;

    START_ARP_FILTER_WITH_HDR(pco_tst->ta, host2_if->if_name,
                              (uint8_t *)host1_hwaddr,
                              NULL,
                              ARPOP_REPLY,
                              TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                              CVT_PROTO_ADDR(host1_addr),
                              (uint8_t *)host1_hwaddr,
                              NULL,
                              NULL,
                              0, handle);
    /* Send invalid ARP request with broadcast address to host1 */
    START_ARP_SENDER(pco_tst->ta, host2_if->if_name, 
                     (uint8_t *)fake_hwaddr,
                     (isbroad) ? NULL : mac_broadcast,
                     ARPOP_REQUEST,
                     CVT_PROTO_ADDR(((isbroad) ? bcast_addr : mcast_addr)),
                     (uint8_t *)fake_hwaddr,
                     CVT_PROTO_ADDR(host1_addr),
                     NULL, 1, NULL);

    TAPI_WAIT_NETWORK;

    RING("Check about ARP entry with %s address",
         (isbroad) ? "broadcast" : "multicast");
    rc = tapi_cfg_get_neigh_entry(pco_iut->ta, host1_if->if_name,
                                  (isbroad) ? bcast_addr : mcast_addr,
                                  NULL, NULL, NULL);
    if (rc == 0)
    {
        ERROR_VERDICT("Test expected that ARP entry with %s address "
                      "doesn't exist",
                      (isbroad) ? "broadcast" : "multicast");
        err_verdict = TRUE;
        tapi_cfg_del_neigh_entry(pco_iut->ta, host1_if->if_name,
                                 (isbroad) ? bcast_addr : mcast_addr);
    }
    else if (rc != TE_RC(TE_CS, TE_ENOENT))
    {
        TEST_FAIL("Unexpected failure of tapi_cfg_get_neigh_entry(): %r",
                  rc);
    }

    STOP_ETH_FILTER(pco_tst->ta, handle, frames_caught);

    if (frames_caught != 0)
    {
        ERROR_VERDICT("IUT has sent ARP reply to %s requester",
                      (isbroad) ? "broadcast" : "multicast");
        err_verdict = TRUE;
    }

    if (err_verdict)
        TEST_FAIL("Test fails because of ERROR_VERDICT(s)");

    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, handle));
    TEST_END;
}
