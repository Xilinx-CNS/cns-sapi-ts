/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * ARP table
 * 
 * $Id$
 */

/** @page arp-stale_entry ARP entry dissapear from ARP table because of timeout
 *
 * @objective Check that ARP entry dissapear from ARP cache because of timeout
 *
 * @type conformance
 *
 * @reference @ref COMER, chapter 5
 *
 * @param pco_iut       PCO on IUT on @p host1
 * @param pco_snd       PCO (IUT or TESTER) on @p host1
 * @param pco_rcv       PCO on TESTER on @p host2
 * @param host1_addr    IP address of @p host1 interface
 *                      attached to subnet @p host1-host2
 * @param host2_addr    IP address of @p host2 interface
 *                      attached to subnet @p host1-host2
 * @param available_time
 *                      Time after which ARP entry should dissapear.
 *                      Passed to test.
 *
 * @par Test sequence:
 * -# If there is @p host2_addr ARP entry in @p host1 ARP cache,
 *    delete it;
 * -# Send UDP datagram from @p pco_snd to @p pco_rcv -
 *    @p host2_addr ARP entry in @p host1 ARP table should
 *    appear;
 * -# Get @p host2_addr ARP entry on @p pco_iut.
 *    Check that it exists.
 * -# Wait for @p available_time;
 * -# Get @p host2_addr ARP entry on @p pco_iut.
 *    Check that it doesn't exist.
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/stale_entry"

#include <sys/time.h>
#include <time.h>

#include "sockapi-test.h"
#include "arp_test_macros.h"
#include "arp_send_recv.h"

int
main(int argc, char *argv[])
{
    int available_time;
    int i;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_snd = NULL;
    rcf_rpc_server         *pco_rcv = NULL;

    tapi_env_host          *host1 = NULL;

    const struct sockaddr  *host1_addr = NULL;
    const struct sockaddr  *host2_addr = NULL;

    const struct if_nameindex  *host1_if = NULL;

    cs_neigh_entry_state    state;
    te_bool                 is_static;


    /* Preambule */
    TEST_START;

    TEST_GET_HOST(host1);
    TEST_GET_IF(host1_if);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_snd);
    TEST_GET_PCO(pco_rcv);

    TEST_GET_ADDR(pco_iut, host1_addr);
    TEST_GET_ADDR(pco_rcv, host2_addr);
    TEST_GET_INT_PARAM(available_time);

    /* Scenario */
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, host1_if->if_name,
                                      host2_addr));

    CFG_WAIT_CHANGES;
    
    TEST_CHECK_ARP_ENTRY_IS_DELETED(pco_iut->ta, host1_if->if_name,
                                    host2_addr);

    TEST_PROVOKE_ARP_REQ(pco_rcv, pco_snd,
                         RPC_SOCK_DGRAM, host2_addr, host1_addr, TRUE);
    CFG_WAIT_CHANGES;

    if (tapi_cfg_get_neigh_entry(pco_iut->ta, host1_if->if_name, host2_addr,
                                 NULL, &is_static, &state) != 0)
    {
        TEST_FAIL("Failed to get ARP entry on IUT: "
                  "ARP entry obtained by sending datagram");
    }
    if (is_static)
        TEST_VERDICT("Unexpected static (permanent) ARP entry found");
    if (state != CS_NEIGH_REACHABLE)
        TEST_VERDICT("Dynamic ARP entry in unexpected state %s found",
                     cs_neigh_entry_state2str(state));

    i = 0;
#define SLEEP_STEP 20
    do {
        SLEEP(SLEEP_STEP);
        if (tapi_cfg_get_neigh_entry(pco_iut->ta,
                                     host1_if->if_name, host2_addr,
                                     NULL, &is_static, &state) != 0)
        {
            RING("ARP entry was removed after %d seconds", i * SLEEP_STEP);
            TEST_SUCCESS;
        }
        if (i * SLEEP_STEP % 60 == 0)
            rpc_system_ex(pco_iut, "ip neigh li dev %s", host1_if->if_name);
        i++;
    } while (i * SLEEP_STEP < available_time);

    if (tapi_cfg_get_neigh_entry(pco_iut->ta, host1_if->if_name, host2_addr,
                                 NULL, &is_static, &state) == 0)
    {
        TEST_VERDICT("%s ARP entry has not been removed from ARP table "
                     "after %d seconds. State is %s.",
                     is_static ? "Static" : "Dynamic", available_time,
                     cs_neigh_entry_state2str(state));
    }

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
