/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/ip/frag_lost  
 * Sending FIN after write shutdown
 * 
 * $Id$
 */

/** @page tcp-shutdown_fin
 *
 * @objective Check that FIN is sent write shutdown.
 *
 * @param pco_iut       PCO on the IUT
 * @param pco_tst       Tester PCO
 * @param iut_s         Socket on @p pco_iut
 * @param tst_s         Socket on @p pco_tst
 * @param cache_socket  If @c TRUE, create cached socket to be reused.
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# If @p cache_socket is @c TRUE, create cached socket in this case.
 * -# Call shutdown(@p iut_s, @c SHUT_WR) on @p pco_iut.
 * -# Check that @p pco_iut sent FIN.
 *
 * @author James Hall <jhall@level5networks.com>
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/shutdown_fin"

#include "sockapi-test.h"
#include "tcp_test_macros.h"

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"



int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    
    int iut_s = -1;
    int tst_s = -1;
    
    csap_handle_t sniff_csap;
    int           sniff_sid;
    asn_value    *sniff_pattern;
    unsigned int  sniff_num = 0;

    te_bool cache_socket;
    te_bool force_ip6 = FALSE;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(cache_socket);

    if (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET6)
        force_ip6 = TRUE;

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    rcf_ta_create_session(pco_tst->ta, &sniff_sid);

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, sniff_sid,
        tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL, tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr), &sniff_csap));

    CHECK_RC(tapi_tcp_ip_segment_pattern(force_ip6, 0, 0,
                                         FALSE, TRUE,
                                         FALSE, FALSE,
                                         FALSE, TRUE,
                                         &sniff_pattern));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sniff_sid, sniff_csap, 
                                   sniff_pattern, TAD_TIMEOUT_INF, 1,
                                   RCF_TRRECV_COUNT));

    rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR); 

    rcf_ta_trrecv_stop(pco_tst->ta, sniff_sid, sniff_csap, 
                       NULL, NULL, &sniff_num);

    if (sniff_num == 0)
        TEST_FAIL("not FIN caught after shutdown!");

    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, sniff_sid,
                                             sniff_csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
