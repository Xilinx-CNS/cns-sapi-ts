/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp_zero_window Zero window probes correctness
 *
 * @objective Check that zero window probes are made frequently enaugh
 *
 * @type Conformance, compatibility
 *
 *
 * @param pco_iut       PCO on IUT
 * @param cache_socket  If @c TRUE, create cached socket to be reused.
 *
 * @par Scenario:
 *
 * -# If @p cache_socket is @c TRUE, create cached socket in this case.
 * -# Create TCP connection between IUT and TST.
 * -# Send a lot of data from IUT to fill all buffers.
 * -# After some time, check that IUT sends zero window probes at least 
 *    every 60 seconds.
 * -# Read all data on TST and check its size.
 * -# Close created sockets.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tcp_zero_window"

#include "sockapi-test.h"
#include "tcp_test_macros.h"
#include "tapi_cfg.h"
#include "tapi_tcp.h"

#define TIME_WAIT           60
#define TIMEOUT_GET_DATA    5

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    int         iut_s = -1;
    int         tst_s = -1;
    te_bool     cache_socket;
    uint64_t    total_filled = 0;
    uint64_t    total_reveived = 0;

    unsigned int         packets = 0;

    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    csap_handle_t               tcp_csap = CSAP_INVALID_HANDLE;
    const struct if_nameindex  *tst_if = NULL;
    asn_value                  *pattern;
    te_bool                     force_ip6;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(cache_socket);

    force_ip6 = iut_addr->sa_family == AF_INET6 ? TRUE : FALSE;

    TEST_STEP("If @p cache_socket is @c TRUE - create cached socket.");
    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, -1,
                                TRUE, cache_socket);

    /* Scenario */
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);
    CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_tst->ta, 0,
                                         tst_if->if_name,
                                         TAD_ETH_RECV_DEF |
                                         TAD_ETH_RECV_NO_PROMISC,
                                         NULL, NULL,
                                         iut_addr->sa_family,
                                         TAD_SA2ARGS(tst_addr, iut_addr),
                                         &tcp_csap));
    rpc_overfill_buffers(pco_iut, iut_s, &total_filled);

    /* Catch zero window probes */
    SLEEP(TIME_WAIT);
    CHECK_RC(tapi_tcp_ip_pattern_gen(TRUE, force_ip6, 0, 0, FALSE, FALSE,
                                     &pattern));
    asn_free_subvalue(pattern, "0.pdus.0.#tcp.flags");
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tcp_csap, pattern,
                                   TIME_WAIT * 1000, 1,
                                   RCF_TRRECV_COUNT));
    rc = rcf_ta_trrecv_wait(pco_tst->ta, 0, tcp_csap, NULL, NULL,
                            &packets);
    if (rc != 0 || packets == 0)
    {
       TEST_FAIL("Failed to catch any TCP packets; rc = %r", rc); 
    }

    /* Receive data and check */
    CHECK_RC(rpc_simple_receiver(pco_tst, tst_s, 
                                 TIMEOUT_GET_DATA, 
                                 &total_reveived));
    if (total_reveived != total_filled)
    {
        TEST_FAIL("Sent %d bytes, received %d bytes", 
                  total_filled, total_reveived);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (tcp_csap != CSAP_INVALID_HANDLE)
        tapi_tad_csap_destroy(pco_tst->ta, 0, tcp_csap);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}

