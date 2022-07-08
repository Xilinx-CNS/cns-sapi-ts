/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP
 */

/**
 * @page udp-check_double_bind Check UDP traffic after double bind
 *
 * @objective Check incoming UDP traffic after double bind
 *
 * @par Scenario:
 *
 * @author Anton Protasov <Anton.Protasov@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/check_double_bind"

#include "sockapi-test.h"
#include "tapi_udp.h"
#include "tapi_cfg.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    int                         iut_s = -1;
    int                         tst_s = -1;

    const struct sockaddr      *iut_addr;
    const struct sockaddr      *tst_addr;
    const struct if_nameindex  *iut_if = NULL;

    csap_handle_t               csap_in = CSAP_INVALID_HANDLE;
    uint32_t                    pkt_num;

    te_bool                     transmit_between_bind;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(transmit_between_bind);

    TEST_STEP("Create UDP socket");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind UDP socket");
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Send some packets to IUT between binds");
    if(transmit_between_bind)
        sockts_test_udp_sendto(pco_tst, tst_s, pco_iut, iut_s, iut_addr);

    TEST_STEP("Bind it again(should fail)");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_bind(pco_iut, iut_s, iut_addr);
    if (rc == 0)
        TEST_VERDICT("The second bind() succeeded");
    else if (rc == -1)
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "bind() returned -1");

    TEST_STEP("Send some packets to IUT, check them for receiving "
              "but not for accelerating");
    sockts_test_udp_sendto(pco_tst, tst_s, pco_iut, iut_s, iut_addr);

    CHECK_RC(
        tapi_udp_ip_eth_csap_create(pco_iut->ta, 0,
                                    iut_if->if_name,
                                    TAD_ETH_RECV_DEF |
                                    TAD_ETH_RECV_NO_PROMISC,
                                    NULL, NULL,
                                    iut_addr->sa_family,
                                    TAD_SA2ARGS(NULL, tst_addr),
                                    &csap_in));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, csap_in,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Send some packets to IUT again");
    sockts_test_udp_sendto(pco_tst, tst_s, pco_iut, iut_s, iut_addr);

    TEST_STEP("Check that incoming UDP traffic is accelerated and properly "
              "received by the socket");
    CHECK_RC(rcf_ta_trrecv_get(pco_iut->ta, 0, csap_in,
                               NULL, NULL, &pkt_num));
    if (pkt_num > 0)
        TEST_VERDICT("Received packets are not accelerated");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap_in));

    TEST_END;
}
