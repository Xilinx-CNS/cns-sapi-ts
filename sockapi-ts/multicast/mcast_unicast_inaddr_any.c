/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/** @page multicast-mcast_unicast_inaddr_any Multicast/unicast datagrams acceleration
 *
 * @objective Check traffic acceleration when a socket is bound to
 *            INADDR_ANY and joined to a multicast group.
 *
 * @param sock_func         Socket creation function.
 * @param proto_def         If @c TRUE, use default protocol value
 *                          instead of @c IPPROTO_UDP.
 *
 * @type Conformance.
 *
 */

#define TE_TEST_NAME "multicast/mcast_unicast_inaddr_any"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_udp.h"
#include "mcast_lib.h"
#include "multicast.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *mcast_addr = NULL;

    struct sockaddr_storage    iut_bind_addr;
    struct sockaddr_storage    iut_unicast_addr;

    const struct if_nameindex *iut_if = NULL;

    sockts_socket_func         sock_func;
    te_bool                    proto_def;

    csap_handle_t   csap_in = CSAP_INVALID_HANDLE;
    csap_handle_t   csap_out = CSAP_INVALID_HANDLE;

    int            iut_s = -1;
    int            tst_s = -1;

    void          *tx_buf = NULL;
    size_t         tx_len;
    char           rx_buf[SOCKTS_MSG_DGRAM_MAX];
    unsigned int   pkt_num;

    te_bool exp_accelerated = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_IF(iut_if);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_BOOL_PARAM(proto_def);

    if (tapi_onload_lib_exists(pco_iut->ta) ||
        sockts_zf_shim_run())
        exp_accelerated = TRUE;

    tapi_rpc_provoke_arp_resolution(pco_iut, tst_addr);

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if, tst_addr,
                                           mcast_addr);

    TEST_STEP("Create UDP socket on IUT.");
    iut_s = sockts_socket(sock_func, pco_iut,
                          rpc_socket_domain_by_addr(mcast_addr),
                          RPC_SOCK_DGRAM,
                          (proto_def ? RPC_PROTO_DEF : RPC_IPPROTO_UDP));

    if (tapi_onload_lib_exists(pco_iut->ta) &&
        !sockts_zf_shim_run())
    {
        if (tapi_onload_check_fd(pco_iut, iut_s,
                                 NULL) == TAPI_FD_IS_SYSTEM)
            TEST_VERDICT("%s() returned system socket",
                         sockts_socket_func2str(sock_func));
    }

    TEST_STEP("Bind the socket to INADDR_ANY.");
    tapi_sockaddr_clone_exact(mcast_addr, &iut_bind_addr);
    te_sockaddr_set_wildcard(SA(&iut_bind_addr));
    rpc_bind(pco_iut, iut_s, SA(&iut_bind_addr));

    TEST_STEP("Join the socket to a multicast group.");
    rpc_common_mcast_join(pco_iut, iut_s, mcast_addr, tst_addr,
                          iut_if->if_index, TARPC_MCAST_ADD_DROP);

    TEST_STEP("Create UDP socket on Tester.");
    tst_s = rpc_create_and_bind_socket(pco_tst, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF,
                                       FALSE, FALSE,
                                       tst_addr);

    TEST_STEP("Create CSAPs on IUT to check whether packets can be detected "
              "by system (i.e. traffic is not accelerated).");

    CHECK_RC(
        tapi_udp_ip4_eth_csap_create(pco_iut->ta, 0,
                                     iut_if->if_name,
                                     TAD_ETH_RECV_DEF |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     NULL, NULL,
                                     0,
                                     SIN(tst_addr)->sin_addr.s_addr,
                                     -1,
                                     SIN(tst_addr)->sin_port,
                                     &csap_in));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, csap_in,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    CHECK_RC(
        tapi_udp_ip4_eth_csap_create(pco_iut->ta, 0,
                                     iut_if->if_name,
                                     TAD_ETH_RECV_OUT |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     NULL, NULL,
                                     SIN(tst_addr)->sin_addr.s_addr,
                                     0,
                                     SIN(tst_addr)->sin_port,
                                     -1,
                                     &csap_out));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, csap_out,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_COUNT));

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&tx_len)));

    TEST_STEP("Send a multicast datagram from Tester.");
    rpc_sendto(pco_tst, tst_s, tx_buf, tx_len, 0, mcast_addr);
    rc = rpc_recv(pco_iut, iut_s, rx_buf, SOCKTS_MSG_DGRAM_MAX, 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_len, rc);

    TEST_STEP("Check that the datagram is not visible for CSAP.");

    CHECK_RC(rcf_ta_trrecv_get(pco_iut->ta, 0, csap_in,
                               NULL, NULL, &pkt_num));
    if (exp_accelerated)
    {
        if (pkt_num > 0)
            RING_VERDICT("Multicast packet from Tester was detected "
                         "by CSAP");
    }
    else
    {
        if (pkt_num <= 0)
            RING_VERDICT("Multicast packet from Tester was not detected "
                         "by CSAP");
    }

    TEST_STEP("Send a unicast datagram from IUT.");

    te_fill_buf(tx_buf, tx_len);
    rpc_sendto(pco_iut, iut_s, tx_buf, tx_len, 0, tst_addr);
    rc = rpc_recv(pco_tst, tst_s, rx_buf, SOCKTS_MSG_DGRAM_MAX, 0);
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_len, rc);

    TEST_STEP("Check that the datagram is not visible for CSAP.");

    CHECK_RC(rcf_ta_trrecv_get(pco_iut->ta, 0, csap_out,
                               NULL, NULL, &pkt_num));
    if (exp_accelerated)
    {
        if (pkt_num > 0)
            RING_VERDICT("Unicast packet from IUT was detected "
                         "by CSAP");
    }
    else
    {
        if (pkt_num <= 0)
            RING_VERDICT("Unicast packet from IUT was not detected "
                         "by CSAP");
    }

    tapi_sockaddr_clone_exact(iut_addr, &iut_unicast_addr);
    te_sockaddr_set_port(SA(&iut_unicast_addr),
                         te_sockaddr_get_port(mcast_addr));

    TEST_STEP("Send a unicast datagram from Tester.");

    te_fill_buf(tx_buf, tx_len);
    rpc_sendto(pco_tst, tst_s, tx_buf, tx_len, 0, SA(&iut_unicast_addr));
    rc = rpc_recv(pco_iut, iut_s, rx_buf, SOCKTS_MSG_DGRAM_MAX, 0);
    SOCKTS_CHECK_RECV(pco_iut, tx_buf, rx_buf, tx_len, rc);

    TEST_STEP("Check that the datagram is visible if @p sock_func is "
              "@c onload_socket_unicast_nonaccel(), else - not visible.");

    CHECK_RC(rcf_ta_trrecv_get(pco_iut->ta, 0, csap_in,
                               NULL, NULL, &pkt_num));
    if (exp_accelerated &&
        sock_func == SOCKTS_SOCK_FUNC_SOCKET)
    {
        if (pkt_num > 0)
            RING_VERDICT("Unicast packet from Tester was detected "
                         "by CSAP");
    }
    else
    {
        if (pkt_num <= 0)
            RING_VERDICT("Unicast packet from Tester was not detected "
                         "by CSAP");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap_in));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap_out));

    free(tx_buf);

    TEST_END;
}
