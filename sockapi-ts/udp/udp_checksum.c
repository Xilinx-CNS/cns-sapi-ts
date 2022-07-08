/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 *
 * $Id: tcp_cork.c 65689 2010-08-24 11:38:18Z rast $
 */

/** @page udp-udp_checksum UDP checksum test
 *
 * @objective Checking UDP checksum functionality.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            IUT network interface
 * @param tst_if            TESTER network interface
 * @param fragmented        Whether UDP packet should be fragmented or not
 * @param last_frag_small   Whether the last fragment should be small or
 *                          almost MTU
 * @param connect_iut       Whether to connect socket on IUT and use
 *                          @b send() instead of @b sendto()
 * @param mtu_size          MTU to be set
 *
 * @par Test sequence:
 *
 * -# Create CSAP on Tester to trace UDP packets.
 * -# Create sockets @p iut_s and @p tst_s, bind them.
 * -# If @p connect_iut is @c TRUE, connect iut_s.
 * -# Set current MTU value to @p mtu_size on @p iut_if and
 *    @p tst_if (if @p mtu_size != -1, otherwise set @p mtu_size
 *    to current @p iut_if MTU).
 * -# Prepare data to send according to @p fragmented and 
 *    @p last_frag_small parameters and @p mtu_size.
 * -# Start CSAP receiving operation.
 * -# Send and receive data, verify it.
 * -# Stop CSAP receiving operation.
 * -# Check if UDP packet has zero checksum.
 * -# Issue verdicts.
 * -# Close all sockets.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/udp_checksum"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

#include "conf_api.h"
#include "tapi_rpc.h"

#include "tapi_test.h"
#include "tapi_ip4.h"
#include "tapi_udp.h"
#include "tapi_tcp.h"

#include "ndn_eth.h"
#include "ndn_ipstack.h"

#if HAVE_NETINET_UDP_H
#include <netinet/udp.h>
/* Size of UDP header */
#define UDP_HDR_SIZE     sizeof(struct udphdr)
#else
/* Size of UDP header */
#define UDP_HDR_SIZE     8
#endif

#define IP_HDR_SIZE     sockts_ip_hdr_len_by_addr(iut_addr)

static void
user_pkt_handler(asn_value *pkt, void *userdata)
{
    size_t          len = sizeof(uint16_t);
    int             rc;
    uint16_t        checksum;

    UNUSED(userdata);

    if ((rc = asn_read_value_field(pkt, &checksum, &len,
                                   "pdus.0.#udp.checksum.#plain")) != 0)
        ERROR("Cannot read checksum: %r", rc);

    RING("UDP packet with checksum 0x%x received", checksum);

    if (checksum == 0)
        RING_VERDICT("UDP packet has zero checksum");

    asn_free_value(pkt);
}

int
main(int argc, char *argv[])
{
    int                     sid;
    csap_handle_t           csap = CSAP_INVALID_HANDLE;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;

    uint8_t                *rx_buf = NULL;
    uint8_t                *tx_buf = NULL;
    
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;

    te_bool                fragmented;
    te_bool                last_frag_small;
    te_bool                connect_iut;
    int                    mtu_size;

    int                    buf_len = 0;
    int                    received;
    unsigned int           num;
    int                    opt_val;

    te_saved_mtus   iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus   tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_BOOL_PARAM(fragmented);
    TEST_GET_BOOL_PARAM(last_frag_small);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_INT_PARAM(mtu_size);

    if (mtu_size != -1)
    {
        CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                        mtu_size, &iut_mtus));
        CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                        mtu_size, &tst_mtus));
    }
    else
        tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name, &mtu_size);

    /* Create CSAP */
    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
    {
        TEST_FAIL("rcf_ta_create_session failed");
        return 1;
    }

    INFO("Test: Created session: %d", sid); 

    CHECK_RC(tapi_udp_ip_eth_csap_create(pco_tst->ta, sid,
                                         tst_if->if_name,
                                         TAD_ETH_RECV_DEF |
                                         TAD_ETH_RECV_NO_PROMISC,
                                         NULL, NULL, tst_addr->sa_family,
                                         TAD_SA2ARGS(tst_addr, iut_addr),
                                         &csap));
    
    /* Create Sockets */
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_IPPROTO_UDP, TRUE, FALSE,
                                       iut_addr);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                     RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (connect_iut)
        rpc_connect(pco_iut, iut_s, tst_addr);

    /* Prepare data to send */
    if (fragmented)
        buf_len = mtu_size - IP_HDR_SIZE - UDP_HDR_SIZE;
    
    if (last_frag_small)
        buf_len += 20;
    else
        buf_len += mtu_size - IP_HDR_SIZE - UDP_HDR_SIZE;

    rx_buf = te_make_buf_by_len(buf_len);
    tx_buf = te_make_buf_by_len(buf_len);

    /* CSAP start */
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 100,
                                   RCF_TRRECV_PACKETS));

    rpc_getsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &opt_val);
    if (opt_val < buf_len)
    {
        opt_val = buf_len;
        rpc_setsockopt(pco_tst, tst_s, RPC_SO_RCVBUF, &opt_val);
    }

    /* Send and receive data */
    if (connect_iut)
        rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    else
        rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);
    received = rpc_read(pco_tst, tst_s, rx_buf, buf_len);

    if (received != buf_len)
        TEST_FAIL("Some data were lost");
    if (memcmp(rx_buf, tx_buf, buf_len) != 0)
        TEST_FAIL("Data corruption occured");

    /* Stop CSAP receiving process */
    if (tapi_tad_trrecv_stop(pco_tst->ta, sid, csap, 
                             tapi_tad_trrecv_make_cb_data(
                                 user_pkt_handler, NULL), &num))
        TEST_FAIL("Failed to stop receiving packets");

    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_tst->ta, sid, csap))
        ERROR("Failed to destroy CSAP");

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
