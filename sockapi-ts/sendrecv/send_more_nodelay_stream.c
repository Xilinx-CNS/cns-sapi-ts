/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-send_more_nodelay_stream MSG_MORE sendmsg() flag and socket option TCP_NODELAY
 *
 * @objective Check that enabling @c TCP_NODELAY socket option after
 *            sending data with @c MSG_MORE flag results in immediate
 *            sending of the queued data to a peer, even if it means
 *            sending not full-sized packet.
 *
 * @type Conformance.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_lo
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_lo_ipv6
 *                      - @ref arg_types_env_peer2peer_fake
 * @param func          Sending function to check:
 *                      - @b send
 *                      - @b sendmsg
 *                      - @b onload_zc_send
 *                      - @b onload_zc_send_user_buf
 * @param first_zc      If @p func is one of ZC functions, then
 *                      if this parameter is @c TRUE, use @p func
 *                      for sending the first buffer; otherwise use
 *                      @b send() for it.
 * @param last_zc       If @p func is one of ZC functions, then
 *                      if this parameter is @c TRUE, use @p func
 *                      for sending the second buffer; otherwise use
 *                      @b send() for it.
 *
 * @par Scenario:
 *
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_more_nodelay_stream"

#include "sockapi-test.h"
#include "tapi_tcp.h"

/** Maximum length of TCP/IP options */
#define OPTS_MAX_LEN 100

/**< Auxiliary structure for processing IUT packets captured by CSAP */
typedef struct pkt_data {
    int first_len;          /**< Where to save payload length of the first
                                 packet */
    int second_len;         /**< Where to save payload length of the second
                                 packet */

    int64_t first_seqn;     /**< Where to save SEQN of the first packet */
    int64_t second_seqn;    /**< Where to save SEQN of the second packet */

    te_bool unexp_packet;   /**< Will be set to TRUE if unexpected TCP
                                 packet was received */
    te_bool failed;         /**< Will be set to TRUE if packets processing
                                 failed in callback */
} pkt_data;

/**
 * Callback for processing IUT packets captured by CSAP.
 *
 * @param pkt         Captured packet.
 * @param user_data   Pointer to pkt_data structure.
 */
static void
user_pkt_handler(asn_value *pkt, void *user_data)
{
    pkt_data *data = (pkt_data *)user_data;
    int payload_len = 0;
    uint32_t seqn;
    te_errno rc;

    rc = asn_read_uint32(pkt, &seqn, "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("asn_read_uint32() failed to get TCP SEQN, "
              "rc = %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    payload_len = sockts_tcp_payload_len(pkt);
    if (payload_len < 0)
    {
        data->failed = TRUE;
        goto cleanup;
    }

    RING("Received packet with SEQN %u and payload length %d",
         seqn, payload_len);

    if (data->first_seqn < 0)
    {
        data->first_seqn = seqn;
        data->first_len = payload_len;
    }
    else if (data->second_seqn < 0)
    {
        data->second_seqn = seqn;
        data->second_len = payload_len;
    }
    else if (!(seqn == data->first_seqn &&
               payload_len == data->first_len) &&
             !(seqn == data->second_seqn &&
               payload_len == data->second_len))
    {
        /*
         * We expect sent data to be split in two TCP packets, now the
         * third distinct packet arrived.
         */
        ERROR("Unexpected TCP packet was received");
        data->unexp_packet = TRUE;
    }

    if (data->first_seqn >= 0 && data->second_seqn >= 0 &&
        tapi_tcp_compare_seqn(data->second_seqn,
                              data->first_seqn) < 0)
    {
        int len_aux;
        uint32_t seqn_aux;

        /* Reordering of packets happened - rearrange data. */
        len_aux = data->first_len;
        seqn_aux = data->first_seqn;
        data->first_len = data->second_len;
        data->first_seqn = data->second_seqn;
        data->second_len = len_aux;
        data->second_seqn = seqn_aux;
    }

cleanup:
    asn_free_value(pkt);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_iut = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct if_nameindex *tst_if = NULL;

    int tst_s = -1;
    int iut_s = -1;
    int mss;
    int first_len;
    int second_len;
    int total_size;

    uint8_t *send_buf = NULL;
    uint8_t *recv_buf = NULL;
    rpc_ptr send_buf_ptr = RPC_NULL;

    csap_handle_t recv_csap;
    tapi_tad_trrecv_cb_data cb_data;
    pkt_data data;
    unsigned int num = 0;

    sockts_send_func func;
    te_bool first_zc;
    te_bool last_zc;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SEND_FUNC_ID(func);
    TEST_GET_BOOL_PARAM(first_zc);
    TEST_GET_BOOL_PARAM(last_zc);

    TEST_STEP("Disable Generic Receive Offload and Large Receive "
              "Offload on @p tst_if.");
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                              pco_tst->ta,
                                              tst_if->if_name,
                                              "rx-gro", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                              pco_tst->ta,
                                              tst_if->if_name,
                                              "rx-lro", 0));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Create a CSAP on Tester to capture packets received from "
              "IUT over @p tst_if interface.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0,
        tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr),
        &recv_csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, recv_csap,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Get value of TCP MSS on the IUT socket, save it "
              "in @b mss.");

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
    if (mss <= OPTS_MAX_LEN)
        TEST_FAIL("MSS is too small");

    TEST_STEP("Choose size of the first data portion @b first_len and "
              "size of the second data portion @b second_len so that "
              "they both are less than @b mss.");

    first_len = rand_range(1, mss - OPTS_MAX_LEN);
    second_len = rand_range(1, mss - OPTS_MAX_LEN);
    total_size = first_len + second_len;

    send_buf = (uint8_t *)tapi_calloc(total_size, 1);
    recv_buf = (uint8_t *)tapi_calloc(total_size, 1);

    send_buf_ptr = rpc_malloc(pco_iut, total_size);
    rpc_set_buf_pattern(pco_iut, TAPI_RPC_BUF_RAND, total_size,
                        send_buf_ptr);
    rpc_get_buf(pco_iut, send_buf_ptr, total_size, send_buf);

    TEST_STEP("Send @b first_len bytes with @c MSG_MORE flag, choosing "
              "sending function according to @p func and @p first_zc.");
    TEST_STEP("Enable @c TCP_NODELAY socket option on the IUT socket.");
    TEST_STEP("Send @b second_len bytes without @c MSG_MORE flag, choosing "
              "sending function according to @p func and @p last_zc.");

    RPC_AWAIT_ERROR(pco_iut);
    if (func == SOCKTS_SENDF_ONLOAD_ZC_SEND ||
        func == SOCKTS_SENDF_ONLOAD_ZC_SEND_USER_BUF)
    {
        rc = rpc_onload_zc_send_msg_more(
                     pco_iut, iut_s,
                     send_buf_ptr,
                     first_len, second_len,
                     first_zc, last_zc,
                     (func == SOCKTS_SENDF_ONLOAD_ZC_SEND_USER_BUF),
                     TRUE);
    }
    else
    {
        rc = rpc_send_msg_more_ext(pco_iut, iut_s, send_buf_ptr,
                                   first_len, second_len,
                                   func, func, TRUE);
    }
    if (rc < 0)
    {
        TEST_VERDICT("Sending RPC call failed with error "
                     RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != total_size)
    {
        TEST_VERDICT("Sending RPC call returned unexpected value");
    }

    TEST_STEP("Receive and check sent data on Tester.");

    TAPI_WAIT_NETWORK;
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, recv_buf, total_size, 0);
    if (rc < 0)
    {
        TEST_VERDICT("recv() on Tester failed with error %r",
                     RPC_ERRNO(pco_tst));
    }
    else if (rc != total_size ||
             memcmp(recv_buf, send_buf, total_size) != 0)
    {
        TEST_VERDICT("recv() on Tester returned unexpected data");
    }

    TEST_STEP("Check packets captured with CSAP on Tester: two packets "
              "should have been sent, first - with payload of @b first_len "
              "bytes, second - with payload of @b second_len bytes.");

    memset(&cb_data, 0, sizeof(cb_data));
    memset(&data, 0, sizeof(data));
    cb_data.callback = &user_pkt_handler;
    cb_data.user_data = &data;
    data.first_seqn = -1;
    data.second_seqn = -1;

    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, recv_csap,
                                  &cb_data, &num));
    if (num == 0)
        TEST_VERDICT("CSAP did not capture any packets");
    if (data.failed)
        TEST_FAIL("CSAP failed to process captured packets");

    if (data.unexp_packet || data.first_seqn < 0 || data.second_seqn < 0 ||
        data.first_len != first_len || data.second_len != second_len)
    {
        TEST_VERDICT("Packets captured by CSAP do not match buffers sent "
                     "from IUT");
    }

    TEST_SUCCESS;

cleanup:

    if (recv_csap != CSAP_INVALID_HANDLE)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               recv_csap));
    }

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (send_buf_ptr != RPC_NULL)
        rpc_free(pco_iut, send_buf_ptr);

    free(send_buf);
    free(recv_buf);

    TEST_END;
}
