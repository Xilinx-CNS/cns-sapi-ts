/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-zc_send_msg_more onload_zc_send() and MSG_MORE flag
 *
 * @objective Check that TCP payload is split into packets correctly
 *            when @b onload_zc_send() (alone or together with usual
 *            @b send()) is used with @c MSG_MORE flag.
 *
 * @type use case
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_gw
 *                      - @ref arg_types_env_peer2peer_gw_ipv6
 * @param split_pos     Where data should be split due to MSS size:
 *                      - @c first (inside the first buffer)
 *                      - @c between (between the first and the second
 *                        buffers)
 *                      - @c second (inside the second buffer)
 * @param first_zc      If @c TRUE, the first buffer should be sent with
 *                      @b onload_zc_send(). Otherwise it should be sent
 *                      with @b send().
 * @param second_zc     If @c TRUE, the second buffer should be sent with
 *                      @b onload_zc_send(). Otherwise it should be sent
 *                      with @b send().
 *
 * @note The purpose of this test is to check all code paths in
 *       ci_tcp_tx_merge_indirect(), see comments in ST-2033.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/zc_send_msg_more"

#include "sockapi-test.h"
#include "onload.h"
#include "tapi_route_gw.h"

/** Minimum TCP MSS in case of IPv4 */
#define MIN_IPV4_MSS 536

/** Minimum TCP MSS in case of IPv6 */
#define MIN_IPV6_MSS 1220

/** Values of "split_pos" parameter */
enum {
    SPLIT_POS_FIRST,    /**< Split inside the first sent buffer */
    SPLIT_POS_BETWEEN,  /**< Split between the two sent buffers */
    SPLIT_POS_SECOND,   /**< Split inside the second sent buffer */
};

/**
 * List of values of "split_pos" parameter for TEST_GET_ENUM_PARAM() macro.
 */
#define SPLIT_POS \
    { "first", SPLIT_POS_FIRST }, \
    { "between", SPLIT_POS_BETWEEN }, \
    { "second", SPLIT_POS_SECOND }

/**< Auxiliary structure for processing IUT packets captured by CSAP */
typedef struct pkt_data {
    te_bool init_run;       /**< If TRUE, this is initial run where
                                 length of TCP/IP headers with options,
                                 maximum TCP payload length and
                                 initial SEQN are obtained */

    unsigned int max_payload_len; /**< Maximum length of TCP payload in
                                       bytes */
    unsigned int ip_tcp_hdrs_len; /**< Length of TCP/IP headers in bytes */
    int64_t init_seqn;            /**< Initial SEQN */

    uint32_t total_len;     /**< Total length of sent data. */
    te_bool small_pkt;      /**< Will be set to TRUE if packet smaller
                                 than maximum possible is not the last
                                 packet sent from IUT */

    te_bool failed;         /**< Will be set to TRUE if something went
                                 wrong when processing captured packets */
} pkt_data;

/**
 * Process IUT packets captured by CSAP in the initial run
 * (to get initial SEQN, TCP/IP headers length and maximum TCP payload
 * length).
 *
 * @param pkt       Captured packet.
 * @param data      Pointer to auxiliary structure used to store
 *                  processing results.
 */
static void
process_init_run(asn_value *pkt, pkt_data *data)
{
    unsigned int payload_len = 0;
    unsigned int hdrs_len = 0;
    uint32_t seqn;
    te_errno rc;

    rc = tapi_tcp_get_hdrs_payload_len(pkt, &hdrs_len, &payload_len);
    if (rc != 0)
    {
        data->failed = TRUE;
        return;
    }

    if (data->max_payload_len < payload_len)
        data->max_payload_len = payload_len;

    data->ip_tcp_hdrs_len = hdrs_len;

    if (data->init_seqn < 0)
    {
        rc = asn_read_uint32(pkt, &seqn,
                             "pdus.0.#tcp.seqn");
        if (rc != 0)
        {
            ERROR("asn_read_uint32() failed to get TCP SEQN, "
                  "rc = %r", rc);
            data->failed = TRUE;
            return;
        }

        data->init_seqn = seqn;
    }
}

/**
 * Process IUT packets captured by CSAP after sending requested
 * buffers with MSG_MORE flag.
 *
 * @param pkt       Captured packet.
 * @param data      Pointer to auxiliary structure used to store
 *                  processing results.
 */
static void
process_main_run(asn_value *pkt, pkt_data *data)
{
    uint32_t seqn;
    uint32_t rel_seqn;
    uint32_t next_rel_seqn;
    te_errno rc;

    unsigned int payload_len = 0;
    te_bool last_packet;

    rc = asn_read_uint32(pkt, &seqn,
                         "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("asn_read_uint32() failed to get TCP SEQN, "
              "rc = %r", rc);
        data->failed = TRUE;
        return;
    }

    if (seqn < (uint32_t)(data->init_seqn))
        rel_seqn = ((1LU << 32) - data->init_seqn) + seqn;
    else
        rel_seqn = seqn - data->init_seqn;

    rc = tapi_tcp_get_hdrs_payload_len(pkt, NULL, &payload_len);
    if (rc != 0)
    {
        data->failed = TRUE;
        return;
    }

    next_rel_seqn = rel_seqn + payload_len;
    if (next_rel_seqn > data->total_len)
    {
        ERROR("CSAP captured packet with payload past the last expected "
              "SEQN");
        data->failed = TRUE;
        return;
    }
    last_packet = (next_rel_seqn == data->total_len);

    RING("Relative SEQN %d, payload length %d, the next relative SEQN %d, "
         "relative SEQN after the last sent byte %d, packet is %sthe last",
         rel_seqn, payload_len, next_rel_seqn, data->total_len,
         (last_packet ? "" : "not "));

    if (!last_packet && payload_len < data->max_payload_len)
    {
        ERROR("Packet is not the last one, but has payload length "
              "smaller than %d", data->max_payload_len);
        data->small_pkt = TRUE;
    }
}

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

    if (data->init_run)
        process_init_run(pkt, data);
    else
        process_main_run(pkt, data);

    asn_free_value(pkt);
}

int
main(int argc, char *argv[])
{
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    tapi_route_gateway gw;

    int iut_s = -1;
    int tst_s = -1;

    int mss;
    int mss_new;
    int max_mss_diff;
    int mss_diff;
    int max_payload_len;
    int mtu;
    te_saved_mtus gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);

    int split_pos;
    te_bool first_zc;
    te_bool second_zc;

    int first_size;
    int second_size;
    int send_size;
    int recv_size;
    char *aux_send_buf = NULL;
    char *aux_recv_buf = NULL;
    rpc_ptr_off *send_buf_off = NULL;
    uint8_t *send_buf = NULL;
    uint8_t *recv_buf = NULL;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    tapi_tad_trrecv_cb_data cb_data;
    unsigned int num = 0;
    pkt_data data;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_ENUM_PARAM(split_pos, SPLIT_POS);
    TEST_GET_BOOL_PARAM(first_zc);
    TEST_GET_BOOL_PARAM(second_zc);

    TEST_STEP("Disable Generic Receive Offload and Large Receive "
              "Offload on @p gw_iut_if.");
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(pco_gw->ta,
                                                 gw_iut_if->if_name,
                                                 "rx-gro", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(pco_gw->ta,
                                                 gw_iut_if->if_name,
                                                 "rx-lro", 0));

    TEST_STEP("Configure routing between IUT and Tester over gateway "
              "host.");
    TAPI_INIT_ROUTE_GATEWAY(gw);
    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create a pair of connected TCP sockets on IUT and Tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Create a CSAP on the gateway host to capture packets "
              "received from IUT over @p gw_iut_if interface.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                            pco_gw->ta, 0, gw_iut_if->if_name,
                            TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                            NULL, NULL,
                            tst_addr->sa_family,
                            TAD_SA2ARGS(tst_addr, iut_addr),
                            &csap));
    CHECK_RC(tapi_tad_trrecv_start(
                               pco_gw->ta, 0, csap, NULL,
                               TAD_TIMEOUT_INF, 0,
                               RCF_TRRECV_PACKETS));
    TAPI_WAIT_NETWORK;

    TEST_STEP("Get initial value of TCP MSS on the IUT socket, save it "
              "in @b mss.");
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    aux_send_buf = tapi_calloc(mss, 1);
    aux_recv_buf = tapi_calloc(mss, 1);
    te_fill_buf(aux_send_buf, mss);

    TEST_STEP("Send @b mss bytes from the IUT socket, receive and check "
              "them on Tester.");
    RPC_SEND(rc, pco_iut, iut_s, aux_send_buf, mss, 0);
    TAPI_WAIT_NETWORK;
    rc = rpc_recv(pco_tst, tst_s, aux_recv_buf, mss, 0);
    if (rc != mss || memcmp(aux_send_buf, aux_recv_buf, mss) != 0)
        TEST_VERDICT("Unexpected data was received when checking MSS");

    TEST_STEP("Process packets captured by CSAP to obtain maximum length "
              "of payload a TCP packet can carry (@b max_payload_len) and "
              "length of TCP/IP headers (together with options).");

    memset(&cb_data, 0, sizeof(cb_data));
    memset(&data, 0, sizeof(data));
    cb_data.callback = &user_pkt_handler;
    cb_data.user_data = &data;
    data.init_run = TRUE;
    data.init_seqn = -1;

    CHECK_RC(tapi_tad_trrecv_get(pco_gw->ta, 0, csap,
                                 &cb_data, &num));
    if (num == 0)
        TEST_FAIL("CSAP did not capture any packets");
    if (data.failed)
        TEST_FAIL("CSAP failed to process captured packets");

    max_payload_len = data.max_payload_len;
    RING("Headers length is %u, maximum TCP payload length is %u",
         data.ip_tcp_hdrs_len, max_payload_len);

    /*
     * It should be much more actually, but if it is less than 3,
     * it cannot be split into two buffers so that one of them
     * can be split again.
     */
    if (max_payload_len < 3)
        TEST_FAIL("Too small maximum payload length");

    TEST_STEP("Let @b mss_diff be zero by default.");
    mss_diff = 0;

    if ((split_pos == SPLIT_POS_FIRST && !first_zc) ||
        (split_pos == SPLIT_POS_SECOND && !second_zc))
    {
        TEST_STEP("If one of the sent buffers should be split between "
                  "packets and this buffer should be sent by usual "
                  "@b send():");

        TEST_SUBSTEP("Choose randomly a positive value @b mss_diff by "
                     "which MSS will be reduced.");

        /*
         * Buffers passed to usual send() are not normally processed in
         * ci_tcp_tx_merge_indirect(); so we change MTU on the gateway
         * to force MSS reduction after buffers were already queued.
         */

        if (iut_addr->sa_family == AF_INET6)
            max_mss_diff = mss - MIN_IPV6_MSS;
        else
            max_mss_diff = mss - MIN_IPV4_MSS;

        if (max_mss_diff < 1 ||
            (split_pos == SPLIT_POS_FIRST && max_mss_diff < 2))
            TEST_FAIL("Impossible to reduce MSS");

        assert(max_mss_diff < max_payload_len);

        TEST_SUBSTEP("Choose length of the first buffer @b first_size "
                     "and length of the second buffer @b second_size so "
                     "that @b first_size + @b second_size = "
                     "@b max_payload_len. If @p split_pos is @c first, "
                     "@b first_size should be greater than "
                     "@b max_payload_len - @b mss_diff; if @p split_pos "
                     "is @c second, @b first_size should be smaller "
                     "than that value.");

        if (split_pos == SPLIT_POS_FIRST)
        {
            /*
             * MSS should be reduced at least by 2 bytes to get
             * inside the first buffer (second one cannot be shorter
             * than 1 byte).
             */
            mss_diff = rand_range(2, max_mss_diff);
            first_size = rand_range(max_payload_len - mss_diff + 1,
                                    max_payload_len - 1);
        }
        else
        {
            /*
             * MSS cannot be reduced by more than max_payload_len - 2,
             * since the first buffer cannot be smaller than 1 byte,
             * and max_payload_len - mss_diff should be inside the
             * second buffer to cause its splitting.
             */
            mss_diff = rand_range(1, MIN(max_mss_diff,
                                         max_payload_len - 2));
            first_size = rand_range(1,
                                    max_payload_len - mss_diff - 1);
        }

        second_size = max_payload_len - first_size;
    }
    else
    {
        TEST_STEP("If @p split_pos is @c between or if buffer to be split "
                  "between packets is sent with @b onload_zc_send():");

        switch (split_pos)
        {
            case SPLIT_POS_FIRST:
                TEST_SUBSTEP("If @p split_pos is @c first, choose "
                             "@b first_size to be more than "
                             "@b max_payload_len (but less than "
                             "double that number), and @b second_size "
                             "to be no more than "
                             "2 * @b max_payload_len - @b first_size.");
                first_size = rand_range(max_payload_len + 1,
                                        2 * max_payload_len - 1);
                second_size = rand_range(1,
                                         2 * max_payload_len - first_size);
                break;

            case SPLIT_POS_BETWEEN:
                TEST_SUBSTEP("If @p split_pos is @c between, let "
                             "@b first_size be equal to "
                             "@b max_payload_len and @b second_size "
                             "be not greater than it.");
                first_size = max_payload_len;
                second_size = rand_range(1, max_payload_len);
                break;

            case SPLIT_POS_SECOND:
                TEST_SUBSTEP("If @p split_pos is @c second, choose "
                             "@b first_size to be less than "
                             "@b max_payload_len, and choose "
                             "@b second_size so that @b first_size + "
                             "@b second_size > @b max_payload_len but "
                             "less than 2 * @b max_payload_len.");
                first_size = rand_range(1, max_payload_len - 1);
                second_size = rand_range(max_payload_len - first_size + 1,
                                         max_payload_len);
                break;
        }
    }

    send_size = first_size + second_size;

    if (mss_diff > 0)
    {
        TEST_STEP("If @b mss_diff was set to positive value, set MTU on "
                  "@b gw_tst_if to sum of TCP/IP headers length and "
                  "(@b max_payload_len - @b mss_diff). This will result "
                  "in MSS update after failure to send the initially "
                  "queued packet, splitting data into two packets of "
                  "different size and sending it again.");
        mtu = data.ip_tcp_hdrs_len + max_payload_len - mss_diff;

        CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_tst_if->if_name,
                                        mtu, &gw_mtus));
        CFG_WAIT_CHANGES;
    }

    rpc_malloc_off(pco_iut, send_size, &send_buf_off);
    rpc_set_buf_pattern_off(pco_iut, TAPI_RPC_BUF_RAND,
                            send_size, send_buf_off);
    send_buf = tapi_calloc(send_size, 1);
    rpc_get_buf_off(pco_iut, send_buf_off, send_size, send_buf);

    recv_size = send_size * 2;
    recv_buf = tapi_calloc(recv_size, 1);

    TEST_STEP("With help of @b rpc_onload_zc_send_msg_more() send "
              "two buffers: the first of @b first_size bytes and "
              "with @c MSG_MORE flag, the second of @b second_size "
              "bytes and without @c MSG_MORE flag. Choose functions "
              "for sending the buffers according to @p first_zc "
              "and @b second_zc.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_onload_zc_send_msg_more(
                                pco_iut, iut_s,
                                send_buf_off->base,
                                first_size, second_size,
                                first_zc, second_zc,
                                TRUE, FALSE);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_onload_zc_send_msg_more() failed unexpectedly "
                     "with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != send_size)
    {
        TEST_VERDICT("rpc_onload_zc_send_msg_more() returned unexpected "
                     "value");
    }

    TEST_STEP("Wait for a while to let all data reach Tester.");
    TAPI_WAIT_NETWORK;

    if (mss_diff > 0)
    {
        TEST_STEP("If @b mss_diff was set to positive value, check that "
                  "TCP MSS was reduced by @b mss_diff after sending due "
                  "to reduced MTU on the gateway.");

        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss_new);
        if (mss_new != mss - mss_diff)
        {
            ERROR("MSS was expected to change from %d to %d, but it "
                  "is %d instead", mss, mss - mss_diff, mss_new);
            TEST_VERDICT("MSS did not change in expected way");
        }
    }

    TEST_STEP("Receive and check data on Tester.");

    rc = rpc_recv(pco_tst, tst_s, recv_buf, recv_size, 0);
    if (rc != send_size)
    {
        TEST_VERDICT("recv() on Tester returned unexpected number of "
                     "bytes");
    }
    else if (memcmp(recv_buf, send_buf, send_size) != 0)
    {
        TEST_VERDICT("recv() on Tester returned unexpected data");
    }

    TEST_STEP("Check packets captured by CSAP on the gateway. Check that "
              "only the last packet can have TCP payload of size smaller "
              "than @b max_payload_len - @b mss_diff bytes.");

    data.init_run = FALSE;
    data.max_payload_len = max_payload_len - mss_diff;
    data.total_len = mss + send_size;
    CHECK_RC(tapi_tad_trrecv_stop(pco_gw->ta, 0, csap,
                                  &cb_data, &num));
    if (num == 0)
        TEST_FAIL("CSAP did not capture any packets");
    if (data.failed)
        TEST_FAIL("CSAP failed to process captured packets");

    if (data.small_pkt)
    {
        TEST_VERDICT("Packet other than the last is smaller than "
                     "maximum possible length");
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (mss_diff > 0)
        CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&gw_mtus));

    free(aux_send_buf);
    free(aux_recv_buf);
    free(send_buf);
    free(recv_buf);
    if (send_buf_off != NULL)
        rpc_free_off(pco_iut, send_buf_off);

    TEST_END;
}
