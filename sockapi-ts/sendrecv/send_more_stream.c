/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 */

/** @page sendrecv-send_more_stream MSG_MORE sendmsg() flag
 *
 * @objective Check that MSG_MORE does really work and concatenate TCP data
 *
 * @type Conformance.
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_lo
 *                      - @ref arg_types_env_peer2peer_fake
 *                      - @ref arg_types_env_peer2peer_ipv6
 *                      - @ref arg_types_env_peer2peer_lo_ipv6
 * @param mtu           MTU used
 * @param sz_first      Size of the first message sent with @c MSG_MORE flag
 * @param sz_last       Size of the last message without @c MSG_MORE flag
 *                      (if 0, no data will be sent the second time)
 * @param func          Sending function to test:
 *                      - @b send()
 *                      - @b onload_zc_send()
 *                      - @b onload_zc_send_user_buf() (@b onload_zc_send() +
 *                        @b onload_zc_register_buffers())
 * @param first_zc      If @c FALSE, the first packet should be sent with
 *                      @b send() even if @b onload_zc_send() is checked.
 * @param last_zc       If @c FALSE, the last packet should be sent with
 *                      @b send() even if @b onload_zc_send() is checked.
 * @param set_nodelay   If @c TRUE, @c TCP_NODELAY should be enabled on the
 *                      IUT socket before checking @c MSG_MORE.
 *
 * @par Scenario:
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_more_stream"

#include "sockapi-test.h"
#include "tapi_test.h"
#include "tapi_tcp.h"
#include "tapi_eth.h"
#include "ndn.h"
#include "ndn_eth.h"

/** Number of attempts to send and receive data */
#define ATTEMPTS_NUM 100
/** Maximum number of failed attempts */
#define MAX_FAILS 20

/** Length of TCP header (including timestamps) */
#define TEST_TCP_HDR_SIZE       32
/** Length of timestamps option */
#define TEST_TCP_HDR_SIZE_TS    12
#define TEST_MAX_INT 0x80000000

/* Store information about received TCP packet */
typedef struct size_and_seqn {
    STAILQ_ENTRY(size_and_seqn)     links;  /**< List links */
    int                             size;   /**< size of packet in bytes */
    te_bool                         psh;    /**< TCP_PSH flag */
    uint32_t                        seqn;   /**< sequence number of packet */
    te_bool                         failed; /**< Will be set to TRUE if some error occurred */
} size_and_seqn;

/** Head of the list size_and_seqn */
typedef STAILQ_HEAD(size_and_seqn_h, size_and_seqn) size_and_seqn_h;

/**
 * Find sequence number of last sent from @p iut_s TCP packet.
 *
 * @param recv_cb_data Pointer to @p size_and_seqn_h singly-linked tail queue
 *                     which contains sequence number of each received packet.
 *
 * @return Sequence number of last sent TCP packet.
 */
static uint32_t
last_seq(size_and_seqn_h *recv_cb_data)
{
    int i = 0;
    uint32_t last_seqn;
    size_and_seqn *recv_data;

    STAILQ_FOREACH(recv_data, recv_cb_data, links)
    {
        if (i++ == 0)
        {
            last_seqn = recv_data->seqn;
        }
        else
        {
            if (recv_data->seqn - last_seqn < TEST_MAX_INT)
                last_seqn = recv_data->seqn;
        }
    }
    return last_seqn;
}

static void
recv_callback(const asn_value *packet, int layer,
              const ndn_eth_header_plain *header,
              const uint8_t *payload, uint16_t plen, void *userdata)
{
    uint32_t seqn;
    uint8_t flags;
    size_t len = sizeof(uint32_t);
    int rc;
    size_and_seqn   *recv_data = NULL;
    size_and_seqn_h *recv_cb_data = (size_and_seqn_h *)userdata;
    UNUSED(header);
    UNUSED(packet);
    UNUSED(layer);
    UNUSED(payload);

    recv_data = TE_ALLOC(sizeof(*recv_data));

    if ((rc = asn_read_value_field(packet, &seqn, &len,
                                   "pdus.0.#tcp.seqn.#plain")) != 0)
    {
        ERROR("Cannot read seqn: %r", rc);
        recv_data->failed = TRUE;
    }
    len = sizeof(uint8_t);
    if ((rc = asn_read_value_field(packet, &flags, &len,
                                   "pdus.0.#tcp.flags.#plain")) != 0)
    {
        ERROR("Cannot read flags: %r", rc);
        recv_data->failed = TRUE;
    }

    recv_data->seqn = seqn;
    recv_data->psh = flags & TCP_PSH_FLAG;
    recv_data->size = plen;
    STAILQ_INSERT_TAIL(recv_cb_data, recv_data, links);
}

/**
 * Call a send function two times on IUT, the first time with @c MSG_MORE
 * flag, the second time - without it. Check that all the sent packets
 * except the last one do not have TCP PSH flag and are of maximum size.
 *
 * @param func                  Sending function to check.
 * @param pco_iut               RPC server on IUT.
 * @param pco_tst               RPC server on Tester.
 * @param iut_s                 IUT socket FD.
 * @param tst_s                 Tester socket FD.
 * @param recv_sid              RCF session ID for CSAP.
 * @param recv_csap             CSAP for capturing packets on Tester.
 * @param first_zc              If @c FALSE, use send() for the first call
 *                              even if another sending function is
 *                              specified by the first parameter.
 * @param last_zc               If @c FALSE, use send() for the last call
 *                              even if another sending function is
 *                              specified by the first parameter.
 * @param sz_first              Number of bytes to send with the first
 *                              call.
 * @param sz_last               Number of bytes to send with the last
 *                              call.
 * @param max_payload_size      Maximum size packet payload can have.
 * @param send_buf_off          RPC pointer to buffer allocated on IUT
 *                              RPC server.
 * @param recv_buf_off          RPC pointer to buffer allocated on Tester
 *                              RPC server.
 * @param send_buf_local        Local buffer to store sent data.
 * @param recv_buf_local        Local buffer to store received data.
 * @param last_pkt_no_psh       Will be set to @c TRUE if there is no TCP PSH
 *                              flag in the last sent packet.
 * @param wrong_psh             Will be set to @c TRUE if TCP PSH flag was
 *                              present not in the last sent packet.
 * @param wrong_size            Will be set to @c TRUE if some packet
 *                              (except the last one) does not contain
 *                              maximum payload.
 */
static void
check_msg_more(sockts_send_func func,
               rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
               int iut_s, int tst_s,
               unsigned int recv_sid, csap_handle_t recv_csap,
               te_bool first_zc, te_bool last_zc, int sz_first, int sz_last,
               int max_payload_size,
               rpc_ptr_off *send_buf_off, rpc_ptr_off *recv_buf_off,
               uint8_t *send_buf_local, uint8_t *recv_buf_local,
               te_bool *last_pkt_no_psh,
               te_bool *wrong_psh, te_bool *wrong_size)
{
    size_and_seqn *recv_data = NULL;
    size_and_seqn_h recv_cb_data = STAILQ_HEAD_INITIALIZER(recv_cb_data);

    int buf_size;
    int data_sent = 0;
    int data_received = 0;
    unsigned int recv_num = 0;

    int i;
    uint32_t last_seqn;
    int fail_counter = 0;
    int psh_counter = 0;
    int rc;

    *last_pkt_no_psh = FALSE;
    *wrong_psh = FALSE;
    *wrong_size = FALSE;
    buf_size = sz_first + sz_last;

    /* Fill send buffer with random values */
    rpc_set_buf_pattern_off(pco_iut, TAPI_RPC_BUF_RAND,
                            buf_size, send_buf_off);

    /* Send data (the first part of data will be sent with MSG_MORE flag,
       the last part of data will be sent with zero flag */

    RPC_AWAIT_ERROR(pco_iut);
    if (func == SOCKTS_SENDF_ONLOAD_ZC_SEND ||
        func == SOCKTS_SENDF_ONLOAD_ZC_SEND_USER_BUF)
    {
        data_sent = rpc_onload_zc_send_msg_more(
                          pco_iut, iut_s,
                          send_buf_off->base,
                          sz_first, sz_last,
                          first_zc, last_zc,
                          (func == SOCKTS_SENDF_ONLOAD_ZC_SEND_USER_BUF),
                          FALSE);
    }
    else
    {
        data_sent = rpc_send_msg_more_ext(pco_iut, iut_s,
                                          send_buf_off->base,
                                          sz_first, sz_last,
                                          func, func, FALSE);
    }

    if (data_sent < 0)
    {
        TEST_VERDICT("Sending operation failed with errno " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }

    /* Check that all data has been sent */
    if (data_sent != buf_size)
        TEST_VERDICT("Some data was not sent");

    while (data_received < data_sent)
    {
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_recvbuf_gen(pco_tst, tst_s, recv_buf_off->base,
                             data_received,
                             buf_size - data_received, 0);
        if (rc < 0)
        {
            TEST_VERDICT("Failed to receive data on Tester, "
                         "error %r", RPC_ERRNO(pco_tst));
        }
        else if (rc == 0)
        {
            TEST_VERDICT("Receiving function returned 0 on Tester");
        }

        data_received += rc;
    }

    if (data_received != buf_size)
        TEST_VERDICT("Some data has not been received");

    TAPI_WAIT_NETWORK;

    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, recv_sid, recv_csap,
                                 tapi_eth_trrecv_cb_data(recv_callback,
                                                         &recv_cb_data),
                                 &recv_num));

    RING("Received %u packets", recv_num);
    if (recv_num == 0)
        TEST_VERDICT("CSAP did not capture any packets");

    i = 0;
    STAILQ_FOREACH(recv_data, &recv_cb_data, links)
    {
        RING("Packet N%d. has %d bytes of payload, seqn %u and TCP_PSH %s",
             i++, recv_data->size, recv_data->seqn,
             recv_data->psh ? "set" : "unset" );
        if (recv_data->failed)
        {
            TEST_VERDICT("Error occurred when processing packets captured "
                         "by CSAP");
        }
    }

    last_seqn = last_seq(&recv_cb_data);
    RING("Last sequence number is %u", last_seqn);

    STAILQ_FOREACH(recv_data, &recv_cb_data, links)
    {
        if ((recv_data->seqn == last_seqn) && (!recv_data->psh))
        {
            ERROR("TCP PSH flag in the last packet is missing");
            *last_pkt_no_psh = TRUE;
        }
        else if (recv_data->seqn != last_seqn)
        {
            if (recv_data->size != max_payload_size)
                fail_counter++;

            if (recv_data->psh)
                psh_counter++;
        }
    }

    if (psh_counter > 0)
    {
        ERROR("Unexpected TCP PSH flag value encountered %d times",
              psh_counter);
        *wrong_psh = TRUE;
    }

    if (fail_counter > 0)
    {
        ERROR("Coalescing missing %d times (packets of "
              "wrong size encountered)", fail_counter);
        *wrong_size = TRUE;
    }

    rpc_get_buf_off(pco_iut, send_buf_off, buf_size, send_buf_local);
    rpc_get_buf_off(pco_tst, recv_buf_off, buf_size, recv_buf_local);
    if (memcmp(send_buf_local, recv_buf_local, buf_size) != 0)
        TEST_VERDICT("Received data did not match sent data");

    while ((recv_data = STAILQ_FIRST(&recv_cb_data)) != NULL)
    {
        STAILQ_REMOVE(&recv_cb_data, recv_data, size_and_seqn, links);
        free(recv_data);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *iut_addr = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    int                        tst_s = -1;
    int                        iut_s = -1;

    rpc_ptr_off               *send_buf_off = NULL;
    rpc_ptr_off               *recv_buf_off = NULL;

    uint8_t                   *send_buf_local = NULL;
    uint8_t                   *recv_buf_local = NULL;

    int                        i;
    int                        mtu;
    int                        recv_sid;
    csap_handle_t              recv_csap;
    int                        buf_size;
    int                        sz_first;
    int                        sz_last;
    te_bool                    first_zc;
    te_bool                    last_zc;
    te_bool                    set_nodelay;
    sockts_send_func           func;
    te_bool                    is_failed = FALSE;
    int                        packet_hdr_size;
    int                        max_payload_size;

    te_saved_mtus       iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus       tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);

    te_bool last_pkt_no_psh = FALSE;
    te_bool wrong_psh = FALSE;
    te_bool wrong_size = FALSE;
    int last_pkt_no_psh_cnt = 0;
    int wrong_psh_cnt = 0;
    int wrong_size_cnt = 0;

    TEST_START;

    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_INT_PARAM(mtu);
    TEST_GET_INT_PARAM(sz_first);
    TEST_GET_INT_PARAM(sz_last);
    TEST_GET_BOOL_PARAM(first_zc);
    TEST_GET_BOOL_PARAM(last_zc);
    TEST_GET_BOOL_PARAM(set_nodelay);
    SOCKTS_GET_SEND_FUNC_ID(func);

    /* Prepare buffers */
    buf_size = sz_first + sz_last;

    send_buf_local = (uint8_t *)tapi_calloc(buf_size, 1);
    recv_buf_local = (uint8_t *)tapi_calloc(buf_size, 1);

    if (!rpc_malloc_off(pco_iut, buf_size, &send_buf_off))
        TEST_VERDICT("Not enough memory on pco_iut");

    if (!rpc_malloc_off(pco_tst, buf_size, &recv_buf_off))
        TEST_VERDICT("Not enough memory on pco_tst");

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

    TEST_STEP("Set MTU to @p mtu on @p iut_if and @p tst_if.");
    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    mtu, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    mtu, &tst_mtus));

    CFG_WAIT_CHANGES;

    packet_hdr_size = sockts_ip_hdr_len_by_addr(iut_addr) + TEST_TCP_HDR_SIZE;

    if (getenv("DISABLE_TIMESTAMPS") != NULL)
        packet_hdr_size -= TEST_TCP_HDR_SIZE_TS;

    max_payload_size = mtu - packet_hdr_size;

    TEST_STEP("Establish TCP connection between sockets on IUT and "
              "Tester.");
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);

    TEST_STEP("Create a CSAP on Tester to check packets sent from IUT.");
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &recv_sid));
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, recv_sid,
        tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr),
        &recv_csap));

    CHECK_RC(rc = tapi_tad_trrecv_start(pco_tst->ta, recv_sid, recv_csap,
                                        NULL, TAD_TIMEOUT_INF, 0,
                                        RCF_TRRECV_PACKETS));

    if (set_nodelay)
    {
        TEST_STEP("If @p set_nodelay is @c TRUE, enable @c TCP_NODELAY "
                  "option on the IUT socket.");
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_NODELAY, 1);
        if (rc < 0)
        {
            TEST_VERDICT("setsockopt() failed to enable TCP_NODELAY, "
                         "errno=%r", RPC_ERRNO(pco_iut));
        }
    }

    /* Do not print out packets captured by CSAP. */
    rcf_tr_op_log(FALSE);

    TEST_STEP("For @c ATTEMPTS_NUM times:");
    for (i = 0; i < ATTEMPTS_NUM; i++)
    {
        RING("Attempt N%d", i);

        TEST_SUBSTEP("Call two times a sending function chosen according "
                     "to @p func, @p first_zc and @p last_zc, first time "
                     "passing @p sz_first bytes and @c MSG_MORE flag, "
                     "second time passing @p sz_last bytes without "
                     "@c MSG_MORE flag.");
        TEST_SUBSTEP("Receive data on Tester. Check with CSAP that only "
                     "the last packet has TCP PSH flag set, and previous "
                     "packets have maximum possible size. Increment fail "
                     "counters if something is not right.");

        check_msg_more(func, pco_iut, pco_tst, iut_s, tst_s, recv_sid,
                       recv_csap, first_zc, last_zc, sz_first, sz_last,
                       max_payload_size, send_buf_off, recv_buf_off,
                       send_buf_local, recv_buf_local, &last_pkt_no_psh,
                       &wrong_psh, &wrong_size);

        if (last_pkt_no_psh)
            last_pkt_no_psh_cnt++;
        if (wrong_psh)
            wrong_psh_cnt++;
        if (wrong_size)
            wrong_size_cnt++;
    }

    if (last_pkt_no_psh_cnt > 0)
    {
        WARN("In %d attempts of %d, TCP PSH flag was missed in the last "
             "packet", last_pkt_no_psh_cnt, ATTEMPTS_NUM);
        RING_VERDICT("TCP PSH flag is missed in the last packet");
    }

    TEST_STEP("Check that in no more than @c MAX_FAILS attempts "
              "TCP PSH flag was set not in the last packet.");

    if (wrong_psh_cnt > 0)
    {
        WARN("In %d attempts of %d, TCP PSH flag was set not in the last "
             "packet", wrong_psh_cnt, ATTEMPTS_NUM);
    }
    if (wrong_psh_cnt > MAX_FAILS)
    {
        ERROR_VERDICT("Too many times TCP PSH flag was used not in the "
                      "last packet");
        is_failed = TRUE;
    }

    TEST_STEP("Check that in no more than @c MAX_FAILS attempts "
              "incorrect packet size was observed.");

    if (wrong_size_cnt > 0)
    {
        WARN("In %d attempts of %d, packets of a wrong size were detected",
             wrong_size_cnt, ATTEMPTS_NUM);
    }
    if (wrong_size_cnt > MAX_FAILS)
    {
        ERROR_VERDICT("Too many times a packet with incorrect size was "
                      "sent");
        is_failed = TRUE;
    }

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (recv_csap != CSAP_INVALID_HANDLE)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, recv_sid,
                                               recv_csap));
    }

    if (tst_s >= 0)
        CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (iut_s >= 0)
        CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (send_buf_off != NULL)
        rpc_free_off(pco_iut, send_buf_off);
    if (recv_buf_off != NULL)
        rpc_free_off(pco_tst, recv_buf_off);

    if (send_buf_local != NULL)
        free(send_buf_local);
    if (recv_buf_local != NULL)
        free(recv_buf_local);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));

    TEST_END;
}
