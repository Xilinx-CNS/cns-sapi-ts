/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-zc_send_big_buf_complete Send big user buffer with onload_zc_send()
 *
 * @objective Check that if bigger than MTU user buffer is sent with
 *            @b onload_zc_send(), exactly one completion is got for it.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive
 *                          - @c tcp_passive_close
 * @param buf_size          Size of buffer to send:
 *                          - @c 5000
 *                          - @c 15000
 *
 * @type Conformance
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/zc_send_big_buf_complete"

#include "sockapi-test.h"

/** Data passed to CSAP callback */
typedef struct pkts_data {
    int           mss;              /**< TCP MSS value */
    int           pkts_num;         /**< Number of packets processed by
                                         callback */
    int           first_small_pkt;  /**< Index of the first packet which
                                         was smaller than MSS */
    te_bool       failed;           /**< Will be set to TRUE if there was
                                         a error during packets
                                         processing */
} pkts_data;

/**
 * Callback used to process packets captured by CSAP.
 *
 * @param pkt         Captured packet.
 * @param user_data   Pointer to pkts_data structure.
 */
static void
pkts_handler(asn_value *pkt, void *user_data)
{
    pkts_data *data = (pkts_data *)user_data;
    int        tcp_payload_len;

    if (data->failed)
        goto cleanup;

    tcp_payload_len = sockts_tcp_payload_len(pkt);
    if (tcp_payload_len < 0)
    {
        data->failed = TRUE;
        goto cleanup;
    }

    RING("Packet %d has %d bytes of payload", data->pkts_num,
         tcp_payload_len);

    if (tcp_payload_len < data->mss)
    {
        if (data->first_small_pkt < 0)
            data->first_small_pkt = data->pkts_num;

        RING("Packet %d is smaller than MSS", data->pkts_num);
    }

cleanup:
    data->pkts_num++;
    asn_free_value(pkt);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    sockts_socket_type         sock_type;

    int        iut_s  = -1;
    int        iut_l  = -1;
    int        tst_s  = -1;
    int        buf_size;

    rpc_msghdr           msg;
    rpc_iovec            iov = {NULL, 0, 0};
    struct rpc_pollfd    pfd;
    char                *recv_buf = NULL;
    size_t               recv_buf_size = 0;
    int                  mss;

    csap_handle_t             recv_csap = CSAP_INVALID_HANDLE;
    tapi_tad_trrecv_cb_data   cb_data;
    pkts_data                 data;
    te_bool                   test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(buf_size);

    recv_buf_size = buf_size * 2;
    recv_buf = tapi_calloc(1, recv_buf_size);

    iov.iov_base = tapi_calloc(1, buf_size);
    iov.iov_len = iov.iov_rlen = buf_size;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = msg.msg_riovlen = 1;

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, &iut_l);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    TEST_STEP("Create a CSAP on Tester to capture packets send from IUT.");
    CHECK_RC(tapi_tcp_ip_eth_csap_create(
        pco_tst->ta, 0,
        tst_if->if_name,
        TAD_ETH_RECV_DEF |
        TAD_ETH_RECV_NO_PROMISC,
        NULL, NULL,
        tst_addr->sa_family,
        TAD_SA2ARGS(tst_addr, iut_addr),
        &recv_csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, recv_csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Send the single user buffer of size @p buf_size from "
              "IUT socket with help of @b onload_zc_send(). RPC wrapper "
              "will expect the single completion event for the sent "
              "buffer.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_simple_zc_send_gen_msg(pco_iut, iut_s, &msg, 0, -1, TRUE);

    if (rc < 0)
    {
        TEST_VERDICT("onload_zc_send() unexpectedly failed with error "
                     RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }
    else if (rc != buf_size)
    {
        TEST_VERDICT("onload_zc_send() did not send expected number of "
                     "bytes");
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Receive and check the data on peer.");
    RPC_AWAIT_ERROR(pco_tst);
    rc = rpc_recv(pco_tst, tst_s, recv_buf, recv_buf_size, 0);
    SOCKTS_CHECK_RECV(pco_tst, iov.iov_base, recv_buf, buf_size, rc);

    TEST_STEP("Check that all packets captured by the CSAP on Tester "
              "except the last one contain MSS bytes of payload.");

    memset(&data, 0, sizeof(data));
    data.mss = mss;
    data.first_small_pkt = -1;
    data.failed = FALSE;

    memset(&cb_data, 0, sizeof(cb_data));
    cb_data.callback = &pkts_handler;
    cb_data.user_data = &data;
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, recv_csap,
                                  &cb_data, NULL));

    test_failed = TRUE;
    if (data.failed)
    {
        ERROR_VERDICT("Failed to process packets captured by CSAP");
    }
    else if (data.pkts_num == 0)
    {
        ERROR_VERDICT("CSAP has not captured any packets");
    }
    else if (data.first_small_pkt >= 0 &&
             data.first_small_pkt < data.pkts_num - 1)
    {
        ERROR_VERDICT("Some packet(s) (except the last) was smaller "
                      "than MSS");
    }
    else
    {
        test_failed = FALSE;
    }

    TEST_STEP("Check that @b poll(@c POLLERR) returns no events on IUT "
              "socket, i.e. that there is no unprocessed completion events "
              "left.");
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = iut_s;
    pfd.events = RPC_POLLERR;
    rc = rpc_poll(pco_iut, &pfd, 1, TAPI_WAIT_NETWORK_DELAY);
    if (rc < 0)
    {
        TEST_VERDICT("poll(POLLERR) failed with %r on IUT socket after "
                     "sending data", RPC_ERRNO(pco_iut));
    }
    else if (rc > 0)
    {
        TEST_VERDICT("poll(POLLERR) returned positive result on IUT socket "
                     "after sending data");
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(recv_buf);
    free(iov.iov_base);

    if (recv_csap != CSAP_INVALID_HANDLE)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, recv_csap));
    }

    TEST_END;
}
