/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TCP Test Suite
 *
 * Implementation of TAPI for checking TCP Initial Sequence Numbers.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#include "tcp_isn_check.h"

/**
 * Handler for processing IUT packets captured by CSAP.
 *
 * @param pkt         Captured packet.
 * @param user_data   Pointer to sockts_isn_pkt_data structure.
 */
static void
iut_pkts_handler(asn_value *pkt, void *user_data)
{
    uint32_t flags;
    uint32_t seqn;
    uint32_t ackn;
    int      rc;

    sockts_isn_pkt_data *data = (sockts_isn_pkt_data *)user_data;

    if (data->failed)
        goto cleanup;

    rc = asn_read_uint32(pkt, &seqn,
                         "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("Failed to get SEQN: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    rc = asn_read_uint32(pkt, &ackn,
                         "pdus.0.#tcp.ackn");
    if (rc != 0)
    {
        ERROR("Failed to get ACKN: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    data->seqn = seqn;
    data->ackn = ackn;

    rc = asn_read_uint32(pkt, &flags,
                         "pdus.0.#tcp.flags");
    if (rc != 0)
    {
        ERROR("Failed to get TCP flags: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if (flags & TCP_SYN_FLAG)
    {
        data->isn = seqn;
        if (sockts_get_csap_pkt_ts(pkt, &data->isn_tv) != 0)
        {
            data->failed = TRUE;
            goto cleanup;
        }
        data->isn_captured = TRUE;
    }

cleanup:

    asn_free_value(pkt);
}

/* See description in tcp_isn_check.h */
void
sockts_isn_conn_init(rcf_rpc_server *pco_iut,
                     rcf_rpc_server *pco_tst,
                     const struct sockaddr *iut_addr,
                     const struct sockaddr *tst_addr,
                     const struct sockaddr *iut_lladdr,
                     const struct sockaddr *tst_lladdr,
                     const struct if_nameindex *iut_if,
                     const struct if_nameindex *tst_if,
                     sockts_isn_conn *conn)
{
    memset(conn, 0, sizeof(*conn));
    conn->iut_s = -1;
    conn->tst_s = -1;
    conn->listener_s = -1;

    conn->pco_iut = pco_iut;
    conn->pco_tst = pco_tst;
    conn->iut_addr = iut_addr;
    conn->tst_addr = tst_addr;
    conn->iut_lladdr = iut_lladdr;
    conn->tst_lladdr = tst_lladdr;
    conn->iut_if = iut_if;
    conn->tst_if = tst_if;

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                                     pco_iut->ta, 0, iut_if->if_name,
                                     TAD_ETH_RECV_DEF |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (const uint8_t *)iut_lladdr->sa_data,
                                     (const uint8_t *)tst_lladdr->sa_data,
                                     iut_addr->sa_family,
                                     TAD_SA2ARGS(iut_addr, tst_addr),
                                     &conn->iut_send_csap));

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                                     pco_tst->ta, 0, tst_if->if_name,
                                     TAD_ETH_RECV_DEF |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (const uint8_t *)tst_lladdr->sa_data,
                                     (const uint8_t *)iut_lladdr->sa_data,
                                     tst_addr->sa_family,
                                     TAD_SA2ARGS(tst_addr, iut_addr),
                                     &conn->tst_recv_csap));

    CHECK_RC(tapi_tcp_template((iut_addr->sa_family == AF_INET6), 0, 0,
                               FALSE, TRUE, NULL, 0, &conn->rst_tmpl));

    memset(&conn->cb_data, 0, sizeof(conn->cb_data));
    conn->cb_data.callback = &iut_pkts_handler;
    conn->cb_data.user_data = &conn->pkt_data;
}

/* See description in tcp_isn_check.h */
void
sockts_isn_conn_establish(sockts_isn_conn *conn, te_bool iut_passive)
{
    rcf_rpc_server        *rpcs_srv;
    rcf_rpc_server        *rpcs_clnt;
    const struct sockaddr *srv_addr;
    const struct sockaddr *clnt_addr;
    int                    conn_s;
    int                    acc_s;

    if (conn->iut_passive != iut_passive && conn->listener_s >= 0)
    {
        RPC_CLOSE(conn->iut_passive ? conn->pco_iut : conn->pco_tst,
                  conn->listener_s);
    }
    conn->iut_passive = iut_passive;

    if (iut_passive)
    {
        rpcs_srv = conn->pco_iut;
        rpcs_clnt = conn->pco_tst;
        srv_addr = conn->iut_addr;
        clnt_addr = conn->tst_addr;
    }
    else
    {
        rpcs_srv = conn->pco_tst;
        rpcs_clnt = conn->pco_iut;
        srv_addr = conn->tst_addr;
        clnt_addr = conn->iut_addr;
    }

    if (conn->listener_s < 0)
    {
        conn->listener_s = rpc_socket(rpcs_srv,
                                      rpc_socket_domain_by_addr(srv_addr),
                                      RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(rpcs_srv, conn->listener_s, srv_addr);
        rpc_listen(rpcs_srv, conn->listener_s, SOCKTS_BACKLOG_DEF);
    }

    CHECK_RC(tapi_tad_trrecv_start(conn->pco_tst->ta, 0,
                                   conn->tst_recv_csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    conn_s = rpc_socket(rpcs_clnt,
                        rpc_socket_domain_by_addr(clnt_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(rpcs_clnt, conn_s, clnt_addr);

    rpc_connect(rpcs_clnt, conn_s, srv_addr);

    acc_s = rpc_accept(rpcs_srv, conn->listener_s, NULL, NULL);

    if (iut_passive)
    {
        conn->tst_s = conn_s;
        conn->iut_s = acc_s;
    }
    else
    {
        conn->tst_s = acc_s;
        conn->iut_s = conn_s;
    }

    memset(&conn->pkt_data, 0, sizeof(sockts_isn_pkt_data));
    CHECK_RC(tapi_tad_trrecv_stop(conn->pco_tst->ta, 0,
                                  conn->tst_recv_csap,
                                  &conn->cb_data, NULL));
}

/* See description in tcp_isn_check.h */
void
sockts_isn_conn_terminate(sockts_isn_conn *conn)
{
    CHECK_RC(tapi_tad_trrecv_start(conn->pco_tst->ta, 0,
                                   conn->tst_recv_csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    RPC_CLOSE(conn->pco_tst, conn->tst_s);
    TAPI_WAIT_NETWORK;
    RPC_CLOSE(conn->pco_iut, conn->iut_s);
    TAPI_WAIT_NETWORK;

    CHECK_RC(tapi_tad_trrecv_stop(conn->pco_tst->ta, 0,
                                  conn->tst_recv_csap,
                                  &conn->cb_data, NULL));

    if (conn->iut_passive)
    {
        CHECK_RC(asn_write_uint32(conn->rst_tmpl, conn->pkt_data.seqn,
                                  "pdus.0.#tcp.seqn.#plain"));
        CHECK_RC(asn_write_uint32(conn->rst_tmpl, conn->pkt_data.ackn,
                                  "pdus.0.#tcp.ackn.#plain"));
        CHECK_RC(tapi_tad_trsend_start(conn->pco_iut->ta, 0,
                                       conn->iut_send_csap,
                                       conn->rst_tmpl,
                                       RCF_MODE_BLOCKING));
        TAPI_WAIT_NETWORK;
    }
}

/* See description in tcp_isn_check.h */
void
sockts_isn_conn_cleanup(sockts_isn_conn *conn)
{
    if (conn->iut_s >= 0)
        RPC_CLOSE(conn->pco_iut, conn->iut_s);
    if (conn->tst_s >= 0)
        RPC_CLOSE(conn->pco_tst, conn->tst_s);

    if (conn->listener_s >= 0)
    {
        RPC_CLOSE(conn->iut_passive ? conn->pco_iut : conn->pco_tst,
                  conn->listener_s);
    }

    if (conn->tst_recv_csap != CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tad_csap_destroy(conn->pco_tst->ta, 0,
                                       conn->tst_recv_csap));
    }

    if (conn->iut_send_csap != CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tad_csap_destroy(conn->pco_iut->ta, 0,
                                       conn->iut_send_csap));
    }

    if (conn->rst_tmpl != NULL)
        asn_free_value(conn->rst_tmpl);
}

/* See description in tcp_isn_check.h */
void
sockts_isn_conn_send(sockts_isn_conn *conn,
                     size_t send_size,
                     int timeout)
{
    tapi_pat_sender      sender_ctx;
    tapi_pat_receiver    receiver_ctx;
    tarpc_pat_gen_arg   *lcg_arg = NULL;
    double               speed;

    /*
     * These should be big enough to ensure that speed of
     * sending is fast enough to outrun ISN counter.
     */
    const int            min_send_size = 2048;
    const int            max_send_size = 4096;

    tapi_pat_sender_init(&sender_ctx);
    sender_ctx.gen_func = RPC_PATTERN_GEN_LCG;
    tapi_rand_gen_set(&sender_ctx.size,
                      min_send_size, max_send_size, FALSE);
    sender_ctx.duration_sec = timeout;
    sender_ctx.total_size = send_size;

    lcg_arg = &sender_ctx.gen_arg;
    lcg_arg->offset = 0;
    lcg_arg->coef1 = rand_range(0, RAND_MAX);
    lcg_arg->coef2 = rand_range(1, RAND_MAX);
    lcg_arg->coef3 = rand_range(0, RAND_MAX);

    tapi_pat_receiver_init(&receiver_ctx);
    receiver_ctx.gen_func = RPC_PATTERN_GEN_LCG;
    receiver_ctx.duration_sec = timeout + 1;
    receiver_ctx.exp_received = sender_ctx.total_size;
    receiver_ctx.gen_arg_ptr = lcg_arg;

    conn->pco_tst->op = RCF_RPC_CALL;
    rpc_pattern_receiver(conn->pco_tst, conn->tst_s, &receiver_ctx);

    rpc_pattern_sender(conn->pco_iut, conn->iut_s, &sender_ctx);

    rpc_pattern_receiver(conn->pco_tst, conn->tst_s, &receiver_ctx);

    if (sender_ctx.sent != send_size)
        TEST_FAIL("Not all the requested data was sent");

    if (receiver_ctx.received != sender_ctx.sent)
    {
        TEST_FAIL("Amount of data received on Tester does not match "
                  "amount of data sent from IUT");
    }

    speed = (double)send_size / (double)conn->pco_tst->duration;
    speed *= 1000000.0;

    RING("Data sending speed was %f bytes/second", speed);
}

/* See description in tcp_isn_check.h */
te_errno
sockts_isn_conn_get_isn(sockts_isn_conn *conn, uint32_t *isn)
{
    if (!conn->pkt_data.isn_captured)
        return TE_ENODATA;

    *isn = conn->pkt_data.isn;
    return 0;
}

/* See description in tcp_isn_check.h */
te_errno
sockts_isn_conn_get_isn_ts(sockts_isn_conn *conn, struct timeval *isn_tv)
{
    if (!conn->pkt_data.isn_captured)
        return TE_ENODATA;

    memcpy(isn_tv, &conn->pkt_data.isn_tv, sizeof(*isn_tv));
    return 0;
}

/* See description in tcp_isn_check.h */
te_errno
sockts_isn_conn_get_last_seqn(sockts_isn_conn *conn, uint32_t *seqn)
{
    if (!conn->pkt_data.isn_captured)
        return TE_ENODATA;

    *seqn = conn->pkt_data.seqn;
    return 0;
}
