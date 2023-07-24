/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Timestamps
 */

/** @page timestamps-ts_tcp_re  TX TCP timestamps with retransmissions
 *
 * @objective Check retransmissions influence on TX TCP timestamps
 *            retrieving.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TESTER
 * @param iomux      I/O multiplexing function type
 * @param onload_ext Onload extension TCP timestamps
 * @param use_tx_ack Use SOF_TIMESTAMPING_TX_SOFTWARE timestamping flag
 * @param select_err_queue  Set SO_SELECT_ERR_QUEUE socket option
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_tcp_re"

#include "sockapi-test.h"
#include "timestamps.h"
#include "iomux.h"
#include "onload.h"
#include "tapi_route_gw.h"

/** Timeout between iterations in usec. */
#define ITERATION_TIMEOUT 100000

/** How long ACK from peer should be blocked, in microseconds. */
#define BLOCK_ACK_TIME TE_SEC2US(2)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_gw = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    iomux_call_type            iomux;
    te_bool                    use_tx_ack;
    te_bool                    onload_ext;
    te_bool                    select_err_queue;

    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;
    const void             *tst_alien_link_addr;
    te_bool                route1_set = FALSE;
    te_bool                route2_set = FALSE;
    rpc_socket_domain      domain;
    int                    acc_s = -1;
    long int               exp_delay = 0;
    long int               real_delay = 0;
    long int               time_limit = 0;

    struct timeval tv_start;
    struct timeval tv_end;

    rpc_onload_scm_timestamping_stream *ts_tx;
    rpc_scm_timestamping *ts_ack = NULL;
    struct cmsghdr *cmsg = NULL;
    iomux_evt_fd    event;
    tarpc_timeval   timeout = {.tv_sec = 0, .tv_usec = 0};
    struct timespec ts;
    rpc_msghdr      msg;
    void           *tx_buf = NULL;
    size_t          buf_len;
    te_bool         vlan = FALSE;
    te_bool         blocked_ack = FALSE;
    te_bool         zero_reported = FALSE;

    int iut_s = -1;
    int tst_s = -1;
    int rets  = 0;
    int flags;
    int exp_ev;
    int exp_rc;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_PCO(pco_gw);
    TEST_GET_ADDR_NO_PORT(gw_iut_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst_addr);
    TEST_GET_LINK_ADDR(tst_alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_BOOL_PARAM(use_tx_ack);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_BOOL_PARAM(select_err_queue);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    tx_buf = sockts_make_buf_stream(&buf_len);
    ts_init_msghdr(TRUE, &msg, buf_len + 300);

    TEST_STEP("Turn on forwarding on router host.");
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    TEST_STEP("Add route on 'pco_iut': 'tst_addr' via gateway 'gw_iut_addr'");
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
                            tst_addr->sa_family,
                            te_sockaddr_get_netaddr(tst_addr),
                            te_netaddr_get_size(tst_addr->sa_family) * 8,
                            te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
        TEST_FAIL("Cannot add route to the dst");
    route1_set = TRUE;

    TEST_STEP("Add route on 'pco_tst': 'iut_addr' via gateway 'gw_tst_addr'.");
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
                            iut_addr->sa_family,
                            te_sockaddr_get_netaddr(iut_addr),
                            te_netaddr_get_size(iut_addr->sa_family) * 8,
                            te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
        TEST_FAIL("Cannot add route to the src");
    route2_set = TRUE;
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create TCP connection between IUT and tester.");
    domain = rpc_socket_domain_by_addr(iut_addr);
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    TEST_STEP("Enable TCP TX HW timestamps.");
    flags = RPC_SOF_TIMESTAMPING_TX_HARDWARE |
            RPC_SOF_TIMESTAMPING_TX_SOFTWARE |
            RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE;

    if (use_tx_ack)
    {
        if (!tapi_getenv_bool("IUT_TS_TX_ACK"))
        {
            RING("Option SOF_TIMESTAMPING_TX_ACK is not supported");
            TEST_SUCCESS;
        }
        flags |= RPC_SOF_TIMESTAMPING_TX_ACK;
    }

    if (onload_ext)
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    if (!tapi_onload_run())
        flags |= RPC_SOF_TIMESTAMPING_OPT_TX_SWHW;

    rpc_setsockopt(pco_iut, iut_s, RPC_SO_TIMESTAMPING, &flags);
    if (select_err_queue)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SELECT_ERR_QUEUE, 1);

    TEST_STEP("Prevent ACKs receiving by IUT to initiate packet retransmission.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             gw_tst_addr, CVT_HW_ADDR(tst_alien_link_addr),
                             TRUE));
    blocked_ack = TRUE;

    exp_ev = iomux_init_rd_error(&event, iut_s, iomux, select_err_queue,
                                 &exp_rc);
    /** Linux bug (see bug 56326): SO_SELECT_ERR_QUEUE does not work
     *  for TCP. */
    if (select_err_queue && !tapi_onload_run())
    {
        exp_rc = 1;
        if (iomux == IC_SELECT || iomux == IC_PSELECT)
            exp_ev = EVT_RD;
        else
            exp_ev = EVT_EXC | EVT_ERR;
    }

    TEST_STEP("Send a packet.");
    rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);

    rc = gettimeofday(&tv_start, NULL);
    if (rc < 0)
        TEST_FAIL("gettimeofday() failed");

    /* Check if TX TCP tmestamp is supported. */
    if (!onload_ext && !ts_any_event(TRUE, RPC_SOCK_STREAM))
    {
        timeout.tv_usec = 500000;
        IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
        if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_VERDICT("recvmsg() had to fail with EAGAIN");
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw_tst_addr);
        TEST_SUCCESS;
    }

    time_limit = BLOCK_ACK_TIME;

    TEST_STEP("Try to read timestamps in a loop, repeatedly calling "
              "@p iomux and recvmsg().");
    while (TRUE)
    {
        usleep(ITERATION_TIMEOUT);

        rc = gettimeofday(&tv_end, NULL);
        if (rc < 0)
            TEST_FAIL("gettimeofday() failed");

        TEST_SUBSTEP("Allow ACK transmission to IUT after at least @c BLOCK_ACK_TIME "
                     "microseconds passed. After that wait for at most the same time "
                     "until ACK from peer is received on IUT (and expected "
                     "timestamp/event is observed).");
        if (TIMEVAL_SUB(tv_end, tv_start) >= time_limit)
        {
            if (blocked_ack)
            {
                tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                         gw_tst_addr);
                blocked_ack = FALSE;
                time_limit = TIMEVAL_SUB(tv_end, tv_start) * 2;
            }
            else
            {
                TEST_FAIL("Maximum attempts number was achieved, timestamp "
                          "does not reveal packet retransmission");
            }
        }

        memset(msg.msg_control, 0, SOCKTS_CMSG_LEN);
        msg.msg_controllen = SOCKTS_CMSG_LEN;

        if (onload_ext)
        {
            TEST_SUBSTEP("If @p onload_ext is @c TRUE, leave the loop as soon "
                         "as last_sent field is updated.");
            if (blocked_ack)
            {
                IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
            }
            else
            {
                timeout.tv_sec = 8;
                IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                                iomux_call(iomux, pco_iut, &event, 1, &timeout));
            }
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
            if (rc < 0 && RPC_ERRNO(pco_iut) != RPC_EAGAIN)
                TEST_FAIL("recvmsg failed with unexpected error %s",
                          errno_rpc2str(RPC_ERRNO(pco_iut)));
            if (rc < 0)
                continue;

            if (rc != 0)
                TEST_VERDICT("recvmsg() returned more than 0 bytes for TX "
                             "with TCP");

            if (blocked_ack)
                TEST_VERDICT("recvmsg() returned an event before ACK was "
                             "received");

            cmsg = sockts_msg_lookup_control_data(&msg, SOL_SOCKET,
                             sockopt_rpc2h(RPC_ONLOAD_SCM_TIMESTAMPING_STREAM));
            if (cmsg == NULL)
            {
                if (msg.msg_controllen > 0)
                    TEST_FAIL("Obtained cmsg has unexpected type %d");
                TEST_FAIL("cmsg was not found");
            }

            ts_tx = (rpc_onload_scm_timestamping_stream *)CMSG_DATA(cmsg);
            ts_print_tcp_tx(ts_tx);

            if (ts_tx->len != buf_len)
                TEST_VERDICT("TCP segment length is not equal to the sent "
                             "packet length");

            if (ts_timespec_is_zero(&ts_tx->last_sent) == FALSE)
                break;
        }
        else
        {
            TEST_SUBSTEP("Otherwise leave the loop as soon as @p iomux "
                         "reports an event after repairing network connection "
                         "from Tester to IUT.");
            rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
            if (rc > 0)
            {
                rets++;
                if (event.revents != exp_ev)
                    ERROR_VERDICT("Iomux function returned unexpected events");

                rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
                ts_check_cmsghdr(&msg, rc, buf_len, tx_buf, TRUE,
                                 RPC_SOCK_STREAM, FALSE, vlan, &ts, NULL);
                ts_check_second_cmsghdr(pco_iut, iut_s, NULL, NULL, NULL,
                                        NULL, FALSE, &zero_reported, NULL);
            }

            if (!blocked_ack && rc != 0)
            {
                if (use_tx_ack)
                {
                    timeout.tv_sec = 8;
                    IOMUX_CHECK_EXP(exp_rc, exp_ev, event,
                                    iomux_call(iomux, pco_iut, &event, 1,
                                               &timeout));

                    memset(msg.msg_control, 0, SOCKTS_CMSG_LEN);
                    msg.msg_controllen = SOCKTS_CMSG_LEN;
                    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
                    ts_ack = ts_get_tx_ack_ts(&msg, rc, buf_len, tx_buf);
                }

                break;
            }
        }
    }

    rc = gettimeofday(&tv_end, NULL);
    if (rc < 0)
        TEST_FAIL("gettimeofday() failed");

    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    IOMUX_CHECK_ZERO(iomux_call(iomux, pco_iut, &event, 1, &timeout));
    if (tapi_onload_run())
        rpc_system(pco_iut, "te_onload_stdump tcp_stats");

    if (onload_ext)
    {
        TEST_STEP("If @p onload_ext: check that value in the field first_sent is "
                  "less than in @b last_sent. Also check that difference between "
                  "these fields is about the same as total time spent in a loop.");

        exp_delay = TIMEVAL_SUB(tv_end, tv_start);
        real_delay = ts_timespec_diff_us(&ts_tx->last_sent,
                                         &ts_tx->first_sent);

        RING("first_sent %lu s %lu ns; last_sent %lu s %lu ns; "
             "difference %ld us; expected difference %ld us",
             ts_tx->first_sent.tv_sec, ts_tx->first_sent.tv_nsec,
             ts_tx->last_sent.tv_sec, ts_tx->last_sent.tv_nsec,
             real_delay, exp_delay);

        if (ts_cmp(&ts_tx->first_sent, &ts_tx->last_sent) >= 0)
            TEST_VERDICT("last_sent is less or equal to first_sent "
                         "timestamp value");

        if (real_delay < exp_delay * 0.9 || real_delay > exp_delay * 1.1)
            TEST_VERDICT("last_sent differs too much from the first_sent "
                         "timestamp value");
    }
    else
    {
        TEST_STEP("Otherwise check that timestamps of retransmitted "
                  "packets were detected.");
        if (rets < 2)
            TEST_VERDICT("Retransmit packet timestamp is not observed");

        TEST_STEP("In case of @p use_tx_ack, check also that timestamp of "
                  "ACK does not differ much from timestamp of the last "
                  "retransmitted packet.");
        if (use_tx_ack)
        {
            RING("Sent packet ACK waiting time %lld microseconds",
                 ts_timespec_diff_us(&ts, &ts_ack->systime));
            if (ts_check_deviation(&ts, &ts_ack->systime, 0,
                                   500000))
                TEST_VERDICT("TCP ACK timestamp differs too much");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (route1_set)
    {
        if (tapi_cfg_del_route_via_gw(pco_iut->ta,
            tst_addr->sa_family,
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(tst_addr->sa_family) * 8,
            te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
        {
            ERROR("Cannot delete first route");
            result = EXIT_FAILURE;
        }
    }

    if (route2_set)
    {
        if (tapi_cfg_del_route_via_gw(pco_tst->ta,
            iut_addr->sa_family,
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(iut_addr->sa_family) * 8,
            te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
        {
            ERROR("Cannot delete second route");
            result = EXIT_FAILURE;
        }
    }

    free(tx_buf);
    sockts_release_msghdr(&msg);

    TEST_END;
}
