/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 * 
 * $Id$
 */

/** @page timestamps-ts_states  Enable timestamps in different socket state
 *
 * @objective Check that HW timestamps can be enabled in any different
 *            states.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on IUT
 * @param pco_tst   PCO on TESTER
 * @param tx        Determine is it TX or RX packet handling
 * @param sock_type Socket type
 * @param state     Determines when setsockopt(SO_TIMESTAMPING) will be called
 * @param sendto    Use sendto() function to send packet if @c TRUE
 * @param onload_ext Onload extension TCP timestamps
 * 
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_states"

#include "sockapi-test.h"
#include "timestamps.h"

#define MAX_ATTEMPTS 10

/**
 * Enumeration to determine calls sequence.
 */
typedef enum {
    STATE_FRESH = 0,     /**< Set options immediately after socket
                              creation */
    STATE_BIND,          /**< Set options after binding */
    STATE_CONNECT,       /**< Set options after connect() */
    STATE_LISTEN,        /**< Set options after listen() */
    STATE_ACCEPT,        /**< Set options after accept() */
} socket_state_type;

#define SOCKET_STATE  \
    { "fresh", STATE_FRESH },   \
    { "bind", STATE_BIND },     \
    { "connect", STATE_CONNECT }, \
    { "listen", STATE_LISTEN }, \
    { "accept", STATE_ACCEPT }

int
main(int argc, char *argv[])
{
    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr;
    const struct if_nameindex *iut_if = NULL;

    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    socket_state_type  state;
    rpc_socket_type    sock_type;
    te_bool            tx;
    te_bool            sendto;
    te_bool            onload_ext;
    struct timespec    ts;
    struct timespec    ts_h;
    tarpc_timeval      tv_h = {.tv_sec = 0, .tv_usec = 0};

    rpc_msghdr  msg = {.msg_iov = NULL, .msg_control = NULL};
    void       *tx_buf = NULL;
    size_t     buf_len;
    int        flags;
    int        iut_s = -1;
    int        tst_s = -1;
    int        acc_s = -1;
    int        domain;
    te_bool    vlan = FALSE;
    te_bool    zero_reported = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ENUM_PARAM(state, SOCKET_STATE);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(tx);
    TEST_GET_BOOL_PARAM(sendto);
    TEST_GET_BOOL_PARAM(onload_ext);
    TEST_GET_IF(iut_if);

    vlan = ts_check_vlan(pco_iut, iut_if->if_name);

    tx_buf = sockts_make_buf_stream(&buf_len);
    ts_init_msghdr(tx, &msg, buf_len + 300);

    flags = RPC_SOF_TIMESTAMPING_RAW_HARDWARE |
            RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
            RPC_SOF_TIMESTAMPING_SOFTWARE;

    if (tx)
    {
        flags |= RPC_SOF_TIMESTAMPING_TX_HARDWARE |
                 RPC_SOF_TIMESTAMPING_TX_SOFTWARE;
        if (sock_type == RPC_SOCK_STREAM && onload_ext)
            flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;
    }
    else
        flags |= RPC_SOF_TIMESTAMPING_RX_HARDWARE |
                 RPC_SOF_TIMESTAMPING_RX_SOFTWARE;
    if (!tapi_onload_run())
        flags |= RPC_SOF_TIMESTAMPING_OPT_TX_SWHW;

    TEST_STEP("Create TCP connection between IUT and tester.");
    domain = rpc_socket_domain_by_addr(iut_addr);
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    TEST_STEP("The place, where setsockopt() to enable TCP TX HW timestamps will "
              "be called, is determined by parameter @p state.");
#define ENABLE_TS(_state) \
do {                                                                 \
    if (state == _state)                                             \
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_TIMESTAMPING, &flags); \
} while (0)

    ENABLE_TS(STATE_FRESH);

    rpc_bind(pco_iut, iut_s, iut_addr);
    ENABLE_TS(STATE_BIND);

    tst_s = rpc_socket(pco_tst, domain, sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        if (state == STATE_LISTEN || state == STATE_ACCEPT)
        {
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            ENABLE_TS(STATE_LISTEN);
            rpc_connect(pco_tst, tst_s, iut_addr);
            acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
            RPC_CLOSE(pco_iut, iut_s);
            iut_s = acc_s;
            ENABLE_TS(STATE_ACCEPT);
        }
        else
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
            rpc_connect(pco_iut, iut_s, tst_addr);
            ENABLE_TS(STATE_CONNECT);
            acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
            RPC_CLOSE(pco_tst, tst_s);
            tst_s = acc_s;
        }
    }
    else
    {
        rpc_connect(pco_tst, tst_s, iut_addr);
        if (!sendto || state == STATE_CONNECT)
        {
            rpc_connect(pco_iut, iut_s, tst_addr);
            ENABLE_TS(STATE_CONNECT);
        }
    }

    TEST_STEP("Send a packet from IUT if @p tx is @c TRUE, else from the tester.");
    rpc_gettimeofday(pco_iut, &tv_h, NULL);
    if (tx)
    {
        if (sendto)
            rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0, tst_addr);
        else
            rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    }
    else
        rpc_send(pco_tst, tst_s, tx_buf, buf_len, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Retrieve timestamp.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, tx ? RPC_MSG_ERRQUEUE : 0);
    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_FAIL("recvmsg failed with unexpected error %s",
                      errno_rpc2str(RPC_ERRNO(pco_iut)));
        if (!ts_any_event(tx, sock_type) && !onload_ext)
            TEST_SUCCESS;

        TEST_VERDICT("Timestamp was not retrieved");
    }

    TEST_STEP("Check timestamp values.");
    TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
    ts_check_cmsghdr(&msg, rc, buf_len, tx_buf, tx, sock_type, onload_ext,
                     vlan, &ts, &ts_h);
    ts_check_deviation(&ts, &ts_h, 0, 500000);
    if (tx)
    {
        TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
        ts_check_second_cmsghdr(pco_iut, iut_s, NULL, &ts_h, NULL, NULL,
                                FALSE, &zero_reported, NULL);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(tx_buf);
    sockts_release_msghdr(&msg);

    TEST_END;
}
