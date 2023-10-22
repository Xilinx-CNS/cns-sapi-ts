/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2023 Advanced Micro Devices, Inc. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-send_retrans_fail Test send functions when TCP retransmission
 *                              fails
 *
 * @objective Check error code/message after TCP send retransmission fails,
 *            for different send functions. The test iterates all the
 *            possible send functions, especially extension ones. It also
 *            iterates various ways for a TCP send retransmission to fail.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param send_func         Send function
 * @param retrans_fail_way  How TCP retransmission should fail:
 *                          - @c rto - standard timeout
 *                          - @c user_timeout - socket option TCP_USER_TIMEOUT
 *                          - @c rst - incoming RST signal
 *
 * @par Scenario:
 *
 * @author Boris Shleyfman <bshleyfman@oktet.co.il>
 */

#define TE_TEST_NAME  "tcp/send_retrans_fail"

#include "sockapi-test.h"

#include "tcp_test_macros.h"
#include "tapi_route_gw.h"
#include "tapi_proc.h"
#include "tapi_tcp.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_sockaddr.h"

#define PAYLOAD_LEN          100

/** Value for socket option @c TCP_USER_TIMEOUT, in seconds */
#define TCP_USER_TO          4

/** Retransmission number for RTO */
#define RETRIES_NUM 3
/**
 * Sleeping time in seconds to get the connection dropped by retransmits
 * (in case RTO); depends on @c RETRIES_NUM
 */
#define RTO_TIMEOUT 10

/**
 * How TCP retransmission should fail.
 */
typedef enum {
    RETRANS_FAIL_WAY_RTO,              /**< Standard timeout */
    RETRANS_FAIL_WAY_USER_TIMEOUT,     /**< Socket option @c TCP_USER_TIMEOUT */
    RETRANS_FAIL_WAY_RST               /**< Incoming RST signal */
} retrans_fail_way_t;

#define RETRANS_FAIL_WAY \
    { "rto", RETRANS_FAIL_WAY_RTO },                           \
    { "user_timeout", RETRANS_FAIL_WAY_USER_TIMEOUT },         \
    { "rst", RETRANS_FAIL_WAY_RST }

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;

    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;

    const void                *alien_link_addr = NULL;
    const char                *tcp_ca_state_seq;

    tsa_session               ss = TSA_SESSION_INITIALIZER;

    rpc_send_f                send_func;
    retrans_fail_way_t        retrans_fail_way;

    char                      tx_buf[PAYLOAD_LEN];

    int                       iut_s = -1;
    int                       ret;
    int                       tcp_retries_n;
    ssize_t                   n_bytes;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);

    TEST_GET_SEND_FUNC(send_func);
    TEST_GET_ENUM_PARAM(retrans_fail_way, RETRANS_FAIL_WAY);

    if (retrans_fail_way == RETRANS_FAIL_WAY_RTO)
    {
        TEST_STEP("If @p retrans_fail_way is @c rto, set retransmission "
                  "number on IUT to @c RETRIES_NUM.");
        CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &tcp_retries_n,
                                         "net/ipv4/tcp_retries2"));
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRIES_NUM, NULL,
                                         "net/ipv4/tcp_retries2"));
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }

    TEST_STEP("Initialize TSA session");
    CHECK_RC(tsa_state_init(&ss, TSA_TST_CSAP));
    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr,
                         ((struct sockaddr *)alien_link_addr)->sa_data));
    CFG_WAIT_CHANGES;

    CHECK_RC(tsa_create_session(&ss, 0));

    TEST_STEP("Emulate an established TCP connection between IUT and TST.");
    tcp_move_to_state(&ss, RPC_TCP_ESTABLISHED, OL_ACTIVE, FALSE);
    iut_s = tsa_iut_sock(&ss);
    if (iut_s == -1)
        TEST_FAIL("Couldn't get socket from tsa_create_session()");

    if (retrans_fail_way == RETRANS_FAIL_WAY_USER_TIMEOUT)
    {
        TEST_STEP("If @p retrans_fail_way is @c user_timeout, set "
                  "@c TCP_USER_TIMEOUT option for IUT socket.");
        RPC_AWAIT_ERROR(pco_iut);
        ret = rpc_setsockopt_int(pco_iut, iut_s, RPC_TCP_USER_TIMEOUT,
                                 TE_SEC2MS(TCP_USER_TO));
        if (ret < 0)
        {
            TEST_VERDICT("setsockopt() failed to enable TCP_USER_TIMEOUT, "
                         "errno=%r", RPC_ERRNO(pco_iut));
        }
    }

    TEST_STEP("Send a TCP packet from IUT to TST using some send"
              " function.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    n_bytes = send_func(pco_iut, iut_s, tx_buf, PAYLOAD_LEN, 0);
    if (n_bytes < 0)
    {
        TEST_VERDICT("send_func() failed with errno %r", RPC_ERRNO(pco_iut));
    }
    if (n_bytes != PAYLOAD_LEN)
    {
        WARN("%d bytes were sent, instead of %d", n_bytes, PAYLOAD_LEN);
        TEST_VERDICT("Incorrect number of bytes were sent");
    }
    TAPI_WAIT_NETWORK;

    TEST_STEP("Make TCP send retransmission fail.\n"
              "If @p retrans_fail_way is @c rst, send RST from TST to "
              "IUT.\n"
              "Otherwise, wait until TCP stops trying to retransmit the "
              "packet.");
    switch(retrans_fail_way)
    {
        case RETRANS_FAIL_WAY_RTO:
            SLEEP(RTO_TIMEOUT);
            break;
        case RETRANS_FAIL_WAY_USER_TIMEOUT:
            SLEEP(TCP_USER_TO);
            break;
        case RETRANS_FAIL_WAY_RST:
            tsa_tst_send_rst(&ss);
            TAPI_WAIT_NETWORK;
            break;
        default:
            TEST_FAIL("Incorrect value of parameter @p retrans_fail_way: %d",
                      retrans_fail_way);
    }

    TEST_STEP("Check that TCP send retransmission failed as expected.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    n_bytes = send_func(pco_iut, iut_s, tx_buf, 1, 0);
    if (n_bytes != -1)
    {
        TEST_FAIL("Attempt to get previous error message returns %d "
                  "instead of -1", n_bytes);
    }
    switch(retrans_fail_way)
    {
        case RETRANS_FAIL_WAY_RTO:
        case RETRANS_FAIL_WAY_USER_TIMEOUT:
            CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT,
                            "send_func() returns -1, but");
            break;
        case RETRANS_FAIL_WAY_RST:
            CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                            "send_func() returns -1, but");
            break;
        default:
            TEST_FAIL("Incorrect value of parameter @p retrans_fail_way: %d",
                      retrans_fail_way);
    }

    TEST_SUCCESS;

cleanup:

    if (retrans_fail_way == RETRANS_FAIL_WAY_RTO)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, tcp_retries_n, NULL,
                                         "net/ipv4/tcp_retries2"));
    }
    ss.state.iut_s = -1;
    CLEANUP_CHECK_RC(tsa_destroy_session(&ss));

    TEST_END;
}
