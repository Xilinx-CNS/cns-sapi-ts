/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page extension-msg_warm Test MSG_WARM innocuity
 *
 * @objective Check that no data is sent when send flag
 *            @c ONLOAD_MSG_WARM is used.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_lo
 * @param sock_type         Socket type:
 *                          - @c tcp_active
 *                          - @c tcp_passive_close
 * @param func              Tested send function:
 *                          - @b send
 *                          - @b sendto
 *                          - @b sendmsg
 *                          - @b onload_zc_send
 * @param buf_len           Send buffer length:
 *                          - @c 0 (@c NULL buffer pointer)
 *                          - @c 1
 *                          - @c 1000
 *                          - @c 4000
 * @param flags             Use an extra flag apart from @c ONLOAD_MSG_WARM:
 *                          - @c none
 *                          - @c MSG_DONTWAIT
 *                          - @c MSG_MORE
 *                          - @c MSG_NOSIGNAL
 * @param send_data_before  Send data before using @c ONLOAD_MSG_WARM if
 *                          @c TRUE
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/msg_warm"

#include "sockapi-test.h"
#include "onload.h"
#include "tapi_tcp.h"

/** Maximum length of buffer. */
#define MAX_BUF_LEN 5000

/** Default length of data to pass to send function. */
#define DEF_SEND_LEN 1024

/**
 * Length of data to send before calling send function
 * with ONLOAD_MSG_WARM, if required.
 */
#define SEND_BEFORE_SIZE 10240

/**
 * Parse flags test parameter.
 *
 * @param flags     String with flags.
 *
 * @return Numeric value.
 */
static int
parse_flags(const char *flags)
{
    if (strcmp(flags, "none") == 0)
        return 0;
    else if (strcmp(flags, "MSG_DONTWAIT") == 0)
        return RPC_MSG_DONTWAIT;
    else if (strcmp(flags, "MSG_MORE") == 0)
        return RPC_MSG_MORE;
    else if (strcmp(flags, "MSG_NOSIGNAL") == 0)
        return RPC_MSG_NOSIGNAL;

    TEST_FAIL("Failed to parse flags");
    return 0;
}

/**
 * Handler for checking packets obtained by CSAP.
 *
 * @param pkt         TCP packet.
 * @param user_data   Not used.
 */
static void
user_pkt_handler(const tcp4_message *pkt, void *user_data)
{
    UNUSED(user_data);

    if (pkt->payload_len > 0)
        TEST_VERDICT("CSAP detected TCP packet with nonzero payload on "
                     "Tester after sending data with ONLOAD_MSG_WARM");
}

/**
 * Send data from one socket to another one, receive it and check.
 *
 * @param rpcs1_        RPC server from which to send.
 * @param s1_           Socket from which to send.
 * @param rpcs2_        RPC server on which to receive.
 * @param s2_           Socket on which to receive.
 */
#define DATA_SEND_RECV(rpcs1_, s1_, rpcs2_, s2_) \
    do {                                                              \
        te_fill_buf(send_buf, DEF_SEND_LEN);                          \
        rc = rpc_send(rpcs1_, s1_, send_buf, DEF_SEND_LEN, 0);        \
        if (rc != DEF_SEND_LEN)                                       \
            TEST_FAIL("send() did not send expected number of "       \
                      "bytes from %s", rpcs1_->name);                 \
                                                                      \
        rc = rpc_recv(rpcs2_, s2_, recv_buf, MAX_BUF_LEN, 0);         \
        if (rc != DEF_SEND_LEN ||                                     \
            memcmp(send_buf, recv_buf, DEF_SEND_LEN) != 0)            \
            TEST_FAIL("Data sent from %s does not match data "        \
                      "received on %s", rpcs1_->name, rpcs2_->name);  \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex *tst_if = NULL;

    int   iut_s = -1;
    int   tst_s = -1;

    char      send_buf[MAX_BUF_LEN];
    char      recv_buf[MAX_BUF_LEN];
    int       total_sent;
    te_bool   done;

    csap_handle_t         csap = CSAP_INVALID_HANDLE;

    sockts_socket_type    sock_type;
    rpc_send_f            func;
    int                   buf_len;
    const char           *flags;
    int                   flags_val;
    te_bool               send_data_before;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_SEND_FUNC(func);
    TEST_GET_INT_PARAM(buf_len);
    TEST_GET_STRING_PARAM(flags);
    TEST_GET_BOOL_PARAM(send_data_before);

    flags_val = parse_flags(flags) | RPC_MSG_WARM;

    TEST_STEP("Establish TCP connection according to @p sock_type.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr, sock_type,
                      &iut_s, &tst_s, NULL);

    TEST_STEP("Check that the connection is accelerated via @b onload_fd_stat() and "
              "exit if it is not.");

    if (tapi_onload_check_fd(pco_iut, iut_s, NULL) != TAPI_FD_IS_ONLOAD)
        TEST_VERDICT("Socket is not Onload");

    TEST_STEP("If @p send_data_before is @c TRUE, send @c SEND_BEFORE_SIZE "
              "bytes from IUT and receive it on Tester.");

    if (send_data_before)
    {
        total_sent = 0;
        do {
            te_fill_buf(send_buf, DEF_SEND_LEN);

            rc = rpc_send(pco_iut, iut_s, send_buf, DEF_SEND_LEN, 0);
            if (rc != DEF_SEND_LEN)
                TEST_FAIL("When sending initial data bunch, "
                          "send() did not sent expected number of bytes");
            total_sent += rc;

            rc = rpc_recv(pco_tst, tst_s, recv_buf, MAX_BUF_LEN, 0);
            if (rc != DEF_SEND_LEN ||
                memcmp(send_buf, recv_buf, DEF_SEND_LEN) != 0)
                TEST_FAIL("When sending initial data bunch, data "
                          "send from IUT does not match data received "
                          "on Tester");

        } while (total_sent < SEND_BEFORE_SIZE);
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Create CSAP on Tester to check packets sent from IUT.");

    /*
     * The CSAP check should be removed if it provokes any instability in
     * the test behavior.
     */

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, 0,
                                          tst_if->if_name,
                                          TAD_ETH_RECV_DEF, NULL, NULL,
                                          SIN(tst_addr)->sin_addr.s_addr,
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          SIN(tst_addr)->sin_port,
                                          SIN(iut_addr)->sin_port,
                                          &csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    TEST_STEP("Block tester in recv() call.");

    pco_tst->op = RCF_RPC_CALL;
    rpc_recv(pco_tst, tst_s, recv_buf, MAX_BUF_LEN, 0);

    te_fill_buf(send_buf, buf_len);

    TEST_STEP("Perform warm send: "
              "- use function @p func; "
              "- pass @p buf_len bytes; "
              "- use extra flags according to @p flags.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = func(pco_iut, iut_s, (buf_len == 0 ? NULL : send_buf),
              buf_len, flags_val);
    if (rc < 0)
        TEST_VERDICT("Tested function failed with errno %r",
                     RPC_ERRNO(pco_iut));

    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that tester recv() call is still blocked.");

    CHECK_RC(rcf_rpc_server_is_op_done(pco_tst, &done));
    if (done)
    {
        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, recv_buf, MAX_BUF_LEN, 0);
        if (rc >= 0)
            TEST_VERDICT("recv() on Tester unexpectedly succeeded");
        else
            TEST_VERDICT("recv() on Tester unexpectedly failed with "
                         "with errno %r", RPC_ERRNO(pco_tst));
    }

    TEST_STEP("Check that the CSAP does not catch packets with "
              "payload length > 0.");

    CHECK_RC(tapi_tad_trrecv_stop(
                pco_tst->ta, 0, csap,
                tapi_tcp_ip4_eth_trrecv_cb_data(user_pkt_handler, NULL),
                NULL));

    TEST_STEP("Send some data in both directions, read and check it.");

    DATA_SEND_RECV(pco_iut, iut_s, pco_tst, tst_s);
    DATA_SEND_RECV(pco_tst, tst_s, pco_iut, iut_s);

    TEST_SUCCESS;

cleanup:

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
