/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Send packets in tcp session and check that tcp_info_ca_state is correct
 */

/**
 * @page sockopts-tcp_info_ca_state Send packets in tcp session and check that tcp_info_ca_state is correct
 *
 * @objective Check that TCP congestion avoidance states are displayed correcly
 *            in (almost) all possible transitions between them
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param alien_link_addr  Invalid ethernet address
 * @param tcp_ca_state_seq Tested sequence of TCP condestion states transitions
 *
 * @par Scenario:
 *
 * @author Ekaterina Yaschenko <Ekaterina.Yaschenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "sockopts/tcp_info_ca_state"

#include "sockapi-test.h"
#include "tapi_tcp.h"

#define CHECK_STATE(_state) \
       {                                                                        \
            struct rpc_tcp_info tmp_info;                                       \
            memset(&info, 0, sizeof(info));                                     \
            rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &tmp_info);            \
            if (tmp_info.tcpi_ca_state != RPC_TCP_CA_##_state)                  \
                TEST_VERDICT("Coudldn't reach "# _state" state");               \
       }


/** TCP retransmittion timeout, milliseconds. */
#define RTO_VALUE 300000
/** Maximum waiting time for a packet arrival, milliseconds. */
#define PKT_TIMEOUT 300

#define DISORDERED_SEND_ATTEMPTS 5
#define MAX_ATTEMPTS 10

/* Send a packet from IUT and receive it on TST*/
static void
send_recv(rcf_rpc_server *pco_iut, int iut_s, const void *buf, size_t mss,
          tapi_tcp_handler_t csap_tst_s, tapi_tcp_protocol_mode_t ack_mode,
          te_dbuf *data)
{
    rpc_send(pco_iut, iut_s, buf, mss, 0);
    CHECK_RC(tapi_tcp_recv_data(csap_tst_s, PKT_TIMEOUT, ack_mode, data));
}

static void
reach_check_state(tapi_tcp_handler_t csap_tst_s,
                  rcf_rpc_server *pco_iut, int iut_s,
                  const void *buf, size_t mss,
                  rpc_tcp_ca_state orig_state,
                  rpc_tcp_ca_state state)
{
    struct rpc_tcp_info info;
    int i;
    tapi_tcp_pos_t ack = tapi_tcp_next_ackn(csap_tst_s);


    if (state == RPC_TCP_CA_DISORDER)
    {
        for (i = 0; i < DISORDERED_SEND_ATTEMPTS; i++)
            rpc_send(pco_iut, iut_s, buf, mss, 0);
    }
    for (i = 0; i < MAX_ATTEMPTS; i++)
    {
        if (state == RPC_TCP_CA_RECOVERY)
        {
            rpc_send(pco_iut, iut_s, buf, mss, 0);
            rpc_send(pco_iut, iut_s, buf, mss, 0);
        }

        CHECK_RC(tapi_tcp_send_ack(csap_tst_s, ack));

        MSLEEP(1);

        memset(&info, 0, sizeof(info));
        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
        if (info.tcpi_ca_state != orig_state)
            break;
    }

    if (info.tcpi_ca_state == state)
        return;

    TEST_VERDICT("Transition from %s to %s was expected, "
                 "but instead %s is observed",
                 tcp_ca_state_rpc2str(orig_state),
                 tcp_ca_state_rpc2str(state),
                 tcp_ca_state_rpc2str(info.tcpi_ca_state));
}

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
    int                       iut_s = -1;
    tapi_tcp_handler_t        csap_tst_s = -1;

    struct rpc_tcp_info       info;
    uint8_t                   *buf;
    te_dbuf                   recv_data = TE_DBUF_INIT(0);
    tapi_tcp_pos_t            ack;
    uint32_t                  mss;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);

    TEST_GET_STRING_PARAM(tcp_ca_state_seq);

    TEST_STEP("Initialize TSA session");
    CHECK_RC(tsa_state_init(&ss, TSA_TST_CSAP));
    CHECK_RC(tsa_iut_set(&ss, pco_iut, iut_if, iut_addr));
    CHECK_RC(tsa_tst_set(&ss, pco_tst, tst_if, tst_addr,
                         ((struct sockaddr *)
                         alien_link_addr)->sa_data));
    CFG_WAIT_CHANGES;

    CHECK_RC(tsa_create_session(&ss, 0));

    iut_s = tsa_iut_sock(&ss);
    csap_tst_s = tsa_tst_sock(&ss);
    if (iut_s == -1 || csap_tst_s == -1)
        TEST_FAIL("Couldn't get socket from tsa_create_session()");

    rc = tsa_do_moves_str(&ss, RPC_TCP_UNKNOWN, RPC_TCP_ESTABLISHED,
                          0, "TCP_ESTABLISHED");

    memset(&info, 0, sizeof(info));
    rpc_getsockopt(pco_iut, tsa_iut_sock(&ss), RPC_TCP_INFO, &info);
    mss = info.tcpi_snd_mss;
    buf = te_make_buf_by_len(mss);

    TEST_STEP("Send two packets from IUT, receiving and acking them in time, "
              "to make sure that initial congestion state is OPEN");
    send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
              &recv_data);
    send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
              &recv_data);

    USLEEP(RTO_VALUE);

    TEST_STEP("Check that TCP_CA_STATE on IUT is OPEN");
    CHECK_STATE(OPEN);

    TEST_STEP("Execute sequence of congestion states defined by @p "
              "tcp_ca_state_seq");
    if (!strcmp(tcp_ca_state_seq, "OPEN-LOSS-OPEN"))
    {
        TEST_STEP("If @p tcp_ca_state_seq is OPEN-LOSS-OPEN then");

        TEST_SUBSTEP("Send packet with data from IUT to TST and receive "
                     "packet on TST without sending ACK");
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_QUIET, &recv_data);

        TEST_SUBSTEP("Wait for RTO");
        USLEEP(RTO_VALUE);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is LOSS");
        CHECK_STATE(LOSS);

        TEST_SUBSTEP("Send apropriate ACK");
        ack = tapi_tcp_next_ackn(csap_tst_s);
        CHECK_RC(tapi_tcp_send_ack(csap_tst_s, ack));

        TEST_SUBSTEP("Twice send packet with data from IUT to TST and "
                     "receive it on TST with sending ACK");
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is OPEN");
        CHECK_STATE(OPEN);
    }

    else if (!strcmp(tcp_ca_state_seq, "OPEN-DISORDER-OPEN"))
    {
        TEST_STEP("If @p tcp_ca_state_seq is OPEN-DISORDER-OPEN then");

        TEST_SUBSTEP("Send a few packets from IUT in a loop, "
                     "in response sending ACKs with old ACKN from Tester, "
                     "until DISORDER congestion state "
                     "is reached on IUT socket");
        reach_check_state(csap_tst_s, pco_iut, iut_s, buf, mss,
                          RPC_TCP_CA_OPEN, RPC_TCP_CA_DISORDER);

        TEST_SUBSTEP("Send an ACK to the last packet");
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_AUTO, &recv_data));

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is OPEN");
        CHECK_STATE(OPEN);
    }

    else if (!strcmp(tcp_ca_state_seq, "OPEN-DISORDER-LOSS-OPEN"))
    {
        TEST_STEP("If @p tcp_ca_state_seq is OPEN-DISORDER-LOSS-OPEN then");

        TEST_SUBSTEP("Send a few packets from IUT in a loop, "
                     "in response sending ACKs with old ACKN from Tester, "
                     "until DISORDER congestion state "
                     "is reached on IUT socket");
        reach_check_state(csap_tst_s, pco_iut, iut_s, buf, mss,
                          RPC_TCP_CA_OPEN, RPC_TCP_CA_DISORDER);

        TEST_SUBSTEP("Wait for RTO");
        USLEEP(RTO_VALUE);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is LOSS");
        CHECK_STATE(LOSS);

        TEST_SUBSTEP("Ack all previous packets");
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_AUTO, &recv_data));

        TEST_SUBSTEP("Twice send packet with data from IUT to TST and "
                     "receive it on TST with sending ACK");
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is OPEN");
        CHECK_STATE(OPEN);
    }

    else if (!strcmp(tcp_ca_state_seq, "OPEN-DISORDER-RECOVERY-OPEN"))
    {
        TEST_STEP("If @p tcp_ca_state_seq is OPEN-DISORDER-RECOVERY-OPEN "
                  "then");

        TEST_SUBSTEP("Send a few packets from IUT in a loop, "
                     "in response sending ACKs with old ACKN from Tester, "
                     "until DISORDER congestion state "
                     "is reached on IUT socket");
        reach_check_state(csap_tst_s, pco_iut, iut_s, buf, mss,
                          RPC_TCP_CA_OPEN, RPC_TCP_CA_DISORDER);

        TEST_SUBSTEP("Send a few packets from IUT in a loop, "
                     "in response sending ACKs with old ACKN from Tester, "
                     "until RECOVERY congestion state "
                     "is reached on IUT socket");
        reach_check_state(csap_tst_s, pco_iut, iut_s, buf, mss,
                          RPC_TCP_CA_DISORDER, RPC_TCP_CA_RECOVERY);

        TEST_SUBSTEP("Ack all previous packets");
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_AUTO, &recv_data));

        TEST_SUBSTEP("Twice send packet with data from IUT to TST and "
                     "receive it on TST with sending ACK");
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is OPEN");
        CHECK_STATE(OPEN);

    }

    else if (!strcmp(tcp_ca_state_seq, "OPEN-DISORDER-RECOVERY-LOSS-OPEN"))
    {
        TEST_STEP("If @p tcp_ca_state_seq is OPEN-DISORDER-RECOVERY-LOSS-"
                  "OPEN then");

        TEST_SUBSTEP("Send a few packets from IUT in a loop, "
                     "in response sending ACKs with old ACKN from Tester, "
                     "until DISORDER congestion state "
                     "is reached on IUT socket");
        reach_check_state(csap_tst_s, pco_iut, iut_s, buf, mss,
                          RPC_TCP_CA_OPEN, RPC_TCP_CA_DISORDER);

        TEST_SUBSTEP("Send a few packets from IUT in a loop, "
                     "in response sending ACKs with old ACKN from Tester, "
                     "until RECOVERY congestion state "
                     "is reached on IUT socket");
        reach_check_state(csap_tst_s, pco_iut, iut_s, buf, mss,
                          RPC_TCP_CA_DISORDER, RPC_TCP_CA_RECOVERY);

        TEST_SUBSTEP("Wait for RTO");
        usleep(RTO_VALUE);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is LOSS");
        CHECK_STATE(LOSS);

        TEST_SUBSTEP("Ack all previous packets");
        CHECK_RC(tapi_tcp_recv_data(csap_tst_s, TAPI_WAIT_NETWORK_DELAY,
                                    TAPI_TCP_AUTO, &recv_data));

        TEST_SUBSTEP("Twice send packet with data from IUT to TST and "
                     "receive it on TST with sending ACK");
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);
        send_recv(pco_iut, iut_s, buf, mss, csap_tst_s, TAPI_TCP_AUTO,
                  &recv_data);

        TEST_SUBSTEP("Check that TCP_CA_STATE on IUT is OPEN");
        CHECK_STATE(OPEN);
    }

    else
        TEST_FAIL("Wrong state sequence specified");

    TEST_SUCCESS;

cleanup:

    free(buf);
    te_dbuf_free(&recv_data);
    CLEANUP_CHECK_RC(tsa_destroy_session(&ss));
    TEST_END;
}
