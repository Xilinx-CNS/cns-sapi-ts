/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 */

/** @page sockopts-ip_mtu_discover_tcp Path MTU discovery on SOCK_STREAM socket
 *
 * @objective Check possibility of performing Path MTU discovery
 *            functionality on @c SOCK_STREAM type socket.
 *
 * @param env    Testing environment:
 *               - @ref arg_types_env_peer2peer_gw
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/ip_mtu_discover_tcp"

#include "sockapi-test.h"
#include "tapi_route_gw.h"

#define TST_TIME_TO_SLEEP           30
#define TST_TIME2RUN                10
#define TIME_TO_WAIT_MTU_INCREASING 1200 / TST_TIME_TO_SLEEP

/**
 * Send traffic on @p sock_snd and receive it on @p sock_rcv.
 *
 * @param[in] pco_snd     Sender RPC server.
 * @param[in] sock_snd    Sender connected socket.
 * @param[in] pco_rcv     Receiver RPC server.
 * @param[in] sock_rcv    Receiver connected socket.
 * @param[out] received   Location for number of received bytes.
 * @param[out] sent       Location for numver of sent bytes.
 */
static void
send_traffic(rcf_rpc_server *pco_snd, int sock_snd, rcf_rpc_server *pco_rcv,
             int sock_rcv, uint64_t *received, uint64_t *sent)
{
    rpc_simple_sender(pco_snd, sock_snd, 1, 10000, 0, 0, 0, 1, TST_TIME2RUN,
                      sent, FALSE);
    rpc_simple_receiver(pco_rcv, sock_rcv, 0, received);
}

static te_bool
check_tcpi_pmtu(rcf_rpc_server *pco, int sock,
                int expected_mtu, int *tcpi_pmtu_cur)
{
    struct rpc_tcp_info tcp_info;

    rpc_getsockopt(pco, sock, RPC_TCP_INFO, &tcp_info);
    *tcpi_pmtu_cur = tcp_info.tcpi_pmtu;

    if (*tcpi_pmtu_cur != expected_mtu)
        return FALSE;

    return TRUE;
}

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;
    int                 iut_s = -1;
    int                 tst_s = -1;

    int                    mtu_sock_saved;
    int                    mtu_sock_current;
    int                    mtu_gw_new;

    int                    pmtu_flags_saved;
    int                    pmtu_flags;
    uint64_t               received;
    uint64_t               sent;
    int                    i;
    int                    ret;

    int tcpi_pmtu_cur = 0;

    te_bool mtu_check_normal = FALSE;
    te_bool mtu_check_tcp_info = FALSE;

    int             mtu_gw_saved = -1;
    te_saved_mtus   gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;

    TAPI_INIT_ROUTE_GATEWAY(gw);

    TEST_STEP("Setup routing via gateway and turn on forwarding on it");
    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    TEST_STEP("Retrieve the gateway interface MTU");
    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_gw->ta, gw_tst_if->if_name,
                                        &mtu_gw_saved));
    RING("Current 'gw' %s MTU=%d", gw_tst_if->if_name, mtu_gw_saved);

    TEST_STEP("Establish connection of the @c SOCK_STREAM type between "
              "IUT and Tester");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Retrieve the current known path MTU of the IUT socket");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &mtu_sock_saved);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_IP, IP_MTU) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    RING("Connected 'iut_s' MTU=%d", mtu_sock_saved);

    TEST_STEP("Retrieve current Path MTU Discovery settings for IUT socket");
    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU_DISCOVER, &pmtu_flags_saved);

    TEST_SUBSTEP("Enable Path MTU Discovery if it is disabled");
    if (pmtu_flags_saved == 0)
    {
        /* It is not necessary for PMTU Discovery processing */
        pmtu_flags = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_MTU_DISCOVER, &pmtu_flags);

        rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU_DISCOVER, &pmtu_flags);

        RING("Returned 'iut_s' Path MTU Discovery flags=%d", pmtu_flags);
        if (pmtu_flags != 1)
            TEST_FAIL("Path MTU flags can't be set on 'iut_s'");
    }

    RING("Current 'iut_s' Path MTU Discovery flags=%d", pmtu_flags_saved);

    TEST_STEP("Start sending data from IUT to Tester during 10 seconds");
    pco_tst->op = RCF_RPC_CALL;
    pco_iut->op = RCF_RPC_CALL;
    send_traffic(pco_iut, iut_s, pco_tst, tst_s, &received, &sent);

    TEST_STEP("Set new MTU on gateway equal to the half of IUT socket MTU");
    mtu_gw_new = mtu_sock_saved / 2;
    CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_tst_if->if_name,
                                    mtu_gw_new, &gw_mtus));

    TEST_STEP("Wait for sending data completing");
    pco_iut->op = RCF_RPC_WAIT;
    pco_tst->op = RCF_RPC_WAIT;
    send_traffic(pco_iut, iut_s, pco_tst, tst_s, &received, &sent);

    TEST_STEP("Check that number of sent data from IUT is the same as "
              "received on Tester");
    if (received != sent)
    {
        TEST_FAIL("The number of sent bytes (%d) is not the same "
                  "as received (%d)", sent, received);
    }

    TEST_STEP("Retrieve current path MTU of IUT socket, log it, and check "
              "that it is equal to the gateway MTU");
    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &mtu_sock_current);

    RING("Current 'iut_s' MTU=%d", mtu_sock_current);

    if (mtu_sock_current != mtu_gw_new)
    {
        TEST_FAIL("Returned socket Path MTU %d is not the same as expected %d",
                  mtu_sock_current, mtu_gw_new);
    }

    if (!check_tcpi_pmtu(pco_iut, iut_s, mtu_gw_new, &tcpi_pmtu_cur))
    {
        ERROR("MTU returned by TCP_INFO %d is not the same as expected %d",
              tcpi_pmtu_cur, mtu_gw_new);

        TEST_VERDICT("After reducing MTU on gateway, "
                     "unexpected value was reported in tcpi_pmtu");
    }

    TEST_STEP("Set original MTU on gateway to create conditions for returning "
              "to initial socket path MTU after Path MTU Discover procedure");
    CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_tst_if->if_name,
                                    mtu_gw_saved, &gw_mtus));

    TEST_STEP("Wait for default interval (>600 seconds) to guarantee PMTU "
              "discovery processing; retrieve current path MTU of IUT socket "
              "and check that it is equal to the initial IUT socket path MTU");
    for (i = 0; i < TIME_TO_WAIT_MTU_INCREASING; i++)
    {
        SLEEP(TST_TIME_TO_SLEEP);

        rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &mtu_sock_current);

        RING("'iut_s' MTU=%d after waiting %d sec",
             mtu_sock_current, (i+1) * TST_TIME_TO_SLEEP);

        if (mtu_sock_current == mtu_sock_saved)
            mtu_check_normal = TRUE;

        if (check_tcpi_pmtu(pco_iut, iut_s,
                            mtu_sock_saved, &tcpi_pmtu_cur))
            mtu_check_tcp_info = TRUE;

        if (mtu_check_normal && mtu_check_tcp_info)
            TEST_SUCCESS;
    }

    if (!mtu_check_normal)
    {
        ERROR("Returned socket Path MTU %d is not the same "
              "as expected mtu_sock_saved=%d",
              mtu_sock_current, mtu_sock_saved);

        ERROR_VERDICT("Unexpected Path MTU value after "
                      "restoring original MTU value");
    }
    if (!mtu_check_tcp_info)
    {
        ERROR("tcpi_pmtu returned by TCP_INFO %d is not the same "
              "as expected %d", tcpi_pmtu_cur, mtu_gw_new);

        ERROR_VERDICT("Unexpected tcpi_pmtu value after "
                      "restoring original MTU value");
    }

    TEST_FAIL("Returned MTU value is wrong");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_CHECK_RC(tapi_set_if_mtu_smart2_rollback(&gw_mtus));

    TEST_END;
}
