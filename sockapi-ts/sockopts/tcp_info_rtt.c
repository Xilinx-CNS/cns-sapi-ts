/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/**
 * @page sockopts-tcp_info_rtt Check tcpi_rtt and tcpi_rttval fields
 *
 * @objective Send data and check tcpi_rtt and tcpi_rttvar
 *
 * @param env Peer to peer test environvent
 *
 * @par Scenario:
 *
 * @author Timofey Alekseev <Timofey.Alekseev@oktetlabs.ru>
 */

#define TE_TEST_NAME "sockopts/tcp_info_rtt"

#include "sockapi-test.h"
#include "tapi_cfg_qdisc.h"
#include "tapi_cfg_netem.h"
#include "tapi_route_gw.h"

/*
 * Delay to set on gateway interface in useconds. It should be big enough
 * so that the test can distinguish delayed/non-delayed conditions.
 */
#define NETEM_DELAY 100000

/**
 * Value in percents, on which RTT may be less than @ref NETEM_DELAY,
 * due to rounding/conversion issues.
 */
#define ACCEPTED_DEVIATION 1.0

static void
get_rtt(rcf_rpc_server *pco, int sock, uint32_t *rtt, uint32_t *rttvar)
{
    struct rpc_tcp_info tcpi;
    rpc_getsockopt(pco, sock, RPC_TCP_INFO, &tcpi);
    *rtt = tcpi.tcpi_rtt;
    *rttvar = tcpi.tcpi_rttvar;
    RING("rtt: %u\n"
         "rttvar: %u",
         *rtt, *rttvar);
}

static void
tcp_conn_and_send(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                  struct sockaddr *iut_addr, struct sockaddr *tst_addr,
                  int *iut_s_p, int *tst_s_p)
{
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_TCP_ACTIVE, FALSE, FALSE, NULL,
                      iut_s_p, tst_s_p, NULL, SOCKTS_SOCK_FUNC_SOCKET);

    sockts_test_connection(pco_iut, *iut_s_p, pco_tst, *tst_s_p);
    TAPI_WAIT_NETWORK;
}

static void
close_sockets(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
              struct sockaddr *iut_addr, struct sockaddr *tst_addr,
              int iut_s, int tst_s)
{
    tapi_allocate_set_port(pco_iut, iut_addr);
    tapi_allocate_set_port(pco_tst, tst_addr);

    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);
}

int
main(int argc, char *argv[])
{
    tapi_route_gateway gw;
    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    int iut_s = -1;
    int tst_s = -1;

    uint32_t rtt;
    uint32_t rttvar;

    TEST_START;
    TAPI_GET_ROUTE_GATEWAY_PARAMS;

    TAPI_INIT_ROUTE_GATEWAY(gw);
    CHECK_RC(tapi_route_gateway_configure(&gw));
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_cfg_qdisc_set_kind(pco_gw->ta, gw_tst_if->if_name,
                                     TAPI_CFG_QDISC_KIND_NETEM));
    tapi_cfg_netem_set_delay(pco_gw->ta, gw_tst_if->if_name, NETEM_DELAY);

    TEST_STEP("Establish TCP connection and send data from IUT to TST.");
    tcp_conn_and_send(pco_iut, pco_tst, iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Get tcpi_rtt and tcpi_rttvar values and check that they "
              "are not zero.");
    get_rtt(pco_iut, iut_s, &rtt, &rttvar);
    if (rtt == 0)
        TEST_VERDICT("tcpi_rtt is 0 before setting delay");
    if (rttvar == 0)
        TEST_VERDICT("tcpi_rttvar is 0 before setting delay");

    TEST_STEP("Close connection.");
    close_sockets(pco_iut, pco_tst, iut_addr, tst_addr, iut_s, tst_s);

    TEST_STEP("Setup delay on gateway interface using net_em.");
    CHECK_RC(tapi_cfg_qdisc_enable(pco_gw->ta, gw_tst_if->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish TCP connection and send data from IUT to TST.");
    tcp_conn_and_send(pco_iut, pco_tst, iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Get tcpi_rtt and tcpi_rttvar values and check that "
              "rtt is not less than netem delay on more than "
              "@b ACCEPTED_DEVIATION and rttvar is not zero.");
    get_rtt(pco_iut, iut_s, &rtt, &rttvar);
    if (rtt < NETEM_DELAY)
    {
        float diff = (NETEM_DELAY - rtt) * 100.0 / NETEM_DELAY;

        RING("Delay on interface is %i microseconds", NETEM_DELAY);
        RING("Difference between qdisc delay and RTT = %f%%", diff);
        if (diff > ACCEPTED_DEVIATION)
        {
            TEST_VERDICT("Average round trip time is less than delay "
                         "on interface");
        }
    }
    if (rttvar == 0)
        TEST_VERDICT("tcpi_rttvar is 0 after seting delay");

    TEST_STEP("Close connection.");
    close_sockets(pco_iut, pco_tst, iut_addr, tst_addr, iut_s, tst_s);

    TEST_STEP("Remove delay from gateway interface.");
    CHECK_RC(tapi_cfg_qdisc_disable(pco_gw->ta, gw_tst_if->if_name));
    CFG_WAIT_CHANGES;

    TEST_STEP("Establish TCP connection and send data from IUT to TST.");
    tcp_conn_and_send(pco_iut, pco_tst, iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Get tcpi_rtt and tcpi_rttvar values and check that they "
              "are not zero.");
    get_rtt(pco_iut, iut_s, &rtt, &rttvar);
    if (rtt == 0)
        TEST_VERDICT("tcpi_rtt is 0 after remove delay");
    if (rttvar == 0)
        TEST_VERDICT("tcpi_rttvar is 0 after remove delay");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
