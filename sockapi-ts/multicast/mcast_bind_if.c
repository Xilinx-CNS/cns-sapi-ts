/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/** @page multicast-mcast_bind_if Outgoing interface for multicast datagrams depends on bound address
 *
 * @objective Check that outgoing interface for multicast datagrams is
 *            selected according to the address a socket is bound to.
 *
 * @type Conformance.
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on Tester
 * @param iut_if1         The first network interface on IUT
 * @param iut_if2         The second network interface on IUT
 * @param tst1_if         Tester network interface connected to @p iut_if1
 * @param tst2_if         Tester network interface connected to @p iut_if2
 * @param iut_addr1       Network address assigned to @p iut_if1
 * @param iut_addr2       Network address assigned to @p iut_if2
 * @param tst1_addr       Network address assigned to @p tst1_if
 * @param tst2_addr       Network address assigned to @p tst2_if
 * @param mcast_addr      Multicast address
 * @param packet_number   Number of datagrams to send for reliability
 * @param sock_func       Socket creation function.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_bind_if"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"
#include "sockapi-ts_monitor.h"

/** Will be set to TRUE if the test failed. */
static te_bool test_failed = FALSE;

/**
 * Check what happens when data is sent from IUT socket
 * to a multicast address.
 *
 * @param pco_iut           RPC server on IUT.
 * @param pco_tst           RPC server on Tester.
 * @param mcast_addr        Multicast address.
 * @param iut_s             Socket on IUT from which to send.
 * @param tst_s             Socket on Tester from which to receive.
 * @param packet_number     Number of packets to send.
 * @param monitor1          Traffic monitor on the first Tester
 *                          interface.
 * @param monitor2          Traffic monitor on the second Tester
 *                          interface.
 * @param first_if          Whether sending from the first interface
 *                          is expected.
 */
static void
check_mcast(rcf_rpc_server *pco_iut,
            rcf_rpc_server *pco_tst,
            const struct sockaddr *mcast_addr,
            int iut_s,
            int tst_s,
            int packet_number,
            sockts_if_monitor *monitor1,
            sockts_if_monitor *monitor2,
            te_bool first_if)
{
    char      buf[SOCKTS_MSG_DGRAM_MAX];
    size_t    send_len;
    te_dbuf   send_dbuf = TE_DBUF_INIT(0);
    te_dbuf   recv_dbuf = TE_DBUF_INIT(0);
    int       i;
    int       rc;
    te_bool   detected1;
    te_bool   detected2;
    te_bool   readable;

    for (i = 0; i < packet_number; i++)
    {
        send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
        te_fill_buf(buf, send_len);

        rpc_sendto(pco_iut, iut_s, buf, send_len, 0, mcast_addr);
        te_dbuf_append(&send_dbuf, buf, send_len);

        RPC_GET_READABILITY(readable, pco_tst, tst_s,
                            TAPI_WAIT_NETWORK_DELAY);
        if (!readable)
            TEST_FAIL("Failed to receive a packet on Tester");

        rc = rpc_recv(pco_tst, tst_s, buf, sizeof(buf), 0);
        te_dbuf_append(&recv_dbuf, buf, rc);
    }

    SOCKTS_CHECK_RECV(pco_tst, send_dbuf.ptr, recv_dbuf.ptr,
                      send_dbuf.len, recv_dbuf.len);
    te_dbuf_free(&send_dbuf);
    te_dbuf_free(&recv_dbuf);

    sockts_if_monitor_check(monitor1, FALSE, &detected1, NULL);
    sockts_if_monitor_check(monitor2, FALSE, &detected2, NULL);

    if (first_if)
    {
        if (!detected1)
        {
            ERROR_VERDICT("Packets were not detected on "
                          "the first interface after sending "
                          "from the first socket");
            test_failed = TRUE;
        }

        if (detected2)
        {
            ERROR_VERDICT("Packets were detected on "
                          "the second interface after sending "
                          "from the first socket");
            test_failed = TRUE;
        }
    }
    else
    {
        if (detected1)
        {
            ERROR_VERDICT("Packets were detected on "
                          "the first interface after sending "
                          "from the second socket");
            test_failed = TRUE;
        }

        if (!detected2)
        {
            ERROR_VERDICT("Packets were not detected on "
                          "the second interface after sending "
                          "from the second socket");
            test_failed = TRUE;
        }
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr1 = NULL;
    const struct sockaddr       *iut_addr2 = NULL;
    const struct sockaddr       *mcast_addr = NULL;
    const struct sockaddr       *tst1_addr = NULL;
    const struct sockaddr       *tst2_addr = NULL;
    const struct if_nameindex   *tst1_if = NULL;
    const struct if_nameindex   *tst2_if = NULL;
    const struct if_nameindex   *iut_if1 = NULL;
    const struct if_nameindex   *iut_if2 = NULL;
    sockts_socket_func           sock_func;
    int                          packet_number = 0;

    sockts_if_monitor   tst_monitor1 = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor   tst_monitor2 = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor   iut_monitor1 = SOCKTS_IF_MONITOR_INIT;
    sockts_if_monitor   iut_monitor2 = SOCKTS_IF_MONITOR_INIT;

    int                 iut_s1 = -1;
    int                 iut_s2 = -1;
    int                 tst_s = -1;
    rpc_socket_domain   domain;
    int                 af;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_INT_PARAM(packet_number);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    af = iut_addr2->sa_family;
    domain = rpc_socket_domain_by_addr(iut_addr2);

    TEST_STEP("Create two UDP sockets on IUT, @b iut_s1 and @b iut_s2. Bind "
              "the first one to @p iut_addr1 and the second one to @p iut_addr2.");

    iut_s1 = sockts_socket(sock_func, pco_iut, domain,
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_iut, iut_s1, iut_addr1);

    iut_s2 = sockts_socket(sock_func, pco_iut, domain,
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_iut, iut_s2, iut_addr2);

    TEST_STEP("Create an UDP socket on Tester @b tst_s. Bind it to @b mcast_addr. "
              "Join multicast group @p mcast_addr on both Tester interfaces.");

    tst_s = rpc_socket(pco_tst, domain,
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, tst_s, mcast_addr);
    rpc_common_mcast_join(pco_tst, tst_s, mcast_addr,
                          tst1_addr, tst1_if->if_index,
                          TARPC_MCAST_JOIN_LEAVE);
    rpc_common_mcast_join(pco_tst, tst_s, mcast_addr,
                          tst2_addr, tst2_if->if_index,
                          TARPC_MCAST_JOIN_LEAVE);

    TEST_STEP("Create CSAPs listening for packets on both IUT and Tester "
              "interfaces.");

    sockts_if_monitor_init(&tst_monitor1, pco_tst->ta, tst1_if->if_name,
                           af, RPC_SOCK_DGRAM, mcast_addr, NULL,
                           TRUE, FALSE);
    sockts_if_monitor_init(&tst_monitor2, pco_tst->ta, tst2_if->if_name,
                           af, RPC_SOCK_DGRAM, mcast_addr, NULL,
                           TRUE, FALSE);

    sockts_if_monitor_init(&iut_monitor1, pco_iut->ta, iut_if1->if_name,
                           af, RPC_SOCK_DGRAM, NULL, mcast_addr,
                           FALSE, TRUE);
    sockts_if_monitor_init(&iut_monitor2, pco_iut->ta, iut_if2->if_name,
                           af, RPC_SOCK_DGRAM, NULL, mcast_addr,
                           FALSE, TRUE);

    TEST_STEP("Send data from @p iut_s1 to @p mcast_addr. Check that data goes "
              "only via @p tst1_if and can be received by @b tst_s.");

    check_mcast(pco_iut, pco_tst, mcast_addr,
                iut_s1, tst_s, packet_number,
                &tst_monitor1, &tst_monitor2, TRUE);

    TEST_STEP("Send data from @p iut_s2 to @p mcast_addr. Check that data goes "
              "only via @p tst2_if and can be received by @b tst_s.");

    check_mcast(pco_iut, pco_tst, mcast_addr,
                iut_s2, tst_s, packet_number,
                &tst_monitor1, &tst_monitor2, FALSE);

    TEST_STEP("Check that on Onload outgoing network traffic is accelerated "
              "(not detectable by CSAP) as expected.");
    CHECK_TWO_IFS_ACCELERATED(&iut_monitor1, &iut_monitor2, "");

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&tst_monitor1));
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&tst_monitor2));
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_monitor1));
    CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_monitor2));

    TEST_END;
}
