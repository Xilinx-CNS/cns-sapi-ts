/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 *
 * $Id: arp_change.c 65547 2010-08-09 11:01:31Z rast $
 */

/** @page arp-arp_change Send some data after changing MAC on recipient
 *
 * @objective Check that arp request is sent after a while in case 
 *            MAC address is changed on receiving side.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of socket
 * @param data_size     The amount of data to be sent
 * @param timeout       Overall timeout for the test in seconds
 *
 * @par Test sequence:
 * -# If there is @p tst_addr ARP entry on @p iut, delete it.
 * -# Create @p sock_type connection between @p pco_iut and @p pco_tst. Two
 *    connected sockets @p iut_s and @p tst_s would appear.
 * -# Send some data from IUT to Tester, check if it is successfully 
 *    received.
 * -# Change MAC address on Tester.
 * -# If @p sock_type is TCP, try to send another packet, check
 *    if it is received successfully. Expect some delay.
 * -# If @p sock_type is UDP, make @p TST_MAX_ATTEMPTS attempts
 *    to send packet from IUT to Tester. Check if at least one of packets
 *    was received.
 * -# @b close() all sockets, restore MAC on Tester.
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "arp/arp_change"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_cfg_base.h"
#include "arp_test_macros.h"
#include "tapi_route_gw.h"


/**
 * Send some data from IUT to Tester. Check if it was received
 * after timeout_ seconds.
 *
 * @param answer_   Variable to store whether the packet was received 
 *                  or not. (It should be of type te_bool)
 * @param timeout_  timeout in seconds
 *
 * @note It calls TES_FAIL in case of failure or when received data
 *       doesn't match with sent data.
 */
#define TST_SEND_RECV(answer_, timeout_) \
    do {                                                                \
        if (sock_type == SOCKTS_SOCK_UDP_NOTCONN)                       \
            rpc_sendto(pco_iut, iut_s, snd_buf, data_size, 0,           \
                       tst_addr);                                       \
        else                                                            \
            rpc_send(pco_iut, iut_s, snd_buf, data_size, 0);            \
                                                                        \
        RPC_GET_READABILITY(answer_, pco_tst, tst_s, (timeout_) * 1000);\
        if (answer_)                                                    \
        {                                                               \
            rc = rpc_recv(pco_tst, tst_s, rcv_buf, data_size, 0);       \
            SOCKTS_CHECK_RECV(pco_tst, snd_buf, rcv_buf,                \
                              data_size, rc);                           \
            RPC_CHECK_READABILITY(pco_tst, tst_s, FALSE);               \
        }                                                               \
    } while (0)

#define TST_MAX_BUF_SIZE        1024
#define TST_MAX_ATTEMPTS        10

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    sockts_socket_type  sock_type;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    int                     iut_s = -1;
    int                     tst_s = -1;

    int                     data_size;
    int                     timeout;

    uint8_t                 mac_tst[ETHER_ADDR_LEN];
    uint8_t                 mac_new[ETHER_ADDR_LEN];

    char                    tst_oid[RCF_MAX_ID];

    te_bool                 answer = FALSE;

    void                    *snd_buf;
    void                    *rcv_buf;

    int                     i;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);

    /* Get MAC address on Tester */
    sprintf(tst_oid, "/agent:%s/interface:%s", pco_tst->ta, tst_if->if_name);
    if (tapi_cfg_base_if_get_mac(tst_oid, mac_tst) != 0)
        TEST_FAIL("Failed to get MAC address on Tester");

    /* Generate new MAC address */
    memcpy(mac_new, mac_tst, sizeof(mac_tst));
    mac_new[1]++;


    snd_buf = te_make_buf_by_len(data_size);
    rcv_buf = te_make_buf_by_len(TST_MAX_BUF_SIZE);

    /* Scenario */

    /* Add dynamic ARP entries for tst_addr on IUT and
     * iut_addr on tester */
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name,
                             pco_tst->ta, tst_if->if_name,
                             tst_addr, NULL, FALSE));
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name,
                             pco_iut->ta, iut_if->if_name,
                             iut_addr, NULL, FALSE));

    CFG_WAIT_CHANGES;

    rpc_system_ex(pco_iut, "ip neigh li dev %s", iut_if->if_name); \

    /* Generate connection of type @p sock_type */
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      sock_type, &iut_s, &tst_s, NULL);

    /* Send some data from IUT to Tester */
    for (i = 0; i < 3; i++)
    {
        MSLEEP(500);
        TST_SEND_RECV(answer, 1);
        if (!answer)
            TEST_FAIL("Failed to send data from IUT to Tester");
    }

    rpc_system_ex(pco_iut, "ip neigh li dev %s", iut_if->if_name);

    /* Change MAC address on Tester */
    if (tapi_cfg_base_if_set_mac(tst_oid, mac_new) != 0)
        TEST_FAIL("Failed to change MAC address on Tester");
    TAPI_WAIT_NETWORK;

    /* Send some data again */
    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM)
    {
        TST_SEND_RECV(answer, timeout);
        if (!answer)
            TEST_VERDICT("Failed to send data from IUT to Tester");
    }
    else if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
    {
        for (i = 0; i < TST_MAX_ATTEMPTS; i++)
        {
            TST_SEND_RECV(answer, timeout / TST_MAX_ATTEMPTS);
            if (answer)
                break;
        }
        if (!answer)
            TEST_VERDICT("Failed to send data from IUT to Tester");
    }

    rpc_system_ex(pco_iut, "ip neigh li dev %s", iut_if->if_name); \
    TEST_SUCCESS;

cleanup:
    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);

    if (tapi_cfg_base_if_set_mac(tst_oid, mac_tst) != 0)
    {
        ERROR("Failed to restore MAC address on Tester");
        result = EXIT_FAILURE;
    }
    
    TEST_END;
}
