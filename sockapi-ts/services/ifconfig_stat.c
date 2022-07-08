/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ifconfig_stat Retrieving statistics via ifconfig.
 *
 * @objective Check that "ifconfig", "ifconfig -a" and "ifconfig" for
 *            particular device return the same and correct statistics.
 *
 * @param iut       IUT PCO 
 * @param iut_s     socket on @p iut
 * @param tst       tester PCO
 * @param tst_s     socket on @p tst
 * 
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario
 * -# Retrieve list of network interfaces using "ifconfig".
 * -# Choose the interface @p i connected to the @p pco_tst host.
 * -# Retrieve statistics on the interface @p i (number of sent/received 
 *    packets and bytes) using "ifconfig".
 * -# Send 100 bulks of data via @p iut_s.
 * -# Send 200 bulks of data via @p tst_s.
 * -# Retrieve statistics on the interface @p i using "ifconfig".
 * -# Check that number of sent/received packets and bytes is equal
 *    or greater that one corresponding to amount of sent data (number 
 *    of packets should be calculated using MTU of the the interface @p i).
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ifconfig_stat"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"
#include "ifconfparse.h"

/** Length of bulk of transferred data */
#define DATA_BULK       500    

/** Number of packets to be sent */
#define TX_PKT_NUM      100

/** Number of packets to be sent */
#define RX_PKT_NUM      200

/** Amount of traffic transmitted via interface */
#define AMOUNT_TX       (DATA_BULK * TX_PKT_NUM)

/** Amount of traffic received via interface */
#define AMOUNT_RX       (DATA_BULK * RX_PKT_NUM)

/** Allowed deviation in percents */
#define DEVIATION       10

/** Auxiliary buffer */
static char tx_buf[DATA_BULK];

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_ifname = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    
    int   iut_s = -1;
    int   tst_s = -1;
    int   i;
    int   req_val = TRUE;
    
    uint64_t diff;
    uint64_t delta;
    
    struct if_info info1;
    struct if_info info2;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_ifname);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (OS(pco_iut) != OS_LINUX)
        TEST_FAIL("This is Linux specific test");

    GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   tst_addr, iut_addr, &tst_s, &iut_s);

    /* 
     * Make sockets non-blocking to prevent test failure in the case
     * of UDP packet loss.
     */
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);
    rpc_ioctl(pco_tst, tst_s, RPC_FIONBIO, &req_val);
    
    if (retrieve_if_info(pco_iut, iut_ifname->if_name, &info1,
                         OS_LINUX) != 0)
        TEST_FAIL("Failed to get interface statistics via ifconfig");

    te_fill_buf(tx_buf, DATA_BULK);
    
    for (i = 0; i < TX_PKT_NUM; i++)
    {
        rpc_write(pco_iut, iut_s, tx_buf, DATA_BULK);
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rpc_read(pco_tst, tst_s, tx_buf, DATA_BULK);
    }

    for (i = 0; i < RX_PKT_NUM; i++)
    {
        rpc_write(pco_tst, tst_s, tx_buf, DATA_BULK);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rpc_read(pco_iut, iut_s, tx_buf, DATA_BULK);
    }

    SLEEP(1);
    if (retrieve_if_info(pco_iut, iut_ifname->if_name, &info2,
                         OS_LINUX) != 0)
        TEST_FAIL("Failed to get interface statistics via ifconfig");
    RING("Statistics on %s:\nBefore traffic:\n%s\nAfter traffic:\n%s",
         iut_ifname->if_name, if_info_str(&info1), 
         if_info_str(&info2));
        
    diff = info2.rx_bytes - info1.rx_bytes;
    delta = AMOUNT_RX > diff ? AMOUNT_RX - diff : diff - AMOUNT_RX;
    if (delta * 100 / AMOUNT_RX > DEVIATION)
    {
        TEST_FAIL("Amount of received data differs from one observed "
                  "via ifconfig too much: %u %u", AMOUNT_RX, diff);
    }
    if (diff != AMOUNT_RX)
    {
        WARN("Expected to recieve %d bytes, but ifconfig reports %d", 
             AMOUNT_RX, diff);
    }
                  
    diff = info2.rx_pkts - info1.rx_pkts;
    delta = RX_PKT_NUM > diff ? RX_PKT_NUM - diff : diff - RX_PKT_NUM;
    if (delta * 100 / RX_PKT_NUM > DEVIATION)
    {
        TEST_FAIL("Number of received packets differs from one observed "
                  "via ifconfig too much: %u %u", RX_PKT_NUM, diff);
    }
    if (diff != RX_PKT_NUM)
    {
        WARN("Expected to recieve %d packets, but ifconfig reports %d", 
             RX_PKT_NUM, diff);
    }

    diff = info2.tx_bytes - info1.tx_bytes;
    delta = AMOUNT_TX > diff ? AMOUNT_TX - diff : diff - AMOUNT_TX;
    if (delta * 100 / AMOUNT_RX > DEVIATION)
    {
        TEST_FAIL("Amount of transmitted data differs from one observed "
                  "via ifconfig too much: %u %u", AMOUNT_TX, diff);
    }
    if (diff != AMOUNT_RX)
    {
        WARN("Expected to transmit %d bytes, but ifconfig reports %d", 
             AMOUNT_TX, diff);
    }

    diff = info2.tx_pkts - info1.tx_pkts;
    delta = TX_PKT_NUM > diff ? TX_PKT_NUM - diff : diff - TX_PKT_NUM;
    if (delta * 100 / RX_PKT_NUM > DEVIATION)
    {
        TEST_FAIL("Number of sent packets differs from one observed "
                  "via ifconfig too much: %u %u", TX_PKT_NUM, diff);
    }
    if (diff != AMOUNT_RX)
    {
        WARN("Expected to transmit %d packets, but ifconfig reports %d", 
             TX_PKT_NUM, diff);
    }
    
    TEST_SUCCESS;

cleanup:
        
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
