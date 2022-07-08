/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_cork TCP_CORK functionality
 *
 * @objective Checking TCP_CORK functionality providing a coalescing
 *            of the TCP packets transmitted during the retransmission
 *            interval time and that packets are not coalesced if
 *            interval between transmission is more than interval of
 *            retransmissions. Coalescing should be made according to
 *            effective MSS.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TESTER
 *
 * @par Test sequence:
 *
 * -# Establish connection of the @c SOCK_STREAM type between @p pco_iut 
 *    and @p pco_tst by means of @c GEN_CONNECTION;
 * -# Turn @c OFF the TCP_NODELAY and turn @c ON the TCP_CORK mode on @p 
 *    iut_s socket;
 * -# Retrieve the current Path MTU value to create needed test
 *    conditions;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() through @p iut_s two packets one after another without
 *    delay with summary length less than currnet MSS value;
 * -# On level 5 the @p tst_s should be unreadable, on linux it should be
 *    reported as readable;
 * -# Check that only one packet is received on @p tst_s with length
 *    equal to sum of two sent packets; Also check that TCP_PSH flag is
 *    set properly.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() through @p iut_s two packets one after another without
 *    delay with summary length more than MSS value but less than 2MSS;
 * -# Check that two packets are received on @p tst_s: first without
 *    any delay (with length according to current MSS) and second after
 *    retransmission timeout; Also check that TCP_PSH flag is set properly.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() through @p iut_s two packets (the length of each less
 *    than current MSS) with interval more than retransmit timeout;
 * -# Check that two packets are received on @p tst_s (the same as 
 *    sent in previous step); Also check that TCP_PSH flag is set properly.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() through @p iut_s a packet with length more than current 
 *    MSS but less than 2MSS;
 * -# Check that two packets are received on @p tst_s: first without any
 *    delay (with length according to current MSS) and second after
 *    retransmission timeout; Also check that TCP_PSH flag is set properly.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close crated sockets, return to the original configuration.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_cork"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

#include "conf_api.h"
#include "tapi_rpc.h"

#include "tapi_test.h"
#include "tapi_ip4.h"
#include "tapi_udp.h"
#include "tapi_tcp.h"

#include "ndn_eth.h"
#include "ndn_ipstack.h"

#include "iomux.h"

#define TST_BUF_LEN        10240

#define CHECK_PACKET_NUMBER(number_expected_) \
    do {                                                            \
        packets_received = 0;                                       \
        psh_counter = 0;                                            \
        if (tapi_tad_trrecv_get(pco_tst->ta, sid, csap,             \
                                tapi_tcp_ip4_eth_trrecv_cb_data(    \
                                user_pkt_handler, NULL), &num))     \
        {                                                           \
            TEST_FAIL("Failed to receive packets on the CSAP");     \
        }                                                           \
        if (packets_received != number_expected_)                   \
        {                                                           \
            TEST_FAIL("%d packets received instead of %d",          \
                      packets_received, number_expected_);          \
        }                                                           \
        if (psh_counter > 0)                                        \
        {                                                           \
            TEST_VERDICT("Unexpected TCP_PSH flag value "           \
                         "encountered %d times", psh_counter);      \
        }                                                           \
    } while (0)

static int packets_received  = 0;
static int length_to_receive = 0;
static int psh_counter       = 0;

static void
user_pkt_handler(const tcp4_message *pkt, void *userdata)
{
    UNUSED(userdata);
    packets_received++;

    if ((pkt->payload_len == length_to_receive) && 
        ((pkt->flags & TCP_PSH_FLAG) == 0))
    {
        RING_VERDICT("TCP_PSH flag in the last packet is missing");
    }
    else if ((pkt->payload_len != length_to_receive) &&
             ((pkt->flags & TCP_PSH_FLAG) != 0))
    {
        WARN("Packet #%d is not the last but has TCP_PSH "
                     "flag set", packets_received);
        psh_counter++;
    }
    
    RING("Packet of size %d is received", pkt->payload_len);
    length_to_receive -= pkt->payload_len;
}

#define SET_NODELAY(optval_) \
    do {                                                          \
        int optval = optval_;                                     \
                                                                  \
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval); \
    } while (0)

int
main(int argc, char *argv[])
{
    int             sid;
    csap_handle_t   csap = CSAP_INVALID_HANDLE;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    uint8_t                rx_buf[TST_BUF_LEN];
    uint8_t                tx_buf[TST_BUF_LEN];
    int                    sent_b;
    int                    recv_b1;
    int                    recv_b2;
    int                    to_send1;

    int                    current_mtu;
    int                    optval;
    
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    
    const struct if_nameindex *tst_if = NULL;

    int                    send_length[2];
    uint64_t               total_sent;
    unsigned int           num;
    int                    ret;


    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
    {
        TEST_FAIL("rcf_ta_create_session failed");
        return 1;
    }

    INFO("Test: Created session: %d", sid); 

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          NULL, NULL,
                                          ((struct sockaddr_in *)tst_addr)->
                                          sin_addr.s_addr,
                                          ((struct sockaddr_in *)iut_addr)->
                                          sin_addr.s_addr,
                                          ((struct sockaddr_in *)tst_addr)->
                                          sin_port,
                                          ((struct sockaddr_in *)iut_addr)->
                                          sin_port, &csap));
    /* CSAP part end */
    
    /* Establishingh the connection */
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    /* 
     * Checking, that TCP_NODELAY is turned OFF and turning on the 
     * TCP_CORK.
     */
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval);
    if (optval)
    {
        RING("Default value for TCP_NODELAY mode is turn on");
        optval = 0;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval);
    }

    optval = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_TCP_CORK, &optval);
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_CORK, &optval);
    if (optval == 0)
        TEST_FAIL("TCP_CORK mode on 'iut_s' can not be turn on");

    /* CSAP manipulation */
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF, 100,
                                   RCF_TRRECV_PACKETS));

    /*
     * Check possibility to coalesce two packets with summary
     * length less than currnet MSS value.
     * Expect one packet on 'tst_s'.
     */

    /* Retreiving the current MTU value */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &current_mtu);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(IP_MTU) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    
    /* Sending two packets with sum length less, than MSS. */
    send_length[0] = current_mtu / 4;
    send_length[1] = current_mtu / 6;
    rpc_many_send(pco_iut, iut_s, 0, send_length, 2, &total_sent);
    if (total_sent != (uint64_t)(current_mtu / 4 + current_mtu / 6))
    {
        TEST_FAIL("sent %ld bytes instead of %d bytes",
                  total_sent, current_mtu / 4 + current_mtu / 6);
    }

    rc = iomux_call_default_simple(pco_tst, tst_s, EVT_RD, NULL, 2000);
    if (rc != 1)
    {
        /* linux should send the uncompleted packet after a timeout */
        TEST_FAIL("Data is not received on the TST side, rc = %d", rc);
    }

    SET_NODELAY(1);

    recv_b1 = rpc_recv(pco_tst, tst_s, rx_buf, TST_BUF_LEN, 0);
    if ((uint64_t)recv_b1 != total_sent)
    {
        TEST_FAIL("tst_s received %d bytes instead of %ld", 
                  recv_b1, total_sent);
    }

    length_to_receive = total_sent;
    CHECK_PACKET_NUMBER(1);
    SET_NODELAY(0);
    
    /*
     * Check the posibility of coalesce for two packets:
     * one of MTU size and one less, sum length should be less,
     * than 2*MSS.
     * Expection two packets, without TCP_CORK there should be
     * three of them.
     */

    /* function to execute number of send() on agent without delay */
    send_length[0] = current_mtu / 2;
    send_length[1] = current_mtu;
    rpc_many_send(pco_iut, iut_s, 0, send_length, 2, &total_sent);
    if (total_sent != (uint64_t)(current_mtu / 2 + current_mtu))
    {
        TEST_FAIL("sent %ld bytes instead of %d bytes",
                  total_sent, current_mtu / 2 + current_mtu);
    }

    sleep(1);
    SET_NODELAY(1);
    
    recv_b1 = rpc_recv(pco_tst, tst_s, rx_buf, TST_BUF_LEN, 0);

    if ((uint64_t)(recv_b1) != total_sent)
        TEST_FAIL("received %d bytes instead of %d",
                  recv_b1, total_sent);
   
    length_to_receive = total_sent;
    CHECK_PACKET_NUMBER(2);
    SET_NODELAY(0);

    /*
     * Check that a packet with length more than current MSS but less
     * than 2MSS will send as two packets:
     *    the first without delay (length according to current MSS);
     *    the second (the rest of original packet) after retransmit 
     *    timeout interval.
     *
     * On linux with TCP_CORK and without the behaviour will be the same
     * (exept the delay of the second packet).
     * On level 5 the second packet will not arrive until the
     * TCP_NODELAY option is turned on.
     */
    to_send1 = current_mtu / 3 + current_mtu;
    RPC_SEND(sent_b, pco_iut, iut_s, tx_buf, to_send1, 0);

    sleep(1);
    recv_b1 = rpc_recv(pco_tst, tst_s, rx_buf, TST_BUF_LEN, 0);
    SET_NODELAY(1);
    recv_b2 = 0;

    if (recv_b1 + recv_b2 != to_send1)
        TEST_FAIL("received %d bytes on 'tst_s' instead of %d, "
                  "second recv() duration is %d usec",
                  recv_b1, to_send1, pco_tst->duration);

    length_to_receive = to_send1;
    CHECK_PACKET_NUMBER(2);
    SET_NODELAY(0);
    
    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        rcf_ta_trrecv_stop(pco_tst->ta, sid, csap, NULL, NULL, &num))
    {
        TEST_FAIL("Failed to stop receiving packets");
    }

    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_tst->ta, sid, csap))
    {
        ERROR("Failed to destroy CSAP");
    }
    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
