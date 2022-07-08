/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP.
 *
 * $Id$
 */

/** @page multicast-mcast_fragmented_mac Fragmented multicast packet header information.
 *
 * @objective Check that fragmented multicast packet has appropriate
 *            source/destination MAC address and other IP header info.
 *
 * @type Conformance
 *
 * @param pco_tst       PCO on Tester
 * @param pco_iut       PCO on IUT
 * @param iut_addr      Address on IUT
 * @param tst_addr      Address on Tester
 * @param mcast_addr    Multicast address
 * @param iut_ll_addr   IUT link-level address
 * @param tst_ll_addr   Tester link-level address
 * @param tst_if        Tester interace connected to IUT
 * @param data_len      Datagram size
 * @param connect_iut   Connect @p iut_s and use @b send() instead of
 *                      @b sendto()
 * @param packet_number Number of datagrams to send for reliability.
 *
 * @par Test sequence:
 * -# Create datagram sockets: @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 * -# Adjoin @p tst_s to @p mcast_addr multicasting group.
 * -# Set @c IP_MULTICAST_IF option on @p iut_s to set @p iut_if as interface
 *    for multicast traffic sending.
 * -# Create CSAP to catch packets from IUT to Tester with appropriate
 *    MAC addresses. (Destination MAC address is computed from destination IP
 *    address). Start listening
 * -# Send @p packet_number @p data_len bytes long datagrams from @p iut_s 
      to @p mcast_addr.
 * -# Receive them on Tester. Verify them.
 * -# Stop the CSAP. Make sure it has caught the multicast datagram.
 *  
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_fragmented_mac"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_ip4.h"
#include "mcast_lib.h"
#include "multicast.h"

#ifndef ETH_ALEN
#define ETH_ALEN        6
#endif

static int              mcast_packets_received = 0;

/**
 * Callback function to proceed received packets.
 *
 * @param pkt       Pointer to packet received
 * @param userdata  User data; unused
 *
 * @return          NULL
 */
static void
callback(const tapi_ip4_packet_t *pkt, void *userdata)
{
    UNUSED(userdata);
    UNUSED(pkt);

    mcast_packets_received++;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             s_tst;          /* Session on Tester */
    csap_handle_t   tst_csap =      /* CSAP on Tester */
                        CSAP_INVALID_HANDLE;

    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *mcast_addr = NULL;
    uint8_t                   *sendbuf = NULL;
    uint8_t                   *recvbuf = NULL;
    unsigned int               num = 0;
    struct tarpc_mreqn         mreq;
    const struct sockaddr     *iut_ll_addr = NULL;
    uint8_t                    tst_ll_addr[ETH_ALEN] = {0x01, 0x00, 0x5e};
    socklen_t                  data_len = 0;
    uint32_t                   mcast_sin_addr;
    int                        i;
    int                        packet_number;
    te_bool                    connect_iut;
    tarpc_joining_method       method;

    mcast_listener_t listener = CSAP_INVALID_HANDLE;
    int              detected = 0;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_LINK_ADDR(iut_ll_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_MCAST_METHOD(method);

    /* Copy lower 3 bytes of IP multicast address to MAC address field */
    mcast_sin_addr = *(uint32_t *)te_sockaddr_get_netaddr(mcast_addr);
    memcpy(tst_ll_addr + 3, (uint8_t *)&mcast_sin_addr + 1,
           sizeof(struct in_addr) - 1);
    /* Clear 24th bit */
    tst_ll_addr[3] &= 0x7F;

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = malloc(data_len));

    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    if (rpc_mcast_join(pco_tst, tst_s, mcast_addr, tst_if->if_index,
                       method) < 0)
    {
        TEST_VERDICT("Socket on Tester cannot join multicast group");
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);

    rpc_bind(pco_tst, tst_s, mcast_addr);

    /* Create CSAP that controls incoming packets on Tester */
    rcf_ta_create_session(pco_tst->ta, &s_tst);
    if (tapi_ip4_eth_csap_create(pco_tst->ta, s_tst, tst_if->if_name,
                                 TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                                 tst_ll_addr,
                                 (uint8_t *)iut_ll_addr->sa_data,
                                 SIN(mcast_addr)->sin_addr.s_addr,
                                 SIN(iut_addr)->sin_addr.s_addr,
                                 IPPROTO_UDP, &tst_csap) != 0)
    {
        TEST_FAIL("Cannot create CSAP on Tester");
    }
    TAPI_WAIT_NETWORK;

    if (connect_iut)
    {
        rpc_connect(pco_iut, iut_s, mcast_addr);
    }

    listener = mcast_listener_init(pco_iut, iut_if, mcast_addr, NULL, 0);

    for (i = 0; i < packet_number; i++)
    {
        mcast_packets_received = 0;

        mcast_listen_start(pco_iut, listener);
        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, s_tst, tst_csap, NULL,
                                       TAD_TIMEOUT_INF, 10,
                                       RCF_TRRECV_PACKETS));

        if (connect_iut)
        {
            rpc_send(pco_iut, iut_s, sendbuf, data_len, 0);
        }
        else
        {
            rpc_sendto(pco_iut, iut_s, sendbuf, data_len, 0, mcast_addr);
        }

        rpc_recv(pco_tst, tst_s, recvbuf, data_len, 0);

        if (memcmp(sendbuf, recvbuf, data_len) != 0)
        {
            TEST_VERDICT("Data verification failed");
        }

        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, s_tst, tst_csap,
                                      tapi_ip4_eth_trrecv_cb_data(
                                           callback, NULL), &num));

        if (mcast_packets_received == 0)
        {
            TEST_VERDICT("No multicast packets with appropriate MAC "
                         "address");
        }
        rc = mcast_listen_stop(pco_iut, listener, NULL);
        if (rc > 0)
        {
            if (detected == 1)
                RING_VERDICT("More than one multicast packet was "
                             "detected by system");
            detected++;
        }
    }
    RING("%d multicast packets were detected", detected);

    if (rpc_mcast_leave(pco_tst, tst_s, mcast_addr, tst_if->if_index,
                        method) < 0)
    {
        TEST_VERDICT("Socket on IUT cannot leave multicast group");
    }

    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener);
    free(sendbuf);
    free(recvbuf);
    if (tst_csap != CSAP_INVALID_HANDLE)
    {
        if ((rc = tapi_tad_csap_destroy(pco_tst->ta,
                                      s_tst, tst_csap)) != 0)
        {
            ERROR("tapi_tad_csap_destroy() failed: %r", rc);
            result = -1;
        }
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
