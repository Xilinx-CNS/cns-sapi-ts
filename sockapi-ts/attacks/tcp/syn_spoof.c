/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Test attacks/tcp/syn_spoof
 * TCP SYN spoofing
 */

/** @page attacks-tcp-syn_spoof  TCP SYN spoofing
 *
 * @objective Check that TCP SYN spoofing does not lead to DoS
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_two_nets_iut_both
 *                  - @ref arg_types_env_two_nets_iut_first
 *                  - @ref arg_types_env_two_nets_iut_second
 *
 * @par Scenario
 * -# Create listening socket on @p pco_iut.
 * -# Start sniffing interfaces of @p pco_tst1 and @p pco_tst2.
 * -# Send a SYN packet (i.e. try to  connect)  with forged source
 *    address from @p pco_tst1 to @p pco_iut.
 * -# Check that @p pco_iut behaves correctly, i.e. drops this SYN
 *    or replies to @p pco_tst1 or @p pco_tst2.
 * -# Check that next connection  with correct source address will
 *    be accepted.
 * -# Check that existing connections may be used to  send/receive
 *    data.
 *
 * @author Igor Muzhichenko <Igor.Muzhichenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/tcp/syn_spoof"

#include "sockapi-test.h"

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#include "te_ethernet.h"
#include "tapi_cfg_base.h"
#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_tcp.h"
#include "ndn.h"

#define TIMEOUT          (1000 * 5)
#define IP_HDR_LEN       20     /**< IP header length in bytes */

te_bool ack_received = FALSE;

/** User data for sniffing callback function */
struct user_data {
    const struct sockaddr *tst1_addr; /**< IP address of the first tester */
    const struct sockaddr *tst2_addr; /**< IP address of the second tester */
};

/** Callback for catching TCP packets */
static void
syn_rcv_callback(const asn_value *packet, int layer,
                 const ndn_eth_header_plain *header,
                 const uint8_t *payload, uint16_t plen, void *userdata)
{
    UNUSED(packet);
    UNUSED(layer);
    UNUSED(header);
    UNUSED(plen);
    struct user_data *ud = userdata;

    if (((struct iphdr *)payload)->protocol == IPPROTO_TCP)
    {
        if ((*(payload + IP_HDR_LEN + 13) & TCP_ACK_FLAG) == 1)
        {
            WARN("ACK was received src");
            ack_received = TRUE;
            if (((struct iphdr *)payload)->saddr ==
                CONST_SIN(ud->tst1_addr)->sin_addr.s_addr)
            {
                TEST_VERDICT("Reply SYN-ACK is send via the same interface.");
            }
            else if (((struct iphdr *)payload)->saddr ==
                     CONST_SIN(ud->tst2_addr)->sin_addr.s_addr)
            {
                TEST_VERDICT("Reply SYN-ACK is send via another interface.");
            }
        }
    }
}

int
main(int argc, char **argv)
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    csap_handle_t  tst1_csap = CSAP_INVALID_HANDLE;
    csap_handle_t  tst2_csap = CSAP_INVALID_HANDLE;
    csap_handle_t  tst1_send_csap = CSAP_INVALID_HANDLE;

    static tapi_tcp_handler_t tcp_conn;

    const struct if_nameindex *iut_if1;
    const struct if_nameindex *tst1_if;
    const struct if_nameindex *tst2_if;

    const struct sockaddr *iut_addr1;
    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;

    struct sockaddr_in taddr;
    struct sockaddr_in iut_taddr;
    struct sockaddr_in tst2_taddr;
    struct user_data   ud;

    int iut_s_tcp = -1;
    int tst1_s_tcp = -1;
    int tst1_sid = -1;
    int tst1_send_sid = -1;
    int tst2_sid = -1;

    unsigned int addrlen = sizeof(struct sockaddr);
    unsigned int num = 1;

    char    oid[RCF_MAX_ID];
    uint8_t iut_mac[ETHER_ADDR_LEN];
    uint8_t tst1_mac[ETHER_ADDR_LEN];

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    /* Get MAC addresses */
    sprintf(oid, "/agent:%s/interface:%s", pco_iut->ta, iut_if1->if_name);
    if (tapi_cfg_base_if_get_mac(oid, iut_mac) != 0)
    {
        ERROR("%s(): Can't get destination ethernet address.", __FUNCTION__);
        TEST_STOP;
    }

    sprintf(oid, "/agent:%s/interface:%s", pco_tst1->ta, tst1_if->if_name);
    if (tapi_cfg_base_if_get_mac(oid, tst1_mac) != 0)
    {
        ERROR("%s(): Can't get destination ethernet address.", __FUNCTION__);
        TEST_STOP;
    }

    memset(&iut_taddr, 0, sizeof(struct sockaddr_in));
    iut_taddr.sin_family = SIN(iut_addr1)->sin_family;
    iut_taddr.sin_addr.s_addr = SIN(iut_addr1)->sin_addr.s_addr;
    TAPI_SET_NEW_PORT(pco_iut, &iut_taddr);

    memset(&tst2_taddr, 0, sizeof(struct sockaddr_in));
    tst2_taddr.sin_family = CONST_SIN(tst2_addr)->sin_family;
    tst2_taddr.sin_addr.s_addr = CONST_SIN(tst2_addr)->sin_addr.s_addr;
    TAPI_SET_NEW_PORT(pco_tst2, &tst2_taddr);

    rcf_ta_create_session(pco_tst1->ta, &tst1_sid);
    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst1->ta, tst1_sid,
                                          tst1_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          NULL, NULL,
                                          CONST_SIN(tst1_addr)->sin_addr.s_addr,
                                          CONST_SIN(&iut_taddr)->sin_addr.s_addr,
                                          CONST_SIN(&tst2_addr)->sin_port,
                                          CONST_SIN(&iut_taddr)->sin_port,
                                          &tst1_csap));

    rcf_ta_create_session(pco_tst2->ta, &tst2_sid);
    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst2->ta, tst2_sid,
                                          tst2_if->if_name,
                                          TAD_ETH_RECV_DEF |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          NULL, NULL,
                                          CONST_SIN(&tst2_taddr)->sin_addr.s_addr,
                                          CONST_SIN(&iut_taddr)->sin_addr.s_addr,
                                          CONST_SIN(&tst2_taddr)->sin_port,
                                          CONST_SIN(&iut_taddr)->sin_port,
                                          &tst2_csap));

    rcf_ta_create_session(pco_tst1->ta, &tst1_send_sid);
    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst1->ta, tst1_send_sid,
                                          tst1_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          tst1_mac, iut_mac,
                                          CONST_SIN(&tst2_taddr)->sin_addr.s_addr,
                                          CONST_SIN(&iut_taddr)->sin_addr.s_addr,
                                          CONST_SIN(&tst2_taddr)->sin_port,
                                          CONST_SIN(&iut_taddr)->sin_port,
                                          &tst1_send_csap));

    CHECK_RC(tapi_tcp_ip4_eth_recv_start(pco_tst1->ta, tst1_sid, tst1_csap,
                                         CONST_SIN(tst1_addr)->sin_addr.s_addr,
                                         CONST_SIN(&iut_taddr)->sin_addr.s_addr,
                                         CONST_SIN(tst1_addr)->sin_port,
                                         CONST_SIN(&iut_taddr)->sin_port,
                                         TIMEOUT, num, RCF_TRRECV_PACKETS));

    CHECK_RC(tapi_tcp_ip4_eth_recv_start(pco_tst2->ta, tst2_sid, tst2_csap,
                                         CONST_SIN(&tst2_taddr)->sin_addr.s_addr,
                                         CONST_SIN(&iut_addr1)->sin_addr.s_addr,
                                         CONST_SIN(&tst2_taddr)->sin_port,
                                         CONST_SIN(&iut_taddr)->sin_port,
                                         TIMEOUT, num, RCF_TRRECV_PACKETS));

    iut_s_tcp = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                           RPC_SOCK_STREAM, RPC_PF_INET);

    tst1_s_tcp = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                           RPC_SOCK_STREAM, RPC_PF_INET);

    rpc_bind(pco_iut, iut_s_tcp, (struct sockaddr *)&iut_taddr);
    rpc_listen(pco_iut, iut_s_tcp, 1);

    CHECK_RC(tapi_tcp_init_connection(pco_tst1->ta, TAPI_TCP_CLIENT,
                                      (struct sockaddr *)&tst2_taddr,
                                      (struct sockaddr *)iut_addr1,
                                      tst1_if->if_name, tst1_mac, iut_mac,
                                      0, &tcp_conn));
    ud.tst1_addr = tst1_addr;
    ud.tst2_addr = tst2_addr;
    tapi_tad_trrecv_stop(pco_tst1->ta, tst1_sid, tst1_csap,
                         tapi_eth_trrecv_cb_data(syn_rcv_callback, &ud), &num);

    tapi_tad_trrecv_stop(pco_tst2->ta, tst2_sid, tst1_csap,
                         tapi_eth_trrecv_cb_data(syn_rcv_callback, &ud), &num);

    if (!ack_received)
        RING_VERDICT("Incorrect SYN is not accepted.");

    CHECK_RC(rpc_connect(pco_tst1, tst1_s_tcp, SA(&iut_taddr)));
    rpc_accept(pco_iut, iut_s_tcp, SA(&taddr), &addrlen);
    if (taddr.sin_addr.s_addr != CONST_SIN(tst1_addr)->sin_addr.s_addr)
        TEST_FAIL("Accepted incorrect source address (%s)",
                   inet_ntoa(taddr.sin_addr));

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_tcp_destroy_connection(tcp_conn));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, tst1_csap));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, tst1_send_csap));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst2->ta, 0, tst2_csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s_tcp);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s_tcp);

    if (pco_iut != NULL && rcf_rpc_server_restart(pco_iut) != 0)
    {
        WARN("It seems that syn_spoof made TA crasy");
        rcf_ta_call(pco_iut->ta, 0, "die", &rc, 0, TRUE);
    }

    TEST_END;
}

