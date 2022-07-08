/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Test attacks/tcp/syn_cookies
 * TCP SYN cookies
 */

/** @page attacks-tcp-syn_cookies Test for tcp syncookies
 *
 * @objective Check that TCP SYN cookies works well.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer
 * @param disable_tst_timestamps If @c TRUE disable TCP timestamps on Tester
 * @param pending_accept         If @c TRUE block IUT process in accept() call
 * @param use_syn_cookies        If @c TRUE set net/ipv4/tcp_syncookies system
 *                               option
 * @param syn_backlog            Set net/ipv4/tcp_max_syn_backlog system
 *                               option to value:
 *                               - 256
 *                               - 131072
 *
 * @par Scenario
 * -# Switch on SYN cookies.
 * -# if @p disable_tst_timestamps is @c TRUE switch off TCP timestamps on
 *    tester.
 * -# Create stream listening socket on @p pco_iut.
 * -# Start the task on the @p pco_tst, which sends flood of
 *    TCP SYN packets from different source IP addresses/ports to
 *    @p iut_addr.
 * -# Create 3 connections between @p pco_iut and @p pco_tst using
 *    already created listening socket.
 * -# Check that existing connections may be used to send/receive data.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "attacks/tcp/syn_cookies"

#include "sockapi-test.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include "tapi_tad.h"
#include "tapi_ip4.h"
#include "tapi_tcp.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"
#include "ndn.h"

#define PKT_NUM         (1024 * 2048) /**< Number of packets for flooding */
#define ADDRESS_NUM      16

#define CONNECT_ACCEPT_SLEEP(_i, _wait) \
do                                                      \
{                                                       \
    rpc_connect(pco_tst, tst_s##_i, iut_addr);          \
    pco_iut->timeout = TE_SEC2MS(20);                   \
    if (_wait)                                          \
        pco_iut->op = RCF_RPC_WAIT;                     \
    acc_s##_i = rpc_accept(pco_iut, iut_s, NULL, NULL); \
    SLEEP(1);                                           \
} while(0);

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if;
    const struct if_nameindex *tst_if;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *tst_lladdr = NULL;
    struct sockaddr_storage    aux_addr;
    struct in_addr            *addr_ptr;
    te_bool                    pending_accept = FALSE;
    te_bool                    use_syn_cookies = FALSE;
    int                        syn_backlog;
    int                        old_syn_backlog = 0;

    static char buf[1024];

    int sid;
    int num;
    int iut_s = -1;
    int acc_s0 = -1;
    int acc_s1 = -1;
    int acc_s2 = -1;
    int acc_s3 = -1;
    int tst_s0 = -1;
    int tst_s1 = -1;
    int tst_s2 = -1;
    int tst_s3 = -1;

    uint8_t mac_iut[ETHER_ADDR_LEN], mac_tst[ETHER_ADDR_LEN];

    size_t mac_len;

    csap_handle_t csap = CSAP_INVALID_HANDLE;
    asn_value    *pkt = NULL;

    cfg_handle    ef_tcp_sc_h = CFG_HANDLE_INVALID;
    char         *old_ef_tcp_sc = NULL;
    cfg_handle    ef_tcp_bm_h = CFG_HANDLE_INVALID;
    char         *old_ef_tcp_bm = NULL;
    cfg_handle    ef_max_end_h = CFG_HANDLE_INVALID;
    char         *old_ef_max_end = NULL;

    int buf_sc_val;

    te_bool disable_tst_timestamps = FALSE;

    int i;
    int last_added_arp = 0;
    int old_tcp_timestamps;

    char aux_buf[16];

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(disable_tst_timestamps);
    TEST_GET_BOOL_PARAM(pending_accept);
    TEST_GET_BOOL_PARAM(use_syn_cookies);
    TEST_GET_INT_PARAM(syn_backlog);

    if (use_syn_cookies)
    {
        if (!te_str_is_null_or_empty(pco_iut->nv_lib))
        {
           ef_tcp_sc_h =
               sockts_set_env_gen(pco_iut, "EF_TCP_SYNCOOKIES",
                                  "1", &old_ef_tcp_sc, FALSE);
        }
        else
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, &buf_sc_val,
                                             "net/ipv4/tcp_syncookies"));
    }

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, syn_backlog,
                                     &old_syn_backlog,
                                     "net/ipv4/tcp_max_syn_backlog"));
    memset(aux_buf, 0, sizeof(aux_buf));
    snprintf(aux_buf, sizeof(aux_buf), "%d", syn_backlog);
    ef_tcp_bm_h =
        sockts_set_env_gen(pco_iut, "EF_TCP_BACKLOG_MAX",
                           aux_buf, &old_ef_tcp_bm, FALSE);
    memset(aux_buf, 0, sizeof(aux_buf));
    snprintf(aux_buf, sizeof(aux_buf), "%d", 4 * syn_backlog);
    ef_max_end_h =
        sockts_set_env_gen(pco_iut, "EF_MAX_ENDPOINTS",
                           aux_buf, &old_ef_max_end, TRUE);

    if (disable_tst_timestamps)
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, 0, &old_tcp_timestamps,
                                         "net/ipv4/tcp_timestamps"));

    mac_len = ETHER_ADDR_LEN;
    tapi_cfg_get_hwaddr(pco_iut->ta, iut_if->if_name, mac_iut,
                        &mac_len);
    mac_len = ETHER_ADDR_LEN;
    tapi_cfg_get_hwaddr(pco_tst->ta, tst_if->if_name, mac_tst,
                        &mac_len);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, 10);

    tst_s0 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s3 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    /* Resolve ARP, check it is OK */
    CONNECT_ACCEPT_SLEEP(0, FALSE);
    sockts_test_connection(pco_iut, acc_s0, pco_tst, tst_s0);

    /* Start flooding on CSAPs */
    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
        TEST_FAIL("Failed to allocate RCF session");

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                          (TAD_ETH_RECV_DEF &
                                           ~TAD_ETH_RECV_OTHER) |
                                          TAD_ETH_RECV_NO_PROMISC,
                                          mac_tst, mac_iut, htonl(INADDR_ANY),
                                          SIN(iut_addr)->sin_addr.s_addr,
                                          -1, -1, &csap));

    /* Use 16 addresses, avoid net, multicasts and broadcasts */
    sprintf(buf,
             "{ arg-sets { simple-for:{begin 1,end %u} },                "
             "  pdus  {                                                  "
             "      tcp:{ dst-port plain:%d,                             "
             "            src-port script:\"expr:(5000+$0)\",            "
             "            flags plain:2,                                 "
             "            seqn plain:666},                               "
             "      ip4:{src-addr script:\"expr:(($0 %% %d) + 0x%08x)\"},"
             "      eth:{}}}                                             ",
             PKT_NUM, htons(SIN(iut_addr)->sin_port), ADDRESS_NUM,
             (ntohl(SIN(tst_addr)->sin_addr.s_addr) & 0xFFFFFF70) | 0x10);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, tst_addr, &aux_addr));
    addr_ptr = (struct in_addr *)te_sockaddr_get_netaddr(SA(&aux_addr));
    for (i = 0; i < ADDRESS_NUM; i++)
    {
        addr_ptr->s_addr =
            htonl(((ntohl(SIN(tst_addr)->sin_addr.s_addr)
                    & 0xFFFFFF70) | 0x10) + i);
        CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                                 SA(&aux_addr), CVT_HW_ADDR(tst_lladdr),
                                 TRUE));
        last_added_arp = i;
    }
    CFG_WAIT_CHANGES;

    CHECK_RC(asn_parse_value_text(buf, ndn_traffic_template, &pkt, &num));

    CHECK_RC(tapi_tad_trsend_start(pco_tst->ta, sid, csap, pkt,
                                   RCF_MODE_NONBLOCKING));
    if (pending_accept)
    {
        pco_iut->op = RCF_RPC_CALL;
        acc_s1 = rpc_accept(pco_iut, iut_s, NULL, NULL);
    }
    SLEEP(2);
    CONNECT_ACCEPT_SLEEP(1, pending_accept);
    MSLEEP(100);
    CONNECT_ACCEPT_SLEEP(2, FALSE);
    MSLEEP(100);
    CONNECT_ACCEPT_SLEEP(3, FALSE);

    sockts_test_connection(pco_iut, acc_s0, pco_tst, tst_s0);
    sockts_test_connection(pco_iut, acc_s1, pco_tst, tst_s1);
    sockts_test_connection(pco_iut, acc_s2, pco_tst, tst_s2);
    sockts_test_connection(pco_iut, acc_s3, pco_tst, tst_s3);

    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    /* Close the listening socket before ARP removal. */
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    /* tapi_sockaddr_clone allocates port, which is bad idea.
     * Just use memcpy. */
    memcpy(&aux_addr, tst_addr, te_sockaddr_get_size(tst_addr));
    addr_ptr = (struct in_addr *)te_sockaddr_get_netaddr(SA(&aux_addr));
    for (i = 0; i < last_added_arp; i++)
    {
        addr_ptr->s_addr =
            htonl(((ntohl(SIN(tst_addr)->sin_addr.s_addr)
                    & 0xFFFFFF70) | 0x10) + i);
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                          iut_if->if_name,
                                          SA(&aux_addr)));
    }
    CFG_WAIT_CHANGES;

    CLEANUP_RPC_CLOSE(pco_tst, tst_s0);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s0);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s1);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s2);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s3);

    CLEANUP_CHECK_RC(
        tapi_cfg_sys_ns_set_int(pco_iut->ta, old_syn_backlog, NULL,
                                "net/ipv4/tcp_max_syn_backlog"));
    if (te_str_is_null_or_empty(pco_iut->nv_lib))
        CLEANUP_CHECK_RC(
            tapi_cfg_sys_ns_set_int(pco_iut->ta, buf_sc_val, NULL,
                                    "net/ipv4/tcp_syncookies"));

    if (disable_tst_timestamps)
        CLEANUP_CHECK_RC(
            tapi_cfg_sys_ns_set_int(pco_tst->ta, old_tcp_timestamps, NULL,
                                    "net/ipv4/tcp_timestamps"));

    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_tcp_sc_h,
                                            old_ef_tcp_sc, FALSE));
    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_tcp_bm_h,
                                            old_ef_tcp_bm, FALSE));
    CLEANUP_CHECK_RC(sockts_restore_env_gen(pco_iut, ef_max_end_h,
                                            old_ef_max_end, FALSE));

    if (rcf_rpc_server_restart(pco_iut) != 0)
    {
        (void)rcf_ta_call(pco_iut->ta, 0, "die", &rc, 0, TRUE);
        CLEANUP_TEST_FAIL("It seems that syn_flood made TA crasy");
    }

    TEST_END;
}
