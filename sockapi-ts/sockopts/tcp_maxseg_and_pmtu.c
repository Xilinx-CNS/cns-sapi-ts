/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-tcp_maxseg_and_pmtu TCP_MAXSEG socket option behaviour when the MTU of the route is changed.
 *
 * @objective Check behaviour of the @c TCP_MAXSEG socket option
 *            in case when MTU of a route is changed (the MSS should be
 *            set to MTU - IP/TCP headers size including options)
 *
 *
 * @type conformance
 *
 * @reference MAN 7 tcp
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param mtu_1            Initial MTU of the route.
 * @param mtu_2            The second MTU value of the route
 *                         ( < @p mtu_1)
 * @param mtu_3            The third MTU value of the route
 *                         ( @p mtu2 < @p mtu3 < @p mtu_1)
 *
 * @par Test sequence:
 * -# Create a new route from IUT to TST with MTU equal to the
 *    @p mtu_1;
 * -# Create a new route from TST to IUT with default MTU;
 * -# Establish a connection between IUT and TST;
 * -# Send some data from the @p iut_s to the @p tst_s until MSS changes;
 * -# Check that MSS on the @p iut_s is equal to
 *    @p mtu_1 - IP/TCP headers length;
 * -# Set the MTU of the route on IUT to the @p mtu_2;
 * -# Send some data from the @p iut_s to the @p tst_s until MSS changes;
 * -# Check that MSS on the @p iut_s is equal to
 *    @p mtu_2 - IP/TCP headers length;
 * -# Set the MTU of the route on IUT to the @p mtu_3;
 * -# Send some data from the @p iut_s to the @p tst_s until MSS changes;
 * -# Check that MSS on the @p iut_s is equal to
 *    @p mtu_3 - IP/TCP headers length;
 * -# Close all opened sockets.
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oketlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_maxseg_and_pmtu"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "iomux.h"
#include "tapi_sockets.h"

/** How long to wait until MSS is changed, in seconds. */
#define MSS_TIMEOUT 5

/** Minimum length of IP header (20) + minimum length of TCP header (20). */
#define IP_TCP_MIN_HDR_LEN 40

/**
 * Compute expected MSS value from MTU.
 *
 * @param mtu_        MTU value.
 * @param opts_len_   IP/TCP options length.
 */
#define MSS_FROM_MTU(mtu_, opts_len_) \
    (mtu_ - IP_TCP_MIN_HDR_LEN - opts_len_)

/**
 * User callback, which is passed to tapi_tad_trrecv_stop()
 * function to handle captured packets.
 *
 * @param pkt       Packet to be handled.
 * @param userdata  Where to save IP/TCP options length.
 *                  Will be set to negative value in case of
 *                  failure, should be initialized to non-negative
 *                  value.
 */
static void
user_pkt_handler(asn_value *pkt, void *userdata)
{
    int     *opts_len = (int *)userdata;
    int      payload_length = 0;

    size_t      len = 0;
    int32_t     ip_total_len = 0;
    int         rc = 0;

    if (*opts_len < 0)
        return;

    payload_length = asn_get_length(pkt, "payload.bytes");
    if (payload_length < 0)
    {
        ERROR("Failed to get payload length");
        *opts_len = -1;
        goto cleanup;
    }

    len = sizeof(ip_total_len);
    rc = asn_read_value_field(pkt, &ip_total_len, &len,
                              "pdus.1.#ip4.total-length");
    if (rc != 0)
    {
        ERROR("Failed to get IP Total Length field");
        *opts_len = -1;
        goto cleanup;
    }

    *opts_len = ip_total_len - IP_TCP_MIN_HDR_LEN - payload_length;

cleanup:

    asn_free_value(pkt);
}

/**
 * Provoke MSS update after changing route MTU by
 * sending some data via TCP connection.
 *
 * @param rpcs1     The first RPC server.
 * @param s1        The first socket.
 * @param rpcs2     The second RPC server.
 * @param s2        The second socket.
 * @param old_mss   Previous MSS value.
 */
static void
provoke_mss_update(rcf_rpc_server *rpcs1, int s1,
                   rcf_rpc_server *rpcs2, int s2,
                   int old_mss)
{
#define PKT_SIZE 1500

    struct timeval tv_start;
    struct timeval tv_cur;
    char           buf[PKT_SIZE];
    int            mss;
    te_dbuf        dbuf = TE_DBUF_INIT(0);
    int            rc;

    rc = gettimeofday(&tv_start, NULL);
    if (rc < 0)
        TEST_FAIL("gettimeofday() failed");

    while (TRUE)
    {
        te_fill_buf(buf, PKT_SIZE);
        rc = rpc_send(rpcs1, s1, buf, PKT_SIZE, 0);
        if (rc != PKT_SIZE)
            TEST_FAIL("send() returned %d instead of %d",
                      rc, PKT_SIZE);

        TAPI_WAIT_NETWORK;

        rc = tapi_sock_read_data(rpcs2, s2, &dbuf);
        if (rc != PKT_SIZE ||
            memcmp(dbuf.ptr, buf, PKT_SIZE) != 0)
            TEST_FAIL("Expected data was not received");

        te_dbuf_free(&dbuf);

        rpc_getsockopt(rpcs1, s1, RPC_TCP_MAXSEG, &mss);
        if (mss != old_mss)
            break;

        rc = gettimeofday(&tv_cur, NULL);
        if (rc < 0)
            TEST_FAIL("gettimeofday() failed");

        if (TIMEVAL_SUB(tv_cur, tv_start) > TE_SEC2US(MSS_TIMEOUT))
            break;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_gw  = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 tst_s = -1;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    const struct sockaddr *tst_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *gw_tst_addr = NULL;

    int                    mss;
    int                    prev_mss;
    int                    exp_mss;

    int                    mtu_1;
    int                    mtu_2;
    int                    mtu_3;

    int                    route_prefix;

    cfg_handle             rt1 = CFG_HANDLE_INVALID;
    cfg_handle             rt2 = CFG_HANDLE_INVALID;

    int                    ret;
    int                    opts_len = 0;

    csap_handle_t             csap = CSAP_INVALID_HANDLE;
    tapi_tad_trrecv_cb_data   cb_data;
    unsigned int              num = 0;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);

    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR_NO_PORT(gw_iut_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst_addr);

    TEST_GET_INT_PARAM(mtu_1);
    TEST_GET_INT_PARAM(mtu_2);
    TEST_GET_INT_PARAM(mtu_3);

    route_prefix = te_netaddr_get_size(addr_family_rpc2h(
                       sockts_domain2family(RPC_PF_INET))) * 8;

    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    if (tapi_cfg_add_route(pco_iut->ta, AF_INET,
                           te_sockaddr_get_netaddr(tst_addr), route_prefix,
                           te_sockaddr_get_netaddr(gw_iut_addr), NULL, NULL,
                           0, 0, 0, mtu_1, 0, 0, &rt1) != 0)
    {

        TEST_FAIL("Cannot add route to 'alien_addr' via 'host2_addr'");
    }
    if (tapi_cfg_add_route(pco_tst->ta, AF_INET,
                           te_sockaddr_get_netaddr(iut_addr), route_prefix,
                           te_sockaddr_get_netaddr(gw_tst_addr), NULL, NULL,
                           0, 0, 0, 0, 0, 0, &rt2) != 0)
    {
        TEST_FAIL("Cannot add route to 'alien_addr' via 'host2_addr'");
    }
    CFG_WAIT_CHANGES;

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(
                            pco_tst->ta, 0, tst_if->if_name,
                            TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                            NULL, NULL,
                            SIN(tst_addr)->sin_addr.s_addr,
                            SIN(iut_addr)->sin_addr.s_addr,
                            SIN(tst_addr)->sin_port,
                            SIN(iut_addr)->sin_port,
                            &csap));

    CHECK_RC(tapi_tad_trrecv_start(
                               pco_tst->ta, 0, csap, NULL,
                               TAD_TIMEOUT_INF, 0,
                               RCF_TRRECV_PACKETS));

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    provoke_mss_update(pco_iut, iut_s, pco_tst, tst_s, -1);

    cb_data.callback = &user_pkt_handler;
    cb_data.user_data = &opts_len;

    if (tapi_tad_trrecv_stop(pco_tst->ta, 0, csap,
                             &cb_data, &num) != 0 ||
        num == 0)
    {
        TEST_FAIL("Failed to capture packets with CSAP");
    }

    if (opts_len < 0)
        TEST_FAIL("Failed to measure IP/TCP options length");

    mss = 0;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_TCP, TCP_MAXSEG) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    exp_mss = MSS_FROM_MTU(mtu_1, opts_len);
    RING("Expected MSS is %d, measured is %d", exp_mss, mss);

    if (mss != exp_mss)
    {
        cfg_val_type    val_type = CVT_INTEGER;
        int             mtu = 0;

        CHECK_RC(cfg_get_instance_fmt(&val_type, &mtu,
                                      "/agent:%s/interface:%s/mtu:",
                                      pco_iut->ta, iut_if->if_name));
        if (mss == MSS_FROM_MTU(mtu, opts_len))
            TEST_VERDICT("Route MTU does not affect TCP MSS");
        else
            TEST_VERDICT("MSS after connection establishment "
                         "has unexpected value");
    }

    if (tapi_cfg_modify_route(pco_iut->ta, AF_INET,
                           te_sockaddr_get_netaddr(tst_addr), route_prefix,
                           te_sockaddr_get_netaddr(gw_iut_addr), NULL, NULL,
                           0, 0, 0, mtu_2, 0, 0, &rt1) != 0)
    {
        TEST_FAIL("Failed to change the MTU of the connection");
    }
    CFG_WAIT_CHANGES;

    provoke_mss_update(pco_iut, iut_s, pco_tst, tst_s, mss);

    prev_mss = mss;
    mss = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    exp_mss = MSS_FROM_MTU(mtu_2, opts_len);
    RING("Expected MSS is %d, measured is %d", exp_mss, mss);

    if (mss != exp_mss)
    {
        if (mss == prev_mss)
            TEST_VERDICT("MSS has not changed after the first MTU change");
        else
            TEST_VERDICT("MSS has unexpected value after the "
                         "first MTU change");
    }

    if (tapi_cfg_modify_route(pco_iut->ta, AF_INET,
                           te_sockaddr_get_netaddr(tst_addr), route_prefix,
                           te_sockaddr_get_netaddr(gw_iut_addr), NULL, NULL,
                           0, 0, 0, mtu_3, 0, 0, &rt1) != 0)
    {
        TEST_FAIL("Failed to change the MTU of the connection");
    }
    CFG_WAIT_CHANGES;

    provoke_mss_update(pco_iut, iut_s, pco_tst, tst_s, mss);

    prev_mss = mss;
    mss = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    exp_mss = MSS_FROM_MTU(mtu_3, opts_len);
    RING("Expected MSS is %d, measured is %d", exp_mss, mss);

    if (mss != exp_mss)
    {
        if (mss == prev_mss)
            TEST_VERDICT("MSS has not changed after the second MTU change");
        else
            TEST_VERDICT("MSS has unexpected value after the "
                         "second MTU change");
    }

    TEST_SUCCESS;

cleanup:

    if (csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_tst->ta, 0, csap) != 0)
    {
        TEST_FAIL("Failed to destroy CSAP");
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (tapi_cfg_del_route(&rt1) != 0)
    {
        TEST_FAIL("Failed to delete route");
    }

    if (tapi_cfg_del_route(&rt2) != 0)
    {
        TEST_FAIL("Failed to delete route");
    }

    TEST_END;
}
