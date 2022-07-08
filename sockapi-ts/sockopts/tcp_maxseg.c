/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */
/** @page sockopts-tcp_maxseg TCP_MAXSEG socket option behaviour on not connected socket and on the connected one.
 *
 * @objective Check the behaviour of the @c TCP_MAXSEG socket option
 *            on the newly created socket. Than check the behaviour on
 *            connected socket and check, that packets are fragmented with
 *            respect to the @c MSS requested by the user.
 *
 * @type conformance
 *
 * @reference MAN 7 tcp
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param mss_1            @c MSS that should be set on the not connected
 *                         socket
 * @param mss_2            @c MSS that should be set on the connected socket
 * @param mss_default      Default MSS value (it's a parameter of linux)
 * @param buf_size         Size of the buffer to be send to check the real
 *                         MSS value.
 * @param passive          Make passive open on IUT side
 * @param before_bind      Call setsockopt(TCP_MAXSEG) before bind()
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Get the @c MSS value of the @p iut_s and check that it is equal to
 *    @p mss_default.
 * -# Set @c MSS to @p mss_1 using the @c TCP_MAXSEG socket option.
 * -# Check that @c MSS is still equal to @p mss_default.
 * -# Bind @p iut_s to the @p iut_addr on the @p pco_iut.
 * -# Bind @p tst_s to the @p tst_addr on the @p pco_tst.
 * -# Call @b listen() on the @p tst_s.
 * -# Call @b connect(iut_s, tst_addr).
 * -# Call @b accept on the @p tst_s to accept the connection and to obtain
 *    new @p acc_s socket.
 * -# Check that actual @c MSS value which is sent to tester within SYN segment
 *    is equal to @p mss_1.
 * -# Check, that the @c MSS value on the @p iut_s is
 *    @p mss_1 or less (it may be less when additional IP/TCP options like
 *    TCP timestamp are present).
 * -# Set @c MSS to @p mss_2 using the @c TCP_MAXSEG socket option.
 * -# Check that @c MSS was not changed.
 * -# Send a packet of the size @p buf_size from the @p iut_s to the @p acc_s.
 * -# Check that on the tst side correct packets are received (all packets
 *    should be of size @c MSS exept one, that should be less).
 * -# Close all opened sockets.
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oketlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_maxseg"

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

#define TST_BUF_LEN       10000

#define MSS_DEFAULT 536

static int        packets_count = 0;
static int        packets_received = 0;
static int        buf_size;
static char       buf[TST_BUF_LEN];
static int        mss_in_syn;

/** Data passed to CSAP callback. */
typedef struct callback_data {
    int       set_mss;  /**< TCP_MAXSEG value set with setsockopt(). */
    int       got_mss;  /**< TCP_MAXSEG value returned by getsockopt(). */
    te_bool   failure;  /**< Will be set to TRUE if some error was
                             encountered. */
} callback_data;

/**
 * User callback to obtain the MSS value from SYN segment.
 * Function is passed to tapi_tad_trrecv_get() function to handle
 * captured packets.
 *
 * @param pkt       Packet to be handled.
 * @param userdata  User data.
 */
static void
get_mss_callback(asn_value *pkt, void *userdata)
{
#define CHECK_RETVAL(expr_, verdict_)                    \
    do {                                                 \
        int rc_;                                         \
                                                         \
        if ((rc_ = (expr_)) != 0)                        \
        {                                                \
            data->failure = TRUE;                        \
            ERROR_VERDICT(verdict_": rc = %r", rc_);     \
            asn_free_value(pkt);                         \
            return;                                      \
        }                                                \
    } while (0)

    int             flags = 0;
    callback_data  *data = (callback_data *)userdata;

    asn_value *tcp_pdu;
    asn_value *tcp_options;
    asn_value *mss_asn;

    CHECK_RETVAL(asn_get_descendent(pkt, &tcp_pdu, "pdus.0.#tcp"),
                 "Failed to get TCP pdu");
    CHECK_RETVAL(ndn_du_read_plain_int(tcp_pdu, NDN_TAG_TCP_FLAGS, &flags),
                 "Failed to read TCP flags");

    if ((flags & TCP_SYN_FLAG) != 0)
    {
        CHECK_RETVAL(asn_get_descendent(tcp_pdu, &tcp_options, "options"),
                     "Failed to read TCP options");
        mss_asn = asn_find_child_choice_value(tcp_options,
                                              NDN_TAG_TCP_OPT_MSS);
        if (mss_asn != NULL)
        {
            CHECK_RETVAL(ndn_du_read_plain_int(mss_asn, NDN_TAG_TCP_OPT_MSS,
                                           &mss_in_syn),
                         "Could not obtain MSS option");
        }
        else
        {
            ERROR_VERDICT("MSS option was not found");
            data->failure = TRUE;
        }
    }

    asn_free_value(pkt);

#undef CHECK_RETVAL
}

/**
 * User callback, which is passed to the tapi_tad_trrecv_start()
 * function to handle captured packets.
 *
 * @param pkt       Packet to be handled.
 * @param userdata  MSS value that should be checked.
 *                  Will be set to negative value in case of failure.
 */
static void
user_pkt_handler(asn_value *pkt, void *userdata)
{
    int             length = 0;
    callback_data  *data = (callback_data *)userdata;
    int             mss = data->got_mss;
    char           *payload = NULL;
    te_errno        rc;

    size_t      len = 0;
    int32_t     ip_total_len = 0;
    int32_t     max_payload_len = 0;
    int         exp_opts_len = 0;
    int         got_opts_len = 0;

    if (data->failure)
        goto cleanup;

    packets_received++;
    if (packets_received > packets_count)
    {
        ERROR_VERDICT("Too many packets were received");
        data->failure = TRUE;
        goto cleanup;
    }

    len = sizeof(ip_total_len);
    rc = asn_read_value_field(pkt, &ip_total_len, &len,
                              "pdus.1.#ip4.total-length");
    if (rc != 0)
    {
        ERROR("Failed to get IP Total Length field");
        data->failure = TRUE;
        goto cleanup;
    }

    /* 40 is minimum length of IP header (20) + minimum length
     * of TCP header (20). */
    max_payload_len = ip_total_len - 40;

    length = asn_get_length(pkt, "payload.bytes");
    if (length < 0)
    {
        ERROR("Failed to get payload length");
        data->failure = TRUE;
        goto cleanup;
    }

    rc = asn_get_field_data(pkt, &payload, "payload.bytes");
    if (rc != 0)
    {
        ERROR("Failed to get payload data, %r", rc);
        data->failure = TRUE;
        goto cleanup;
    }

    RING("Packet with %d bytes received, packet number is %d "
         "length = %d, mss = %d",
         length, packets_received, length, mss);

    got_opts_len = max_payload_len - length;
    exp_opts_len = data->set_mss - data->got_mss;
    if (got_opts_len != exp_opts_len)
    {
        ERROR("Unexpected length of header options %d != %d",
              got_opts_len, exp_opts_len);
        ERROR_VERDICT("Unexpected length of header options");
        data->failure = TRUE;
        goto cleanup;
    }

    if (packets_received < packets_count &&
        length != mss)
    {
        ERROR("Unexpected packet length %d != mss %d", length, mss);
        ERROR_VERDICT("Packet of unexpected length was received");
        data->failure = TRUE;
        goto cleanup;
    }
    else if (packets_received == packets_count &&
             length != (buf_size % mss))
    {
        ERROR("Unexpected packet length %d != %d", length, buf_size % mss);
        ERROR_VERDICT("Packet of unexpected length was received");
        data->failure = TRUE;
        goto cleanup;
    }

    if (memcmp(payload, buf + mss * (packets_received - 1), length) != 0)
    {
        WARN("Wrong packet payload");
        data->failure = TRUE;
        goto cleanup;
    }

cleanup:

    asn_free_value(pkt);
}

void set_tcp_maxseg(rcf_rpc_server *pco, int s, int mss)
{
    int ret;

    RPC_AWAIT_IUT_ERROR(pco);
    ret = rpc_setsockopt(pco, s, RPC_TCP_MAXSEG, &mss);
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(SOL_TCP, TCP_MAXSEG) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco)));
    }
}

int
main(int argc, char *argv[])
{
    int             sid;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_lsn = NULL;
    rcf_rpc_server *pco_cln = NULL;

    int     iut_s = -1;
    int     tst_s = -1;
    int     lsn_s = -1;
    int     cln_s = -1;
    int     acc_s = -1;

    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *lsn_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;

    int     mss;
    int     mss_1 = 0;
    int     mss_2 = 0;
    int     mss_default = 0;

    csap_handle_t             csap = CSAP_INVALID_HANDLE;
    tapi_tad_trrecv_cb_data   cb_data;
    callback_data             data;

    unsigned int    num;

    te_bool passive, before_bind;
    int     ret;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(mss_1);
    TEST_GET_INT_PARAM(mss_2);
    TEST_GET_INT_PARAM(buf_size);
    TEST_GET_BOOL_PARAM(passive);
    TEST_GET_BOOL_PARAM(before_bind);

    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                          pco_tst->ta, tst_if->if_name,
                                          "rx-gro", 0));
    CHECK_RC(sockts_disable_tcp_segmentation(pco_iut->ta, iut_if->if_name));

    /* Prepare CSAP */
    if (rcf_ta_create_session(pco_tst->ta, &sid) != 0)
    {
        TEST_FAIL("rcf_ta_create_session failed");
        return 1;
    }

    rc = tapi_tcp_ip4_eth_csap_create(
                            pco_tst->ta, sid, tst_if->if_name,
                            TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                            NULL, NULL,
                            SIN(tst_addr)->sin_addr.s_addr,
                            SIN(iut_addr)->sin_addr.s_addr,
                            SIN(tst_addr)->sin_port,
                            SIN(iut_addr)->sin_port,
                            &csap);

    /* CSAP part end */

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss_default);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(SOL_TCP, TCP_MAXSEG) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    if (mss_default != MSS_DEFAULT)
    {
        RING("MSS returned %d instead of %d", mss_default, MSS_DEFAULT);
    }

    mss = mss_1;
    if (before_bind)
        set_tcp_maxseg(pco_iut, iut_s, mss);

    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (passive)
    {
        pco_lsn = pco_iut;
        pco_cln = pco_tst;
        lsn_s = iut_s;
        cln_s = tst_s;
        lsn_addr = iut_addr;
    }
    else
    {
        pco_lsn = pco_tst;
        pco_cln = pco_iut;
        lsn_s = tst_s;
        cln_s = iut_s;
        lsn_addr = tst_addr;
    }

    rpc_listen(pco_lsn, lsn_s, SOCKTS_BACKLOG_DEF);

    if (!before_bind)
        set_tcp_maxseg(pco_iut, iut_s, mss);
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
    if (mss != mss_default && (mss_default != 0 || mss != mss_1))
    {
        TEST_VERDICT("The mss value after setsockopt() call is %d "
                     "instead of %d", mss, mss_default);
    }

    rc = tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                               TAD_TIMEOUT_INF, 0,
                               RCF_TRRECV_PACKETS);
    if (rc != 0)
        TEST_FAIL("Failed to start receiving on the CSAP, rc = %r", rc);

    rpc_connect(pco_cln, cln_s, lsn_addr);
    acc_s = rpc_accept(pco_lsn, lsn_s, NULL, NULL);
    rpc_close(pco_lsn, lsn_s);

    data.failure = FALSE;
    cb_data.callback = &get_mss_callback;
    cb_data.user_data = &data;
    CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, sid, csap, &cb_data,
                                 (unsigned int *)&num));

    if (data.failure)
        TEST_STOP;

    if (mss_in_syn > mss_1)
        TEST_VERDICT("Actual MSS obtained from SYN segment is greater "
                     "than established one");
    else if (mss_in_syn < mss_1)
        RING_VERDICT("Actual MSS obtained from SYN segment is less "
                     "than established one");

    if (passive)
        iut_s = acc_s;
    else
        tst_s = acc_s;
    acc_s = -1;

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
    if (mss > mss_1)
    {
        TEST_FAIL("MSS value of established connection is too large (%d > %d)",
                  mss, mss_1);
    }
    else if (mss < mss_1)
    {
        RING("MSS value after the connection establishment is %d "
             "instead of %d; probably some IP or TCP options are enabled",
             mss, mss_1);
    }

    data.set_mss = mss_1;
    data.got_mss = mss;

    mss = mss_2;
    rpc_setsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
    if (mss != data.got_mss)
    {
        RING("The mss value after setsockopt() call on the connected "
             "socket is %d instead of %d", mss, data.got_mss);

        if (mss > mss_2)
            TEST_VERDICT("Too big MSS value was set on connected socket");
        else
            RING_VERDICT("MSS was changed on connected socket");

        data.set_mss = mss_2;
        data.got_mss = mss;
    }

    packets_count = (buf_size - 1) / mss + 1;

    data.failure = FALSE;
    cb_data.callback = &user_pkt_handler;
    cb_data.user_data = &data;

    te_fill_buf(buf, buf_size);
    rpc_send(pco_iut, iut_s, buf, buf_size, 0);
    rpc_recv(pco_tst, tst_s, buf, buf_size, 0);
    if (tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                             &cb_data, &num))
    {
        TEST_FAIL("Failed to receive packets");
    }

    if (data.failure)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_tst->ta, sid, csap))
    {
        ERROR("Failed to destroy CSAP");
    }

    CLEANUP_RPC_CLOSE(passive ? pco_iut : pco_tst, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
