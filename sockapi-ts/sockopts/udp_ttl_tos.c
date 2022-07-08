/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-udp_ttl_tos Usage of IP_TTL/IP_TOS/IPV6_UNICAST_HOPS/IPV6_TCLASS and IP_RECVTTL/IP_RECVTOS/IPV6_RECVHOPLIMIT/IPV6_RECVTCLASS socket options with connectionless sockets
 *
 * @objective Check that @c IP_TTL / @c IP_TOS / @c IPV6_UNICAST_HOPS /
 *            @c IPV6_TCLASS socket options can be used to change TTL /
 *            TOS / Hop Limit / Traffic Class value of IP header in all
 *            packets originated from a socket, and that the checked field
 *            value can be received in control messages if @c IP_RECVTTL,
 *            @c IP_RECVTOS, @c IPV6_RECVHOPLIMIT or @c IPV6_RECVTCLASS are
 *            enabled on receiver socket.
 *
 * @type conformance
 *
 * @reference MAN 7 ip
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_peer2peer
 *                            - @ref arg_types_env_peer2peer_ipv6
 * @param sock_opt            Socket option used in the test:
 *                            @c IP_TTL - to test @c IP_TTL and
 *                              @c IP_RECVTTL socket options;
 *                            @c IP_TOS - to test @c IP_TOS and
 *                              @c IP_RECVTOS socket options;
 *                            @c IPV6_UNICAST_HOPS - to test
 *                              @c IPV6_UNICAST_HOPS and
 *                              @c IPV6_RECVHOPLIMIT socket options
 *                            @c IPV6_TCLASS - to test
 *                              @c IPV6_TCLASS and @c IPV6_RECVTCLASS
 *                              socket options
 * @param connect_sender      If @c TRUE, call @b connect() on sender
 *                            socket and use @b send(); otherwise use
 *                            @b sendto()
 * @param recv_iut            If @c TRUE, send data from Tester and receive
 *                            it on IUT; otherwise do the opposite.
 * @param fragmented_packets  If @c TRUE, send datagram bigger than MTU,
 *                            so that it will be fragmented
 * @param with_cmsg           If @c TRUE, IP_TOS or IPV6_TCLASS would be
 *                            sent with cmsg, otherwise setsockopt would be used
 * @param recv_f              Function to use for receiving data:
 *                            - @b recvmsg()
 *                            - @b recvmmsg()
 *                            - @b onload_zc_recv()
 *
 * @note
 * -# @anchor sockopts_ip_ttl_tos_1
 *    Some implementations can use @c IP_RECVTTL / @c IP_RECVTOS as the
 *    value of @a cmsg_type field of @c cmsghdr structure, so that it
 *    is better to check @a cmsg_type field of each structure agains
 *    @c IP_TTL / @c IP_TOS and @c IP_RECVTTL / @c IP_RECVTOS
 *    values and report actual value;
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/udp_ttl_tos"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_ip_common.h"
#include "sockopts_common.h"

/**
 * Number of vectors for recvmsg-like functions.
 * Multiple vectors are required when onload_zc_recv()
 * receives large (fragmented) datagram.
 */
#define TST_VEC_NUM    3

/** Length of buffer storing control messages */
#define TST_CMSG_LEN   300

/** Too big value for the checked option */
#define TST_BAD_VAL    1000

/** Data passed to CSAP callback */
typedef struct csap_cb_data {
    rpc_sockopt sock_opt;   /**< Tested socket option */
    int         exp_val;    /**< Expected value of header field */
    te_bool     unexp_val;  /**< Will be set to TRUE by callback
                                 if unexpected value was encountered */
    te_bool     failed;     /**< Will be set to TRUE if some
                                 error was encountered while processing
                                 packets */
} csap_cb_data;

/**
 * Callback for processing packets captured by CSAP.
 *
 * @param pkt       Captured packet.
 * @param userdata  Pointer to csap_cb_data structure.
 */
static void
callback(asn_value *pkt, void *userdata)
{
    csap_cb_data *data = (csap_cb_data *)userdata;

    const char *labels = NULL;
    te_errno    rc;
    uint32_t    got_val;

    switch (data->sock_opt)
    {
        case RPC_IP_TTL:
            labels = "pdus.0.#ip4.time-to-live.plain";
            break;

        case RPC_IP_TOS:
            labels = "pdus.0.#ip4.type-of-service.plain";
            break;

        case RPC_IPV6_UNICAST_HOPS:
            labels = "pdus.0.#ip6.hop-limit.plain";
            break;

        case RPC_IPV6_TCLASS:
            labels = "pdus.0.#ip6.traffic-class.plain";
            break;

        default:
            ERROR("%s(): not supported option %s",
                  __FUNCTION__, sockopt_rpc2str(data->sock_opt));
            data->failed = TRUE;
            goto cleanup;
    }

    rc = asn_read_uint32(pkt, &got_val, labels);
    if (rc != 0)
    {
        ERROR("Failed to read %s field: %r", labels, rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if ((int)got_val != data->exp_val)
    {
        ERROR("Packet has %s %d instead of %d",
              sockopt_rpc2str(data->sock_opt), got_val, data->exp_val);
        data->unexp_val = TRUE;
    }

cleanup:

    asn_free_value(pkt);
}

/**
 * Send data, receive it on peer, check whether control message
 * is received or not as expected. Check that packets captured by
 * CSAP have expected header field value.
 *
 * @param rpcs_snd            RPC server from which data is sent.
 * @param snd_s               Sending socket.
 * @param rpcs_rcv            RPC server where data is received.
 * @param rcv_s               Receiving socket.
 * @param send_size           How many bytes to send.
 * @param connected           Whether sending socket is connected.
 * @param dst_addr            Address to which to send.
 * @param recv_f              Function to use for receiving data.
 * @param sock_opt            Tested option.
 * @param recv_cmsg_enabled   Whether control message receiving is
 *                            enabled on receiving socket.
 * @param sid                 RCF session ID.
 * @param csap                CSAP capturing sent packets.
 * @param vpref               Prefix to print in verdicts.
 *
 * @return Status code.
 */
static te_errno
check_send_recv(rcf_rpc_server *rpcs_snd, int snd_s,
                rcf_rpc_server *rpcs_rcv, int rcv_s,
                size_t send_size, te_bool connected,
                const struct sockaddr *dst_addr,
                rpc_msg_read_f recv_f,
                rpc_sockopt sock_opt, int exp_val,
                te_bool recv_cmsg_enabled,
                int sid, csap_handle_t csap,
                const char *vpref,
                te_bool with_cmsg)
{
    uint8_t             cmsg_buf[TST_CMSG_LEN];
    struct cmsghdr     *cmsg = NULL;
    struct msghdr       hmsg;
    int                 cmsg_level;
    int                 cmsg_type;
    int                 val = -1;
    te_bool             exp_cmsg = FALSE;
    te_bool             unexp_cmsg = FALSE;

    int                 i;
    struct rpc_iovec    rx_vector[TST_VEC_NUM];
    rpc_msghdr          rx_msghdr;
    char               *tx_buf = NULL;
    char               *rx_buf_aux = NULL;
    char               *rx_buf = NULL;
    int                 rc;
    unsigned int        num = 0;
    csap_cb_data        data;

    te_errno            res = 0;

    if (sock_opt == RPC_IPV6_UNICAST_HOPS)
    {
        cmsg_type = IPV6_HOPLIMIT;
        cmsg_level = SOL_IPV6;
    }
    else
    {
        cmsg_type = sockopt_rpc2h(sock_opt);
        cmsg_level = socklevel_rpc2h(rpc_sockopt2level(sock_opt));
    }

    memset(&rx_vector, 0, sizeof(rx_vector));
    memset(&rx_msghdr, 0, sizeof(rx_msghdr));

    tx_buf = te_make_buf_by_len(send_size);
    rx_buf = te_make_buf_by_len(send_size);
    rx_buf_aux = te_make_buf_by_len(send_size * TST_VEC_NUM);

    for (i = 0; i < TST_VEC_NUM; i++)
    {
        rx_vector[i].iov_base = rx_buf_aux + i * send_size;
        rx_vector[i].iov_len = rx_vector[i].iov_rlen = send_size;
    }

    rx_msghdr.msg_iovlen = rx_msghdr.msg_riovlen = TST_VEC_NUM;
    rx_msghdr.msg_iov = rx_vector;
    rx_msghdr.msg_control = cmsg_buf;
    rx_msghdr.msg_controllen = TST_CMSG_LEN;
    rx_msghdr.msg_cmsghdr_num = 1;

    memset(cmsg_buf, 0, TST_CMSG_LEN);
    te_fill_buf(tx_buf, send_size);

    RPC_AWAIT_ERROR(rpcs_snd);
    if (!with_cmsg)
    {
        if (connected)
            rc = rpc_send(rpcs_snd, snd_s, tx_buf, send_size, 0);
        else
            rc = rpc_sendto(rpcs_snd, snd_s, tx_buf, send_size, 0, dst_addr);
    }
    else
    {
        rc = sockts_sendmsg_with_cmsg(rpcs_snd, snd_s, dst_addr,
                                      with_cmsg, cmsg_level,
                                      cmsg_type, exp_val,
                                      tx_buf, send_size);
    }

    if (rc < 0)
    {
        ERROR_VERDICT("%s: sending failed with errno %r", vpref,
                      RPC_ERRNO(rpcs_snd));
        res = TE_EFAIL;
        goto cleanup;
    }
    else if ((size_t)rc != send_size)
    {
        ERROR_VERDICT("%s: sending function returned unexpected result",
                      vpref);
        res = TE_EFAIL;
        goto cleanup;
    }

    RPC_AWAIT_ERROR(rpcs_rcv);
    rc = recv_f(rpcs_rcv, rcv_s, &rx_msghdr, 0);
    if (rc < 0)
    {
        ERROR_VERDICT("%s: recv_f() failed with errno %r",
                      vpref, RPC_ERRNO(rpcs_rcv));
        res = TE_EFAIL;
        goto cleanup;
    }

    (void)iovecs_to_buf(rx_vector, rx_msghdr.msg_iovlen,
                        rx_buf, send_size);

    if ((size_t)rc != send_size ||
        memcmp(tx_buf, rx_buf, send_size) != 0)
    {
        ERROR_VERDICT("%s: recv_f() retrieved unexpected data", vpref);
        res = TE_EFAIL;
        goto cleanup;
    }

    if (csap != CSAP_INVALID_HANDLE)
    {
        tapi_tad_trrecv_cb_data   cb_data;

        memset(&cb_data, 0, sizeof(cb_data));
        memset(&data, 0, sizeof(data));

        data.sock_opt = sock_opt;
        data.exp_val = exp_val;
        data.unexp_val = FALSE;
        data.failed = FALSE;
        cb_data.callback = &callback;
        cb_data.user_data = &data;
        CHECK_RC(tapi_tad_trrecv_get(
                        rpcs_rcv->ta, sid, csap,
                        &cb_data, &num));

        if (num == 0)
        {
            ERROR_VERDICT("%s: CSAP did not catch any packets", vpref);
            res = TE_EFAIL;
        }
        else if (data.unexp_val)
        {
            ERROR_VERDICT("%s: unexpected value in the checked header field",
                          vpref);
            res = TE_EFAIL;
        }

        if (data.failed)
        {
            ERROR_VERDICT("%s: failed to process some packets captured "
                          "by CSAP", vpref);
            res = TE_EFAIL;
        }
    }

    memset(&hmsg, 0, sizeof(hmsg));
    hmsg.msg_control = rx_msghdr.msg_control;
    hmsg.msg_controllen = rx_msghdr.msg_controllen;

    for (cmsg = CMSG_FIRSTHDR(&hmsg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&hmsg, cmsg))
    {
        RING("Control message: level %d, type %d: %s",
             cmsg->cmsg_level, cmsg->cmsg_type,
             sockopt_rpc2str(cmsg_type_h2rpc(cmsg->cmsg_level,
                                             cmsg->cmsg_type)));
        if (cmsg->cmsg_level == cmsg_level && cmsg->cmsg_type == cmsg_type)
        {
            if (!exp_cmsg)
            {
                val = *(int *)(CMSG_DATA(cmsg));
                RING("Control message stores value %d", val);
                exp_cmsg = TRUE;
            }
            else
            {
                unexp_cmsg = TRUE;
            }
        }
        else
        {
            unexp_cmsg = TRUE;
        }
    }

    if (unexp_cmsg)
    {
        ERROR_VERDICT("%s: unexpected control message(s) was received",
                      vpref);
        res = TE_EFAIL;
    }

    if (!recv_cmsg_enabled)
    {
        if (exp_cmsg)
        {
            ERROR_VERDICT("%s: control message for %s was received "
                          "unexpectedly", vpref, sockopt_rpc2str(sock_opt));
            res = TE_EFAIL;
        }
    }
    else
    {
        if (!exp_cmsg)
        {
            ERROR_VERDICT("%s: control message for %s was not received",
                          vpref, sockopt_rpc2str(sock_opt));
            res = TE_EFAIL;
        }
        else if (val != exp_val)
        {
            ERROR("Control message stored %d instead of %d", val, exp_val);
            ERROR_VERDICT("%s: control message for %s contained unexpected "
                          "value", vpref, sockopt_rpc2str(sock_opt));
            res = TE_EFAIL;
        }
    }

cleanup:

    free(tx_buf);
    free(rx_buf);
    free(rx_buf_aux);
    return res;
}

static void
set_check_sockopt(rcf_rpc_server *pco_snd,
                  int snd,
                  rpc_sockopt sock_opt,
                  int new_val,
                  const char *opt_name,
                  int init_val)
{
    int rc = 0;
    int opt_val;

    RPC_AWAIT_ERROR(pco_snd);
    rc = rpc_setsockopt_int(pco_snd, snd, sock_opt, new_val);
    if (rc < 0)
    {
        TEST_VERDICT("setsockopt(%s) failed with errno %r",
                     opt_name, RPC_ERRNO(pco_snd));
    }

    rpc_getsockopt(pco_snd, snd, sock_opt, &opt_val);
    if (opt_val != new_val)
    {
        TEST_VERDICT("After trying to change %s value, getsockopt() "
                     "reports %s one", opt_name,
                     (opt_val == init_val ? "initial" : "unexpected"));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             sid;            /* Session on receiver */
    csap_handle_t   rcv_csap =      /* CSAP on receiver */
                        CSAP_INVALID_HANDLE;

    const struct sockaddr       *iut_addr = NULL;
    const struct sockaddr       *tst_addr = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;
    const struct sockaddr       *iut_lladdr = NULL;
    const struct sockaddr       *tst_lladdr = NULL;

    rcf_rpc_server              *pco_snd = NULL;
    rcf_rpc_server              *pco_rcv = NULL;
    const struct sockaddr       *dst_addr = NULL;
    const struct if_nameindex   *snd_if = NULL;
    int                          snd = -1;
    int                          rcv = -1;

    te_bool                 connect_sender;
    te_bool                 recv_iut;
    te_bool                 fragmented_packets;
    te_bool                 with_cmsg;
    rpc_sockopt             sock_opt = RPC_SOCKOPT_UNKNOWN;
    rpc_msg_read_f          recv_f;

    const char             *opt_name = NULL;
    int                     recv_sockopt;

    te_bool                 test_failed = FALSE;

    int                     ret;
    int                     init_val;
    int                     max_val = 0xff;
    int                     new_val;
    int                     recv_init;
    int                     opt_val;
    cfg_val_type            type = CVT_INTEGER;
    int                     mtu_saved;
    int                     buf_len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_SOCKOPT(sock_opt);
    TEST_GET_BOOL_PARAM(connect_sender);
    TEST_GET_BOOL_PARAM(recv_iut);
    TEST_GET_BOOL_PARAM(fragmented_packets);
    TEST_GET_MSG_READ_FUNC(recv_f);
    TEST_GET_BOOL_PARAM(with_cmsg);

    opt_name = sockopt_rpc2str(sock_opt);

    if (recv_iut)
    {
        TEST_STEP("If @p recv_iut is @c TRUE, then "
                  "@b pco_snd = @p pco_tst, @b pco_rcv = @p pco_iut, "
                  "@b dst_addr = @p iut_addr.");
        pco_snd = pco_tst;
        pco_rcv = pco_iut;
        dst_addr = iut_addr;
        snd_if = tst_if;
    }
    else
    {
        TEST_STEP("If @p recv_iut is @c FALSE, then "
                  "@b pco_snd = @p pco_iut, @b pco_rcv = @p pco_tst, "
                  "@b dst_addr = @p tst_addr.");
        pco_snd = pco_iut;
        pco_rcv = pco_tst;
        dst_addr = tst_addr;
        snd_if = iut_if;
    }

    switch (sock_opt)
    {
        case RPC_IP_TTL:
            TEST_STEP("If @p sock_opt is @c RPC_IP_TTL, set "
                      "@b recv_sockopt to @c RPC_IP_RECVTTL.");
            recv_sockopt = RPC_IP_RECVTTL;
            break;

        case RPC_IP_TOS:
            TEST_STEP("If @p sock_opt is @c RPC_IP_TOS, set "
                      "@b recv_sockopt to @c RPC_IP_RECVTOS.");
            recv_sockopt = RPC_IP_RECVTOS;
            break;

        case RPC_IPV6_UNICAST_HOPS:
            TEST_STEP("If @p sock_opt is @c RPC_IPV6_UNICAST_HOPS, set "
                      "@b recv_sockopt to @c RPC_IPV6_RECVHOPLIMIT.");
            recv_sockopt = RPC_IPV6_RECVHOPLIMIT;
            break;

        case RPC_IPV6_TCLASS:
            TEST_STEP("If @p sock_opt is @c RPC_IPV6_TCLASS, set "
                      "@b recv_sockopt to @c RPC_IPV6_RECVTCLASS.");
            recv_sockopt = RPC_IPV6_RECVTCLASS;
            break;

        default:
            TEST_FAIL("Option %s is not supported", opt_name);
            break;
    }

    CHECK_RC(cfg_get_instance_fmt(&type, (void *)&mtu_saved,
                                  "/agent:%s/interface:%s/mtu:",
                                  pco_snd->ta, snd_if->if_name));

    TEST_STEP("Choose size of data to be tranmitted in the next steps. "
              "If @p fragmented_packets is @c TRUE, it should be greater "
              "than MTU, otherwise it should be less than MTU.");

    buf_len = (fragmented_packets ? mtu_saved * 2 : mtu_saved / 2);

    TEST_STEP("Create @b snd socket of @c SOCK_DGRAM type on @b pco_snd.");
    snd = rpc_socket(pco_snd, rpc_socket_domain_by_addr(tst_addr),
                     RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Create @b rcv socket of @c SOCK_DGRAM type on @b pco_rcv.");
    rcv = rpc_socket(pco_rcv, rpc_socket_domain_by_addr(tst_addr),
                     RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @b rcv to @b dst_addr.");
    rpc_bind(pco_rcv, rcv, dst_addr);

    if (!recv_iut)
    {
        TEST_STEP("If @p recv_iut is @c FALSE, create CSAP on Tester "
                  "to capture IP packets sent from IUT.");
        CHECK_RC(rcf_ta_create_session(pco_rcv->ta, &sid));
        CHECK_RC(tapi_ip_eth_csap_create(
                             pco_tst->ta, sid, tst_if->if_name,
                             TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                             (const uint8_t *)CVT_HW_ADDR(tst_lladdr),
                             (const uint8_t *)CVT_HW_ADDR(iut_lladdr),
                             tst_addr->sa_family,
                             te_sockaddr_get_netaddr(tst_addr),
                             te_sockaddr_get_netaddr(iut_addr),
                             (tst_addr->sa_family == AF_INET6 &&
                              fragmented_packets ?
                                    IPPROTO_FRAGMENT : IPPROTO_UDP),
                             &rcv_csap));

        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, sid, rcv_csap, NULL,
                                       TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_PACKETS));
    }

    TEST_STEP("Obtain initial value of @p sock_opt option on @b snd, "
              "save it in @b init_val.");
    rpc_getsockopt(pco_snd, snd, sock_opt, &init_val);
    WARN("For %s socket option, default value is %d", opt_name, init_val);

    TEST_STEP("Make sure that @b recv_sockopt option is set to @c 0 "
              "on @b rcv.");

    RPC_AWAIT_ERROR(pco_rcv);
    ret = rpc_getsockopt(pco_rcv, rcv, recv_sockopt, &recv_init);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(%s) failed with errno %r",
                     sockopt_rpc2str(recv_sockopt), RPC_ERRNO(pco_rcv));
    }
    if (recv_init != 0)
    {
        WARN("For %s socket option default value is %d, expected 0",
             sockopt_rpc2str(recv_sockopt), recv_init);
        rpc_setsockopt_int(pco_rcv, rcv, recv_sockopt, 0);
    }

    TEST_STEP("If @p connect_sender is @c TRUE, @b connect() @b snd "
              "to @b dst_addr.");

    if (connect_sender)
        rpc_connect(pco_snd, snd, dst_addr);

    TEST_STEP("Send data from @b snd and receive it on @b rcv.");
    TEST_STEP("If @p with_cmsg is @c TRUE, send data with @b sendmsg with "
              "@c IP_TOS or IPV6_TCLASS set in cmsg, otherwise "
              "send data with @b send or @b sendto.");
    TEST_STEP("Check that no control message corresponding to @p sock_opt "
              "was received on @b rcv.");
    TEST_STEP("If @p recv_iut is @c FALSE, check that in packets captured "
              "by CSAP header field corresponding to @p sock_opt was set "
              "to @b init_val.");

    CHECK_RC(check_send_recv(
                    pco_snd, snd, pco_rcv, rcv, buf_len,
                    connect_sender, dst_addr, recv_f, sock_opt, init_val,
                    FALSE, sid, rcv_csap, "Initial send", with_cmsg));

    TEST_STEP("Set @b recv_sockopt to @c 1 on @p rcv socket.");

    rpc_setsockopt_int(pco_rcv, rcv, recv_sockopt, 1);

    rpc_getsockopt(pco_rcv, rcv, recv_sockopt, &opt_val);
    if (opt_val == 0)
    {
        TEST_VERDICT("After enabling %s getsockopt() still reports "
                     "zero for it", sockopt_rpc2str(recv_sockopt));
    }

    TEST_STEP("If @p with_cmsg is @c TRUE, send data with @b sendmsg with "
              "@c IP_TOS or IPV6_TCLASS set in cmsg, otherwise "
              "send data with @b send or @b sendto.");
    TEST_STEP("Send data from @b snd again, check that now control "
              "message corresponding to @p sock_opt is received on "
              "@b rcv.");
    TEST_STEP("If @p recv_iut is @c FALSE, check that in packets captured "
              "by CSAP header field corresponding to @p sock_opt was set "
              "to @b init_val.");

    CHECK_RC(check_send_recv(
                    pco_snd, snd, pco_rcv, rcv, buf_len,
                    connect_sender, dst_addr, recv_f, sock_opt, init_val,
                    TRUE, sid, rcv_csap, "The second sending", with_cmsg));

    if (!recv_iut)
    {
        TEST_STEP("If @p recv_iut is @c FALSE, try to set too big value "
                  "for @p sock_opt on @b snd, check that it fails.");

        RPC_AWAIT_ERROR(pco_snd);
        rc = rpc_setsockopt_int(pco_snd, snd, sock_opt, TST_BAD_VAL);
        if (rc == 0)
        {
            rpc_getsockopt(pco_snd, snd, sock_opt, &opt_val);
            WARN_VERDICT("setsockopt(%s) with too big value returned "
                         "success, applied value is %s",
                         opt_name,
                         opt_val == max_val ?
                            "truncated to maximum possible value" :
                             (opt_val == (TST_BAD_VAL & max_val) ?
                                "masked by maximum possible value" :
                                "unexpected"));
        }
        else
        {
            CHECK_RPC_ERRNO(pco_snd, RPC_EINVAL,
                            "setsockopt(%s) with too big value failed, "
                            "but", opt_name);
        }
    }

    do {
        new_val = rand_range(1, max_val);
    } while (new_val == init_val);

    if (!with_cmsg)
    {
        TEST_STEP("If @p with_cmsg is @c FALSE "
                  "set @p sock_opt on @b snd socket to @b new_val.");
        set_check_sockopt(pco_snd, snd, sock_opt,
                          new_val, opt_name, init_val);
    }
    TEST_STEP("Send data from @b snd and receive it on @b rcv.");
    TEST_STEP("Check that control message corresponding to @p sock_opt "
              "is received on @b rcv.");
    TEST_STEP("If @p with_cmsg is @c TRUE, send data with @b sendmsg with "
              "@c IP_TOS or IPV6_TCLASS set in cmsg, otherwise set @c IP_TOS "
              "with @b setsockopt and send data with @b send or @b sendto "
              "check that in packets captured "
              "by CSAP header field corresponding to @p sock_opt was set "
              "to @b new_val.");
    CHECK_RC(check_send_recv(
                    pco_snd, snd, pco_rcv, rcv, buf_len,
                    connect_sender, dst_addr, recv_f, sock_opt, new_val,
                    TRUE, sid, rcv_csap,
                    "Sending after changing checked option value", with_cmsg));

    TEST_STEP("Set @b recv_sockopt to @c 0 on @p rcv socket.");
    rpc_setsockopt_int(pco_rcv, rcv, recv_sockopt, 0);

    TEST_STEP("Again send data from @b snd and receive it on @b rcv.");
    TEST_STEP("Check that no control message corresponding to @p sock_opt "
              "was received on @b rcv.");
    TEST_STEP("If @p recv_iut is @c FALSE, check that in packets captured "
              "by CSAP header field corresponding to @p sock_opt was set "
              "to @b new_val.");

    CHECK_RC(check_send_recv(
                    pco_snd, snd, pco_rcv, rcv, buf_len,
                    connect_sender, dst_addr, recv_f, sock_opt, new_val,
                    FALSE, sid, rcv_csap,
                    "The second sending after changing checked option "
                    "value", with_cmsg));

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (rcv_csap != CSAP_INVALID_HANDLE)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(
                                        pco_tst->ta,
                                        sid, rcv_csap));
    }
    CLEANUP_RPC_CLOSE(pco_snd, snd);
    CLEANUP_RPC_CLOSE(pco_rcv, rcv);

    TEST_END;
}
