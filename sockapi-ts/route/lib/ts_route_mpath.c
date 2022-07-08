/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
#include <math.h>

#include "ts_route.h"
#include "ts_route_mpath.h"
#include "te_string.h"
#include "tapi_ip_common.h"
#include "ts_route.h"

/** Maximum packet length. */
#define MAX_PKT_LEN 1024

/** Maximum length of log message. */
#define MAX_MSG_LEN 1024

/**
 * Structure used to store data related to processing captured packets.
 */
typedef struct pkts_data_t {
    const char      *if_name;       /**< Interface name. */
    uint64_t         first_ts;      /**< Timestamp of the first packet
                                         from IUT (in microseconds). */
    struct sockaddr *iut_addr;      /**< IUT address. */
    struct sockaddr *tst_addr;      /**< Tester address. */
    unsigned int     pkts_count;    /**< Number of packets captured. */
    unsigned int     bytes_count;   /**< Number of bytes captured. */
    te_bool          no_pkts_log;   /**< If @c TRUE, don't log packets. */
    te_bool          failed;        /**< Will be set to TRUE in case
                                         of failure when processing
                                         packets. */
} pkts_data_t;

static void tst_packets_handler(asn_value *pkt, void *userdata);

/**
 * Init arguments passed to CSAP callbacks.
 *
 * @param cb_data         CSAP callback argument.
 * @param tst_data        @b user_data in CSAP callback argument.
 * @param if_name         Interface name on which packets are
 *                        captured.
 * @param iut_addr        IUT address of checked connection.
 * @param tst_addr        Tester address of checked connection.
 */
static void
init_pkts_data(tapi_tad_trrecv_cb_data *cb_data,
               pkts_data_t *tst_data, const char *if_name,
               struct sockaddr *iut_addr, struct sockaddr *tst_addr)
{
    memset(tst_data, 0, sizeof(*tst_data));
    memset(cb_data, 0, sizeof(*cb_data));
    cb_data->callback = &tst_packets_handler;
    cb_data->user_data = tst_data;
    tst_data->if_name = if_name;
    tst_data->iut_addr = iut_addr;
    tst_data->tst_addr = tst_addr;
}

/**
 * Process TCP or UDP packets sent by IUT.
 *
 * @param pkt         Captured packet.
 * @param userdata    Pointer to pkts_data_t structure.
 */
static void
tst_packets_handler(asn_value *pkt, void *userdata)
{
    uint16_t   src_port;
    uint16_t   dst_port;
    te_bool    is_udp = FALSE;
    size_t     len;
    te_errno   rc;

    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    size_t                  addr_len;
    size_t                  addr_len_aux;

    struct timeval   tv;
    pkts_data_t     *data = (pkts_data_t *)userdata;
    te_string        addrs_log = TE_STRING_INIT_STATIC(1024);
    const char      *pkt_source = "unknown connection";

    if (data->failed)
        goto cleanup;

    /*
     * Ignore packets with VLAN tag, they should be processed
     * for corresponding VLAN interface (where they are captured
     * without VLAN tag), not for its parent.
     */
    if (sockts_tcp_udp_ip_eth_pkt_is_vlan(pkt))
        goto cleanup;

    rc = sockts_get_csap_pkt_ts(pkt, &tv);
    if (rc != 0)
    {
        data->failed = TRUE;
        goto cleanup;
    }

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    src.ss_family = data->iut_addr->sa_family;
    dst.ss_family = data->iut_addr->sa_family;

    len = sizeof(src_port);
    rc = asn_read_value_field(pkt, &src_port, &len, "pdus.0.#udp.src-port");
    if (rc == 0)
    {
        len = sizeof(dst_port);
        rc = asn_read_value_field(pkt, &dst_port, &len, "pdus.0.#udp.dst-port");
        if (rc != 0)
        {
            ERROR("asn_read_value_field() failed to retrieve udp.dst-port, "
                  "rc=%r", rc);
            data->failed = TRUE;
            goto cleanup;
        }
        is_udp = TRUE;
    }
    else
    {
        len = sizeof(src_port);
        rc = asn_read_value_field(pkt, &src_port, &len, "pdus.0.#tcp.src-port");
        if (rc != 0)
        {
            ERROR("asn_read_value_field() failed to retrieve src-port, rc=%r",
                  rc);
            data->failed = TRUE;
            goto cleanup;
        }

        len = sizeof(dst_port);
        rc = asn_read_value_field(pkt, &dst_port, &len, "pdus.0.#tcp.dst-port");
        if (rc != 0)
        {
            ERROR("asn_read_value_field() failed to retrieve tcp.dst-port, "
                  "rc=%r", rc);
            data->failed = TRUE;
            goto cleanup;
        }
    }

    te_sockaddr_set_port(SA(&src), htons(src_port));
    te_sockaddr_set_port(SA(&dst), htons(dst_port));

    addr_len = (src.ss_family == AF_INET ? sizeof(struct in_addr) :
                                           sizeof(struct in6_addr));

    addr_len_aux = addr_len;
    rc = asn_read_value_field(pkt,
                              te_sockaddr_get_netaddr(SA(&src)),
                              &addr_len_aux,
                              (src.ss_family == AF_INET ?
                                    "pdus.1.#ip4.src-addr.plain" :
                                    "pdus.1.#ip6.src-addr.plain"));
    if (rc != 0)
    {
        ERROR("asn_read_value_field() failed to retrieve source address, "
              "rc=%r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    addr_len_aux = addr_len;
    rc = asn_read_value_field(pkt,
                              te_sockaddr_get_netaddr(SA(&dst)),
                              &addr_len_aux,
                              (src.ss_family == AF_INET ?
                                    "pdus.1.#ip4.dst-addr.plain" :
                                    "pdus.1.#ip6.dst-addr.plain"));
    if (rc != 0)
    {
        ERROR("asn_read_value_field() failed to retrieve destination "
              "address, rc=%r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    /*
     * IUT can use different source addresses if UDP is checked
     * and UDP socket was not bound to specific address, so we
     * compare only ports for IUT.
     */
    if (te_sockaddr_get_port(SA(&src)) ==
                      te_sockaddr_get_port(data->iut_addr) &&
        tapi_sockaddr_cmp(SA(&dst), data->tst_addr) == 0)
    {
        int payload_len;
        data->pkts_count++;

        if (is_udp)
        {
            uint16_t udp_len;
            size_t len = sizeof(udp_len);

            if ((rc = asn_read_value_field(pkt, &udp_len, &len,
                                           "pdus.0.#udp.length")) != 0)
            {
                ERROR("asn_read_value_field(udp_len) returned error: %r", rc);
                data->failed = TRUE;
                goto cleanup;
            }
            payload_len = udp_len - TAD_UDP_HDR_LEN;
        }
        else
        {
            if ((payload_len = sockts_tcp_payload_len(pkt)) < 0)
            {
                ERROR("sockts_tcp_payload_len() returned negative value");
                data->failed = TRUE;
                goto cleanup;
            }
        }

        data->bytes_count += payload_len;
        if (data->pkts_count == 1)
            data->first_ts = tv.tv_sec * 1000000LLU + tv.tv_usec;

        pkt_source = "IUT";
    }
    else if (tapi_sockaddr_cmp(SA(&src), data->tst_addr) == 0 &&
             te_sockaddr_get_port(SA(&dst)) ==
                      te_sockaddr_get_port(data->iut_addr))
    {
        pkt_source = "Tester";
    }
    else
    {
        WARN("Captured packet was not recognized");
    }

    rc = te_string_append(&addrs_log, " with src=%s",
                          sockaddr_h2str(SA(&src)));
    if (rc == 0)
    {
        rc = te_string_append(&addrs_log, " dst=%s",
                              sockaddr_h2str(SA(&dst)));
    }
    if (rc != 0)
    {
        ERROR("%s(): te_string_append() returned %r", __FUNCTION__, rc);
        te_string_reset(&addrs_log);
    }

    if (!data->no_pkts_log)
    {
        RING("Packet from %s%s was captured on %s at %u.%.6u",
             pkt_source, addrs_log.ptr, data->if_name,
             (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);
    }

cleanup:

    asn_free_value(pkt);
}

/**
 * Update address to which a socket is bound by calling
 * @b getsockname().
 *
 * @note If @b getsockname() retrieves wildcard address,
 *       then only port is updated.
 *
 * @param rpcs    RPC server.
 * @param sock    Socket FD.
 * @param addr    Address which should be updated.
 */
static void
update_bound_addr(rcf_rpc_server *rpcs, int sock,
                  struct sockaddr *addr)
{
    struct sockaddr_storage name;
    socklen_t               name_len;

    name_len = sizeof(name);
    rpc_getsockname(rpcs, sock, SA(&name), &name_len);

    if (te_sockaddr_is_wildcard(SA(&name)))
    {
        te_sockaddr_set_port(addr, te_sockaddr_get_port(SA(&name)));
    }
    else
    {
        tapi_sockaddr_clone_exact(SA(&name), SS(addr));
    }
}

/**
 * Check whether socket was bound to link-local IPv6 address,
 * print verdict if it was.
 *
 * @note This function is called when peer socket is not readable,
 *       so that normal execution of the test is no longer possible
 *       and some verdicts should be printed before finishing the test.
 *
 * @param rpcs        RPC server.
 * @param s           Socket FD.
 * @param msg         String to print in the beginning of verdict.
 */
static void
check_ipv6_linklocal(rcf_rpc_server *rpcs, int s, const char *msg)
{
    struct sockaddr_storage name;
    socklen_t               name_len;

    name_len = sizeof(name);
    rpc_getsockname(rpcs, s, SA(&name), &name_len);
    if (name.ss_family == AF_INET6 &&
        IN6_IS_ADDR_LINKLOCAL(&SIN6(&name)->sin6_addr))
    {
        ERROR_VERDICT("%ssocket was bound to link-local IPv6 address",
                      msg);
    }
}

/**
 * Create pair of connected sockets, print verdict if
 * listener is not readable or connect() failed.
 *
 * @param pco_iut       RPC server on IUT.
 * @param pco_tst       RPC server on Tester.
 * @param iut_addr      Network address on IUT (port may
 *                      be updated by this function if
 *                      bind() is not called on IUT socket).
 * @param tst_addr      Network address on Tester.
 * @param sock_type     Socket type.
 * @param bind_iut      Whether to bind IUT socket.
 * @param iut_s_ptr     Where to save IUT socket.
 * @param tst_s_ptr     Where to save Tester socket.
 * @param msg           Format string for message to print in verdicts.
 * @param ...           Arguments for the format string.
 */
static void
establish_connection(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                     struct sockaddr *iut_addr,
                     const struct sockaddr *tst_addr,
                     sockts_socket_type sock_type, te_bool bind_iut,
                     int *iut_s_ptr, int *tst_s_ptr,
                     const char *msg, ...)
{
    int tst_s;
    int iut_s;

    char        msg_buf[MAX_MSG_LEN] = "";
    te_string   str = TE_STRING_BUF_INIT(msg_buf);
    va_list     ap;

    if (msg[0] != '\0')
    {
        va_start(ap, msg);
        CHECK_RC(te_string_append_va(&str, msg, ap));
        CHECK_RC(te_string_append(&str, ": "));
    }

    iut_s = *iut_s_ptr =
              rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                         sock_type_sockts2rpc(sock_type), RPC_PROTO_DEF);
    if (bind_iut)
        rpc_bind(pco_iut, iut_s, iut_addr);

    tst_s = *tst_s_ptr =
              rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                         sock_type_sockts2rpc(sock_type), RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
    {
        if (bind_iut)
            rpc_connect(pco_tst, tst_s, iut_addr);
        if (sock_type == SOCKTS_SOCK_UDP)
            rpc_connect(pco_iut, iut_s, tst_addr);
    }
    else
    {
        int                   s_listener;
        int                   s_conn;
        int                   s_acc;
        rcf_rpc_server        *pco_srv;
        rcf_rpc_server        *pco_clnt;
        const struct sockaddr *srv_addr;
        te_bool                readable;
        te_errno               rc;

        if (sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            pco_srv = pco_tst;
            pco_clnt = pco_iut;
            s_listener = tst_s;
            s_conn = iut_s;
            srv_addr = tst_addr;
        }
        else
        {
            pco_srv = pco_iut;
            pco_clnt = pco_tst;
            s_listener = iut_s;
            s_conn = tst_s;
            srv_addr = iut_addr;
        }

        rpc_listen(pco_srv, s_listener, SOCKTS_BACKLOG_DEF);
        if (pco_srv == pco_iut && !bind_iut)
            update_bound_addr(pco_iut, s_listener, iut_addr);

        rpc_fcntl(pco_clnt, s_conn, RPC_F_SETFL, RPC_O_NONBLOCK);
        RPC_AWAIT_ERROR(pco_clnt);
        rc = rpc_connect(pco_clnt, s_conn, srv_addr);
        if (rc < 0 && RPC_ERRNO(pco_clnt) != RPC_EINPROGRESS)
            TEST_VERDICT("%sNonblocking connect() failed with unexpected "
                         "errno %r", str.ptr, RPC_ERRNO(pco_clnt));
        else if (rc >= 0)
            TEST_VERDICT("%sNonblocking connect() unexpectedly succeeded",
                         str.ptr);

        RPC_GET_READABILITY(readable, pco_srv, s_listener,
                            TAPI_WAIT_NETWORK_DELAY);
        if (!readable)
        {
            if (tst_addr->sa_family == AF_INET6)
                check_ipv6_linklocal(pco_clnt, s_conn, str.ptr);

            TEST_VERDICT("%sListener socket did not become readable",
                         str.ptr);
        }

        s_acc = rpc_accept(pco_srv, s_listener, NULL, NULL);
        RPC_CLOSE(pco_srv, s_listener);
        if (pco_srv == pco_iut)
            *iut_s_ptr = s_acc;
        else
            *tst_s_ptr = s_acc;

        RPC_AWAIT_ERROR(pco_clnt);
        rc = rpc_connect(pco_clnt, s_conn, srv_addr);
        if (rc != 0)
            TEST_VERDICT("%sFinal connect() failed unexpectedly with "
                         "errno %r", str.ptr, RPC_ERRNO(pco_clnt));
        rpc_fcntl(pco_clnt, s_conn, RPC_F_SETFL, 0);

        if (pco_clnt == pco_iut && !bind_iut)
            update_bound_addr(pco_iut, s_conn, iut_addr);
    }
}

/**
 * Send a number of packets from a socket, receive and check them on peer.
 *
 * @param from_tester       If @c TRUE, data is sent from Tester socket.
 * @param rpc_sender        RPC from which to send data.
 * @param s_sender          Socket from which to send data.
 * @param rpc_receiver      RPC where to receive data.
 * @param s_receiver        Socket from which to receive data.
 * @param sock_type         Socket type.
 * @param dst_addr          Destination address (required only in case
 *                          of @c SOCKTS_SOCK_UDP_NOTCONN).
 * @param pkts_num          Number of packets to send.
 * @param msg               Format string for a message to print in
 *                          verdicts.
 * @param ...               Arguments for the format string.
 */
static void
send_recv_data(te_bool from_tester,
               rcf_rpc_server *rpc_sender, int s_sender,
               rcf_rpc_server *rpc_receiver, int s_receiver,
               sockts_socket_type sock_type,
               const struct sockaddr *dst_addr,
               unsigned int pkts_num,
               const char *msg, ...)
{
    char          snd_buf[MAX_PKT_LEN];
    char          rcv_buf[MAX_PKT_LEN];
    size_t        data_len;
    unsigned int  i;
    te_bool       readable;
    te_errno      rc;

    char        msg_buf[MAX_MSG_LEN] = "";
    te_string   str = TE_STRING_BUF_INIT(msg_buf);
    va_list     ap;

    if (msg[0] != '\0')
    {
        va_start(ap, msg);
        CHECK_RC(te_string_append_va(&str, msg, ap));
        CHECK_RC(te_string_append(&str, ": "));
    }

    for (i = 0; i < pkts_num; i++)
    {
        data_len = rand_range(1, MAX_PKT_LEN);
        te_fill_buf(snd_buf, data_len);

        RPC_AWAIT_ERROR(rpc_sender);
        if ((sock_type == SOCKTS_SOCK_UDP_NOTCONN ||
             (from_tester &&
              sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)) &&
            dst_addr != NULL)
        {
            rc = rpc_sendto(rpc_sender, s_sender, snd_buf, data_len, 0,
                            dst_addr);
        }
        else
        {
            rc = rpc_send(rpc_sender, s_sender, snd_buf, data_len, 0);
        }

        if (rc < 0)
            TEST_VERDICT("%ssending failed unexpectedly with errno %r",
                         str.ptr, RPC_ERRNO(rpc_sender));
        else if ((size_t)rc != data_len)
            TEST_VERDICT("%ssending returned unexpected value", str.ptr);

        RPC_GET_READABILITY(readable, rpc_receiver, s_receiver,
                            TAPI_WAIT_NETWORK_DELAY);
        if (!readable)
        {
            check_ipv6_linklocal(rpc_sender, s_sender, str.ptr);
            TEST_VERDICT("%ssocket did not become readable after "
                         "sending data", str.ptr);
        }

        RPC_AWAIT_ERROR(rpc_receiver);
        rc = rpc_recv(rpc_receiver, s_receiver, rcv_buf,
                      sizeof(rcv_buf), 0);
        if (rc < 0)
            TEST_VERDICT("%srecv() failed unexpectedly with errno %r",
                         str.ptr, RPC_ERRNO(rpc_receiver));
        else if ((size_t)rc != data_len)
            TEST_VERDICT("%srecv() returned unexpected value", str.ptr);
        else if (memcmp(snd_buf, rcv_buf, data_len) != 0)
            TEST_VERDICT("%sreceived data differs from sent data",
                         str.ptr);
    }
}

/* See description in ts_route_mpath.h */
te_errno
multipath_check_state_clean(multipath_check_state *state)
{
    te_bool   sock_closed = FALSE;
    te_errno  rc = 0;
    te_errno  rc2;

    if (state->tst_csap1 != CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tad_csap_destroy(state->pco_tst->ta, 0,
                                       state->tst_csap1));
        state->tst_csap1 = CSAP_INVALID_HANDLE;
    }

    if (state->tst_csap2 != CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tad_csap_destroy(state->pco_tst->ta, 0,
                                       state->tst_csap2));
        state->tst_csap2 = CSAP_INVALID_HANDLE;
    }

    if (!state->reused_socks)
    {
        if (state->tst_s >= 0)
        {
            RPC_CLOSE(state->pco_tst, state->tst_s);
            sock_closed = TRUE;
        }
        if (state->iut_s >= 0)
        {
            RPC_CLOSE(state->pco_iut, state->iut_s);
            sock_closed = TRUE;
        }
    }

    if (state->saved_conns_num > 0)
    {
        unsigned int i;

        for (i = 0; i < state->saved_conns_num; i++)
        {
            RPC_CLOSE(state->pco_tst, state->saved_conns[i].tst_s);
            RPC_CLOSE(state->pco_iut, state->saved_conns[i].iut_s);
            sock_closed = TRUE;
        }

        free(state->saved_conns);
        state->saved_conns = NULL;
        state->saved_conns_num = 0;
    }

    if (sock_closed &&
        sock_type_sockts2rpc(state->sock_type) == RPC_SOCK_STREAM)
    {
        /* Let all closed TCP connections to fully terminate */
        TAPI_WAIT_NETWORK;
    }

    if (state->iut_rt_hndl != CFG_HANDLE_INVALID)
    {
        rc2 = cfg_del_instance(state->iut_rt_hndl, FALSE);
        if (rc == 0)
            rc = rc2;
        state->iut_rt_hndl = CFG_HANDLE_INVALID;
    }

    if (state->tst_rt_hndl != CFG_HANDLE_INVALID)
    {
        rc2 = cfg_del_instance(state->tst_rt_hndl, FALSE);
        if (rc == 0)
            rc = rc2;
        state->tst_rt_hndl = CFG_HANDLE_INVALID;
    }

    if (state->tst_rule_added)
    {
        rc2 = tapi_cfg_del_rule(state->pco_tst->ta,
                                state->iut_addr->sa_family,
                                state->tst_rule.mask,
                                &state->tst_rule);
        state->tst_rule_added = FALSE;
        if (rc == 0)
            rc = rc2;
    }

    return rc;
}

/**
 * Create CSAPs for capturing packets on checked interfaces, if
 * they do not exist.
 *
 * @param state       Pointer to mpath_check_state structure storing
 *                    information about RPC servers, interfaces, etc.
 */
static void
create_csaps(multipath_check_state *state)
{
    if (state->tst_csap1 == CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                state->pco_tst->ta, 0, state->tst1_if->if_name,
                TAD_ETH_RECV_DEF | TAD_ETH_RECV_OUT |
                TAD_ETH_RECV_NO_PROMISC,
                NULL, NULL,
                state->tst_addr->sa_family,
                (sock_type_sockts2rpc(state->sock_type) == RPC_SOCK_DGRAM ?
                  IPPROTO_UDP : IPPROTO_TCP),
                TAD_SA2ARGS(NULL, NULL),
                &state->tst_csap1));
    }

    if (state->tst_csap2 == CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                state->pco_tst->ta, 0, state->tst2_if->if_name,
                TAD_ETH_RECV_DEF | TAD_ETH_RECV_OUT |
                TAD_ETH_RECV_NO_PROMISC,
                NULL, NULL,
                state->tst_addr->sa_family,
                (sock_type_sockts2rpc(state->sock_type) == RPC_SOCK_DGRAM ?
                  IPPROTO_UDP : IPPROTO_TCP),
                TAD_SA2ARGS(NULL, NULL),
                &state->tst_csap2));
    }

    if (state->iut_csap1 == CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                state->pco_iut->ta, 0, state->iut1_if->if_name,
                TAD_ETH_RECV_DEF | TAD_ETH_RECV_OUT |
                TAD_ETH_RECV_NO_PROMISC,
                NULL, NULL,
                state->iut_addr->sa_family,
                (sock_type_sockts2rpc(state->sock_type) == RPC_SOCK_DGRAM ?
                  IPPROTO_UDP : IPPROTO_TCP),
                TAD_SA2ARGS(NULL, NULL),
                &state->iut_csap1));
    }

    if (state->iut_csap2 == CSAP_INVALID_HANDLE)
    {
        CHECK_RC(tapi_tcp_udp_ip_eth_csap_create(
                state->pco_iut->ta, 0, state->iut2_if->if_name,
                TAD_ETH_RECV_DEF | TAD_ETH_RECV_OUT |
                TAD_ETH_RECV_NO_PROMISC,
                NULL, NULL,
                state->iut_addr->sa_family,
                (sock_type_sockts2rpc(state->sock_type) == RPC_SOCK_DGRAM ?
                  IPPROTO_UDP : IPPROTO_TCP),
                TAD_SA2ARGS(NULL, NULL),
                &state->iut_csap2));
    }
}

/**
 * Check number of packets captured on IUT interface.
 *
 * @param iut_pkts          Number of packets captured on IUT interface.
 * @param tst_pkts          Number of packets captured on Tester interface.
 * @param iut_bytes         Number of bytes captured on IUT interface.
 * @param tst_bytes         Number of bytes captured on Tester interface.
 * @param iut_if_acc        If @c TRUE, traffic over IUT interface should
 *                          be accelerated.
 * @param no_accel          Will be set to @c TRUE if not accelerated
 *                          traffic was detected unexpectedly.
 * @param missing_pkts      Will be set to @c TRUE if less packets than
 *                          expected was captured on IUT.
 * @param missing_bytes     Will be set to @c TRUE if the number of bytes
 *                          captured on Tester and IUT does not match.
 */
static void
check_iut_pkts_num(unsigned int iut_pkts, unsigned int tst_pkts,
                   unsigned int iut_bytes, unsigned int tst_bytes,
                   te_bool iut_if_acc,
                   te_bool *no_accel, te_bool *missing_pkts,
                   te_bool *missing_bytes)
{
    if (iut_if_acc)
    {
        /*
         * One packet is fine - it may be due to neighbor address
         * resolution.
         */
        if (iut_pkts > 1)
        {
            ERROR("Not accelerated traffic was detected");
            *no_accel = TRUE;
        }
    }
    else
    {
        if (iut_pkts < tst_pkts)
        {
            ERROR("Less packets than expected were captured on IUT");
            *missing_pkts = TRUE;
        }
        if (iut_bytes != tst_bytes)
        {
            ERROR("Data sent from IUT does not match data received on Tester");
            *missing_bytes = TRUE;
        }
    }
}

/**
 * Fill route parameters for route creation/modification TAPI functions.
 *
 * @param rt_params         Pointer to route parameters structure.
 * @param hops              Pointer to array of tapi_cfg_rt_nexthop
 *                          structures (it should have two elements).
 * @param weight1           Weight of the first path (if zero, single-path
 *                          route is created).
 * @param weight2           Weight of the second path (if zero, single-path
 *                          route is created).
 * @param gw1               Gateway address for the first path.
 * @param gw2               Gateway address for the second path.
 * @param if1_name          Interface name for the first path.
 * @param if2_name          Interface name for the second path.
 */
static void
fill_rt_params(tapi_cfg_rt_params *rt_params, tapi_cfg_rt_nexthop *hops,
               unsigned int weight1, unsigned int weight2,
               const struct sockaddr *gw1, const struct sockaddr *gw2,
               const char *if1_name, const char *if2_name)
{
    if (weight1 == 0)
    {
        rt_params->gw_addr = gw2;
        rt_params->dev = if2_name;
    }
    else if (weight2 == 0)
    {
        rt_params->gw_addr = gw1;
        rt_params->dev = if1_name;
    }
    else
    {
        memset(hops, 0, 2 * sizeof(*hops));

        hops[0].weight = weight1;
        strncpy(hops[0].ifname, if1_name, IF_NAMESIZE);
        tapi_sockaddr_clone_exact(gw1, &hops[0].gw);

        hops[1].weight = weight2;
        strncpy(hops[1].ifname, if2_name, IF_NAMESIZE);
        tapi_sockaddr_clone_exact(gw2, &hops[1].gw);

        rt_params->hops = hops;
        rt_params->hops_num = 2;
        rt_params->dev = "";
    }
}

/* See description in ts_route_mpath.h */
void
configure_multipath_routes(multipath_check_state *state)
{
    int af = state->iut_addr->sa_family;

    tapi_cfg_rt_nexthop  iut_hops[2];
    tapi_cfg_rt_params   iut_rt_params;
    tapi_cfg_rt_nexthop  tst_hops[2];
    tapi_cfg_rt_params   tst_rt_params;

    if (state->weight1 == 0 && state->weight2 == 0)
        TEST_FAIL("Weights of both paths are zero");

    if (!state->conf_fixed)
    {
        /*
         * If diff_addrs is FALSE, set fib_multipath_hash_policy to 1
         * on IUT and Tester, so that ports will be taken into account
         * when determining over which path to send packets.
         */
        if (!state->diff_addrs)
        {
            CHECK_RC(multipath_set_hash_policy(state->iut_addr->sa_family,
                                               state->pco_iut, 1));
            CHECK_RC(multipath_set_hash_policy(state->tst_addr->sa_family,
                                               state->pco_tst, 1));
        }

        if (state->iut_addr->sa_family == AF_INET)
        {
            CHECK_RC(tapi_cfg_base_ipv4_fw(state->pco_gwa->ta, TRUE));
            CHECK_RC(tapi_cfg_base_ipv4_fw(state->pco_gwb->ta, TRUE));
        }
        else
        {
            CHECK_RC(tapi_cfg_base_ipv6_fw(state->pco_gwa->ta, TRUE));
            CHECK_RC(tapi_cfg_base_ipv6_fw(state->pco_gwb->ta, TRUE));
        }

        state->conf_fixed = TRUE;
    }

    /*
     * Add a policy routing rule on Tester assigning lookup table
     * SOCKTS_RT_TABLE_FOO for packets sent to IUT addresses. This
     * is done to ensure that multipath route will be chosen for
     * such packets (instead of default routes based on addresses
     * assigned to interfaces), so that Tester will use both paths
     * sending data to one of IUT addresses.
     */

    if (!state->tst_rule_added)
    {
        te_conf_ip_rule_init(&state->tst_rule);
        sockts_rt_fill_add_rule(state->pco_tst, af, SOCKTS_RT_RULE_TO,
                                SOCKTS_RT_TABLE_FOO,
                                NULL, -1, SA(&state->iut_common_net),
                                state->iut_common_pfx, -1, -1,
                                &state->tst_rule,
                                &state->tst_rule_added);
    }

    if (state->rt_weight1 != state->weight1 ||
        state->rt_weight2 != state->weight2)
    {
        tapi_cfg_rt_params_init(&iut_rt_params);
        iut_rt_params.dst_addr = (af == AF_INET ?
                                    state->tst_net->ip4addr :
                                    state->tst_net->ip6addr);
        iut_rt_params.prefix = (af == AF_INET ?
                                  state->tst_net->ip4pfx :
                                  state->tst_net->ip6pfx);

        fill_rt_params(&iut_rt_params, iut_hops,
                       state->weight1, state->weight2,
                       state->gwa_addr, state->tst2_addr,
                       state->iut1_if->if_name,
                       state->iut2_if->if_name);

        iut_rt_params.src_addr = state->iut_src_addr;

        if (state->iut_rt_hndl == CFG_HANDLE_INVALID)
        {
            CHECK_RC(tapi_cfg_add_route2(state->pco_iut->ta, &iut_rt_params,
                                         &state->iut_rt_hndl));
        }
        else
        {
            CHECK_RC(tapi_cfg_modify_route2(state->pco_iut->ta,
                                            &iut_rt_params,
                                            &state->iut_rt_hndl));
        }

        /*
         * Remove previously created route on Tester and create changed
         * route in its place instead of trying to edit it like it is done
         * on IUT: on earlier Linux kernels this can fail with EHOSTUNREACH
         * for IPv6, presumably because route destination matches addresses
         * assigned to Tester interfaces. More specifically, the problem was
         * observed on Ubuntu 18.04, kernel 4.15.0-45 (hosts dwalin/balin,
         * fror/fundin).
         */
        if (state->tst_rt_hndl != CFG_HANDLE_INVALID)
        {
            CHECK_RC(cfg_del_instance(state->tst_rt_hndl, FALSE));
            state->tst_rt_hndl = CFG_HANDLE_INVALID;
        }

        tapi_cfg_rt_params_init(&tst_rt_params);
        tst_rt_params.dst_addr = SA(&state->iut_common_net);
        tst_rt_params.prefix = state->iut_common_pfx;
        tst_rt_params.table = SOCKTS_RT_TABLE_FOO;

        fill_rt_params(&tst_rt_params, tst_hops,
                       state->weight1, state->weight2,
                       state->gwb_addr, state->iut2_addr,
                       state->tst1_if->if_name,
                       state->tst2_if->if_name);

        CHECK_RC(tapi_cfg_add_route2(state->pco_tst->ta, &tst_rt_params,
                                     &state->tst_rt_hndl));

        state->rt_weight1 = state->weight1;
        state->rt_weight2 = state->weight2;
    }
}

/**
 * Compute deviation between real packet distribution and expected one.
 * Deviation is computed as a distance between points representing real
 * and expected packets distributions in normalized coordinates (so that
 * it is a number in [0, 1]).
 *
 * @param weight1     Weight of the first path of a multipath route.
 * @param weight2     Weight of the second path of a multipath route.
 * @param pkts1       Number of packets captured from the first path of
 *                    a multipath route.
 * @param pkts2       Number of packets captured from the second path of
 *                    a multipath route.
 *
 * @return Deviation value.
 */
static double
compute_deviation(unsigned int weight1, unsigned int weight2,
                  unsigned int pkts1, unsigned int pkts2)
{
    double       tot_pkts;
    double       tot_weight;
    double       exp_weight1;
    double       exp_weight2;
    double       real_weight1;
    double       real_weight2;
    double       res;

    tot_pkts = pkts1 + pkts2;
    tot_weight = weight1 + weight2;
    real_weight1 = (double)pkts1 / tot_pkts;
    real_weight2 = (double)pkts2 / tot_pkts;
    exp_weight1 = (double)weight1 / tot_weight;
    exp_weight2 = (double)weight2 / tot_weight;

    res = sqrt((exp_weight1 - real_weight1) * (exp_weight1 - real_weight1) +
               (exp_weight2 - real_weight2) * (exp_weight2 - real_weight2));
    return res;
}

/* See description in ts_route_mpath.h */
te_errno
check_multipath_route(multipath_check_state *state,
                      const char *stage)
{
    rcf_rpc_server            *pco_iut = state->pco_iut;
    rcf_rpc_server            *pco_tst = state->pco_tst;
    const struct sockaddr     *iut_addr = state->iut_addr;
    const struct sockaddr     *tst_addr = state->tst_addr;
    te_bool                    diff_addrs = state->diff_addrs;
    tapi_env_net              *tst_net = state->tst_net;
    const struct if_nameindex *iut1_if = state->iut1_if;
    const struct if_nameindex *iut2_if = state->iut2_if;
    const struct if_nameindex *tst_bind_if = state->tst_bind_if;
    const struct if_nameindex *tst1_if = state->tst1_if;
    const struct if_nameindex *tst2_if = state->tst2_if;
    sockts_socket_type         sock_type = state->sock_type;
    unsigned int               conns_num = state->conns_num;
    unsigned int               pkts_per_conn = state->pkts_per_conn;
    unsigned int               weight1 = state->weight1;
    unsigned int               weight2 = state->weight2;

    unsigned int            i;
    int                     af;
    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage tst_bind_addr;

    tapi_tad_trrecv_cb_data   tst_cb_data1;
    tapi_tad_trrecv_cb_data   tst_cb_data2;
    pkts_data_t               tst_data1;
    pkts_data_t               tst_data2;
    unsigned int              tst_total1;
    unsigned int              tst_total2;
    unsigned int              tst_bytes_total1 = 0;
    unsigned int              tst_bytes_total2 = 0;

    tapi_tad_trrecv_cb_data   iut_cb_data1;
    tapi_tad_trrecv_cb_data   iut_cb_data2;
    pkts_data_t               iut_data1;
    pkts_data_t               iut_data2;

    te_bool                   tst_csap1_started = FALSE;
    te_bool                   tst_csap2_started = FALSE;
    te_bool                   iut_csap1_started = FALSE;
    te_bool                   iut_csap2_started = FALSE;

    te_bool                   tst_silent_def = pco_tst->silent_default;
    te_bool                   iut_silent_def = pco_iut->silent_default;

    te_bool                   ipv6_linklocal_detected = FALSE;
    unsigned int              first_packet_other_path = 0;
    unsigned int              not_first_packet_other_path = 0;
    unsigned int              many_packets_other_path = 0;
    te_bool                   first_path_no_accel = FALSE;
    te_bool                   second_path_no_accel = FALSE;
    te_bool                   first_path_no_iut_pkts = FALSE;
    te_bool                   first_path_no_iut_bytes = FALSE;
    te_bool                   second_path_no_iut_pkts = FALSE;
    te_bool                   second_path_no_iut_bytes = FALSE;

    double exp_ratio;
    double real_ratio;
    double deviation;

    char msg[MAX_MSG_LEN] = "";

    struct sockaddr_storage   *tst_addrs = NULL;
    unsigned int               tst_addrs_num = 0;
    int                        rc = 0;
    te_bool                    saved_rcf_tr_op_log = rcf_tr_op_log_get();
    te_bool                    save_conns = FALSE;
    te_bool                    existing_conns = FALSE;

    if (stage[0] != '\0')
        TE_SPRINTF(msg, "%s: ", stage);

    if (state->iut_src_addr != NULL)
        iut_addr = state->iut_src_addr;

    init_pkts_data(&tst_cb_data1, &tst_data1, tst1_if->if_name,
                   SA(&iut_bind_addr), SA(&tst_bind_addr));
    init_pkts_data(&tst_cb_data2, &tst_data2, tst2_if->if_name,
                   SA(&iut_bind_addr), SA(&tst_bind_addr));
    if (!state->verbose)
    {
        tst_data1.no_pkts_log = TRUE;
        tst_data2.no_pkts_log = TRUE;
    }

    init_pkts_data(&iut_cb_data1, &iut_data1, iut1_if->if_name,
                   SA(&iut_bind_addr), SA(&tst_bind_addr));
    init_pkts_data(&iut_cb_data2, &iut_data2, iut2_if->if_name,
                   SA(&iut_bind_addr), SA(&tst_bind_addr));
    iut_data1.no_pkts_log = TRUE;
    iut_data2.no_pkts_log = TRUE;

    tst_total1 = 0;
    tst_total2 = 0;

    create_csaps(state);

    af = iut_addr->sa_family;

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, state->tst_csap1, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));
    tst_csap1_started = TRUE;

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, state->tst_csap2, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));
    tst_csap2_started = TRUE;

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, state->iut_csap1, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));
    iut_csap1_started = TRUE;

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, state->iut_csap2, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));
    iut_csap2_started = TRUE;

    /* Make sure that CSAPs really started */
    TAPI_WAIT_NETWORK;

    if (diff_addrs)
    {
        rc = sockts_get_net_addrs_from_if(pco_tst, tst_bind_if->if_name,
                                          tst_net, af,
                                          &tst_addrs, &tst_addrs_num);
        if (rc != 0)
            goto cleanup;
    }

    rcf_tr_op_log(FALSE);

    if (state->reuse_conns)
    {
        if (state->saved_conns_num == 0)
        {
            state->saved_conns = TE_ALLOC(conns_num *
                                          sizeof(multipath_conn));
            save_conns = TRUE;
            for (i = 0; i < conns_num; i++)
            {
                state->saved_conns[i].iut_s = -1;
                state->saved_conns[i].tst_s = -1;
            }
        }
        else
        {
            if (conns_num > state->saved_conns_num)
            {
                ERROR("%sThere is not enough connections to be reused",
                      msg);
                rc = TE_EFAIL;
                goto cleanup;
            }
            existing_conns = TRUE;
        }
    }

    if (!state->verbose)
    {
        pco_iut->silent_default = pco_iut->silent = TRUE;
        pco_tst->silent_default = pco_tst->silent = TRUE;
    }

    for (i = 0; i < conns_num; i++)
    {
        RING("%sChecking connection %u", msg, i);

        if (existing_conns)
        {
            tapi_sockaddr_clone_exact(SA(&state->saved_conns[i].iut_addr),
                                      &iut_bind_addr);
            tapi_sockaddr_clone_exact(SA(&state->saved_conns[i].tst_addr),
                                      &tst_bind_addr);
            state->iut_s = state->saved_conns[i].iut_s;
            state->tst_s = state->saved_conns[i].tst_s;
            state->reused_socks = TRUE;
        }
        else
        {
            CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                         &iut_bind_addr));
            if (diff_addrs)
            {
                CHECK_RC(tapi_sockaddr_clone(
                                     pco_tst,
                                     SA(&tst_addrs[i % tst_addrs_num]),
                                     &tst_bind_addr));
            }
            else
            {
                CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                             &tst_bind_addr));
            }

            establish_connection(pco_iut, pco_tst, SA(&iut_bind_addr),
                                 SA(&tst_bind_addr),
                                 sock_type, state->bind_iut,
                                 &state->iut_s, &state->tst_s,
                                 "%sEstablishing connection", msg);
        }

        send_recv_data(FALSE, pco_iut, state->iut_s, pco_tst, state->tst_s,
                       sock_type, SA(&tst_bind_addr), pkts_per_conn,
                       "%sSending data from IUT", msg);

        if (!existing_conns && !(state->bind_iut) &&
            sock_type_sockts2rpc(sock_type) == RPC_SOCK_DGRAM)
        {
            update_bound_addr(pco_iut, state->iut_s, SA(&iut_bind_addr));
            if (te_sockaddr_get_port(SA(&iut_bind_addr)) == 0)
            {
                ERROR_VERDICT("getsockname() returned zero port for IUT "
                              "socket after sending data from it");
                rc = TE_EFAIL;
                goto cleanup;
            }
            /*
             * Tester socket is not connected here because if connection
             * is rechecked after adding a path to a multipath route,
             * not bound IUT UDP socket may choose another source address
             * if it now sends packet via a different interface. If Tester
             * socket was connected to another address before, it will
             * reject new packets in this case.
             */
        }

        if (iut_bind_addr.ss_family == AF_INET6 &&
            IN6_IS_ADDR_LINKLOCAL(&SIN6(&iut_bind_addr)->sin6_addr))
        {
            ipv6_linklocal_detected = TRUE;
        }

        send_recv_data(TRUE, pco_tst, state->tst_s, pco_iut, state->iut_s,
                       sock_type, SA(&iut_bind_addr), pkts_per_conn,
                       "%sSending data from Tester", msg);

        if (save_conns)
        {
            state->saved_conns[i].iut_s = state->iut_s;
            state->saved_conns[i].tst_s = state->tst_s;
            state->iut_s = -1;
            state->tst_s = -1;
            tapi_sockaddr_clone_exact(SA(&iut_bind_addr),
                                      &state->saved_conns[i].iut_addr);
            tapi_sockaddr_clone_exact(SA(&tst_bind_addr),
                                      &state->saved_conns[i].tst_addr);
            state->saved_conns_num++;
        }
        else if (!existing_conns)
        {
            RPC_CLOSE(pco_tst, state->tst_s);
            RPC_CLOSE(pco_iut, state->iut_s);
        }

        tst_data1.pkts_count = tst_data1.bytes_count = 0;
        tst_data2.pkts_count = tst_data2.bytes_count = 0;
        CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, state->tst_csap1,
                                     &tst_cb_data1, NULL));
        CHECK_RC(tapi_tad_trrecv_get(pco_tst->ta, 0, state->tst_csap2,
                                     &tst_cb_data2, NULL));

        RING("%u packets with %u bytes captured on the first Tester interface",
             tst_data1.pkts_count, tst_data1.bytes_count);

        RING("%u packets with %u bytes captured on the second Tester interface",
             tst_data2.pkts_count, tst_data2.bytes_count);

        if (tst_data1.pkts_count > 0 && tst_data2.pkts_count > 0)
        {

            if (tst_data1.pkts_count > 1 && tst_data2.pkts_count > 1)
            {
                many_packets_other_path++;
                RING("%sConnection sent multiple packets over both paths",
                     msg);
            }
            else
            {
                uint64_t ts_single;
                uint64_t ts_many;

                if (tst_data1.pkts_count == 1)
                {
                    ts_single = tst_data1.first_ts;
                    ts_many = tst_data2.first_ts;
                }
                else
                {
                    ts_single = tst_data2.first_ts;
                    ts_many = tst_data1.first_ts;
                }

                if (ts_single <= ts_many)
                {
                    RING("%sConnection sent the first packet over "
                         "different path", msg);
                    first_packet_other_path++;
                }
                else
                {
                    RING("%sConnection sent a single (not first) packet "
                         "over different path", msg);
                    not_first_packet_other_path++;
                }
            }
        }

        tst_total1 += tst_data1.pkts_count;
        tst_bytes_total1 += tst_data1.bytes_count;
        tst_total2 += tst_data2.pkts_count;
        tst_bytes_total2 += tst_data2.bytes_count;

        if (tst_data1.failed || tst_data2.failed)
        {
            ERROR_VERDICT("%sFailed to process packets captured by CSAP",
                          msg);
            rc = TE_EFAIL;
            goto cleanup;
        }

        if (tst_data1.pkts_count == 0 && tst_data2.pkts_count == 0)
        {
            ERROR_VERDICT("%sNo packets were captured on Tester "
                          "interfaces when checking connection", msg);
            rc = TE_EFAIL;
            goto cleanup;
        }

        iut_data1.pkts_count = iut_data1.bytes_count = 0;
        iut_data2.pkts_count = iut_data2.bytes_count = 0;
        CHECK_RC(tapi_tad_trrecv_get(pco_iut->ta, 0, state->iut_csap1,
                                     &iut_cb_data1, NULL));
        CHECK_RC(tapi_tad_trrecv_get(pco_iut->ta, 0, state->iut_csap2,
                                     &iut_cb_data2, NULL));

        RING("%u packets with %u bytes captured on the first IUT interface",
             iut_data1.pkts_count, iut_data1.bytes_count);
        check_iut_pkts_num(iut_data1.pkts_count, tst_data1.pkts_count,
                           iut_data1.bytes_count, tst_data1.bytes_count,
                           state->iut1_acc, &first_path_no_accel,
                           &first_path_no_iut_pkts, &first_path_no_iut_bytes);

        RING("%u packets with %u bytes captured on the second IUT interface",
             iut_data2.pkts_count, iut_data2.bytes_count);
        check_iut_pkts_num(iut_data2.pkts_count, tst_data2.pkts_count,
                           iut_data2.bytes_count, tst_data2.bytes_count,
                           state->iut2_acc, &second_path_no_accel,
                           &second_path_no_iut_pkts, &second_path_no_iut_bytes);
    }

    RING("%sNumber of connections which sent multiple packets "
         "over both paths: %u", msg, many_packets_other_path);

    RING("%sNumber of connections which sent the first packet "
         "over different path: %u", msg, first_packet_other_path);

    RING("%sNumber of connections which sent a single (not first) packet "
         "over different path: %u", msg, not_first_packet_other_path);

    if (ipv6_linklocal_detected)
    {
        ERROR_VERDICT("%sIUT socket was bound to link-local IPv6 "
                      "address", msg);
    }

    if (many_packets_other_path > 0)
    {
        RING_VERDICT("%sSome connection(s) sent multiple packets over "
                     "both paths", msg);
    }

    if (not_first_packet_other_path > 0)
    {
        RING_VERDICT("%sSome connection(s) sent a single (not first) "
                     "packet over different path", msg);
    }

    if (first_packet_other_path > 0)
    {
        if (first_packet_other_path == 1)
        {
            RING_VERDICT("%sA single connection sent the first packet over "
                         "different path", msg);
        }
        else
        {
            RING_VERDICT("%sMore than one connection sent the first packet "
                         "over different path", msg);
        }
    }

    RING("%s%u packets with %u bytes received over the first path",
         msg, tst_total1, tst_bytes_total1);
    RING("%s%u packets with %u bytes received over the second path",
         msg, tst_total2, tst_bytes_total2);

    if (tst_total1 == 0 && tst_total2 == 0)
    {
        ERROR_VERDICT("%sNo packets was captured", msg);
        rc = TE_EFAIL;
        goto cleanup;
    }
    else if (tst_total1 == 0 || tst_total2 == 0)
    {
        if ((weight1 == 0 && tst_total1 == 0) ||
            (weight2 == 0 && tst_total2 == 0))
        {
            rc = 0;
            goto cleanup;
        }
        else if (weight1 == 0 || weight2 == 0)
        {
            ERROR_VERDICT("%sAll packets went through the wrong path", msg);
        }
        else
        {
            ERROR_VERDICT("%sAll packets went through one of the paths", msg);
        }

        rc = TE_EFAIL;
        goto cleanup;
    }

    exp_ratio = (double)weight2 / (double)weight1;
    real_ratio = (double)tst_bytes_total2 / (double)tst_bytes_total1;
    deviation = compute_deviation(weight1, weight2,
                                  tst_bytes_total1, tst_bytes_total2);

    RING("%sExpected data ratio between paths is %f, "
         "observed is %f, deviation is %f", msg, exp_ratio, real_ratio,
         deviation);

    if (deviation > 0.25)
    {
        ERROR_VERDICT("%sReal distribution of data among route paths "
                      "differs too much from expected one", msg);
        rc = TE_EFAIL;
    }

    if (first_path_no_accel)
    {
        ERROR_VERDICT("%sNot accelerated traffic was detected over "
                      "the first path", msg);
    }
    else if (first_path_no_iut_bytes)
    {
        ERROR_VERDICT("%sNot all expected data was captured on IUT on "
                      "the first path", msg);
    }

    if (second_path_no_accel)
    {
        ERROR_VERDICT("%sNot accelerated traffic was detected over "
                      "the second path", msg);
    }
    else if (second_path_no_iut_bytes)
    {
        ERROR_VERDICT("%sNot all expected data was captured on IUT on "
                      "the second path", msg);
    }

cleanup:

    if (sock_type_sockts2rpc(sock_type) == RPC_SOCK_STREAM)
    {
        /* Allow all connections to close normally */
        TAPI_WAIT_NETWORK;
    }

    rcf_tr_op_log(saved_rcf_tr_op_log);
    free(tst_addrs);

    if (tst_csap1_started)
    {
        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, state->tst_csap1,
                                      NULL, NULL));
    }
    if (tst_csap2_started)
    {
        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0, state->tst_csap2,
                                      NULL, NULL));
    }

    if (iut_csap1_started)
    {
        CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, 0, state->iut_csap1,
                                      NULL, NULL));
    }
    if (iut_csap2_started)
    {
        CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, 0, state->iut_csap2,
                                      NULL, NULL));
    }

    pco_iut->silent_default = pco_iut->silent = iut_silent_def;
    pco_tst->silent_default = pco_tst->silent = tst_silent_def;

    return rc;
}

/* See description in ts_route_mpath.h */
te_errno
multipath_set_hash_policy(int af, rcf_rpc_server *rpcs, int value)
{
    te_errno    rc;
    const char *sys_path;

    sys_path = (af == AF_INET ?
                  "net/ipv4/fib_multipath_hash_policy" :
                  "net/ipv6/fib_multipath_hash_policy");

    rc = tapi_cfg_sys_set_int(rpcs->ta, value, NULL, sys_path);
    if (rc != 0 && rc != TE_RC(TE_CS, TE_ENOENT))
    {
        ERROR("%s(): failed to set %s on %s, rc = %r",
              __FUNCTION__, sys_path, rpcs->ta, rc);
        return rc;
    }

    return 0;
}

/* See description in ts_route_mpath.h */
void
multipath_get_common_net(const struct sockaddr *addr1,
                         const struct sockaddr *addr2,
                         struct sockaddr_storage *net_addr,
                         unsigned int *net_prefix)
{
    struct sockaddr_storage addr1_copy;
    struct sockaddr_storage addr2_copy;
    int                     i;

    tapi_sockaddr_clone_exact(addr1, &addr1_copy);
    tapi_sockaddr_clone_exact(addr2, &addr2_copy);
    te_sockaddr_set_port(SA(&addr1_copy), 0);
    te_sockaddr_set_port(SA(&addr2_copy), 0);

    for (i = te_netaddr_get_size(addr1->sa_family) * 8; i >= 0; i--)
    {
        te_sockaddr_cleanup_to_prefix(SA(&addr1_copy), i);
        te_sockaddr_cleanup_to_prefix(SA(&addr2_copy), i);
        if (tapi_sockaddr_cmp(SA(&addr1_copy), SA(&addr2_copy)) == 0)
            break;
    }
    if (i < 0)
        TEST_FAIL("%s(): failed to find common network", __FUNCTION__);

    *net_prefix = i;
    tapi_sockaddr_clone_exact(SA(&addr1_copy), net_addr);
}
