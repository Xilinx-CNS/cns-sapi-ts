/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page tcp-listen_backlog_max Maximum number of half-opened connections
 *
 * @objective Test listen backlog maximum with a lot of half-opened
 *            connections.
 *
 * @type conformance, robustness
 *
 * @param net                  Network to which IP addresses
 *                             should belong
 * @param pco_iut              PCO on IUT
 * @param pco_tst              PCO on TESTER
 * @param iut_if               IUT interface
 * @param tst_if               Tester interface
 * @param iut_addr             IUT IP address
 * @param iut_lladdr           IUT MAC address
 * @param alien_link_address   Alien MAC address not assigned to
 *                             any host
 * @param backlog_max          TCP backlog maximum to be set
 * @param completed_conns_num  How many connections should be
 *                             completed, including the first
 *                             and the last one
 * @param ef_prefault_packets  If @c TRUE, set EF_PREFAULT_PACKETS
 *
 * @par Test sequence:
**
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/listen_backlog_max"

#include "sockapi-test.h"
#include "te_ethernet.h"
#include "tapi_tcp.h"
#include "tapi_mem.h"
#include "tapi_route_gw.h"

#include "ndn_ipstack.h"
#include "ndn_eth.h"

/** Minimum port number. */
#define PORT_MIN 20000

/** Maximum port number. */
#define PORT_MAX 50000

/** Number of ports used with a single address. */
#define PORTS_NUM (PORT_MAX - PORT_MIN + 1)

/** Compute port number from array index. */
#define PORT_ID2NUM(id_) (id_ + PORT_MIN)

/** Compute array index from port number. */
#define PORT_NUM2ID(port_) (port_ - PORT_MIN)

/** Number of sender CSAPs. */
#define SENDERS_NUM 20

/** Number of SYN-ACK retransmits. */
#define TCP_SYNACK_RETRIES 10

/**
 * This number is to be added to values of
 * variables like EF_FDTABLE_SIZE to account
 * for additional file descriptors (like that
 * of listener socket) which may be opened.
 */
#define EXTRA_FDS_NUM 100

/**
 * Compare addresses from two sockaddr_storage structures.
 * Ports are ignored.
 *
 * @param sa1   Pointer to the first structure
 * @param sa2   Pointer to the second structure
 *
 * @return @c true if addresses are equal, @c false otherwise.
 */
#define ADDR_IS_EQUAL(sa1, sa2) \
    (te_sockaddrcmp_no_ports(                           \
        SA(sa1), te_sockaddr_get_size(SA(sa1)),         \
        SA(sa2), te_sockaddr_get_size(SA(sa2))) == 0)

/** Index of sender CSAP to use next. */
static unsigned int cur_sender = 0;
/** Whether the next sender CSAP was not used yet. */
static te_bool send_first_time = TRUE;
/** Will be set to TRUE if the test failed. */
static te_bool test_failed = FALSE;

/**
 * Structure describing TCP peer. */
typedef struct port_peer {
    te_bool   syn_sent;     /**< TRUE if SYN was sent. */
    te_bool   ack_sent;     /**< TRUE if ACK to SYN-ACK was sent. */
    te_bool   fin_sent;     /**< TRUE if FIN was sent. */
    te_bool   rst_got;      /**< TRUE if RST was received. */
    te_bool   fin_got;      /**< TRUE if FIN was received. */

    int       syn_acks;     /**< Number of received SYN-ACKs. */

    uint32_t  seqn_got;     /**< Last SEQN received. */
    uint32_t  ackn_got;     /**< Last ACKN received. */
    uint32_t  last_len_got; /**< Length of the last received packet. */
    uint32_t  next_seqn;    /**< Next SEQN to be used for sending. */

    te_bool   closed;       /**< TRUE if connection was correctly closed. */
} port_peer;

/**
 * Group of TCP peers having the same IP address.
 */
typedef struct addr_peers {
    struct sockaddr_storage addr;         /**< IP address. */
    cfg_handle              addr_handle;  /**< Handle of IP address in
                                               configuration tree. */

    port_peer ppeers[PORTS_NUM];          /**< Array of TCP peers. */
} addr_peers;

/**
 * Structure describing TCP peers.
 */
typedef struct peers_descr {
    addr_peers *apeers;     /**< TCP peers grouped by IP addresses. */
    int         addrs_num;  /**< Number of IP addresses. */
    te_bool     is_ipv6;    /**< TRUE if peers have IPv6 addresses. */

    int ack_syn_wait_num; /**< How many connections wait for ACK
                               to SYN-ACK. */
    int syn_ack_num;      /**< Number of peers which received SYN-ACK. */
    int rst_num;          /**< Number of peers which received RST. */
    int fin_num;          /**< Number of peers which received FIN. */
    int accepted_num;     /**< Number of accepted connections on IUT. */
    int closed_num;       /**< Number of connections which were correctly
                               closed. */
} peers_descr;

/**
 * Print statistics for TCP connections.
 *
 * @param peers       TCP peers.
 * @param msg         Message to print in log.
 */
static void
peers_print_stats(peers_descr *peers, const char *msg)
{
    RING("%s: SYN-ACK %d FIN %d RST %d ACCEPTED %d CLOSED %d",
         msg, peers->syn_ack_num, peers->fin_num,
         peers->rst_num, peers->accepted_num, peers->closed_num);
}

/**
 * TCP packet handler used with CSAP.
 *
 * @param pkt         Packet described in ASN.
 * @param user_data   Pointer to peers_descr structure.
 */
static void
tcp_pkt_handler(asn_value *pkt, void *user_data)
{
    peers_descr *peers = (peers_descr *)user_data;

    asn_value  *tcp_pdu;
    asn_value  *ip_pdu;

    int32_t         seqn_got;
    int32_t         ackn_got;
    int32_t         flags;
    size_t          len;
    int             i;

    struct sockaddr_storage dst_addr = {
        .ss_family = peers->is_ipv6 ? AF_INET6 : AF_INET
    };

    tcp_pdu = asn_read_indexed(pkt, 0, "pdus");

    len = sizeof(uint16_t);
    CHECK_RC(asn_read_value_field(tcp_pdu,
                                  te_sockaddr_get_port_ptr(SA(&dst_addr)),
                                  &len, "dst-port"));

    CHECK_RC(ndn_du_read_plain_int(tcp_pdu, NDN_TAG_TCP_FLAGS, &flags));
    CHECK_RC(ndn_du_read_plain_int(tcp_pdu, NDN_TAG_TCP_SEQN, &seqn_got));
    CHECK_RC(ndn_du_read_plain_int(tcp_pdu, NDN_TAG_TCP_ACKN, &ackn_got));

    ip_pdu = asn_read_indexed(pkt, 1, "pdus");

    len = te_netaddr_get_size(dst_addr.ss_family);
    CHECK_RC(asn_read_value_field(ip_pdu,
                                  te_sockaddr_get_netaddr(SA(&dst_addr)),
                                  &len, "dst-addr"));

    asn_free_value(ip_pdu);
    asn_free_value(tcp_pdu);
    asn_free_value(pkt);

    for (i = 0; i < peers->addrs_num; i++)
    {
        if (ADDR_IS_EQUAL(&peers->apeers[i].addr, &dst_addr))
        {
            int        port_id;
            port_peer *peer = NULL;
            uint16_t   dst_port = te_sockaddr_get_port(SA(&dst_addr));

            if (dst_port < PORT_MIN ||
                dst_port > PORT_MAX)
                TEST_FAIL("Incorrect port encountered");

            port_id = PORT_NUM2ID(dst_port);
            peer = &(peers->apeers[i].ppeers[port_id]);

            peer->last_len_got = 0;

            if (flags & TCP_RST_FLAG)
            {
                if (!peer->rst_got)
                {
                    peer->rst_got = TRUE;
                    peers->rst_num++;
                    if (peer->syn_acks > 0)
                        peers->ack_syn_wait_num--;
                }
            }
            else if ((flags & TCP_SYN_FLAG) &&
                     (flags & TCP_ACK_FLAG))
            {
                if (peer->syn_acks == 0)
                {
                    peers->syn_ack_num++;
                    peers->ack_syn_wait_num++;
                }

                peer->syn_acks++;
                peer->seqn_got = seqn_got;
                peer->ackn_got = ackn_got;
                peer->last_len_got = 1;
            }
            else if (flags & TCP_FIN_FLAG)
            {
                if (!peer->fin_got)
                    peers->fin_num++;

                peer->fin_got = TRUE;
                peer->seqn_got = seqn_got;
                peer->last_len_got = 1;

                if (flags & TCP_ACK_FLAG)
                    peer->ackn_got = ackn_got;
            }
            else if (flags & TCP_ACK_FLAG)
            {
                peer->ackn_got = ackn_got;
            }
            else
            {
                TEST_FAIL("A packet with unexpected "
                          "TCP flags 0x%x was received", flags);
            }

            if (peer->fin_sent && peer->fin_got && !peer->rst_got &&
                peer->next_seqn == peer->ackn_got)
            {
                if (!peer->closed)
                    peers->closed_num++;

                peer->closed = TRUE;
            }

            return;
        }
    }

    TEST_FAIL("Unknown source address encountered");
}

/**
 * Send TCP packet with help of CSAP.
 *
 * @param ta            Test Agent name.
 * @param csap_senders  Pointer to array of sender CSAPs.
 * @param template      Template for TCP packet.
 */
static void
csap_send_packet(const char *ta,
                 csap_handle_t *csap_senders,
                 asn_value *template)
{
    if (!send_first_time)
    {
        CHECK_RC(rcf_ta_trsend_stop(ta, 0,
                                    csap_senders[cur_sender], NULL));
    }

    CHECK_RC(tapi_tad_trsend_start(ta, 0,
                                   csap_senders[cur_sender], template,
                                   RCF_MODE_NONBLOCKING));

    cur_sender++;
    if (cur_sender >= SENDERS_NUM)
    {
        cur_sender = 0;
        send_first_time = FALSE;
    }
}

/**
 * Receive and process packets on Tester if required.
 *
 * @note This function should be called often to avoid consuming
 *       too much memory to store a lot of packets received from IUT.
 *
 * @param ta          Test agent name.
 * @param csap_recv   CSAP used for receiving.
 * @param peers       Pointer to peers_descr structure.
 * @param force       If @c TRUE, always try to receive packets.
 *                    Otherwise this function will often do nothing
 *                    to reduce number of checks on CSAP.
 */
static void
csap_receive_packets(const char *ta,
                     csap_handle_t csap_recv,
                     peers_descr *peers,
                     te_bool force)
{
#define RECV_CALL_NUM 1000

    static int call_num = 0;

    tapi_tad_trrecv_cb_data    cb_data;

    cb_data.callback = tcp_pkt_handler;
    cb_data.user_data = peers;

    call_num++;
    if (call_num >= RECV_CALL_NUM)
    {
        call_num = 0;
    }

    if (call_num == 0 || force)
        CHECK_RC(tapi_tad_trrecv_get(ta, 0, csap_recv,
                                     &cb_data, NULL));
}

/**
 * Send SYN packets to IUT.
 *
 * @param net               Network to which source addresses should belong.
 * @param alien_link_addr   MAC address not assigned to any host
 *                          from which packets will be sent.
 * @param backlog_max       How many connections to initiate.
 * @param pco_iut           RPC server on IUT.
 * @param pco_tst           RPC server on TESTER.
 * @param iut_if            Network interface on IUT.
 * @param csap_senders      Array of sender CSAPs.
 * @param peers             Pointer to peers_descr structure.
 */
static void
send_syns(tapi_env_net *net,
          const struct sockaddr *alien_link_addr,
          int backlog_max,
          rcf_rpc_server *pco_iut,
          rcf_rpc_server *pco_tst,
          const struct if_nameindex *iut_if,
          csap_handle_t *csap_senders,
          csap_handle_t csap_recv,
          peers_descr *peers)
{
    addr_peers        *apeers = NULL;
    int                cur_addr_id = 0;
    int                cur_port_id = 0;
    int                i;

    asn_value         *syn_templ = NULL;
    struct sockaddr   *addr_aux = NULL;
    port_peer         *peer = NULL;

    apeers = peers->apeers;

    CHECK_RC(tapi_tcp_template(peers->is_ipv6, 0, 0, TRUE, FALSE, NULL, 0,
                               &syn_templ));

    for (i = 0; i < backlog_max; i++)
    {
        if (cur_port_id == 0)
        {
            CHECK_RC(tapi_cfg_alloc_net_addr(
                                peers->is_ipv6 ? net->ip6net : net->ip4net,
                                &apeers[cur_addr_id].addr_handle,
                                &addr_aux));
            tapi_sockaddr_clone_exact(addr_aux,
                                      &apeers[cur_addr_id].addr);
            free(addr_aux);
            addr_aux = NULL;

            CHECK_RC(
              asn_write_value_field_fmt(
                    syn_templ,
                    te_sockaddr_get_netaddr(SA(&apeers[cur_addr_id].addr)),
                    te_netaddr_get_size(apeers[cur_addr_id].addr.ss_family),
                    "pdus.1.#ip%s.src-addr.#plain",
                    peers->is_ipv6 ? "6" : "4"));
            CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                                     SA(&apeers[cur_addr_id].addr),
                                     (uint8_t *)alien_link_addr->sa_data,
                                     TRUE));
        }

        CHECK_RC(asn_write_int32(syn_templ, PORT_ID2NUM(cur_port_id),
                                "pdus.0.#tcp.src-port.#plain"));

        peer = &(apeers[cur_addr_id].ppeers[cur_port_id]);
        peer->next_seqn = rand_range(1, INT_MAX);

        CHECK_RC(asn_write_int32(syn_templ, peer->next_seqn,
                                "pdus.0.#tcp.seqn.#plain"));

        csap_send_packet(pco_tst->ta, csap_senders, syn_templ);
        peer->syn_sent = TRUE;
        peer->next_seqn++;

        cur_port_id++;
        if (PORT_ID2NUM(cur_port_id) > PORT_MAX)
        {
            cur_port_id = 0;
            cur_addr_id++;
        }

        csap_receive_packets(pco_tst->ta, csap_recv, peers, FALSE);
    }

    asn_free_value(syn_templ);
}

/**
 * Send ACKs or FIN-ACKs from TCP peers.
 *
 * @param backlog_max          Total number of initiated connections.
 * @param pco_iut              RPC server on IUT.
 * @param pco_tst              RPC server on TESTER.
 * @param csap_senders         Array of sender CSAPs.
 * @param completed_conns_num  For how many connections establishment
 *                             should be completed.
 * @param send_fin             If @c TRUE, set FIN flag.
 * @param peers                TCP peers description.
 */
static void
send_acks(int backlog_max,
          rcf_rpc_server *pco_iut,
          rcf_rpc_server *pco_tst,
          csap_handle_t *csap_senders,
          csap_handle_t csap_recv,
          int completed_conns_num,
          te_bool send_fin,
          peers_descr *peers)
{
    addr_peers   *apeers = NULL;

    int     cur_addr_id = 0;
    int     cur_port_id = 0;
    int     i;
    int     j;
    int     k;
    int     t;

    asn_value     *ack_templ = NULL;
    port_peer     *peer = NULL;
    te_bool        send_packet;

    UNUSED(pco_iut);

    apeers = peers->apeers;

    CHECK_RC(tapi_tcp_template(peers->is_ipv6, 0, 0, FALSE, TRUE, NULL, 0,
                               &ack_templ));

    if (completed_conns_num > peers->ack_syn_wait_num)
        completed_conns_num = peers->ack_syn_wait_num;

    if (completed_conns_num == 0 && !send_fin)
        return;

    for (i = 0, j = 0, k = 0; i < backlog_max; i++)
    {
        cur_addr_id = i / PORTS_NUM;
        cur_port_id = i % PORTS_NUM;
        peer = &(apeers[cur_addr_id].ppeers[cur_port_id]);

        if (peer->syn_acks == 0 ||
            peer->rst_got)
            continue;

        j++;

        send_packet = FALSE;

        if (send_fin)
        {
            if (peer->ack_sent)
                send_packet = TRUE;
        }
        else
        {
            if (k >= completed_conns_num)
                break;

            if (completed_conns_num == 1)
            {
                t = 1;
            }
            else
            {
                /*
                 * Compute number of the next connection to
                 * establish. If we need N connections including
                 * the first and the last ones, and the total number
                 * of connections which may be completed is T, then
                 * after the first connection we should try to
                 * establish another one after skipping about
                 * T / (N - 1), and so on.
                 */
                t = (peers->ack_syn_wait_num * k) /
                                  (completed_conns_num - 1) + 1;
                if (k == completed_conns_num - 1)
                    t = peers->ack_syn_wait_num;
            }

            if (j == t)
            {
                k++;
                send_packet = TRUE;
            }
        }

        if (send_packet)
        {
            CHECK_RC(
              asn_write_value_field_fmt(
                    ack_templ,
                    te_sockaddr_get_netaddr(SA(&apeers[cur_addr_id].addr)),
                    te_netaddr_get_size(apeers[cur_addr_id].addr.ss_family),
                    "pdus.1.#ip%s.src-addr.#plain",
                    peers->is_ipv6 ? "6" : "4"));

            CHECK_RC(asn_write_int32(ack_templ, PORT_ID2NUM(cur_port_id),
                                    "pdus.0.#tcp.src-port.#plain"));

            CHECK_RC(asn_write_int32(
                          ack_templ,
                          peer->next_seqn,
                          "pdus.0.#tcp.seqn.#plain"));

            CHECK_RC(asn_write_int32(
                          ack_templ,
                          peer->seqn_got + peer->last_len_got,
                          "pdus.0.#tcp.ackn.#plain"));

            if (send_fin)
            {
                int32_t flags;

                CHECK_RC(asn_read_int32(ack_templ, &flags,
                                        "pdus.0.#tcp.flags.#plain"));
                flags |= TCP_FIN_FLAG;
                CHECK_RC(asn_write_int32(
                              ack_templ,
                               flags,
                              "pdus.0.#tcp.flags.#plain"));
            }

            csap_send_packet(pco_tst->ta, csap_senders, ack_templ);

            peer->ack_sent = TRUE;
            if (send_fin)
            {
                peer->fin_sent = TRUE;
                peer->next_seqn++;
            }
        }

        csap_receive_packets(pco_tst->ta, csap_recv, peers, FALSE);
    }

    asn_free_value(ack_templ);
}

/**
 * Terminate established connections.
 *
 * @param backlog_max          How many connections were initiated.
 * @param pco_iut              RPC server on IUT.
 * @param pco_tst              RPC server on TESTER.
 * @param iut_listener         Listener socket on IUT.
 * @param csap_senders         Array of sender CSAPs.
 * @param csap_recv            CSAP to use for receiving IUT packets.
 * @param completed_conns_num  For how many connections establishment
 *                             should have been completed.
 * @param peers                Pointer to peers_descr structure.
 */
static void
close_conns(int backlog_max,
            rcf_rpc_server *pco_iut,
            rcf_rpc_server *pco_tst,
            int iut_listener,
            csap_handle_t *csap_senders,
            csap_handle_t csap_recv,
            int completed_conns_num,
            peers_descr *peers)
{
    te_bool readable;
    int     iut_s;

    while (TRUE)
    {
        RPC_GET_READABILITY(readable, pco_iut, iut_listener,
                            TAPI_WAIT_NETWORK_DELAY);
        if (!readable)
            break;

        RPC_AWAIT_ERROR(pco_iut);
        iut_s = rpc_accept(pco_iut, iut_listener, NULL, NULL);
        if (iut_s < 0)
            TEST_VERDICT("accept() unexpectedly failed with errno %r",
                         RPC_ERRNO(pco_iut));

        peers->accepted_num++;

        rpc_close(pco_iut, iut_s);

        csap_receive_packets(pco_tst->ta, csap_recv, peers, TRUE);
    }

    TAPI_WAIT_NETWORK;

    csap_receive_packets(pco_tst->ta, csap_recv, peers, TRUE);

    send_acks(backlog_max, pco_iut, pco_tst,
              csap_senders, csap_recv,
              completed_conns_num, TRUE, peers);

    TAPI_WAIT_NETWORK;

    csap_receive_packets(pco_tst->ta, csap_recv, peers, TRUE);
}

/**
 * Perform test steps.
 *
 * @param net                  Network to which peer IP addresses
 *                             should belong.
 * @param alien_link_address   Alien MAC address.
 * @param backlog_max          How many connections to initiate.
 * @param pco_iut              RPC server on IUT.
 * @param pco_tst              RPC server on TESTER.
 * @param iut_if               Network interface on IUT.
 * @param iut_listener         Listener socket on IUT.
 * @param csap_senders         Array of sender CSAPs.
 * @param csap_recv            CSAP to use for receiving iUT packets.
 * @param completed_conns_num  For how many connections establishment
 *                             should be completed.
 * @param force_ipv6           TRUE for IPv6 testing.
 */
static void
do_test_steps(tapi_env_net *net,
              const struct sockaddr *alien_link_addr,
              int backlog_max,
              rcf_rpc_server *pco_iut,
              rcf_rpc_server *pco_tst,
              const struct if_nameindex *iut_if,
              int iut_listener,
              csap_handle_t *csap_senders,
              csap_handle_t csap_recv,
              int completed_conns_num,
              te_bool force_ipv6)
{
    peers_descr   peers;
    addr_peers   *apeers = NULL;
    int           addrs_num;
    int           i;

    memset(&peers, 0, sizeof(peers));

    addrs_num = (backlog_max - 1) / PORTS_NUM + 1;

    apeers = tapi_calloc(addrs_num, sizeof(*apeers));
    for (i = 0; i < addrs_num; i++)
        apeers[i].addr_handle = CFG_HANDLE_INVALID;

    peers.apeers = apeers;
    peers.addrs_num = addrs_num;
    peers.is_ipv6 = force_ipv6;

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap_recv,
                                   NULL, TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    send_syns(net, alien_link_addr, backlog_max,
              pco_iut, pco_tst, iut_if,
              csap_senders, csap_recv, &peers);

    TAPI_WAIT_NETWORK;

    csap_receive_packets(pco_tst->ta, csap_recv, &peers, TRUE);

    peers_print_stats(&peers, "After sending SYNs");

    send_acks(backlog_max, pco_iut, pco_tst,
              csap_senders, csap_recv,
              completed_conns_num, FALSE, &peers);

    TAPI_WAIT_NETWORK;

    csap_receive_packets(pco_tst->ta, csap_recv, &peers, TRUE);

    peers_print_stats(&peers, "After sending ACKs to SYN-ACKs");

    close_conns(backlog_max, pco_iut, pco_tst,
                iut_listener,
                csap_senders, csap_recv,
                completed_conns_num,
                &peers);

    peers_print_stats(&peers, "After closing connections");

    if (peers.syn_ack_num < backlog_max * 3/4)
    {
        ERROR_VERDICT("Too small number of SYN-ACKS was received");
        test_failed = TRUE;
    }
    if (peers.accepted_num < completed_conns_num)
    {
        ERROR_VERDICT("Too small number of connections was accepted");
        test_failed = TRUE;
    }
    if (peers.closed_num < peers.accepted_num)
    {
        ERROR_VERDICT("Not all accepted connections were properly closed");
        test_failed = TRUE;
    }
    if (peers.rst_num > 0)
    {
        ERROR_VERDICT("Some connections were reset");
        test_failed = TRUE;
    }

    for (i = 0; i < addrs_num; i++)
    {
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                          SA(&apeers[i].addr)));
        CHECK_RC(tapi_cfg_free_entry(&apeers[i].addr_handle));
    }

    free(apeers);
}

int
main(int argc, char *argv[])
{
    tapi_env_net      *net = NULL;
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;

    const struct sockaddr       *iut_addr = NULL;
    const struct if_nameindex   *iut_if = NULL;
    const struct if_nameindex   *tst_if = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *alien_link_addr = NULL;

    csap_handle_t  csap_recv = CSAP_INVALID_HANDLE;
    csap_handle_t  csap_senders[SENDERS_NUM] = { CSAP_INVALID_HANDLE, };
    int            i;

    int     iut_s;
    int     backlog_max;
    int     completed_conns_num;
    te_bool ef_prefault_packets;
    int     old_syn_backlog = -1;
    int     old_syncookies = -1;
    int     old_synack_retries = -1;
    te_bool force_ipv6 = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(backlog_max);
    TEST_GET_INT_PARAM(completed_conns_num);
    TEST_GET_BOOL_PARAM(ef_prefault_packets);

    if (completed_conns_num > backlog_max)
        TEST_VERDICT("Bad completed_conns_num and backlog_max parameter "
                     "values combination");

    if (iut_addr->sa_family == AF_INET6)
        force_ipv6 = TRUE;

    TEST_STEP("Set tcp_max_syn_backlog to @p backlog_max.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, backlog_max,
                                     &old_syn_backlog,
                                     "net/ipv4/tcp_max_syn_backlog"));

    TEST_STEP("Disable TCP syncookies.");
    rc = tapi_cfg_sys_ns_set_int(pco_iut->ta, 0, &old_syncookies,
                                     "net/ipv4/tcp_syncookies");
    if (rc != 0)
    {
        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
        {
            RING("Lack of the \"tcp_syncookies\" option means that syncookies "
                 "are disabled.");
        }
        else
        {
            TEST_FAIL("tapi_cfg_sys_ns_set_int() returned 0x%X (%r), "
                      "but expected 0", rc, rc);
        }
    }

    TEST_STEP("Set tcp_synack_retries to @c TCP_SYNACK_RETRIES to prevent "
              "dropping connections due to timeout when the test execution "
              "takes several minutes.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, TCP_SYNACK_RETRIES,
                                     &old_synack_retries,
                                     "net/ipv4/tcp_synack_retries"));

    TEST_STEP("If @p ef_prefault_packets, set EF_PREFAULT_PACKETS environment "
              "variable.");
    if (ef_prefault_packets)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_PREFAULT_PACKETS",
                                     30000, TRUE, FALSE));

    TEST_STEP("Set EF_RETRANSMIT_THRESHOLD_SYNACK to @c TCP_SYNACK_RETRIES.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_RETRANSMIT_THRESHOLD_SYNACK",
                                 TCP_SYNACK_RETRIES, TRUE, FALSE));
    TEST_STEP("Set EF_TCP_BACKLOG_MAX to @p backlog_max.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_BACKLOG_MAX",
                                 backlog_max, TRUE, FALSE));

    TEST_STEP("Set EF_MAX_ENDPOINTS and EF_FDTABLE_SIZE to "
              "@p backlog_max + @c EXTRA_FDS_NUM.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MAX_ENDPOINTS",
                                 backlog_max + EXTRA_FDS_NUM,
                                 TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_FDTABLE_SIZE",
                                 backlog_max + EXTRA_FDS_NUM,
                                 TRUE, TRUE));

    TEST_STEP("Create TCP socket on IUT, bind it to @p iut_addr, "
              "call listen().");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, backlog_max);

    TEST_STEP("Create receiving and sending CSAPs on Tester.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_tst->ta, 0, tst_if->if_name,
                                         TAD_ETH_RECV_DEF,
                                         NULL,
                                         (uint8_t *)iut_lladdr->sa_data,
                                         iut_addr->sa_family,
                                         TAD_SA2ARGS(NULL, iut_addr),
                                         &csap_recv));

    for (i = 0; i < SENDERS_NUM; i++)
    {
        CHECK_RC(tapi_tcp_ip_eth_csap_create(
                                      pco_tst->ta, 0, tst_if->if_name,
                                      TAD_ETH_RECV_HOST |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      (uint8_t *)alien_link_addr->sa_data,
                                      (uint8_t *)iut_lladdr->sa_data,
                                      iut_addr->sa_family,
                                      TAD_SA2ARGS(NULL, iut_addr),
                                      &csap_senders[i]));
    }

    TEST_STEP("Initiate @p backlog_max connections from Tester by sending SYN "
              "from different IP addresses and ports. Send ACKs to SYN-ACKs for "
              "@p completed_conns_num connections. Then terminate successfully "
              "established connections. Check that all works OK.");

    CHECK_RC(rcf_tr_op_log(FALSE));
    do_test_steps(net, alien_link_addr, backlog_max, pco_iut, pco_tst,
                  iut_if, iut_s, csap_senders, csap_recv,
                  completed_conns_num, force_ipv6);

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (old_syn_backlog >= 0)
        CLEANUP_CHECK_RC(
            tapi_cfg_sys_ns_set_int(pco_iut->ta, old_syn_backlog, NULL,
                                    "net/ipv4/tcp_max_syn_backlog"));

    if (old_syncookies >= 0)
        CLEANUP_CHECK_RC(
          tapi_cfg_sys_ns_set_int(pco_iut->ta, old_syncookies, NULL,
                                  "net/ipv4/tcp_syncookies"));

    if (old_synack_retries >= 0)
        CLEANUP_CHECK_RC(
          tapi_cfg_sys_ns_set_int(pco_iut->ta, old_synack_retries, NULL,
                                  "net/ipv4/tcp_synack_retries"));

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap_recv));
    for (i = 0; i < SENDERS_NUM; i++)
    {
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0,
                                               csap_senders[i]));
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_dynamic(pco_iut->ta,
                                                iut_if->if_name));

    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_TCP_BACKLOG_MAX",
                                       TRUE, TRUE));
    CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut,
                                       "EF_RETRANSMIT_THRESHOLD_SYNACK",
                                       TRUE, TRUE));
    if (ef_prefault_packets)
        CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_PREFAULT_PACKETS",
                                           TRUE, TRUE));

    TEST_END;
}
