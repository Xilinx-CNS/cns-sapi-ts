/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief UDP Test Suite
 *
 * Common TAPI for checking datagrams reception from multiple
 * sources.
 */

#include "udp_multisrc.h"

/** Maximum number of peers */
#define MAX_PEERS 20

/**
 * Maximum number of messages received by a single
 * recvmmsg() or onload_zc_recv() call
 */
#define MAX_MSGS 5

/** Maximum number of iovecs per message */
#define MAX_IOVS 20

/** Length of an iovec buffer */
#define IOV_LEN 2000

/** Maximum length of the datagram */
#define MAX_PAYLOAD_LEN 20000

/** Packet sent from a peer */
typedef struct test_packet {
    char buf[MAX_PAYLOAD_LEN];      /**< Packet payload */
    size_t len;                     /**< Packet length */
    int received;                   /**< This field is set to
                                         the index of the packet
                                         in a sequence of received
                                         packets when the packet is
                                         received */
} test_packet;

/**
 * Check that received packet has correct payload and source
 * address (if the tested receiving function reports the address).
 *
 * @param buf           Received data.
 * @param len           Data length.
 * @param src_addr      Source address (NULL if not reported by
 *                      receiving function).
 * @param addr_len      Address length.
 * @param peers         Array of structures describing peers and packets
 *                      sent by them.
 * @param peers_num     Number of peers.
 * @param packet_idx    Index of the packet in the sequence of received
 *                      packets (will be saved in matching test_packet
 *                      structure and used later to check for reordering).
 */
static void
check_received_packet(char *buf, size_t len, struct sockaddr *src_addr,
                      socklen_t addr_len, udp_multisrc_peer *peers,
                      int peers_num, int packet_idx)
{
    int i;
    te_bool matched = FALSE;
    te_bool known_address = FALSE;

    test_packet *packet;

    for (i = 0; i < peers_num; i++)
    {
        packet = (test_packet *)(peers[i].packet);

        if (packet->received >= 0)
            continue;

        if (src_addr != NULL)
        {
            if (te_sockaddrcmp(
                  src_addr, addr_len,
                  SA(&peers[i].peer_addr),
                  te_sockaddr_get_size(SA(&peers[i].peer_addr))) != 0)
            {
                continue;
            }
            else
            {
                known_address = TRUE;
            }
        }

        if (len == packet->len &&
            memcmp(packet->buf, buf, len) == 0)
        {
            matched = TRUE;
            packet->received = packet_idx;
            break;
        }
    }

    if (src_addr != NULL && !known_address)
    {
        TEST_VERDICT("Packet with unknown source address was received");
    }
    else if (!matched)
    {
        TEST_VERDICT("Packet with unexpected data or length was received");
    }
}

/**
 * Initialize rpc_msghdr structure for functions like recvmsg().
 *
 * @param msg         Structure to initialize.
 * @param bufs        Buffers to store received data.
 * @param iovs        iovec structures to use.
 * @param addr        Where source address should be saved.
 */
static void
test_init_msghdr(rpc_msghdr *msg, char bufs[][IOV_LEN],
                 struct rpc_iovec iovs[], struct sockaddr_storage *addr)
{
    int i;

    memset(msg, 0, sizeof(*msg));

    msg->msg_name = addr;
    msg->msg_namelen = msg->msg_rnamelen = sizeof(*addr);
    msg->msg_iov = iovs;
    msg->msg_riovlen = msg->msg_iovlen = MAX_IOVS;

    for (i = 0; i < MAX_IOVS; i++)
    {
        iovs[i].iov_base = bufs[i];
        iovs[i].iov_rlen = iovs[i].iov_len = IOV_LEN;
    }
}

/**
 * Initialize rpc_mmsghdr structures for functions like recvmmsg().
 *
 * @param mmsgs       Array of rpc_mmsghdr structures.
 * @param msgs_num    Number of rpc_mmsghdr structures.
 * @param bufs        Buffers to store received data.
 * @param iovs        iovec structures to use.
 * @param addrs       Where source addresses should be saved.
 */
static void
test_init_mmsghdr(struct rpc_mmsghdr *mmsgs, int msgs_num,
                  char bufs[][MAX_IOVS][IOV_LEN],
                  struct rpc_iovec iovs[][MAX_IOVS],
                  struct sockaddr_storage addrs[])
{
    int i;

    if (msgs_num > MAX_MSGS)
        TEST_FAIL("%s(): too many messages are requested", __FUNCTION__);

    for (i = 0; i < msgs_num; i++)
    {
        memset(&mmsgs[i], 0, sizeof(struct rpc_mmsghdr));
        test_init_msghdr(&mmsgs[i].msg_hdr, bufs[i], iovs[i],
                         &addrs[i]);
    }
}

/**
 * Check return value of the receiving function, print verdict and stop
 * testing if it is negative.
 *
 * @param rpcs      RPC server.
 * @param rc        Return value.
 */
static inline void
check_recv_rc(rcf_rpc_server *rpcs, int rc)
{
    if (rc < 0)
    {
        TEST_VERDICT("Receiving function failed with error " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(rpcs));
    }
}

/* See description in udp_multisrc.h */
void
udp_multisrc_create_peers(rcf_rpc_server *pco_iut,
                          rcf_rpc_server *pco_tst1,
                          rcf_rpc_server *pco_tst2,
                          tapi_env_net *net1,
                          tapi_env_net *net2,
                          const struct if_nameindex *tst1_if,
                          const struct if_nameindex *tst2_if,
                          const struct sockaddr *iut_addr1,
                          const struct sockaddr *iut_addr2,
                          const struct sockaddr *tst1_addr,
                          const struct sockaddr *tst2_addr,
                          te_bool diff_addrs, int max_data_len,
                          int *iut_s, udp_multisrc_peer *peers,
                          int peers_num)
{
    rcf_rpc_server *pco_tst;
    const struct sockaddr *tst_addr;
    const struct if_nameindex *tst_if;
    const struct sockaddr *iut_addr;
    cfg_handle net_handle;
    int net_prefix;
    tapi_env_net *net;

    int existing_tst_addrs = 0;
    struct sockaddr *addr_aux = NULL;
    te_bool second_if_first;

    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage iut_conn_addr2;

    int rcvbuf_size;
    int req_rcvbuf_size;
    int i;

    if (pco_tst2 == NULL)
        pco_tst2 = pco_tst1;
    if (net2 == NULL)
        net2 = net1;
    if (tst2_if == NULL)
        tst2_if = tst1_if;
    if (iut_addr2 == NULL)
        iut_addr2 = iut_addr1;
    if (tst2_addr == NULL)
        tst2_addr = tst1_addr;

    if (tst2_addr != tst1_addr)
        existing_tst_addrs = 2;
    else
        existing_tst_addrs = 1;

    for (i = 0; i < peers_num; i++)
    {
        peers[i].s = -1;
    }

    tapi_sockaddr_clone_exact(iut_addr1, &iut_bind_addr);
    if (iut_addr1 != iut_addr2)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    tapi_sockaddr_clone_exact(iut_addr2, &iut_conn_addr2);
    te_sockaddr_set_port(SA(&iut_conn_addr2),
                         te_sockaddr_get_port(iut_addr1));

    *iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, *iut_s, SA(&iut_bind_addr));

    req_rcvbuf_size = peers_num * max_data_len;
    rpc_getsockopt(pco_iut, *iut_s, RPC_SO_RCVBUF, &rcvbuf_size);
    /* Linux reserves 2 times as much space for "bookkeeping overhead" */
    if (rcvbuf_size < req_rcvbuf_size * 2)
    {
        rpc_setsockopt_int(pco_iut, *iut_s, RPC_SO_RCVBUF,
                           req_rcvbuf_size);
    }

    second_if_first = rand_range(0, 1);

    for (i = 0; i < peers_num; i++)
    {
        if (i % 2 == second_if_first)
        {
            pco_tst = pco_tst1;
            tst_addr = tst1_addr;
            tst_if = tst1_if;
            net = net1;
            iut_addr = iut_addr1;
        }
        else
        {
            pco_tst = pco_tst2;
            tst_addr = tst2_addr;
            tst_if = tst2_if;
            net = net2;
            iut_addr = SA(&iut_conn_addr2);
        }

        if (diff_addrs && i > existing_tst_addrs)
        {
            if (iut_addr1->sa_family == AF_INET)
            {
                net_handle = net->ip4net;
                net_prefix = net->ip4pfx;
            }
            else
            {
                net_handle = net->ip6net;
                net_prefix = net->ip6pfx;
            }

            CHECK_RC(tapi_cfg_alloc_net_addr(
                              net_handle, NULL, &addr_aux));
            CHECK_RC(tapi_cfg_base_if_add_net_addr(
                              pco_tst->ta, tst_if->if_name,
                              addr_aux, net_prefix,
                              FALSE, NULL));

            CHECK_RC(tapi_sockaddr_clone(pco_tst, addr_aux,
                                         &peers[i].peer_addr));
            free(addr_aux);
        }
        else
        {
            CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                         &peers[i].peer_addr));
        }

        tapi_rpc_provoke_arp_resolution(pco_iut, SA(&peers[i].peer_addr));
        /* ST-2346: give some time to ICMP message. */
        TAPI_WAIT_NETWORK;

        peers[i].rpcs = pco_tst;
        peers[i].s = rpc_socket(pco_tst,
                                rpc_socket_domain_by_addr(tst_addr),
                                RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, peers[i].s, SA(&peers[i].peer_addr));
        rpc_connect(pco_tst, peers[i].s, iut_addr);
    }
}

/* See description in udp_multisrc.h */
void
udp_multisrc_send_receive(rcf_rpc_server *pco_iut, int iut_s,
                          udp_multisrc_peer *peers,
                          int peers_num, int max_data_len,
                          int recv_func)
{
    test_packet packets[MAX_PEERS];
    int i;
    int j;
    int rc;

    char buf[MAX_IOVS * IOV_LEN];
    char recv_bufs[MAX_MSGS][MAX_IOVS][IOV_LEN];
    struct rpc_iovec recv_iovs[MAX_MSGS][MAX_IOVS];
    struct sockaddr_storage recv_addrs[MAX_MSGS];
    socklen_t addr_len;

    te_bool readable;
    te_bool missed_packet = FALSE;
    te_bool reordering = FALSE;

    if (peers_num > MAX_PEERS)
        TEST_FAIL("peers_num parameter is too big, adjust MAX_PEERS");

    if (max_data_len > MAX_PAYLOAD_LEN)
    {
        TEST_FAIL("max_data_len parameter has too big value, "
                  "adjust MAX_PAYLOAD_LEN in the test");
    }

    for (i = 0; i < peers_num; i++)
    {
        memset(&packets[i], 0, sizeof(test_packet));
        packets[i].received = -1;
        packets[i].len = rand_range(1, max_data_len);
        te_fill_buf(packets[i].buf, packets[i].len);
        peers[i].packet = &packets[i];

        RPC_SEND(rc, peers[i].rpcs, peers[i].s, packets[i].buf,
                 packets[i].len, 0);
        TAPI_WAIT_NETWORK;
    }

    i = 0;
    while (TRUE)
    {
        RPC_GET_READABILITY(readable, pco_iut, iut_s,
                            TAPI_WAIT_NETWORK_DELAY);
        if (!readable)
            break;
        if (i >= peers_num)
        {
            TEST_VERDICT("Socket is readable after receiving "
                         "all the expected messages");
        }

        switch (recv_func)
        {
            case SOCKTS_RECVF_READ:
            case SOCKTS_RECVF_READV:
            case SOCKTS_RECVF_RECV:

                RPC_AWAIT_ERROR(pco_iut);
                if (recv_func == SOCKTS_RECVF_READ)
                {
                    rc = rpc_read(pco_iut, iut_s, buf, sizeof(buf));
                }
                else if (recv_func == SOCKTS_RECVF_READV)
                {
                    rc = rpc_recv_func_readv(pco_iut, iut_s, buf,
                                             sizeof(buf), 0);
                }
                else
                {
                    rc = rpc_recv(pco_iut, iut_s, buf, sizeof(buf), 0);
                }

                check_recv_rc(pco_iut, rc);
                check_received_packet(buf, rc, NULL, 0,
                                      peers, peers_num, i);

                break;

            case SOCKTS_RECVF_RECVFROM:

                addr_len = sizeof(recv_addrs[0]);
                RPC_AWAIT_ERROR(pco_iut);
                rc = rpc_recvfrom(pco_iut, iut_s, buf, sizeof(buf), 0,
                                  SA(&recv_addrs[0]), &addr_len);
                check_recv_rc(pco_iut, rc);
                check_received_packet(buf, rc, SA(&recv_addrs[0]), addr_len,
                                      peers, peers_num, i);
                break;

            case SOCKTS_RECVF_RECVMSG:
            case SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_ZC:
            case SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_COPY:
                {
                    rpc_msghdr msg;

                    test_init_msghdr(&msg, recv_bufs[0], recv_iovs[0],
                                     &recv_addrs[0]);

                    RPC_AWAIT_ERROR(pco_iut);
                    if (recv_func == SOCKTS_RECVF_RECVMSG)
                    {
                        rc = rpc_recvmsg(pco_iut, iut_s, &msg, 0);
                    }
                    else if (recv_func ==
                                    SOCKTS_RECVF_ONLOAD_ZC_HLRX_RECV_ZC)
                    {
                        rc = rpc_simple_hlrx_recv_zc(pco_iut, iut_s, &msg,
                                                     0, TRUE);
                    }
                    else
                    {
                        rc = rpc_simple_hlrx_recv_copy(pco_iut, iut_s, &msg,
                                                       0, TRUE);
                    }
                    check_recv_rc(pco_iut, rc);

                    iovecs_to_buf(msg.msg_iov, msg.msg_iovlen,
                                  buf, sizeof(buf));
                    check_received_packet(buf, rc, msg.msg_name,
                                          msg.msg_namelen,
                                          peers, peers_num, i);

                    break;
                }

            case SOCKTS_RECVF_RECVMMSG:
            case SOCKTS_RECVF_ONLOAD_ZC_RECV:
                {
                    struct rpc_mmsghdr mmsgs[MAX_MSGS];
                    rpc_msghdr *msg;
                    int msgs_num;

                    msgs_num = rand_range(1, MAX_MSGS);

                    test_init_mmsghdr(mmsgs, msgs_num, recv_bufs, recv_iovs,
                                      recv_addrs);

                    RPC_AWAIT_ERROR(pco_iut);
                    if (recv_func == SOCKTS_RECVF_RECVMMSG)
                    {
                        /*
                         * If MSG_DONTWAIT is not used, this function hangs
                         * until all the requested messages are got, which
                         * is not desirable here.
                         */
                        rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsgs,
                                              msgs_num, RPC_MSG_DONTWAIT,
                                              NULL);
                    }
                    else
                    {
                        rc = rpc_simple_zc_recv_gen_mmsg(pco_iut, iut_s,
                                                         mmsgs, msgs_num,
                                                         NULL, 0, NULL,
                                                         TRUE);
                    }
                    check_recv_rc(pco_iut, rc);
                    if (rc == 0)
                    {
                        TEST_VERDICT("IUT socket is readable but no "
                                     "messages is received");
                    }

                    for (j = 0; j < rc; j++)
                    {
                        msg = &mmsgs[j].msg_hdr;

                        iovecs_to_buf(msg->msg_iov,
                                      msg->msg_iovlen,
                                      buf, sizeof(buf));
                        check_received_packet(buf, mmsgs[j].msg_len,
                                              msg->msg_name,
                                              msg->msg_namelen,
                                              peers, peers_num, i + j);
                    }
                    i = i + rc - 1;

                    break;
                }

            default:

                TEST_FAIL("Unsupported recv_func value");
        }

        i++;
    }

    j = -1;
    for (i = 0; i < peers_num; i++)
    {
        if (packets[i].received < 0)
            missed_packet = TRUE;
        else if (packets[i].received < j)
            reordering = TRUE;

        j = packets[i].received;
    }

    if (missed_packet)
        ERROR_VERDICT("Not all the packets were received");
    if (reordering)
        ERROR_VERDICT("Some packets were received out of order");
    if (missed_packet || reordering)
        TEST_STOP;
}
