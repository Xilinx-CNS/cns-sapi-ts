/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "mcast_lib.h"

/** Maximum number of packets to capture */
#define MAX_PACKET_NUM 100

/**
 * Callback function to proceed received packets.
 *
 * @param pkt       Pointer to packet received
 * @param userdata  Listener pointer
 */
static void
mcast_callback(const tapi_ip4_packet_t *pkt, void *userdata)
{
    mcast_listener_t listener = (mcast_listener_t)userdata;

    if ((!listener->use_src || pkt->src_addr == listener->src_addr) &&
        pkt->dst_addr == listener->dst_addr)
    {
        listener->packets_received++;
    }
}

/* Description in mcast_lib.h */
mcast_listener_t
mcast_listener_init(rcf_rpc_server *rpcs,
                    const struct if_nameindex *interface,
                    const struct sockaddr *dst_addr,
                    const struct sockaddr *src_addr,
                    int in)
{
    mcast_listener_t listener;

    assert(rpcs != NULL);
    assert(interface != NULL);
    assert(dst_addr != NULL);

    listener = calloc(1, sizeof(struct mcast_listener_struct));

    if (src_addr != NULL)
    {
        memcpy(&listener->src_addr, te_sockaddr_get_netaddr(src_addr),
               sizeof(listener->src_addr));
        listener->use_src = 1;
    }
    else
        listener->use_src = 0;
    memcpy(&listener->dst_addr, te_sockaddr_get_netaddr(dst_addr),
           sizeof(listener->dst_addr));
    if (tapi_ip4_eth_csap_create(rpcs->ta, 0, interface->if_name,
                                 (in) ?
                                    TAD_ETH_RECV_DEF |
                                    TAD_ETH_RECV_NO_PROMISC :
                                    TAD_ETH_RECV_OUT,
                                 NULL, NULL,
                                 SIN(dst_addr)->sin_addr.s_addr,
                                 (src_addr != NULL) ?
                                    SIN(src_addr)->sin_addr.s_addr :
                                    htonl(INADDR_ANY),
                                 IPPROTO_UDP,
                                 &listener->listener_handle) != 0)
        TEST_FAIL("Fail to create CSAP.");
    return listener;
}

/* Description in mcast_lib.h */
void
mcast_listen_start(rcf_rpc_server *rpcs, mcast_listener_t listener)
{
    assert(listener != NULL &&
           listener->listener_handle != CSAP_INVALID_HANDLE);
    if (tapi_tad_trrecv_start(rpcs->ta, 0, listener->listener_handle,
                              NULL, TAD_TIMEOUT_INF, MAX_PACKET_NUM,
                              RCF_TRRECV_PACKETS) != 0)
        TEST_FAIL("Fail to start recieving operation on CSAP.");
    return;
}

/* Description in mcast_lib.h */
int
mcast_listen_stop(rcf_rpc_server *rpcs, mcast_listener_t listener,
                  tapi_tad_trrecv_cb_data *cb_data)
{
    assert(listener != NULL &&
           listener->listener_handle != CSAP_INVALID_HANDLE);

    listener->packets_received = 0;
    if (tapi_tad_trrecv_stop(rpcs->ta, 0, listener->listener_handle,
                             (cb_data == NULL) ?
                                tapi_ip4_eth_trrecv_cb_data(mcast_callback,
                                                            listener) :
                                cb_data, NULL) < 0)
        TEST_FAIL("Multicast listener CSAP stopping failed");
    return listener->packets_received;
}

/* Description in mcast_lib.h */
void
mcast_listener_fini(rcf_rpc_server *rpcs, mcast_listener_t listener)
{
    if (listener == NULL ||
        listener->listener_handle == CSAP_INVALID_HANDLE)
        return;

    tapi_tad_csap_destroy(rpcs->ta, 0, listener->listener_handle);
    free(listener);

    return;
}

/* Description in mcast_lib.h */
int
create_joined_socket(rcf_rpc_server *rpcs,
                     const struct if_nameindex *iface,
                     const struct sockaddr *bind_addr,
                     const struct sockaddr *mcast_addr,
                     tarpc_joining_method method)
{
    return create_joined_socket_ext(SOCKTS_SOCK_FUNC_SOCKET,
                                    rpcs, iface,
                                    bind_addr, mcast_addr,
                                    method);
}

/* Description in mcast_lib.h */
int
create_joined_socket_ext(sockts_socket_func sock_func,
                         rcf_rpc_server *rpcs,
                         const struct if_nameindex *iface,
                         const struct sockaddr *bind_addr,
                         const struct sockaddr *mcast_addr,
                         tarpc_joining_method method)
{
    int sock;
    int opt_val = 1;

    sock = sockts_socket(sock_func, rpcs,
                         rpc_socket_domain_by_addr(mcast_addr),
                         RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_setsockopt(rpcs, sock, RPC_SO_REUSEADDR, &opt_val);

    rpc_bind(rpcs, sock, bind_addr);
    rpc_mcast_join(rpcs, sock, mcast_addr, iface->if_index, method);

    return sock;
}

/* Description in mcast_lib.h */
int
read_check_pkt(rcf_rpc_server *rpcs, int sock, char *sendbuf, int buflen)
{
    te_bool readable;
    int     rc;
    char   *recvbuf;

    RPC_GET_READABILITY(readable, rpcs, sock, 0);
    if (readable)
    {
        recvbuf = te_make_buf_by_len(buflen * 2);

        rc = rpc_recv(rpcs, sock, recvbuf, buflen * 2, 0);
        if (rc != buflen)
            TEST_VERDICT("Received packet has unexpected length");
        if (memcmp(sendbuf, recvbuf, rc) != 0)
            TEST_VERDICT("Received packet has corrupted data");

        free(recvbuf);
    }

    return readable;
}

/* Description in mcast_lib.h */
void
cmp_exp_results(cmp_results_type *res, const char *receiver)
{
    if (res->got == res->exp)
        return;

    if (res->exp)
        RING_VERDICT("%s didn't get packet", receiver);
    else
        RING_VERDICT("%s got packet", receiver);
}

/* Description in mcast_lib.h */
te_bool
check_mcast_hash_collision_create_sock(rcf_rpc_server *rpcs_iut,
                                       rcf_rpc_server *rpcs_tst,
                                       const struct if_nameindex *interface,
                                       const struct sockaddr *tst_addr,
                                       const struct sockaddr *mcast_addr)
{
    te_bool              detected = FALSE;
    struct tarpc_mreqn   mreq;
    int                  sock;

    sock = rpc_socket(rpcs_tst, rpc_socket_domain_by_addr(mcast_addr),
                      RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;

    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(struct in_addr));
    rpc_setsockopt(rpcs_tst, sock, RPC_IP_MULTICAST_IF, &mreq);

    detected = check_mcast_hash_collision(rpcs_iut, rpcs_tst, interface,
                                          sock, mcast_addr);

    rpc_close(rpcs_tst, sock);

    return detected;
}


/* Description in mcast_lib.h */
te_bool
check_mcast_hash_collision(rcf_rpc_server *rpcs_iut, rcf_rpc_server *rpcs_tst,
                           const struct if_nameindex *interface, int sock,
                           const struct sockaddr *mcast_addr)
{
    mcast_listener_t listener = CSAP_INVALID_HANDLE;
    char            *tx_buf = NULL;
    size_t           buf_len;
    int              send_len;
    int              rc;
    te_bool          detected = FALSE;

    tx_buf = sockts_make_buf_dgram(&buf_len);

    listener = mcast_listener_init(rpcs_iut, interface, mcast_addr,
                                   NULL, 1);
    mcast_listen_start(rpcs_iut, listener);

    TAPI_WAIT_NETWORK;

    send_len = rpc_sendto(rpcs_tst, sock, tx_buf, buf_len, 0, mcast_addr);
    if (send_len != (int)buf_len)
    {
        mcast_listener_fini(rpcs_iut, listener);
        TEST_FAIL("send() returned %d instead %u", send_len, buf_len);
    }

    TAPI_WAIT_NETWORK;

    rc = mcast_listen_stop(rpcs_iut, listener, NULL);
    if (rc > 0)
    {
        RING_VERDICT("Multicast hash collision was detected");
        detected = TRUE;
    }

    mcast_listener_fini(rpcs_iut, listener);
    free(tx_buf);

    return detected;
}
