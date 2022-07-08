/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "reuseport.h"

/**
 * Maximum attempts number trying to establish connection with all listeners
 * in the cluster.
 */
#define REUSEPORT_MAX_ATTEMPTS 20

/* See description in reuseport.h */
void
reuseport_connection(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                     rpc_socket_type sock_type,
                     const struct sockaddr *iut_addr,
                     const struct sockaddr *tst_addr,
                     te_bool set_reuseport, te_bool set_reuseport_tst,
                     int *iut_s, int *tst_s)
{
    int acc_s;

    *iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);
    *tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        sock_type, RPC_PROTO_DEF);

    if (set_reuseport)
        rpc_setsockopt_int(pco_iut, *iut_s, RPC_SO_REUSEPORT, 1);

    if (set_reuseport_tst)
        rpc_setsockopt_int(pco_tst, *tst_s, RPC_SO_REUSEPORT, 1);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_bind(pco_iut, *iut_s, iut_addr) != 0)
        TEST_VERDICT("bind() failed with %r", RPC_ERRNO(pco_iut));

    rpc_bind(pco_tst, *tst_s, tst_addr);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        rpc_connect(pco_iut, *iut_s, tst_addr);
        rpc_connect(pco_tst, *tst_s, iut_addr);
        return;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_listen(pco_iut, *iut_s, 1) != 0)
        TEST_VERDICT("listen() failed with %r", RPC_ERRNO(pco_iut));

    rpc_connect(pco_tst, *tst_s, iut_addr);

    acc_s = rpc_accept(pco_iut, *iut_s, NULL, 0);
    RPC_CLOSE(pco_iut, *iut_s);
    *iut_s = acc_s;
}

/* See description in reuseport.h */
void
reuseport_close_sockets(reuseport_socket_ctx *s, te_bool cleanup)
{
    int result = 0;

    if (s == NULL || s->iut_s == 0 || s->pco_iut == NULL)
        return;

    if (cleanup)
    {
        CLEANUP_RPC_CLOSE(s->pco_iut, s->iut_s);
        CLEANUP_RPC_CLOSE(s->pco_iut, s->iut_acc);
        CLEANUP_RPC_CLOSE(s->pco_tst, s->tst_s);

        if (result != 0)
            TEST_STOP;
    }
    else
    {
        if (s->iut_s >= 0)
            RPC_CLOSE(s->pco_iut, s->iut_s);

        if (s->iut_acc >= 0)
            RPC_CLOSE(s->pco_iut, s->iut_acc);

        if (s->tst_s >= 0)
            RPC_CLOSE(s->pco_tst, s->tst_s);
    }
}

/* See description in reuseport.h */
void
reuseport_close_pair(reuseport_socket_ctx *s1, reuseport_socket_ctx *s2)
{
    reuseport_close_sockets(s1, TRUE);
    reuseport_close_sockets(s2, TRUE);
}

/* See description in reuseport.h */
int
reuseport_try_accept(rcf_rpc_server *pco_iut, int sock)
{
    int acc_s;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    acc_s = rpc_accept(pco_iut, sock, NULL, 0);
    if (acc_s < 0)
    {
        if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_VERDICT("accept() failed with unexpected errno %r",
                         RPC_ERRNO(pco_iut));
        return -1;
    }
    
    return acc_s;
}

/* See description in reuseport.h */
void
reuseport_close_tcp_conn(reuseport_socket_ctx *s)
{
    if (s->iut_acc >= 0 && s->tst_s >= 0)
    {
        char buf[1];

        /* Close connection avoiding IUT socket in TIME_WAIT state.*/
        s->pco_iut->op = RCF_RPC_CALL;
        rpc_read(s->pco_iut, s->iut_acc, buf, sizeof(buf));

        RPC_CLOSE(s->pco_tst, s->tst_s);
        if (rpc_read(s->pco_iut, s->iut_acc, buf, sizeof(buf)) != 0)
            TEST_VERDICT("read() returned non-zero value when peer "
                         "socket was closed");
        RPC_CLOSE(s->pco_iut, s->iut_acc);
    }
    else
    {
        if (s->tst_s >= 0)
            RPC_CLOSE(s->pco_tst, s->tst_s);

        if (s->iut_acc >= 0)
            RPC_CLOSE(s->pco_iut, s->iut_acc);
    }
}

/* See description in reuseport.h */
te_bool
reuseport_try_accept_pair(reuseport_socket_ctx *s, int tst_s)
{
    int acc;

    if ((acc = reuseport_try_accept(s->pco_iut, s->iut_s)) >= 0)
    {
        reuseport_close_tcp_conn(s);

        s->iut_acc = acc;
        s->tst_s = tst_s;
        return TRUE;
    }

    return FALSE;
}

/* See description in reuseport.h */
void
try_connect_pair(reuseport_socket_ctx *s1, reuseport_socket_ctx *s2)
{
    const struct sockaddr *i_addr = s1->iut_addr;
    rcf_rpc_server        *pco_tst = s1->pco_tst;
    struct sockaddr        t_addr;
    te_bool                changed = FALSE;
    te_bool                readable = FALSE;

    int tst_s;
    int i;
    int j;

    memcpy(&t_addr, s1->tst_addr, sizeof(t_addr));

    for (i = 0; i < REUSEPORT_MAX_ATTEMPTS; i++)
    {
        if (i > 0 && !changed)
        {
            memcpy(&t_addr, s2->tst_addr, sizeof(t_addr));
            i_addr = s2->iut_addr;
            pco_tst = s2->pco_tst;
            changed = TRUE;
        }

        TAPI_SET_NEW_PORT(pco_tst, &t_addr);
        tst_s = reuseport_create_bind_socket(pco_tst, RPC_SOCK_STREAM,
                                             &t_addr, FALSE);

        RPC_AWAIT_IUT_ERROR(pco_tst);
        if (rpc_connect(pco_tst, tst_s, i_addr) != 0)
            TEST_VERDICT("connect() failed on tester with %r",
                         RPC_ERRNO(pco_tst));

        for (j = 0; j < TAPI_WAIT_NETWORK_DELAY / 2; j++)
        {
            s1->pco_iut->silent = TRUE;
            RPC_GET_READABILITY(readable, s1->pco_iut, s1->iut_s, 1);
            if (readable)
            {
                if (!reuseport_try_accept_pair(s1, tst_s))
                    TEST_VERDICT("Failed to accept connection on a reable "
                                 "listener");
                break;
            }

            s2->pco_iut->silent = TRUE;
            RPC_GET_READABILITY(readable, s2->pco_iut, s2->iut_s, 1);
            if (readable)
            {
                if (!reuseport_try_accept_pair(s2, tst_s))
                    TEST_VERDICT("Failed to accept connection on a reable "
                                 "listener");
                break;
            }
        }

        if (s1->iut_acc >= 0 && s2->iut_acc >= 0)
            return;

        if (!readable)
            TEST_VERDICT("Connection request was lost");
    }

    RING("Accepted connections number: first socket %d, second socket %d",
         s1->count, s2->count);
    TEST_VERDICT("Failed to establish connections on both socket pairs");
}

/**
 * Update UDP Tester socket in a given socket pair context.
 * Current Tester socket is closed and replaced with a new one
 * as a result.
 *
 * @param ctx           Reuseport socket context.
 * @param tst_s         New Tester socket.
 * @param new_addr      Address to which new socket is bound.
 * @param connect_iut   If @c TRUE, connect IUT socket to the
 *                      @p new_addr.
 */
static void
update_udp_tst_socket(reuseport_socket_ctx *ctx, int tst_s,
                      struct sockaddr_storage *new_addr,
                      te_bool connect_iut)
{
    char buf[SOCKTS_MSG_DGRAM_MAX];

    rpc_recv(ctx->pco_iut, ctx->iut_s, buf, sizeof(buf), 0);

    if (ctx->tst_s >= 0)
        RPC_CLOSE(ctx->pco_tst, ctx->tst_s);

    ctx->tst_s = tst_s;
    memcpy(&ctx->new_tst_addr, new_addr,
           sizeof(struct sockaddr_storage));
    ctx->tst_addr = SA(&ctx->new_tst_addr);

    rpc_connect(ctx->pco_tst, ctx->tst_s, ctx->iut_addr);
    if (connect_iut)
        rpc_connect(ctx->pco_iut, ctx->iut_s, ctx->tst_addr);
}

/* See description in reuseport.h */
void
try_connect_udp_pair(const struct if_nameindex *tst_if,
                     tapi_env_net *net,
                     reuseport_socket_ctx *s1, reuseport_socket_ctx *s2,
                     te_bool connect_iut)
{
    int                       i;
    int                       j;
    int                       tst_s;
    struct sockaddr_storage   new_addr;
    char                      buf[SOCKTS_MSG_DGRAM_MAX];
    te_bool                   readable1 = FALSE;
    te_bool                   readable2 = FALSE;

    for (i = 0; i < REUSEPORT_MAX_ATTEMPTS; i++)
    {
        tst_s = reuseport_create_tst_udp_sock(s1->pco_tst,
                                              tst_if, net,
                                              &new_addr, NULL);

        tapi_rpc_provoke_arp_resolution(s1->pco_iut, SA(&new_addr));

        rpc_connect(s1->pco_tst, tst_s, s1->iut_addr);

        rpc_send(s1->pco_tst, tst_s, buf, sizeof(buf), 0);

        for (j = 0; j < TAPI_WAIT_NETWORK_DELAY; j++)
        {
            usleep(1000);
            s1->pco_iut->silent = TRUE;
            RPC_GET_READABILITY(readable1, s1->pco_iut, s1->iut_s, 0);
            if (readable1)
            {
                update_udp_tst_socket(s1, tst_s, &new_addr,
                                      connect_iut);
            }
            s2->pco_iut->silent = TRUE;
            RPC_GET_READABILITY(readable2, s2->pco_iut, s2->iut_s, 0);
            if (readable2)
            {
                if (readable1)
                    TEST_VERDICT("Both UDP socket on IUT "
                                 "received a packet");
                update_udp_tst_socket(s2, tst_s, &new_addr,
                                      connect_iut);
            }

            if (readable1 || readable2)
                break;
        }
        if (!(readable1 || readable2))
            TEST_VERDICT("None of the two IUT UDP sockets "
                         "received a packet");

        if (s1->tst_s >= 0 && s2->tst_s >= 0)
            break;
    }

    if (!(s1->tst_s >= 0 && s2->tst_s >= 0))
        TEST_VERDICT("Failed to create a pair of UDP sockets on Tester "
                     "corresponding to a pair of IUT sockets");
}

/* See description in reuseport.h */
void
reuseport_pair_connection(rpc_socket_type sock_type,
                          reuseport_socket_ctx *s1,
                          reuseport_socket_ctx *s2)
{
    s1->iut_s = reuseport_create_bind_socket(s1->pco_iut, sock_type,
                                             s1->iut_addr_bind, TRUE);
    s2->iut_s = reuseport_create_bind_socket(s2->pco_iut, sock_type,
                                             s2->iut_addr_bind, TRUE);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        s1->tst_s = reuseport_create_bind_socket(s1->pco_tst, sock_type,
                                                 s1->tst_addr, FALSE);
        rpc_connect(s1->pco_iut, s1->iut_s, s1->tst_addr);
        rpc_connect(s1->pco_tst, s1->tst_s, s1->iut_addr);

        s2->tst_s = reuseport_create_bind_socket(s2->pco_tst, sock_type,
                                                 s2->tst_addr, FALSE);
        rpc_connect(s2->pco_iut, s2->iut_s, s2->tst_addr);
        rpc_connect(s2->pco_tst, s2->tst_s, s2->iut_addr);
        s1->iut_acc = s1->iut_s;
        s2->iut_acc = s2->iut_s;

        return;
    }

    rpc_listen(s1->pco_iut, s1->iut_s, 1);
    rpc_listen(s2->pco_iut, s2->iut_s, 1);
    rpc_fcntl(s1->pco_iut, s1->iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);
    rpc_fcntl(s2->pco_iut, s2->iut_s, RPC_F_SETFL, RPC_O_NONBLOCK);

    try_connect_pair(s1, s2);
}

/* See description in reuseport.h */
void
reuseport_pair_connection2(rpc_socket_type sock_type,
                           const struct if_nameindex *tst_if,
                           tapi_env_net *net,
                           reuseport_socket_ctx *s1,
                           reuseport_socket_ctx *s2,
                           te_bool connect_iut)
{
    if (sock_type == RPC_SOCK_STREAM)
    {
        reuseport_pair_connection(RPC_SOCK_STREAM, s1, s2);
    }
    else
    {
        s1->iut_s = reuseport_create_bind_socket(s1->pco_iut, sock_type,
                                                 s1->iut_addr_bind, TRUE);
        s2->iut_s = reuseport_create_bind_socket(s2->pco_iut, sock_type,
                                                 s2->iut_addr_bind, TRUE);
        try_connect_udp_pair(tst_if, net, s1, s2, connect_iut);
    }
}

/* See description in reuseport.h */
void
init_aux_rpcs(rcf_rpc_server *parent, rcf_rpc_server **child,
              thread_process_type thread_process)
{
    static int num = 0;
    char name[30] = {0,};

    num++;
    snprintf(name, sizeof(name), "iut_child%d", num);

    switch (thread_process)
    {
        case TP_NONE:
            *child = parent;
            break;

        case TP_THREAD:
            CHECK_RC(rcf_rpc_server_thread_create(parent, name, child));
            break;

        case TP_PROCESS:
            CHECK_RC(rcf_rpc_server_fork_exec(parent, name, child));
            break;

        default:
            TEST_FAIL("Unexpected value of argument thread_process");
    }
}

/* See description in reuseport.h */
int
reuseport_create_tst_udp_sock_gen(rcf_rpc_server *rpcs,
                                  const struct if_nameindex *if_idx,
                                  tapi_env_net *net,
                                  struct sockaddr_storage *new_addr,
                                  cfg_handle *addr_handle,
                                  te_bool any_port)
{
    struct sockaddr   *addr = NULL;
    int                sock;

    CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &addr, NULL));
    if (any_port)
    {
        te_sockaddr_set_port(addr, 0);
    }
    else
    {
        CHECK_RC(tapi_allocate_port_htons(rpcs,
                                          te_sockaddr_get_port_ptr(addr)));
    }

    CHECK_RC(tapi_cfg_base_if_add_net_addr(rpcs->ta, if_idx->if_name,
                                               addr, net->ip4pfx,
                                               FALSE, addr_handle));
    sock = rpc_socket(rpcs, rpc_socket_domain_by_addr(addr),
                      RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(rpcs, sock, addr);

    if (new_addr != NULL)
        tapi_sockaddr_clone_exact(addr, new_addr);
    free(addr);

    return sock;
}


/* See description in reuseport.h */
void
reuseport_fix_connection(rpc_tcp_state state, tapi_route_gateway *gateway)
{
    switch (state)
    {
        case RPC_TCP_CLOSING:
        case RPC_TCP_FIN_WAIT1:
        case RPC_TCP_LAST_ACK:
            CHECK_RC(tapi_route_gateway_repair_gw_tst(gateway));
            CFG_WAIT_CHANGES;
            break;

        default:
            ;
    }
}

/* See description in reuseport.h */
void
reuseport_check_sockets_closing(rcf_rpc_server *pco_iut,
                                const struct sockaddr *iut_addr,
                                const struct sockaddr *tst_addr,
                                te_bool destroyed)
{
    te_bool res;

    res = sockts_socket_is_closed(pco_iut, iut_addr, tst_addr, TRUE,
                                  TRUE);
    if (res != destroyed)
        TEST_VERDICT("Socket %s", destroyed ? "is alive" : "was destroyed");
}

/* See description in reuseport.h */
void
reuseport_close_state_prepare(tapi_route_gateway *gateway,
                              rpc_tcp_state state, reuseport_socket_ctx *s1,
                              reuseport_socket_ctx *s2)
{
    switch (state)
    {
        case RPC_TCP_CLOSING:
        case RPC_TCP_FIN_WAIT1:
            CHECK_RC(tapi_route_gateway_break_gw_tst(gateway));
            CFG_WAIT_CHANGES;
            break;

        case RPC_TCP_LAST_ACK:
            if (s1 != NULL)
                RPC_CLOSE(s1->pco_tst, s1->tst_s);
            if (s2 != NULL)
                RPC_CLOSE(s2->pco_tst, s2->tst_s);
            TAPI_WAIT_NETWORK;
            CHECK_RC(tapi_route_gateway_break_gw_tst(gateway));
            CFG_WAIT_CHANGES;
            break;

        case RPC_TCP_FIN_WAIT2:
        case RPC_TCP_TIME_WAIT:
            break;

        default:
            TEST_FAIL("Unexpected value of test parameter state: %s",
                      tcp_state_rpc2str(state));
    }
}

/* See description in reuseport.h */
void
reuseport_close_state_finish(rpc_tcp_state state, reuseport_socket_ctx *s1,
                             reuseport_socket_ctx *s2)
{
    switch (state)
    {
        case RPC_TCP_TIME_WAIT:
            if (s1 != NULL)
                RPC_CLOSE(s1->pco_tst, s1->tst_s);
            if (s2 != NULL)
                RPC_CLOSE(s2->pco_tst, s2->tst_s);
            TAPI_WAIT_NETWORK;
            break;

        case RPC_TCP_CLOSING:
            if (s1 != NULL)
                RPC_CLOSE(s1->pco_tst, s1->tst_s);
            if (s2 != NULL)
                RPC_CLOSE(s2->pco_tst, s2->tst_s);
            TAPI_WAIT_NETWORK;
            break;

        default:
            ;
    }
}
