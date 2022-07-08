/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-conn_two_socks_same_addr Connect two sockets joined to multicasting group to the same address
 *
 * @objective Test whether two sockets bound to full mulicast address
 *            or its port and joined to corresponding multicasting group will
 *            receive multicasting packets from peer to which address they
 *            were connected.
 *
 * @type Conformance.
 *
 *
 * @param pco_iut           PCO on IUT
 * @param iut_if            Interface on IUT
 * @param pco_tst           PCO on TESTER
 * @param tst_addr          Address on TESTER
 * @param mcast_addr        Multicast address
 * @param data_len          Length of data to be sent
 * @param join_method       Multicast group joining method
 * @param call_exec         Whether to call @b exec() after @b fork()
 * @param loc_wildcard      Whether to bind IUT sockets to wildcard
 *                          address with port of multicast group
 *                          address, or just to multicast group address
 * @param use_zc            Use @b onload_zc_recv() instead of @b recv()
 *                          on IUT
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 * -# Create @p iut_s1 socket on @p pco_iut, @b bind() it to address
 *    determined according to @p loc_wildcard, connect it to @p tst_addr.
 * -# Create new IUT RPC server @p pco_iut2 with help of @b fork(), and
 *    call exec() in this child server if @p call_exec is set.
 * -# Create @p iut_s2 socket on @p pco_iut2, @b bind() it and @b
 *    connect() to the same addresses as @p iut_s1 socket.
 * -# Join both sockets to multicasting group with address @p mcast_addr.
 * -# Create @p tst_s socket on @p pco_tst, @b bind() it to @p tst_addr
 *    address.
 * -# @b send() @p data_len bytes from @p tst_s to @p mcast_addr.
 * -# Check that both IUT sockets received correct amount of data.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/conn_two_socks_same_addr"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define BIND_CONNECT(pco_, s_, bind_addr_, conn_addr_) \
    do {                                                        \
        int opt_val = 1;                                        \
        rpc_setsockopt(pco_, s_, RPC_SO_REUSEADDR, &opt_val);   \
        rpc_bind(pco_, s_, bind_addr_);                         \
        rpc_connect(pco_, s_, conn_addr_);                      \
    } while (0)

#define RECEIVE_CHECK(pco_, s_) \
    do {                                                            \
        int     tot_len = 0;                                        \
        te_bool detected = FALSE;                                   \
                                                                    \
        rc = 0;                                                     \
        do {                                                        \
            tot_len += rc;                                          \
            RPC_AWAIT_IUT_ERROR(pco_);                              \
            if (!use_zc)                                            \
                rc = rpc_recv(pco_, s_, recvbuf,                    \
                              data_len, RPC_MSG_DONTWAIT);          \
            else                                                    \
                RECV_VIA_ZC(pco_, s_, recvbuf, data_len,            \
                            RPC_MSG_DONTWAIT, NULL, NULL,           \
                            !detected, &detected, FALSE,            \
                            "Multicasting packets were detected "   \
                            "on IUT interface");                    \
        } while (rc != -1);                                         \
                                                                    \
        if (RPC_ERRNO(pco_) != RPC_EAGAIN)                          \
        {                                                           \
            is_failed = TRUE;                                       \
            RING_VERDICT("On socket %s recv() returned %s "         \
                         "error", #s_,                              \
                         errno_rpc2str(RPC_ERRNO(pco_)));           \
        }                                                           \
                                                                    \
        if (tot_len != data_len)                                    \
        {                                                           \
            is_failed = TRUE;                                       \
            RING_VERDICT("Socket %s received %d instead of %d "     \
                         "bytes", #s_, tot_len, data_len);          \
        }                                                           \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_iut2 = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct sockaddr      *mcast_addr = NULL;
    struct sockaddr             bind_addr;
    struct sockaddr             sock_name;
    socklen_t                   name_len = sizeof(sock_name);
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;

    te_bool                     call_exec = FALSE;
    te_bool                     loc_wildcard = FALSE;
    te_bool                     use_zc = FALSE;
    te_bool                     is_failed = FALSE;
    int                         iut_s1 = -1;
    int                         iut_s2 = -1;
    int                         tst_s = -1;
    tarpc_joining_method        join_method;
    mcast_listener_t            listener = NULL;
    int                         data_len;
    char                       *sendbuf;
    char                       *recvbuf;

    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, mcast_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_BOOL_PARAM(call_exec);
    TEST_GET_BOOL_PARAM(loc_wildcard);
    TEST_GET_MCAST_METHOD(join_method);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = malloc(data_len));

    memcpy(&bind_addr, mcast_addr, sizeof(bind_addr));

    if (loc_wildcard)
        te_sockaddr_set_wildcard(&bind_addr);

    iut_s1 = sockts_socket(sock_func, pco_iut,
                           rpc_socket_domain_by_addr(mcast_addr),
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    BIND_CONNECT(pco_iut, iut_s1, &bind_addr, tst_addr);

    rpc_getsockname(pco_iut, iut_s1, &sock_name, &name_len);
    if (te_sockaddrcmp(&bind_addr, sizeof(bind_addr),
                       &sock_name, sizeof(sock_name)) != 0)
        RING_VERDICT("connect() replaced address to which "
                     "iut_s1 socket was bound");

    if (call_exec)
        rcf_rpc_server_fork_exec(pco_iut, "IUT_child_proc_1", &pco_iut2);
    else
        rcf_rpc_server_fork(pco_iut, "IUT_child_proc_1", &pco_iut2);

    iut_s2 = sockts_socket(sock_func, pco_iut2,
                           rpc_socket_domain_by_addr(mcast_addr),
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    BIND_CONNECT(pco_iut2, iut_s2, &bind_addr, tst_addr);

    rpc_getsockname(pco_iut2, iut_s2, &sock_name, &name_len);
    if (te_sockaddrcmp(&bind_addr, sizeof(bind_addr),
                       &sock_name, sizeof(sock_name)) != 0)
        RING_VERDICT("connect() replaced address to which "
                     "iut_s2 socket was bound");

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if,
                                           tst_addr, mcast_addr);

    if (rpc_mcast_join(pco_iut, iut_s1, mcast_addr, iut_if->if_index,
                       join_method) != 0)
        TEST_FAIL("Cannot join multicast group");

    if (rpc_mcast_join(pco_iut2, iut_s2, mcast_addr, iut_if->if_index,
                       join_method) != 0)
        TEST_FAIL("Cannot join multicast group");

    if (!use_zc)
    {
        listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                       NULL, 1);
        mcast_listen_start(pco_iut, listener);
        /* Make sure that CSAP really started */
        TAPI_WAIT_NETWORK;
    }

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_sendto(pco_tst, tst_s, sendbuf, data_len, 0, mcast_addr);

    TAPI_WAIT_NETWORK;
    
    RECEIVE_CHECK(pco_iut, iut_s1);
    RECEIVE_CHECK(pco_iut2, iut_s2);

    if (!use_zc)
    {
        rc = mcast_listen_stop(pco_iut, listener, NULL);
        if (rc > 0)
            RING_VERDICT("Multicasting packets were detected on "
                         "IUT interface");
    }

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (!use_zc)
        mcast_listener_fini(pco_iut, listener);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(recvbuf);
    free(sendbuf);
    
    rcf_rpc_server_destroy(pco_iut2);

    TEST_END;
}
