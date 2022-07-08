/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$ 
 */

/** @page multicast-mcast_two_sockets Two sockets joined to the same multicast group
 *
 * @objective Check that if two sockets join to the same multicast group,
 *            socket joined to the group secondly receives multicasting
 *            packets after socket joined to the group firstly leaved the
 *            group.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Network interface on @p pco_iut
 * @param tst_if            Network interface on @p pco_tst
 * @param iut_addr          Network address on @p pco_iut
 * @param tst_addr          Network address on @p pco_tst
 * @param mcast_addr        Multicast address
 * @param method            Method used for joining to multicast group
 * @param forkexec          If TRUE call @b fork() and @b exec() on @p pco_iut
 *                          to create @p pco_iut_child RPC server.
 * @param sock_func         Socket creation function
 *
 * @par Test sequence:
 * -# Create @p iut_s socket on @p pco_iut, join it to a multicast group
 *    with address @p mcast_addr, set @c RPC_SO_REUSEADDR socket option for
 *    @p iut_s, @b bind() it to @p mcast_addr address.
 * -# If @p forkexec is TRUE, call @b fork() and @b exec() on @p pco_iut
 *    to create @p pco_iut_child RPC server, otherwise let @p pco_iut_child
 *    be the same as @p pco_iut.
 * -# Create @p iut_child_s socket on @p pco_iut_child, join it to a
 *    multicast group with address @p mcast_addr, set @c RPC_SO_REUSEADDR
 *    socket option for @p iut_child_s, @b bind() it to @p mcast_addr address.
 * -# Create @p tst_s socket on @p pco_tst, @b send() some data from it
 *    to @p mcast_addr addres. Check that both IUT sockets received
 *    correct data from correct address.
 * -# Let socket @p iut_s leave multicast group, @b send() some data
 *    from @p tst_s socket again, check that @p iut_child_s socket
 *    received correct data from correct source.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/mcast_two_sockets"

#include "sockapi-test.h"
#include "mcast_lib.h"
#include "multicast.h"
#include "iomux.h"

#define CHECK_RECEIVED_DATA(pco_, s_, str_, evt_, addr_, addr_len_, \
                            exp_addr_, exp_addr_len_, data_, \
                            len_, exp_data_, \
                            exp_len_, failed_) \
    do {                                                                \
        if (!(evt_.revents & EVT_RD))                                   \
        {                                                               \
            RING_VERDICT("%s socket didn't received any data",          \
                         str_);                                         \
            failed_ = TRUE;                                             \
        }                                                               \
        else                                                            \
        {                                                               \
            if (use_zc)                                                 \
            {                                                           \
                memset(&msg, 0, sizeof(msg));                           \
                vector.iov_base = data_;                                \
                vector.iov_len = vector.iov_rlen = exp_len_;            \
                msg.msg_iov = &vector;                                  \
                msg.msg_iovlen = msg.msg_riovlen = 1;                   \
                msg.msg_name = addr_;                                   \
                msg.msg_namelen = msg.msg_rnamelen = addr_len_;         \
                RPC_AWAIT_IUT_ERROR(pco_);                              \
                rc = rpc_simple_zc_recv_acc(pco_, s_, &msg, 0);         \
                if (rc == -1)                                           \
                {                                                       \
                    CHECK_RPC_ERRNO(pco_, RPC_ENOTEMPTY,                \
                                    "onload_zc_recv() returns %d, but", \
                                    rc);                                \
                    rc = rpc_simple_zc_recv(pco_, s_, &msg, 0);         \
                    detected = 1;                                       \
                }                                                       \
                addr_len_ = msg.msg_namelen;                            \
            }                                                           \
            else                                                        \
                len_ = rpc_recvfrom(pco_, s_, data_, exp_len_,          \
                                    0, SA(addr_), &addr_len_);          \
                                                                        \
            if (te_sockaddrcmp(SA(addr_), addr_len_, SA(exp_addr_),     \
                               exp_addr_len_))                          \
            {                                                           \
                RING_VERDICT("%s socket received data from "            \
                             "unexpected address", str_);               \
                failed_ = TRUE;                                         \
            }                                                           \
            else if ((int)len_ != (int)exp_len_)                        \
            {                                                           \
                RING_VERDICT("%s socket received unexpected number"     \
                             " of bytes", str_);                        \
                failed_ = TRUE;                                         \
            }                                                           \
            else if (memcmp(data_, exp_data_, exp_len_))                \
            {                                                           \
                RING_VERDICT("%s socket received unexpected data",      \
                             str_);                                     \
                failed_ = TRUE;                                         \
            }                                                           \
        }                                                               \
    } while (0)

int
main(int argc, char **argv)
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_iut_child = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    mcast_listener_t listener = NULL;

    int                    detected = 0;

    int                    iut_s;
    int                    iut_child_s;
    int                    tst_s;

    int opt_val;

    te_bool   forkexec = FALSE;
    te_bool   is_failed = FALSE;

    void     *tst_buf = NULL;
    void     *local_buf = NULL;
    size_t    buf_len;

    tarpc_joining_method   method;
    sockts_socket_func     sock_func;

    struct sockaddr_storage    peer_addr;
    socklen_t                  peer_addrlen = sizeof(peer_addr);

    iomux_evt_fd    events[2];
    tarpc_timeval   tv;

    te_bool          use_zc = FALSE;
    rpc_msghdr       msg;
    struct rpc_iovec vector;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(forkexec);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    CHECK_NOT_NULL(tst_buf = sockts_make_buf_dgram(&buf_len));
    local_buf = calloc(buf_len, sizeof(char));

    CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(pco_iut, pco_tst, iut_if, tst_addr,
                                           mcast_addr);

    iut_s = sockts_socket(sock_func, pco_iut,
                          rpc_socket_domain_by_addr(iut_addr),
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_REUSEADDR, &opt_val);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_bind(pco_iut, iut_s, mcast_addr);

    if (rpc_mcast_join(pco_iut, iut_s, mcast_addr,
                       iut_if->if_index, method) != 0)
        TEST_FAIL("Cannot join multicast group on pco_iut");

    if (forkexec)
    {
        CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "iut_child",
                                          &pco_iut_child));
    }
    else
        pco_iut_child = pco_iut;

    iut_child_s = sockts_socket(sock_func, pco_iut_child,
                                rpc_socket_domain_by_addr(iut_addr),
                                RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    opt_val = 1;
    rpc_setsockopt(pco_iut_child, iut_child_s, RPC_SO_REUSEADDR, &opt_val);

    rpc_bind(pco_iut_child, iut_child_s, mcast_addr);

    if (rpc_mcast_join(pco_iut_child, iut_child_s, mcast_addr,
                       iut_if->if_index, method) != 0)
        TEST_FAIL("Cannot join multicast group on pco_iut_child");

    TAPI_WAIT_NETWORK;

    if (!use_zc)
    {
        listener = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                       tst_addr, 1);
        mcast_listen_start(pco_iut, listener);
    }

    events[0].fd = iut_child_s;
    events[0].events = EVT_RD;
    events[1].fd = iut_s;
    events[1].events = EVT_RD;

    /* Half of default timeout is set as timeout for poll() call */
    tv.tv_sec = pco_iut_child->def_timeout / 2000;
    tv.tv_usec = pco_iut_child->def_timeout * 500 % 1000000;

    rpc_sendto(pco_tst, tst_s, tst_buf, buf_len, 0, mcast_addr);

    iomux_call(IC_DEFAULT, pco_iut_child, events, 1, &tv);
    iomux_call(IC_DEFAULT, pco_iut, events + 1, 1, &tv);

    CHECK_RECEIVED_DATA(pco_iut, iut_s, "First", events[1],
                        &peer_addr, peer_addrlen, tst_addr,
                        te_sockaddr_get_size(tst_addr),
                        local_buf, rc, tst_buf, buf_len, is_failed);

    CHECK_RECEIVED_DATA(pco_iut_child, iut_child_s, "Second", events[0],
                        &peer_addr, peer_addrlen, tst_addr,
                        te_sockaddr_get_size(tst_addr),
                        local_buf, rc, tst_buf, buf_len, is_failed);

    if (!use_zc)
    {
        rc = mcast_listen_stop(pco_iut, listener, NULL);
        if (rc > 0)
            detected = 1;
    }
    if (detected)
        RING_VERDICT("Multicast packets were detected on IUT interface"
                     " when both sockets were joined to multicast group");
    detected = 0;
    if (rpc_mcast_leave(pco_iut, iut_s, mcast_addr,
                        iut_if->if_index, method) != 0)
        TEST_FAIL("Cannot leave multicast group on pco_iut");

    TAPI_WAIT_NETWORK;

    if (!use_zc)
        mcast_listen_start(pco_iut, listener);

    rpc_sendto(pco_tst, tst_s, tst_buf, buf_len, 0, mcast_addr);

    iomux_call(IC_DEFAULT, pco_iut_child, events, 1, &tv);

    CHECK_RECEIVED_DATA(pco_iut_child, iut_child_s, "After first socket "
                        "left the group, second", events[0],
                        &peer_addr, peer_addrlen, tst_addr,
                        te_sockaddr_get_size(tst_addr),
                        local_buf, rc, tst_buf, buf_len, is_failed);

    if (!use_zc)
    {
        rc = mcast_listen_stop(pco_iut, listener, NULL);
        if (rc > 0)
            detected = 1;
    }
    if (detected)
        RING_VERDICT("Multicast packets were detected on IUT interface"
                     " after one of the sockets leaved multicast group");

    if (is_failed)
        TEST_STOP;
    else
        TEST_SUCCESS;

cleanup:

    if (rpc_mcast_leave(pco_iut_child, iut_child_s, mcast_addr,
                        iut_if->if_index, method) != 0)
        TEST_FAIL("Cannot leave multicast group on pco_iut_child");

    free(tst_buf);
    free(local_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut_child, iut_child_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (!use_zc)
        mcast_listener_fini(pco_iut, listener);

    if (forkexec)
        rcf_rpc_server_destroy(pco_iut_child);

    TEST_END;
}
