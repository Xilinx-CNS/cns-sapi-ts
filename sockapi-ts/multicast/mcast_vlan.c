/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$ 
 */

/** @page multicast-mcast_vlan IP multicasting with VLANs
 *
 * @objective Check that if a socket is joined to a multicasting group on
 *            a specific vlan interface, only multicasting packets received
 *            from that particular interface are processed by the socket.
 *
 * @type conformance
 *
 * @reference STEVENS, chapter 21
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_if            Network interface on @p pco_iut
 * @param tst_if            Network interface on @p pco_tst
 * @param iut_addr          Network address on @p pco_iut
 * @param tst_addr          Network address on @p pco_tst
 * @param mcast_addr        Multicast address
 * @param vlan1             Identifier of VLAN interface to be
 *                          created on @p pco_iut and @p pco_tst
 * @param vlan2             Identifier of another VLAN interface
 *                          to be created on @p pco_iut and @p pco_tst
 * @param method            Method used for joining to multicast group
 * @param parent_rcv_first  Whether IUT socket on IUT should join
 *                          multicast group on parent interface firstly
 * @param vlan1_rcv_first   Whether IUT socket on IUT should join
 *                          multicast group on vlan1 VLAN interface
 *                          firstly
 * @param vlan2_rcv_first   Whether IUT socket on IUT should join
 *                          multicast group on vlan2 VLAN interface
 *                          firstly
 * @param parent_rcv_second Whether IUT socket on IUT should join
 *                          multicast group on parent interface secondly
 * @param vlan1_rcv_second  Whether IUT socket on IUT should join
 *                          multicast group on vlan1 VLAN interface
 *                          secondly
 * @param vlan2_rcv_second  Whether IUT socket on IUT should join
 *                          multicast group on vlan2 VLAN interface
 *                          secondly
 *
 * @par Test sequence:
 * -# Create and configure VLAN interfaces with IDs @p vlan1 and @p vlan2
 *    on @p pco_iut and @p pco_tst so that addresses assigned to VLAN
 *    interfaces with different IDs are from different networks and
 *    addresses assigned to VLAN interfaces and addresses assigned to
 *    master interfaces are from different networks.
 * -# Join @p iut_s socket on @p pco_iut to a multicast group with
 *    address @p mcast_addr on interfaces specified by
 *    @p parent_rcv_first, @p vlan1_rcv_first, @p vlan2_rcv_first.
 * -# Create sockets @p tst_s1, @p tst_s2 and @p tst_s3 on @p pco_tst
 *    and assign interfaces @p tst_vlan1_if, @p tst_vlan2_if,
 *    @p tst_if for outgoing multicast packets to them correspondingly.
 *    Bind each socket to an address assigned to corresponding
 *    interface.
 * -# Send some data from @p tst_s1, @p tst_s2 and @p tst_s3
 *    to @p mcast_addr address. Check that @p iut_s socket receives
 *    data of expected length only from correct peers, and multicast
 *    packets are detected only on expected interfaces.
 * -# Modify membership of @p iut_s in multicast group on different
 *    interfaces accordind to @p parent_rcv_second, @p vlan1_rcv_second,
 *    @p vlan2_rcv_second.
 * -# Again send packets from sockets on @p pco_tst and check
 *    that @p iut_s socket receives data of expected length only from
 *    correct peers and multicast packets are detected only on expected
 *    interfaces.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/mcast_vlan"

#include "sockapi-test.h"
#include "vlan_common.h"
#include "mcast_lib.h"
#include "multicast.h"

#define STRLEN 100
char exp_addrs[STRLEN];
char exp_ifs[STRLEN];

#define MSG_CONCAT(_msg, _str, _k) \
    do {                                                    \
        if (_k != 0)                                        \
            _k += snprintf(_msg + _k, STRLEN - _k, " or "); \
        _k += snprintf(_msg + _k, STRLEN - _k, _str);       \
    } while (0)

#define MSGS_CONCAT(_addr, _if_nmb) \
    do {                                                    \
            MSG_CONCAT(exp_addrs,                           \
                       get_name_by_addr(SA(_addr),          \
                                        peer_names),        \
                       k_addrs);                            \
            MSG_CONCAT(exp_ifs, if_names[_if_nmb], k_ifs);  \
    } while (0)

#define GET_EXP_PEER_NAMES(_parent_rcv, _vlan1_rcv, _vlan2_rcv) \
    do {                                                    \
        int k_addrs = 0;                                    \
        int k_ifs = 0;                                      \
        exp_addrs[0] = '\0';                                \
        exp_ifs[0] = '\0';                                  \
                                                            \
        if (_vlan1_rcv)                                     \
            MSGS_CONCAT(tst_vlan1_addr, 0);                 \
        if (_vlan2_rcv)                                     \
            MSGS_CONCAT(tst_vlan2_addr, 1);                 \
        if (_parent_rcv)                                    \
            MSGS_CONCAT(tst_addr, 2);                       \
    } while (0)

#define CHECK_LISTENER(_pco, _listener, _if_name, _exp_if_name, \
                       _is_received) \
    do {                                                                \
        rc = mcast_listen_stop(_pco, _listener, NULL);                  \
        if (rc > 0)                                                     \
        {                                                               \
            if (_is_received)                                           \
                RING_VERDICT("Multicast packets were detected on "      \
                             "%s interface", _if_name);                 \
            else                                                        \
                RING_VERDICT("Multicast packets were detected on "      \
                             "%s interface when they should be "        \
                             "detected only on %s interface", _if_name, \
                             _exp_if_name);                             \
        }                                                               \
    } while (0)

#define CHECK_VLANS(_first_received, _second_received, _third_received) \
    do {                                                                \
        te_bool parent_addr = FALSE;                                    \
        te_bool vlan1_addr = FALSE;                                     \
        te_bool vlan2_addr = FALSE;                                     \
        te_bool parent_wait = _third_received;                          \
        te_bool vlan1_wait = _first_received;                           \
        te_bool vlan2_wait = _second_received;                          \
                                                                        \
        mcast_listen_start(pco_iut, listener1);                         \
        mcast_listen_start(pco_iut, listener2);                         \
        mcast_listen_start(pco_iut, listener3);                         \
                                                                        \
        rpc_sendto(pco_tst, tst_s1, tst_buf1, tst_buf_len1,             \
                   0, mcast_addr);                                      \
        rpc_sendto(pco_tst, tst_s2, tst_buf2, tst_buf_len2,             \
                   0, mcast_addr);                                      \
        rpc_sendto(pco_tst, tst_s3, tst_buf3, tst_buf_len3,             \
                   0, mcast_addr);                                      \
                                                                        \
        TAPI_WAIT_NETWORK;                                              \
                                                                        \
        RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);               \
                                                                        \
        CHECK_LISTENER(pco_iut, listener1,                              \
                       if_names[0], exp_ifs, _first_received);          \
        CHECK_LISTENER(pco_iut, listener2,                              \
                       if_names[1], exp_ifs, _second_received);         \
        CHECK_LISTENER(pco_iut, listener3,                              \
                       if_names[2], exp_ifs, _third_received);          \
                                                                        \
        while (readable)                                                \
        {                                                               \
            if (use_zc)                                                 \
            {                                                           \
                memset(&msg, 0, sizeof(msg));                           \
                vector.iov_base = local_buf;                            \
                vector.iov_len = vector.iov_rlen = tst_buf_len1 +       \
                                                   tst_buf_len2 +       \
                                                   tst_buf_len3;        \
                msg.msg_iov = &vector;                                  \
                msg.msg_iovlen = msg.msg_riovlen = 1;                   \
                msg.msg_name = &peer_addr;                              \
                msg.msg_namelen = msg.msg_rnamelen = peer_addrlen;      \
                RPC_AWAIT_ERROR(pco_iut);                               \
                rc = rpc_simple_zc_recv(pco_iut, iut_s, &msg, 0);       \
                if (rc < 0)                                             \
                    TEST_VERDICT("onload_zc_recv() failed with "        \
                                 "errno %r", RPC_ERRNO(pco_iut));       \
                peer_addrlen = msg.msg_namelen;                         \
            }                                                           \
            else                                                        \
                rc = rpc_recvfrom(pco_iut, iut_s, local_buf,            \
                                  tst_buf_len1 + tst_buf_len2           \
                                  + tst_buf_len3,                       \
                                  0, SA(&peer_addr), &peer_addrlen);    \
                                                                        \
            parent_addr = !te_sockaddrcmp(SA(&peer_addr), peer_addrlen, \
                            SA(tst_addr),                               \
                            te_sockaddr_get_size(tst_addr));            \
            vlan1_addr = !te_sockaddrcmp(SA(&peer_addr), peer_addrlen,  \
                            SA(tst_vlan1_addr),                         \
                            te_sockaddr_get_size(tst_vlan1_addr));      \
            vlan2_addr = !te_sockaddrcmp(SA(&peer_addr), peer_addrlen,  \
                            SA(tst_vlan2_addr),                         \
                            te_sockaddr_get_size(tst_vlan2_addr));      \
                                                                        \
            if (_first_received && vlan1_addr)                          \
            {                                                           \
                CHECK_RETURNED_LEN(rc, tst_buf_len1, SA(&peer_addr),    \
                                   tst_vlan1_addr, RING_VERDICT,        \
                                   RING_VERDICT, peer_names,            \
                                   &unexp_len, &unexp_peer,             \
                                   "IUT socket");                       \
                vlan1_wait = FALSE;                                     \
            }                                                           \
            else if (_second_received && vlan2_addr)                    \
            {                                                           \
                CHECK_RETURNED_LEN(rc, tst_buf_len2, SA(&peer_addr),    \
                                   tst_vlan2_addr, RING_VERDICT,        \
                                   RING_VERDICT, peer_names,            \
                                   &unexp_len, &unexp_peer,             \
                                   "IUT socket");                       \
                vlan2_wait = FALSE;                                     \
            }                                                           \
            else if (_third_received && parent_addr)                    \
            {                                                           \
                CHECK_RETURNED_LEN(rc, tst_buf_len3, SA(&peer_addr),    \
                                   tst_addr, RING_VERDICT,              \
                                   RING_VERDICT, peer_names,            \
                                   &unexp_len, &unexp_peer,             \
                                   "IUT socket");                       \
                parent_wait = FALSE;                                    \
            }                                                           \
            else                                                        \
            {                                                           \
                RING_VERDICT("IUT socket receives data from %s "        \
                             "but it is expected to receive from %s",   \
                             get_name_by_addr(SA(&peer_addr),           \
                                              peer_names), exp_addrs);  \
                unexp_peer = TRUE;                                      \
            }                                                           \
                                                                        \
            RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);           \
        }                                                               \
                                                                        \
        if (vlan1_wait)                                                 \
            RING_VERDICT("IUT socket didn't receive data from %s",      \
                         get_name_by_addr(SA(tst_vlan1_addr),           \
                                          peer_names));                 \
        if (vlan2_wait)                                                 \
            RING_VERDICT("IUT socket didn't receive data from %s",      \
                         get_name_by_addr(SA(tst_vlan2_addr),           \
                                          peer_names));                 \
        if (parent_wait)                                                \
            RING_VERDICT("IUT socket didn't receive data from %s",      \
                         get_name_by_addr(SA(tst_addr),                 \
                                          peer_names));                 \
                                                                        \
        if (vlan1_wait || vlan2_wait || parent_wait)                    \
            unexp_unreadable = TRUE;                                    \
                                                                        \
    } while (0)

#define VLAN_FREE(_pco, _id) \
    do {                                                \
        if (_pco ## _vlan ## _id ## _if != NULL)        \
        {                                               \
            free(_pco ## _vlan ## _id ## _if->if_name); \
            free(_pco ## _vlan ## _id ## _if);          \
        }                                               \
    } while (0)

#define JOIN_LEAVE_MCAST(_if, _name, _old, _new) \
    do {                                                                \
        if (_old && !_new)                                              \
        {                                                               \
            if (rpc_mcast_leave(pco_iut, iut_s, mcast_addr,             \
                                _if->if_index, method) != 0)            \
                TEST_FAIL("Cannot leave multicast group on pco_iut, "   \
                          "%s interface", _name);                       \
        }                                                               \
        if (!_old && _new)                                              \
        {                                                               \
            if (rpc_mcast_join(pco_iut, iut_s, mcast_addr,              \
                               _if->if_index, method) != 0)             \
                TEST_FAIL("Cannot join multicast group on pco_iut, "    \
                          "%s interface", _name);                       \
        }                                                               \
    } while (0)

#define JOIN_LEAVE_MCASTS(parent_rcv_old, vlan1_rcv_old, vlan2_rcv_old, \
                          parent_rcv_new, vlan1_rcv_new, vlan2_rcv_new) \
    do {                                                                \
        JOIN_LEAVE_MCAST(iut_vlan1_if, if_names[0], vlan1_rcv_old,      \
                         vlan1_rcv_new);                                \
        vlan1_joined = vlan1_rcv_new;                                   \
        JOIN_LEAVE_MCAST(iut_if, if_names[2], parent_rcv_old,           \
                         parent_rcv_new);                               \
        parent_joined = parent_rcv_new;                                 \
        JOIN_LEAVE_MCAST(iut_vlan2_if, if_names[1], vlan2_rcv_old,      \
                         vlan2_rcv_new);                                \
        vlan2_joined = vlan2_rcv_new;                                   \
        GET_EXP_PEER_NAMES(parent_rcv_new, vlan1_rcv_new,               \
                           vlan2_rcv_new);                              \
    } while (0)


int
main(int argc, char **argv)
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    int                         vlan1;
    int                         vlan2;
    cfg_handle                  vlan1_net_handle = CFG_HANDLE_INVALID;
    cfg_handle                  vlan2_net_handle = CFG_HANDLE_INVALID;
    cfg_handle                  iut_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  tst_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  iut_vlan2_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  tst_vlan2_addr_handle = CFG_HANDLE_INVALID;

    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    struct if_nameindex        *iut_vlan1_if = NULL;
    struct if_nameindex        *tst_vlan1_if = NULL;
    struct if_nameindex        *iut_vlan2_if = NULL;
    struct if_nameindex        *tst_vlan2_if = NULL;

    int                    iut_s = -1;
    int                    tst_s1 = -1;
    int                    tst_s2 = -1;
    int                    tst_s3 = -1;

    te_bool                iut_vlan1_configured = FALSE;
    te_bool                tst_vlan1_configured = FALSE;
    te_bool                iut_vlan2_configured = FALSE;
    te_bool                tst_vlan2_configured = FALSE;

    struct sockaddr *iut_vlan1_addr = NULL;
    struct sockaddr *iut_vlan2_addr = NULL;
    struct sockaddr *tst_vlan1_addr = NULL;
    struct sockaddr *tst_vlan2_addr = NULL;

    te_bool   readable = FALSE;
    te_bool   unexp_len = FALSE;
    te_bool   unexp_peer = FALSE;
    te_bool   unexp_unreadable = FALSE;

    struct sockaddr_storage    peer_addr;
    socklen_t                  peer_addrlen = sizeof(peer_addr);

    peer_name_t peer_names[] = {{&tst_vlan1_addr, "address on"
                                 " TESTER vlan1 interface"},
                                {&tst_vlan2_addr, "address on"
                                 " TESTER vlan2 interface"},
                                {(struct sockaddr **)&tst_addr,
                                 "address on TESTER master interface"},
                                {NULL, NULL}};

    char *if_names[] = {"IUT vlan1", "IUT vlan2", "IUT master"};

    void     *tst_buf1 = NULL;
    size_t    tst_buf_len1;
    void     *tst_buf2 = NULL;
    size_t    tst_buf_len2;
    void     *tst_buf3 = NULL;
    size_t    tst_buf_len3;
    void     *local_buf = NULL;

    tarpc_joining_method   method;

    mcast_listener_t listener1 = NULL;
    mcast_listener_t listener2 = NULL;
    mcast_listener_t listener3 = NULL;

    te_bool     parent_rcv_first = FALSE;
    te_bool     vlan1_rcv_first = FALSE;
    te_bool     vlan2_rcv_first = FALSE;

    te_bool     parent_rcv_second = FALSE;
    te_bool     vlan1_rcv_second = FALSE;
    te_bool     vlan2_rcv_second = FALSE;

    te_bool     parent_joined = FALSE;
    te_bool     vlan1_joined = FALSE;
    te_bool     vlan2_joined = FALSE;

    te_bool          use_zc = FALSE;
    rpc_msghdr       msg;
    struct rpc_iovec vector;

    sockts_socket_func  sock_func;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(vlan1);
    TEST_GET_INT_PARAM(vlan2);
    TEST_GET_MCAST_METHOD(method);
    TEST_GET_BOOL_PARAM(parent_rcv_first);
    TEST_GET_BOOL_PARAM(vlan1_rcv_first);
    TEST_GET_BOOL_PARAM(vlan2_rcv_first);
    TEST_GET_BOOL_PARAM(parent_rcv_second);
    TEST_GET_BOOL_PARAM(vlan1_rcv_second);
    TEST_GET_BOOL_PARAM(vlan2_rcv_second);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    CHECK_NOT_NULL(tst_buf1 = sockts_make_buf_dgram(&tst_buf_len1));
    CHECK_NOT_NULL(tst_buf2 = sockts_make_buf_dgram(&tst_buf_len2));
    CHECK_NOT_NULL(tst_buf3 = sockts_make_buf_dgram(&tst_buf_len3));
    CHECK_NOT_NULL(local_buf =
            te_make_buf_by_len(tst_buf_len1 + tst_buf_len2 + tst_buf_len3));

    create_net_channel(pco_iut, pco_tst, iut_if, tst_if, NULL, NULL, NULL,
                       (struct sockaddr **)&iut_addr,
                       (struct sockaddr **)&tst_addr, mcast_addr,
                       sock_func,
                       &iut_s, &tst_s3, TRUE,
                       FALSE, NULL, NULL,
                       0, NULL,
                       NULL);

    create_net_channel(pco_iut, pco_tst, iut_if, tst_if, &vlan1_net_handle,
                       &iut_vlan1_addr_handle, &tst_vlan1_addr_handle,
                       &iut_vlan1_addr, &tst_vlan1_addr, mcast_addr,
                       sock_func,
                       NULL, &tst_s1, TRUE,
                       TRUE, &iut_vlan1_if, &tst_vlan1_if,
                       vlan1, &iut_vlan1_configured,
                       &tst_vlan1_configured);

    create_net_channel(pco_iut, pco_tst, iut_if, tst_if, &vlan2_net_handle,
                       &iut_vlan2_addr_handle, &tst_vlan2_addr_handle,
                       &iut_vlan2_addr, &tst_vlan2_addr, mcast_addr,
                       sock_func,
                       NULL, &tst_s2, TRUE,
                       TRUE, &iut_vlan2_if, &tst_vlan2_if,
                       vlan2, &iut_vlan2_configured,
                       &tst_vlan2_configured);
    CFG_WAIT_CHANGES;

    if (sockts_iface_is_iut(&env, "iut_if"))
    {
        check_mcast_hash_collision(pco_iut, pco_tst, iut_vlan1_if, tst_s1,
                                   mcast_addr);
        check_mcast_hash_collision(pco_iut, pco_tst, iut_vlan2_if, tst_s2,
                                   mcast_addr);
        check_mcast_hash_collision(pco_iut, pco_tst, iut_if, tst_s3,
                                   mcast_addr);
    }

    listener1 = mcast_listener_init(pco_iut, iut_vlan1_if, mcast_addr,
                                    tst_vlan1_addr, 1);
    listener2 = mcast_listener_init(pco_iut, iut_vlan2_if, mcast_addr,
                                    tst_vlan2_addr, 1);
    listener3 = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                    tst_addr, 1);

    JOIN_LEAVE_MCASTS(FALSE, FALSE, FALSE, parent_rcv_first,
                      vlan1_rcv_first, vlan2_rcv_first);

    CHECK_VLANS(vlan1_rcv_first, vlan2_rcv_first,
                parent_rcv_first);

    JOIN_LEAVE_MCASTS(parent_rcv_first, vlan1_rcv_first,
                      vlan2_rcv_first, parent_rcv_second,
                      vlan1_rcv_second, vlan2_rcv_second);

    CHECK_VLANS(vlan1_rcv_second, vlan2_rcv_second,
                parent_rcv_second);

    if (!unexp_unreadable && !unexp_len && !unexp_peer)
        TEST_SUCCESS;
    else
        TEST_STOP;

cleanup:

    if (parent_joined)
        CLEANUP_MULTICAST_LEAVE(pco_iut, iut_s, mcast_addr,
                                iut_if->if_index, method);
    if (vlan1_joined)
        CLEANUP_MULTICAST_LEAVE(pco_iut, iut_s, mcast_addr,
                                iut_vlan1_if->if_index, method);
    if (vlan2_joined)
        CLEANUP_MULTICAST_LEAVE(pco_iut, iut_s, mcast_addr,
                                iut_vlan2_if->if_index, method);

    mcast_listener_fini(pco_iut, listener1);
    mcast_listener_fini(pco_iut, listener2);
    mcast_listener_fini(pco_iut, listener3);

    free(tst_buf1);
    free(tst_buf2);
    free(tst_buf3);
    free(local_buf);

    VLAN_FREE(iut, 1);
    VLAN_FREE(iut, 2);
    VLAN_FREE(tst, 1);
    VLAN_FREE(tst, 2);

    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan1, iut_vlan1_configured);
    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan2, iut_vlan2_configured);
    CLEANUP_REMOVE_VLAN(pco_tst, tst_if, vlan1, tst_vlan1_configured);
    CLEANUP_REMOVE_VLAN(pco_tst, tst_if, vlan2, tst_vlan2_configured);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);

    tapi_cfg_free_entry(&vlan1_net_handle);
    tapi_cfg_free_entry(&vlan2_net_handle);
    tapi_cfg_free_entry(&iut_vlan1_addr_handle);
    tapi_cfg_free_entry(&tst_vlan1_addr_handle);
    tapi_cfg_free_entry(&iut_vlan2_addr_handle);
    tapi_cfg_free_entry(&tst_vlan2_addr_handle);

    TEST_END;
}
