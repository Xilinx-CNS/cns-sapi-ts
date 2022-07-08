/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-mcast_vlan_two_sockets IP multicasting with VLANs
 *
 * @objective Check that if two sockets are joined to the same
 *            multicasting group on different vlan interfaces,
 *            only multicasting packets received from the interface
 *            on which the socket was joined to the group are
 *            processed by each socket.
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
 * @param first_sock_vlan   Whether first sockets should join multicast
 *                          group on parent or VLAN interface
 * @param second_sock_vlan  Whether second sockets should join multicast
 *                          group on parent or VLAN interface
 * @param first_sock_rcv    Whether first socket on IUT should send or
 *                          receive packets
 * @param second_sock_rcv   Whether second socket on IUT should send or
 *                          receive packets
 * @param forkexec          Whether second IUT socket should be created
 *                          after @b fork() and @b exec() call in a child
 *                          process or not
 * @param use_zc            Use @b onload_zc_recv() instead of @b recv()
 *                          on IUT
 * @param sock_func         Socket creation function
 *
 * @par Test sequence:
 * -# Create two sockets on IUT and TESTER side, create and configure
 *    required VLAN interface(s), join each socket to a multicast group
 *    with address @p mcast_addr on corresponding interface. Each pair
 *    of interfaces corresponding to a pair of sockets (first or second
 *    ones) on IUT and TESTER should have address assigned to them from
 *    network different from network of addresses assigned to another pair.
 * -# Send multicast packets from sockets specified by @p first_sock_rcv
 *    and @p second_sock_rcv parameters.
 * -# Check that each receiving socket received data only from correct
 *    peer, and sending sockets didn't receive anything.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/mcast_vlan_two_sockets"

#include "sockapi-test.h"
#include "vlan_common.h"
#include "mcast_lib.h"
#include "multicast.h"

#define CHECK_RECEIVED_DATA(_pco, _s, _buf, _exp_addr, \
                            _verd_txt...) \
    do {                                                            \
        while (readable)                                            \
        {                                                           \
            if (use_zc && (_pco == pco_iut ||                       \
                           _pco == pco_iut2))                       \
                RECV_VIA_ZC(_pco, _s, _buf, buf_len, 0,             \
                            SA(&peer_addr), &peer_addrlen,          \
                            TRUE, NULL, FALSE, _verd_txt);          \
            else                                                    \
                rc = rpc_recvfrom(_pco, _s, _buf, buf_len,          \
                                  0, SA(&peer_addr),                \
                                  &peer_addrlen);                   \
                                                                    \
            if (rc < 0)                                             \
                TEST_VERDICT("Receiving data failed: %s",           \
                             errno_rpc2str(RPC_ERRNO(pco_iut)));    \
            else                                                    \
                CHECK_RETURNED_LEN(rc, buf_len / 2, SA(&peer_addr), \
                                   _exp_addr, RING_VERDICT,         \
                                   RING_VERDICT, peer_names,        \
                                   &unexp_len, &unexp_peer,         \
                                   get_name_by_sock(_s, _pco,       \
                                                    sock_names));   \
                                                                    \
            RPC_GET_READABILITY(readable, _pco, _s, 1);             \
        }                                                           \
    } while (0)

#define LISTENER_STOP(listener_, in_, name_) \
    do {                                                    \
        rc = mcast_listen_stop(pco_iut, listener_, NULL);   \
        if (rc > 0)                                         \
            RING_VERDICT("%s packets were detected on %s",  \
                         in_ ? "Incoming" : "Outcoming",    \
                         name_);                            \
    } while (0)

#define GET_IF_NAME(if_) \
    (if_ == iut_if ? "IUT parent interface" :           \
      if_ == tst_if ? "TESTER parent interface" :       \
       if_ == iut_if1 ? "IUT vlan1 interface" :         \
        if_ == iut_if2 ? "IUT vlan2 interface" :        \
         if_ == tst_if1 ? "TESTER vlan1 interface" :    \
          if_ == tst_if2 ? "TESTER vlan2 interface" :   \
           "unknown interface")

#define PARENT_LISTENER_NOT_USE \
    (use_zc && ((first_sock_rcv && first_rcv_if == iut_if) || \
                (second_sock_rcv && second_rcv_if == iut_if)))

#define VLAN1_LISTENER_NOT_USE \
    (use_zc && ((first_sock_rcv && first_rcv_if == iut_if1) || \
                (second_sock_rcv && second_rcv_if == iut_if1)))

#define VLAN2_LISTENER_NOT_USE \
    (use_zc && ((first_sock_rcv && first_rcv_if == iut_if2) || \
                (second_sock_rcv && second_rcv_if == iut_if2)))

int
main(int argc, char **argv)
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    int                         vlan1;
    int                         vlan2;
    cfg_handle                  vlan1_net_handle;
    cfg_handle                  vlan2_net_handle;
    cfg_handle                  iut_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  tst_vlan1_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  iut_vlan2_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  tst_vlan2_addr_handle = CFG_HANDLE_INVALID;

    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    te_bool                iut_vlan1_configured = FALSE;
    te_bool                tst_vlan1_configured = FALSE;
    te_bool                iut_vlan2_configured = FALSE;
    te_bool                tst_vlan2_configured = FALSE;

    te_bool   readable = FALSE;
    te_bool   unexp_len = FALSE;
    te_bool   unexp_peer = FALSE;
    te_bool   unexp_unreadable = FALSE;

    struct sockaddr_storage    peer_addr;
    socklen_t                  peer_addrlen = sizeof(peer_addr);

    peer_name_t peer_names[8] = {{NULL, NULL}, };
    sock_name_t sock_names[5] = {{NULL, NULL, NULL}, };

    size_t    buf_len = 200;
    void     *snd_buf1 = NULL;
    void     *snd_buf2 = NULL;
    void     *rcv_buf1 = NULL;
    void     *rcv_buf2 = NULL;

    tarpc_joining_method   method;

    te_bool first_sock_vlan = FALSE;
    te_bool first_sock_rcv = FALSE;
    te_bool second_sock_vlan = FALSE;
    te_bool second_sock_rcv = FALSE;
    te_bool forkexec = FALSE;
    te_bool use_zc = FALSE;
    te_bool set_bindtodevice = FALSE;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int tst_s1 = -1;
    int tst_s2 = -1;

    struct if_nameindex  *iut_if1 = NULL;
    struct if_nameindex  *iut_if2 = NULL;
    struct if_nameindex  *tst_if1 = NULL;
    struct if_nameindex  *tst_if2 = NULL;
    struct if_nameindex  *first_rcv_if = NULL;
    struct if_nameindex  *second_rcv_if = NULL;
    struct if_nameindex  *first_snd_if = NULL;
    struct if_nameindex  *second_snd_if = NULL;

    struct sockaddr *iut_addr1 = NULL;
    struct sockaddr *iut_addr2 = NULL;
    struct sockaddr *tst_addr1 = NULL;
    struct sockaddr *tst_addr2 = NULL;

    struct sockaddr *first_exp_addr = NULL;
    struct sockaddr *second_exp_addr = NULL;
    struct sockaddr  unexp_addr;
    struct sockaddr *unexp_addr_p = &unexp_addr;

    rcf_rpc_server *pco_iut2 = NULL;
    rcf_rpc_server *first_snd = NULL;
    rcf_rpc_server *first_rcv = NULL;
    rcf_rpc_server *second_snd = NULL;
    rcf_rpc_server *second_rcv = NULL;

    const char     *action_after_send;

    sockts_socket_func  sock_func;

    int first_snd_s;
    int first_rcv_s;
    int second_snd_s;
    int second_rcv_s;

    int k = 2;

    te_bool first_joined = FALSE;
    te_bool second_joined = FALSE;

    mcast_listener_t listener_parent_in = CSAP_INVALID_HANDLE;
    mcast_listener_t listener_parent_out = CSAP_INVALID_HANDLE;
    mcast_listener_t listener_vlan1_in = CSAP_INVALID_HANDLE;
    mcast_listener_t listener_vlan1_out = CSAP_INVALID_HANDLE;
    mcast_listener_t listener_vlan2_in = CSAP_INVALID_HANDLE;
    mcast_listener_t listener_vlan2_out = CSAP_INVALID_HANDLE;

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
    TEST_GET_BOOL_PARAM(first_sock_vlan);
    TEST_GET_BOOL_PARAM(first_sock_rcv);
    TEST_GET_BOOL_PARAM(second_sock_vlan);
    TEST_GET_BOOL_PARAM(second_sock_rcv);
    TEST_GET_BOOL_PARAM(forkexec);
    TEST_GET_BOOL_PARAM(use_zc);
    TEST_GET_BOOL_PARAM(set_bindtodevice);
    TEST_GET_STRING_PARAM(action_after_send);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    if (forkexec)
        CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "iut_child",
                                          &pco_iut2));
    else
        pco_iut2 = pco_iut;

    if (!first_sock_vlan && !second_sock_vlan)
        TEST_FAIL("Attempt to use parent interface twice");

    memset(&unexp_addr, 0, sizeof(unexp_addr));
    unexp_addr.sa_family = AF_INET;

    peer_names[0].name = "address on IUT parent interface";
    peer_names[0].addr = (struct sockaddr **)&iut_addr;
    peer_names[1].name = "address on TESTER parent interface";
    peer_names[1].addr = (struct sockaddr **)&tst_addr;

    sock_names[0].sock = &iut_s1;
    sock_names[0].pco = &pco_iut;
    sock_names[1].sock = &tst_s1;
    sock_names[1].pco = &pco_tst;
    sock_names[2].sock = &iut_s2;
    sock_names[2].pco = &pco_iut2;
    sock_names[3].sock = &tst_s2;
    sock_names[3].pco = &pco_tst;

    if (!first_sock_vlan)
    {
        iut_if1 = (struct if_nameindex *)iut_if;
        tst_if1 = (struct if_nameindex *)tst_if;
        iut_addr1 = (struct sockaddr *)iut_addr;
        tst_addr1 = (struct sockaddr *)tst_addr;
        sock_names[0].name = "IUT socket on parent interface";
        sock_names[1].name = "TESTER socket on parent interface";
    }
    else
    {
        peer_names[2].name = "address on IUT vlan1 interface";
        peer_names[2].addr = &iut_addr1;
        peer_names[3].name = "address on TESTER vlan1 interface";
        peer_names[3].addr = &tst_addr1;
        k += 2;
        sock_names[0].name = "IUT socket on vlan1 interface";
        sock_names[1].name = "TESTER socket on vlan1 interface";
    }

    if (!second_sock_vlan)
    {
        iut_if2 = (struct if_nameindex *)iut_if;
        tst_if2 = (struct if_nameindex *)tst_if;
        iut_addr2 = (struct sockaddr *)iut_addr;
        tst_addr2 = (struct sockaddr *)tst_addr;
        sock_names[2].name = "IUT socket on parent interface";
        sock_names[3].name = "TESTER socket on parent interface";
    }
    else
    {
        peer_names[k].name = "address on IUT vlan2 interface";
        peer_names[k].addr = &iut_addr2;
        peer_names[k + 1].name = "address on TESTER vlan2 interface";
        peer_names[k + 1].addr = &tst_addr2;
        k += 2;
        sock_names[2].name = "IUT socket on vlan2 interface";
        sock_names[3].name = "TESTER socket on vlan2 interface";
    }

    peer_names[k].name = "nowhere";
    peer_names[k].addr = &unexp_addr_p;

    create_net_channel(pco_iut, pco_tst, iut_if, tst_if,
                       &vlan1_net_handle, &iut_vlan1_addr_handle,
                       &tst_vlan1_addr_handle,
                       &iut_addr1, &tst_addr1, mcast_addr,
                       sock_func,
                       &iut_s1, &tst_s1, first_sock_rcv,
                       first_sock_vlan, &iut_if1, &tst_if1,
                       vlan1, &iut_vlan1_configured,
                       &tst_vlan1_configured);

    create_net_channel(pco_iut2, pco_tst, iut_if, tst_if,
                       &vlan2_net_handle, &iut_vlan2_addr_handle,
                       &tst_vlan2_addr_handle,
                       &iut_addr2, &tst_addr2, mcast_addr,
                       sock_func,
                       &iut_s2, &tst_s2, second_sock_rcv,
                       second_sock_vlan, &iut_if2, &tst_if2,
                       vlan2, &iut_vlan2_configured,
                       &tst_vlan2_configured);

    CFG_WAIT_CHANGES;

    snd_buf1 = te_make_buf_by_len(buf_len);
    snd_buf2 = te_make_buf_by_len(buf_len);
    rcv_buf1 = te_make_buf_by_len(buf_len);
    rcv_buf2 = te_make_buf_by_len(buf_len);

    first_snd_if = first_sock_rcv ? tst_if1 : iut_if1;
    first_rcv_if = first_sock_rcv ? iut_if1 : tst_if1;
    first_snd = first_sock_rcv ? pco_tst : pco_iut;
    first_rcv = first_sock_rcv ? pco_iut : pco_tst;
    first_snd_s = first_sock_rcv ? tst_s1 : iut_s1;
    first_rcv_s = first_sock_rcv ? iut_s1 : tst_s1;
    first_exp_addr = first_sock_rcv ? tst_addr1 : iut_addr1;

    second_snd_if = second_sock_rcv ? tst_if2 : tst_if2;
    second_rcv_if = second_sock_rcv ? iut_if2 : tst_if2;
    second_snd = second_sock_rcv ? pco_tst : pco_iut2;
    second_rcv = second_sock_rcv ? pco_iut2 : pco_tst;
    second_snd_s = second_sock_rcv ? tst_s2 : iut_s2;
    second_rcv_s = second_sock_rcv ? iut_s2 : tst_s2;
    second_exp_addr = second_sock_rcv ? tst_addr2 : iut_addr2;

    if (sockts_iface_is_iut(&env, "iut_if"))
    {
        if (first_sock_rcv)
        {
            check_mcast_hash_collision(pco_iut, pco_tst,
                                       first_sock_vlan ? iut_if1 : iut_if,
                                       tst_s1, mcast_addr);
        }

        if (second_sock_rcv)
        {
            check_mcast_hash_collision(pco_iut, pco_tst,
                                       second_sock_vlan ? iut_if2 : iut_if,
                                       tst_s2, mcast_addr);
        }
    }

    RPC_AWAIT_IUT_ERROR(first_rcv);
    if ((rc = rpc_mcast_join(first_rcv, first_rcv_s, mcast_addr,
                             first_rcv_if->if_index, method)) != 0)
        TEST_VERDICT("Cannot join multicast group for "
                     "the first socket");
    first_joined = TRUE;

    RPC_AWAIT_IUT_ERROR(second_rcv);
    if (rpc_mcast_join(second_rcv, second_rcv_s, mcast_addr,
                       second_rcv_if->if_index, method) != 0)
        TEST_VERDICT("Cannot join multicast group for "
                     "the second socket");
    second_joined = TRUE;

    if (set_bindtodevice)
    {
        rpc_bind_to_device(first_rcv, first_rcv_s,
                           first_rcv_if->if_name);
        rpc_bind_to_device(second_rcv, second_rcv_s,
                           second_rcv_if->if_name);
    }

    if (!PARENT_LISTENER_NOT_USE)
    {
        listener_parent_in = mcast_listener_init(pco_iut, iut_if,
                                                 mcast_addr, NULL, 1);
        mcast_listen_start(pco_iut, listener_parent_in);
    }

    listener_parent_out = mcast_listener_init(pco_iut, iut_if, mcast_addr,
                                              NULL, 0);
    mcast_listen_start(pco_iut, listener_parent_out);

    if (first_sock_vlan)
    {
        if (!VLAN1_LISTENER_NOT_USE)
        {
            listener_vlan1_in = mcast_listener_init(pco_iut, iut_if1,
                                                    mcast_addr, NULL, 1);
            mcast_listen_start(pco_iut, listener_vlan1_in);
        }

        listener_vlan1_out = mcast_listener_init(pco_iut, iut_if1,
                                                 mcast_addr, NULL, 0);
        mcast_listen_start(pco_iut, listener_vlan1_out);
    }

    if (second_sock_vlan)
    {
        if (!VLAN2_LISTENER_NOT_USE)
        {
            listener_vlan2_in = mcast_listener_init(pco_iut, iut_if2,
                                                    mcast_addr, NULL, 1);
            mcast_listen_start(pco_iut, listener_vlan2_in);
        }

        listener_vlan2_out = mcast_listener_init(pco_iut, iut_if2,
                                                 mcast_addr, NULL, 0);
        mcast_listen_start(pco_iut, listener_vlan2_out);
    }

    rpc_sendto(first_snd, first_snd_s, snd_buf1, buf_len / 2,
               0, mcast_addr);
    rpc_sendto(second_snd, second_snd_s, snd_buf2, buf_len / 2,
               0, mcast_addr);

    TAPI_WAIT_NETWORK;

    RPC_GET_READABILITY(readable, first_rcv, first_rcv_s, 1);
    if (!readable)
    {
        RING_VERDICT("%s didn't receive data",
                     get_name_by_sock(first_rcv_s, first_rcv,
                                      sock_names));
        unexp_unreadable = TRUE;
    }
    else
        CHECK_RECEIVED_DATA(first_rcv, first_rcv_s, rcv_buf1,
                            first_exp_addr, "Incoming packets were "
                            "detected on %s", GET_IF_NAME(first_rcv_if));

    RPC_GET_READABILITY(readable, second_rcv, second_rcv_s, 1);
    if (!readable)
    {
        RING_VERDICT("%s didn't receive data",
                     get_name_by_sock(second_rcv_s, second_rcv,
                                      sock_names));
        unexp_unreadable = TRUE;
    }
    else
        CHECK_RECEIVED_DATA(second_rcv, second_rcv_s, rcv_buf2,
                            second_exp_addr, "Incoming packets were "
                            "detected on %s", GET_IF_NAME(second_rcv_if));

    RPC_GET_READABILITY(readable, first_snd, first_snd_s, 1);
    if (readable)
        CHECK_RECEIVED_DATA(first_snd, first_snd_s, snd_buf1,
                            unexp_addr_p, "Incoming packets were "
                            "detected on %s", GET_IF_NAME(first_snd_if));

    RPC_GET_READABILITY(readable, second_snd, second_snd_s, 1);
    if (readable)
        CHECK_RECEIVED_DATA(second_snd, second_snd_s, snd_buf2,
                            unexp_addr_p, "Incoming packets were "
                            "detected on %s", GET_IF_NAME(second_snd_if));

    if (!PARENT_LISTENER_NOT_USE)
        LISTENER_STOP(listener_parent_in, TRUE, GET_IF_NAME(iut_if));
    LISTENER_STOP(listener_parent_out, FALSE, GET_IF_NAME(iut_if));

    if (first_sock_vlan)
    {
        if (!VLAN1_LISTENER_NOT_USE)
            LISTENER_STOP(listener_vlan1_in, TRUE, GET_IF_NAME(iut_if1));
        LISTENER_STOP(listener_vlan1_out, FALSE, GET_IF_NAME(iut_if1));
    }

    if (second_sock_vlan)
    {
        if (!VLAN2_LISTENER_NOT_USE)
            LISTENER_STOP(listener_vlan2_in, TRUE, GET_IF_NAME(iut_if2));
        LISTENER_STOP(listener_vlan2_out, FALSE, GET_IF_NAME(iut_if2));
    }

    if (strcmp(action_after_send, "close") == 0)
    {
        RPC_CLOSE(pco_iut, iut_s1);
        first_joined = FALSE;
    }
    else if (strcmp(action_after_send, "drop") == 0)
    {
        RPC_AWAIT_IUT_ERROR(first_rcv);
        if ((rc = rpc_mcast_leave(first_rcv, iut_s1, mcast_addr,
                                  first_rcv_if->if_index, method)) != 0)
            TEST_VERDICT("Cannot leave multicast group for "
                         "the first socket");
        first_joined = FALSE;
    }
    else if (strcmp(action_after_send, "none") == 0)
        TEST_SUCCESS;
    else
        TEST_FAIL("Incorrect value of 'action_after_send' parameter");

    if (!second_sock_vlan)
    {
        sock_names[2].name =
          "IUT socket on parent interface after close/drop on first socket";
        sock_names[3].name =
          "TESTER socket on parent interface after close/drop on first socket";
    }
    else
    {
        sock_names[2].name =
          "IUT socket on vlan2 interface after close/drop on first socket";
        sock_names[3].name =
          "TESTER socket on vlan2 interface after close/drop on first socket";
    }

    if (!PARENT_LISTENER_NOT_USE)
        mcast_listen_start(pco_iut, listener_parent_in);

    if (first_sock_vlan && !VLAN1_LISTENER_NOT_USE)
        mcast_listen_start(pco_iut, listener_vlan1_in);

    if (second_sock_vlan && !VLAN2_LISTENER_NOT_USE)
        mcast_listen_start(pco_iut, listener_vlan2_in);

    rpc_sendto(first_snd, first_snd_s, snd_buf1, buf_len / 2,
               0, mcast_addr);
    rpc_sendto(second_snd, second_snd_s, snd_buf2, buf_len / 2,
               0, mcast_addr);

    TAPI_WAIT_NETWORK;

    if (strcmp(action_after_send, "drop") == 0)
    {
        RPC_GET_READABILITY(readable, first_rcv, first_rcv_s, 1);
        if (readable)
        {
            RING_VERDICT("%s received data",
                         get_name_by_sock(first_rcv_s, first_rcv,
                                          sock_names));
            unexp_unreadable = TRUE;
        }
    }

    RPC_GET_READABILITY(readable, second_rcv, second_rcv_s, 1);
    if (!readable)
    {
        RING_VERDICT("%s didn't receive data",
                     get_name_by_sock(second_rcv_s, second_rcv,
                                      sock_names));
        unexp_unreadable = TRUE;
    }
    else
        CHECK_RECEIVED_DATA(second_rcv, second_rcv_s, rcv_buf2,
                            second_exp_addr, "Incoming packets were "
                            "detected on %s", GET_IF_NAME(second_rcv_if));

    if (strcmp(action_after_send, "drop") == 0)
    {
        RPC_GET_READABILITY(readable, first_snd, first_snd_s, 1);
        if (readable)
            CHECK_RECEIVED_DATA(first_snd, first_snd_s, snd_buf1,
                                unexp_addr_p, "Incoming packets were "
                                "detected on %s",
                                GET_IF_NAME(first_snd_if));
    }

    RPC_GET_READABILITY(readable, second_snd, second_snd_s, 1);
    if (readable)
        CHECK_RECEIVED_DATA(second_snd, second_snd_s, snd_buf2,
                            unexp_addr_p, "Incoming packets were "
                            "detected on %s", GET_IF_NAME(second_snd_if));

    if (!PARENT_LISTENER_NOT_USE)
        LISTENER_STOP(listener_parent_in, TRUE, GET_IF_NAME(iut_if));

    if (first_sock_vlan && !VLAN1_LISTENER_NOT_USE)
    {
        if (!VLAN1_LISTENER_NOT_USE)
            LISTENER_STOP(listener_vlan1_in, TRUE, GET_IF_NAME(iut_if1));
        LISTENER_STOP(listener_vlan1_out, FALSE, GET_IF_NAME(iut_if1));
    }

    if (second_sock_vlan && !VLAN2_LISTENER_NOT_USE)
    {
        if (!VLAN2_LISTENER_NOT_USE)
            LISTENER_STOP(listener_vlan2_in, TRUE, GET_IF_NAME(iut_if2));
        LISTENER_STOP(listener_vlan2_out, FALSE, GET_IF_NAME(iut_if2));
    }

    if (!unexp_unreadable && !unexp_len && !unexp_peer)
        TEST_SUCCESS;
    else
        TEST_STOP;

cleanup:
    if (!PARENT_LISTENER_NOT_USE)
        mcast_listener_fini(pco_iut, listener_parent_in);
    mcast_listener_fini(pco_iut, listener_parent_out);

    if (first_sock_vlan)
    {
        if (!VLAN1_LISTENER_NOT_USE)
            mcast_listener_fini(pco_iut, listener_vlan1_in);
        mcast_listener_fini(pco_iut, listener_vlan1_out);
    }

    if (second_sock_vlan)
    {
        if (!VLAN2_LISTENER_NOT_USE)
            mcast_listener_fini(pco_iut, listener_vlan2_in);
        mcast_listener_fini(pco_iut, listener_vlan2_out);
    }

    if (first_joined)
        CLEANUP_MULTICAST_LEAVE(first_rcv, first_rcv_s, mcast_addr,
                                first_rcv_if->if_index, method);
    if (second_joined)
        CLEANUP_MULTICAST_LEAVE(second_rcv, second_rcv_s, mcast_addr,
                                second_rcv_if->if_index, method);

    free(rcv_buf1);
    free(rcv_buf2);
    free(snd_buf1);
    free(snd_buf2);

    if (first_sock_vlan)
    {
        if (iut_if1 != NULL)
        {
            free(iut_if1->if_name);
            free(iut_if1);
        }
        if (tst_if1 != NULL)
        {
            free(tst_if1->if_name);
            free(tst_if1);
        }
    }

    if (second_sock_vlan)
    {
        if (iut_if2 != NULL)
        {
            free(iut_if2->if_name);
            free(iut_if2);
        }
        if (tst_if2 != NULL)
        {
            free(tst_if2->if_name);
            free(tst_if2);
        }
    }

    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan1, iut_vlan1_configured);
    CLEANUP_REMOVE_VLAN(pco_iut, iut_if, vlan2, iut_vlan2_configured);
    CLEANUP_REMOVE_VLAN(pco_tst, tst_if, vlan1, tst_vlan1_configured);
    CLEANUP_REMOVE_VLAN(pco_tst, tst_if, vlan2, tst_vlan2_configured);

    tapi_cfg_free_entry(&vlan1_net_handle);
    tapi_cfg_free_entry(&vlan2_net_handle);
    tapi_cfg_free_entry(&iut_vlan1_addr_handle);
    tapi_cfg_free_entry(&tst_vlan1_addr_handle);
    tapi_cfg_free_entry(&iut_vlan2_addr_handle);
    tapi_cfg_free_entry(&tst_vlan2_addr_handle);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    if (forkexec)
        rcf_rpc_server_destroy(pco_iut2);

    TEST_END;
}
