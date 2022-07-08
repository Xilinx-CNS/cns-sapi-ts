/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page multicast-ip_add_drop_membership Usage of IP_ADD_MEMBERSHIP/IP_DROP_MEMBERSHIP socket options
 *
 * @objective Check that @c IP_ADD_MEMBERSHIP socket option joins and
 *            IP_DROP_MEMBERSHIP unjoins a multicast group on a specified
 *            local interface.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 19.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on TESTER1
 * @param iut_ifname1   Network interface on @p pco_iut connected
 *                      to @p pco_tst1
 * @param tst1_if       Interface on TESTER1 connected to IUT
 * @param pco_tst2      PCO on TESTER2
 * @param iut_ifname2   Network interface on @p pco_iut connected
 *                      to @p pco_tst2
 * @param tst2_if       Interface on TESTER2 connected to IUT                     
 * @param mcast_addr    Multicast IP address
 * @param use_mreq      Set options using struct ip_mreq instead of ip_mreqn
 * @param use_route     Set interface for outgoing multicast datagrams
 *                      using a route instead of IP_MULTICAST_IF option
 * @param sock_func     Socket creation function.
 *
 * @par Test sequence:
 * -# Create datagram sockets: @p iut_s socket on @p pco_iut,
 *    @p tst1_s and @p tst2_s on @p pco_tst1.
 * -# Obtain an IPv4 address @p iut_addr1 of @p iut_ifname1 interface. 
 * -# Obtain an IPv4 address @p iut_addr2 of @p iut_ifname2 interface.
 * -# Create a buffer @p tst1_buf of @p tst1_buf_len bytes.
 * -# Create a buffer @p tst2_buf of @p tst2_buf_len bytes.
 * -# Create a buffer @p local_buf of @p tst1_buf_len + @p tst2_buf_len
 *    bytes.
 * -# Bind @p iut_s socket to wildcard network address and a particular 
 *    port @p P.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Check that non-joined socket does not receive multicast datagrams:
 *     -# Send @p tst1_buf from @p tst1_s socket to multicast address
 *        @p mcast_addr (it should not be all-hosts multicast address).
 *     -# Send @p tst2_buf from @p tst2_s socket to @p mcast_addr.
 *     -# Check that @p iut_s socket is not readable.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() function with @c IP_ADD_MEMBERSHIP socket option
 *    on @p iut_s socket adjoining it to @p mcast_addr multicast group on
 *    @p iut_ifname1 interface. Check that the function returns @c 0.
 * -# Check that multicast datagrams are received on joined interface only:
 *     -# Send @p tst2_buf from @p tst2_s socket to @p mcast_addr.
 *     -# Send @p tst1_buf from @p tst1_s socket to @p mcast_addr.
 *     -# Check that @p iut_s socket is readable.
 *     -# Call @b recv() on @p iut_s with @p local_buf as destination buffer.
 *     -# Check that exactly @p tst1_buf_len bytes were received.
 *     -# Verify them to the contents of @p tst1_buf.
 *     -# Check that @p iut_s socket is not readable.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() function with @c IP_ADD_MEMBERSHIP socket option
 *    on @p iut_s socket adjoining it to @p mcast_addr multicast group on
 *    @p iut_ifname2 interface. Check that the function returns @c 0.
 * -# Check that now both interfaces receive multicast datagrams:
 *     -# Send @p tst2_buf from @p tst2_s socket to @p mcast_addr.
 *     -# Send @p tst1_buf from @p tst1_s socket to @p mcast_addr.
 *     -# Check that @p iut_s socket is readable.
 *     -# Call @b recv() on @p iut_s with @p local_buf as destination buffer.
 *     -# Check that exactly @p tst2_buf_len bytes were received.
 *     -# Verify then to the content of @p tst2_buf buffer.
 *     -# Check that @p iut_s socket is readable.
 *     -# Call @b recv() on @p iut_s with @p local_buf as destination buffer.
 *     -# Check that the function returns @p tst1_buf_len.
 *     -# Check that the last @p tst1_buf_len bytes of @p local_buf are
 *        the same as the content of @p tst1_buf buffer.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Check that multicast datagrams for destination address mapped to
 *    the same link layer address as @p mcast_addr are not received:
 *     -# Copy @p mcast_addr to @p mcast_addr_aux.
 *     -# Change lower 2 bits in @p mcast_addr_aux.
 *     -# Send @p tst1_buf from @p tst1_s socket to @p mcast_addr_aux.
 *     -# Check that @p iut_s socket is not readable.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() function with @c IP_DROP_MEMBERSHIP socket option
 *    on @p iut_s socket making it unjoin @p mcast_addr multicast group on
 *    @p iut_ifname1 interface. Chech that the function returns 0.
 * -# Check that @p iut_s receives multicast traffic from @p pco_tst2 only:
 *     -# Send @p tst1_buf from @p tst1_sock socket to @p mcast_addr.
 *     -# Send @p tst2_buf from @p tst2_sock socket to @p mcast_addr.
 *     -# Check that @p pco_iut socket is readable.
 *     -# Receive data on @p pco_iut into @p local_buf.
 *     -# Check that the function returns @p tst2_buf_len.
 *     -# Check that the first @p tst2_buf_len bytes of @p local_buf are the
 *        same as @p tst2_buf buffer.
 *     -# Check that @p pco_iut socket is not readable.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() function with @c IP_DROP_MEMBERSHIP socket option
 *    on @p pco_iut socket leaving @p mcast_addr multicast group on
 *    @p iut_ifname2 interface.
 * -# Check that @p iut_s does not receive multicast traffic:
 *     -# Send @p tst1_buf from @p tst1_sock socket using as the destination
 *        address IPv4 multicast address @p mcast_addr
 *     -# Send @p tst2_buf from @p tst2_sock socket using as the destination
 *        address @p mcast_addr.
 *     -# Check that @p pco_iut socket is not readable.
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete all the buffers.
 * -# Close @p iut_s, @p tst1_s and @p tst2_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_add_drop_membership"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"

#define VERDICT_INTERFACES_INDISTINGUISHED \
     "Non-joined interface receives multicast traffic"  \
     " together with joined one"

int
main(int argc, char *argv[])
{
    rpc_socket_domain           domain;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    struct tarpc_mreqn mrequest;
    struct group_req   gr_req;
    int                optname;
    void              *opt_ptr;

    int             iut_s = -1;
    int             tst1_s = -1;
    int             tst2_s = -1;

    const struct sockaddr       *mcast_addr = NULL;
    struct sockaddr_storage      mcast_addr_aux;

    const struct if_nameindex   *iut_ifname1 = NULL;
    const struct sockaddr       *iut_addr1 = NULL;

    const struct if_nameindex   *iut_ifname2 = NULL;
    const struct sockaddr       *iut_addr2 = NULL;

    const struct if_nameindex   *tst1_if = NULL;
    const struct sockaddr       *tst1_addr = NULL;

    const struct if_nameindex   *tst2_if = NULL;
    const struct sockaddr       *tst2_addr = NULL;

    struct sockaddr_storage      iut_addr_to_bind;
    struct sockaddr_storage      peer_addr;
    socklen_t                    peer_addrlen;

    int                          dgrams_received;

    void           *tst1_buf = NULL;
    void           *tst2_buf = NULL;
    void           *local_buf = NULL;
    size_t          tst1_buf_len;
    size_t          tst2_buf_len;

    rpc_msghdr       msg;
    struct rpc_iovec vector;

    const char     *struct_to_use;

    cfg_handle      route_handle1 = CFG_HANDLE_INVALID;
    cfg_handle      route_handle2 = CFG_HANDLE_INVALID;
    te_bool         use_route;
    te_bool         bug_caught = FALSE;

    mcast_listener_t listener1 = CSAP_INVALID_HANDLE;
    mcast_listener_t listener2 = CSAP_INVALID_HANDLE;
    int              detected1 = 0;
    int              detected2 = 0;

    te_bool             use_zc = FALSE;
    sockts_socket_func  sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_IF(iut_ifname1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_IF(iut_ifname2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_IF(tst1_if);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_IF(tst2_if);

    TEST_GET_STRING_PARAM(struct_to_use);
    TEST_GET_BOOL_PARAM(use_route);
    TEST_GET_BOOL_PARAM(use_zc);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    domain = rpc_socket_domain_by_addr(iut_addr1);

    CHECK_NOT_NULL(tst1_buf = sockts_make_buf_dgram(&tst1_buf_len));
    CHECK_NOT_NULL(tst2_buf = sockts_make_buf_dgram(&tst2_buf_len));
    CHECK_NOT_NULL(local_buf = 
            te_make_buf_by_len(tst1_buf_len + tst2_buf_len));
    vector.iov_base = local_buf;

    VERB("ifname 1: %s; ifindex 1: %d;     ifname 2 %s, ifindex 2: %d", 
            iut_ifname1->if_name, iut_ifname1->if_index,
            iut_ifname2->if_name, iut_ifname2->if_index);

    iut_s = sockts_socket(sock_func, pco_iut, domain,
                          RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    /* 
     * Bind @p iut_s socket to wildcard network address and 
     * a particular port @p P;
     */
    assert(sizeof(iut_addr_to_bind) >= te_sockaddr_get_size(mcast_addr));
    memcpy(&iut_addr_to_bind, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(SA(&iut_addr_to_bind));

    rpc_bind(pco_iut, iut_s, SA(&iut_addr_to_bind));

    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    if (use_route)
    {
        int             af;
        int             route_prefix;

        af = addr_family_rpc2h(sockts_domain2family(domain));
        route_prefix = te_netaddr_get_size(af) * 8;

        if (tapi_cfg_add_route(pco_tst1->ta, af,
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, NULL, tst1_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &route_handle1) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address on Tester1");
        }

        if (tapi_cfg_add_route(pco_tst2->ta, af,
                               te_sockaddr_get_netaddr(mcast_addr),
                               route_prefix, NULL, tst2_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &route_handle2) < 0)
        {
            TEST_FAIL("Cannot add route to multicast address on Tester2");
        }

        CFG_WAIT_CHANGES;
    }
    else
    {
        tarpc_mreqn     mreq;

        memset(&mreq, 0, sizeof(mreq));
        mreq.type = OPT_IPADDR;

        memcpy(&mreq.address, te_sockaddr_get_netaddr(tst1_addr),
               sizeof(struct in_addr));
        rpc_setsockopt(pco_tst1, tst1_s, RPC_IP_MULTICAST_IF, &mreq);

        memcpy(&mreq.address, te_sockaddr_get_netaddr(tst2_addr),
               sizeof(struct in_addr));
        rpc_setsockopt(pco_tst2, tst2_s, RPC_IP_MULTICAST_IF, &mreq);
    }

    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst1, iut_ifname1, tst1_s,
                               mcast_addr);
    CHECK_MCAST_HASH_COLLISION(pco_iut, pco_tst2, iut_ifname2, tst2_s,
                               mcast_addr);

    listener1 = mcast_listener_init(pco_iut, iut_ifname1, mcast_addr,
                                    NULL, 1);
    listener2 = mcast_listener_init(pco_iut, iut_ifname2, mcast_addr,
                                    NULL, 1);

#define ADD_DROP_MEMBERSHIP_SEQ(_add_drop, _addr, _if) \
do {                                                                       \
    if (strcmp(struct_to_use, "group_req") != 0)                           \
    {                                                                      \
        memset(&mrequest, 0, sizeof(mrequest));                            \
                                                                           \
        memcpy(&mrequest.multiaddr, te_sockaddr_get_netaddr(mcast_addr),   \
               sizeof(struct in_addr));                                    \
                                                                           \
        if (strcmp(struct_to_use, "mreq") != 0)                            \
        {                                                                  \
            mrequest.type = OPT_MREQ;                                      \
            memcpy(&mrequest.address, te_sockaddr_get_netaddr(_addr),      \
                   sizeof(struct in_addr));                                \
        }                                                                  \
        else                                                               \
        {                                                                  \
            mrequest.type = OPT_MREQN;                                     \
            mrequest.ifindex = _if->if_index;                              \
        }                                                                  \
        optname = (strcmp(_add_drop, "add") == 0) ? RPC_IP_ADD_MEMBERSHIP :\
                                                    RPC_IP_DROP_MEMBERSHIP;\
        opt_ptr = &mrequest;                                               \
    }                                                                      \
    else                                                                   \
    {                                                                      \
        memset(&gr_req, 0, sizeof(gr_req));                                \
        memcpy(&gr_req.gr_group, mcast_addr, sizeof(struct sockaddr));     \
        gr_req.gr_interface = _if->if_index;                               \
                                                                           \
        optname = (strcmp(_add_drop, "add") == 0) ? RPC_MCAST_JOIN_GROUP : \
                                                    RPC_MCAST_LEAVE_GROUP; \
        opt_ptr = &gr_req;                                                 \
    }                                                                      \
    RPC_AWAIT_IUT_ERROR(pco_iut);                                          \
    rc = rpc_setsockopt(pco_iut, iut_s, optname, opt_ptr);                 \
    if (rc != 0)                                                           \
    {                                                                      \
        TEST_VERDICT("Action %s membership using %s structure failed "     \
                     "with %r error", _add_drop, struct_to_use,            \
                     RPC_ERRNO(pco_iut));                                  \
    }                                                                      \
    MSLEEP(500);                                                           \
} while(0)

    ADD_DROP_MEMBERSHIP_SEQ("add", iut_addr1, iut_ifname1);

    if (!use_zc)
    {
        mcast_listen_start(pco_iut, listener1);
        mcast_listen_start(pco_iut, listener2);
    }
    RPC_SENDTO(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0, mcast_addr);
    RPC_SENDTO(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0, mcast_addr);

    if (!use_zc)
    {
        rc = mcast_listen_stop(pco_iut, listener1, NULL);
        if (rc > 0)
            detected1++;
        rc = mcast_listen_stop(pco_iut, listener2, NULL);
        if (rc > 0)
            detected2++;
    }

#define IADM_RECEIVE_DGRAMS(__received)                                 \
do {                                                                    \
    int             i;                                                  \
    te_bool         socket_readable;                                    \
    te_bool         detect;                                             \
                                                                        \
    __received = 0;                                                     \
    RPC_GET_READABILITY(socket_readable, pco_iut, iut_s, 1);            \
                                                                        \
    for (i = 0; i < 2 && socket_readable; i++)                          \
    {                                                                   \
        detect = FALSE;                                                 \
        peer_addrlen = sizeof(peer_addr);                               \
        if (use_zc)                                                     \
        {                                                               \
            memset(&msg, 0, sizeof(msg));                               \
            vector.iov_len = vector.iov_rlen = tst1_buf_len +           \
                                               tst2_buf_len;            \
            msg.msg_iov = &vector;                                      \
            msg.msg_iovlen = msg.msg_riovlen = 1;                       \
            msg.msg_name = &peer_addr;                                  \
            msg.msg_namelen = msg.msg_rnamelen = peer_addrlen;          \
            RPC_AWAIT_IUT_ERROR(pco_iut);                               \
            rc = rpc_simple_zc_recv_acc(pco_iut, iut_s, &msg, 0);       \
            if (rc == -1)                                               \
            {                                                           \
                CHECK_RPC_ERRNO(pco_iut, RPC_ENOTEMPTY,                 \
                                "onload_zc_recv() returns %d, but",     \
                                rc);                                    \
                rc = rpc_simple_zc_recv(pco_iut, iut_s, &msg, 0);       \
                detect = TRUE;                                          \
            }                                                           \
            peer_addrlen = msg.msg_namelen;                             \
        }                                                               \
        else                                                            \
        {                                                               \
            rc = rpc_recvfrom(pco_iut, iut_s, local_buf,                \
                              tst1_buf_len + tst2_buf_len, 0,           \
                              SA(&peer_addr), &peer_addrlen);           \
        }                                                               \
        if (te_sockaddrcmp(SA(&peer_addr), peer_addrlen, tst1_addr,     \
                           te_sockaddr_get_size(tst1_addr)) == 0)       \
        {                                                               \
            if (detect)                                                 \
                detected1++;                                            \
            __received |= 1;                                            \
            if ((unsigned)rc != tst1_buf_len)                           \
            {                                                           \
                TEST_FAIL("Wrong size of datagram from Tester1");       \
            }                                                           \
            if (memcmp(local_buf, tst1_buf, rc) != 0)                   \
                TEST_FAIL("Received buffer differ from sent one");      \
            if (i == 1)                                                 \
                WARN("Datagram was sent earlier than another one,"      \
                     " but received later");                            \
        }                                                               \
        else if (te_sockaddrcmp(SA(&peer_addr), peer_addrlen, tst2_addr,\
                                te_sockaddr_get_size(tst2_addr)) == 0)  \
        {                                                               \
            if (detect)                                                 \
                detected2++;                                            \
            __received |= 2;                                            \
            if ((unsigned)rc != tst2_buf_len)                           \
            {                                                           \
                TEST_FAIL("Wrong size of datagram from Tester2");       \
            }                                                           \
            if (memcmp(local_buf, tst2_buf, rc) != 0)                   \
                TEST_FAIL("Received buffer differ from sent one");      \
        }                                                               \
        else                                                            \
        {                                                               \
            TEST_FAIL("Received data from unexpected address");         \
        }                                                               \
        RPC_GET_READABILITY(socket_readable, pco_iut, iut_s, 1);        \
    }                                                                   \
    if (detected1 == 1)                                                 \
        RING_VERDICT("Multicast packet was detected by system on "      \
                     "iut_ifname1");                                    \
    if (detected2 == 1)                                                 \
        RING_VERDICT("Multicast packet was detected by system on "      \
                     "iut_ifname2");                                    \
} while(0)

    IADM_RECEIVE_DGRAMS(dgrams_received);

    /* 
     * dgram_received has first bit set if IUT has received a datagram
     * from Tester1, and 2nd bit set if IUT received a datagram from Tester2.
     */
    if (dgrams_received == 3)
    {
        /* IUT received datagrams from both Testers */
        ERROR_VERDICT(VERDICT_INTERFACES_INDISTINGUISHED);
        bug_caught = TRUE;
    }
    else if (dgrams_received == 0)
    {
        TEST_FAIL("No data were received");
    }

    /*
     * Add membership on second interface
     */
    ADD_DROP_MEMBERSHIP_SEQ("add", iut_addr2, iut_ifname2);

    if (!use_zc)
    {
        mcast_listen_start(pco_iut, listener1);
        mcast_listen_start(pco_iut, listener2);
    }
    RPC_SENDTO(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0, mcast_addr);
    RPC_SENDTO(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0, mcast_addr);

    TAPI_WAIT_NETWORK;
    if (!use_zc)
    {
        rc = mcast_listen_stop(pco_iut, listener1, NULL);
        if (rc > 0)
            detected1++;
        rc = mcast_listen_stop(pco_iut, listener2, NULL);
        if (rc > 0)
            detected2++;
    }

    IADM_RECEIVE_DGRAMS(dgrams_received);

    if ((dgrams_received & 1) == 0)
    {
        TEST_VERDICT("Cannot receive datagram from Tester1");
    }
    if ((dgrams_received & 2) == 0)
    {
        TEST_VERDICT("Cannot receive datagram from Tester2");
    }

    memcpy(&mcast_addr_aux, mcast_addr, te_sockaddr_get_size(mcast_addr));

    if (!use_zc)
    {
        mcast_listen_start(pco_iut, listener1);
        mcast_listen_start(pco_iut, listener2);
    }
    /* Change two lower bits in first byte of network address */
    ((uint8_t *)te_sockaddr_get_netaddr(SA(&mcast_addr_aux)))[0] ^= 3;

    RPC_SENDTO(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0,
               CONST_SA(&mcast_addr_aux)); 

    TAPI_WAIT_NETWORK;
    rc = mcast_listen_stop(pco_iut, listener1, NULL);
    if (rc > 0 && detected1 == 0)
    {
        detected1 = 1;
        RING_VERDICT("Multicast packet was detected by system on "
                     "iut_ifname1");
    }
    rc = mcast_listen_stop(pco_iut, listener2, NULL);
    if (rc > 0 && detected2 == 0)
    {
        detected2 = 1;
        RING_VERDICT("Multicast packet was detected by system on "
                     "iut_ifname2");
    }

    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

   /*
     * Drop membership on first iface
     */
    ADD_DROP_MEMBERSHIP_SEQ("drop", iut_addr1, iut_ifname1);

    if (!use_zc)
    {
        mcast_listen_start(pco_iut, listener1);
        mcast_listen_start(pco_iut, listener2);
    }
    RPC_SENDTO(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0, mcast_addr); 
    RPC_SENDTO(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0, mcast_addr);

    TAPI_WAIT_NETWORK;
    if (!use_zc)
    {
        rc = mcast_listen_stop(pco_iut, listener1, NULL);
        if (rc > 0)
            detected1++;
        rc = mcast_listen_stop(pco_iut, listener2, NULL);
        if (rc > 0)
            detected2++;
    }

    /* 
     * Check that appropriate data received from second interace 
     */
    IADM_RECEIVE_DGRAMS(dgrams_received);

    if (dgrams_received == 3 && !bug_caught)
    {
        /* IUT received datagrams from both Testers */
        ERROR_VERDICT(VERDICT_INTERFACES_INDISTINGUISHED);
        bug_caught = TRUE;
    }
    else if (dgrams_received == 0)
    {
        TEST_VERDICT("IP_DROP_MEMBERSHIP set on iut_if1, "
                     "but iut_if2 has also left the group");
    }

    /*
     * Drop membership on second iface
     */
    ADD_DROP_MEMBERSHIP_SEQ("drop", iut_addr2, iut_ifname2);

    mcast_listen_start(pco_iut, listener1);
    mcast_listen_start(pco_iut, listener2);

    RPC_SENDTO(rc, pco_tst1, tst1_s, tst1_buf, tst1_buf_len, 0, mcast_addr); 
    RPC_SENDTO(rc, pco_tst2, tst2_s, tst2_buf, tst2_buf_len, 0, mcast_addr);

    TAPI_WAIT_NETWORK;
    rc = mcast_listen_stop(pco_iut, listener1, NULL);

    /**
     * DROP results in non-receiving the multicast packets for sure
     * only for interfaces that belong to IUT network in environment.
     * See ST-2191
     */
    if (rc > 0 && detected1 == 0 &&
        sockts_iface_is_iut(&env, "iut_ifname1"))
    {
        detected1 = 1;
        TEST_VERDICT("Multicast packet was detected by system "
                     "after drop");
    }
    rc = mcast_listen_stop(pco_iut, listener2, NULL);
    if (rc > 0 &&
        sockts_iface_is_iut(&env, "iut_ifname2"))
    {
        RING_VERDICT("Multicast packet was detected by system on "
                     "after drop");
    }

    RPC_CHECK_READABILITY(pco_iut, iut_s, FALSE);

    if (bug_caught)
    {
        TEST_FAIL("Bug detected: non-joined interface caught "
                  "multicast datagrams");
    }

    TEST_SUCCESS;

cleanup:
    /* First of all, drop multicast filter on NIC */
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    /* next, remove routes */
    if (route_handle1 != CFG_HANDLE_INVALID)
        tapi_cfg_del_route(&route_handle1);
    if (route_handle2 != CFG_HANDLE_INVALID)
        tapi_cfg_del_route(&route_handle2);

    mcast_listener_fini(pco_iut, listener1);
    mcast_listener_fini(pco_iut, listener2);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    TEST_END;
}
