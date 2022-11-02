/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page multicast-ip_multicast_if Usage of IP_MULTICAST_IF socket option
 
 
 *
 * @objective Check that @c IP_MULTICAST_IF socket option allows to specify
 *            the interface for outgoing multicast datagrams sent on the
 *            socket.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, section 19.5
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst1      PCO on TESTER1
 * @param pco_tst2      PCO on TESTER2
 * @param tst1_if       Interface name/index on @p pco_tst1
 * @param tst2_if       Interface name/index on @p pco_tst2
 * @param iut_if        Interface name/index on @p pco_iut
 * @param mcast_addr    Multicast address used in the test
 * @param opt_param     String that describes structure used as option value:
 *                      "addr" for plain IP address,
 *                      "{addr}" for ip_mreqn stucture with address field
 *                      equal to @p iut_addr and other fields zeroed,
 *                      "{addr index}" for ip_mreqn structure with
 *                      address equal to @p iut_addr and ifindex equal to
 *                      @p iut_if index.
 * @param connect_iut   Connect @p iut_s and use @b send() instead of @b sendto                     
 * @param packet_number     Number of datagrams to send for reliability.
 * 
 * @par Test sequence:
 * -# If address and interface index from different interfaces are going
 *    to be used, add corresponding routes on Testers.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create datagram sockets: @p iut_s on @p pco_iut, @p tst1_s on @p pco_tst1,
 *    and @p tst2_s on @p pco_tst2.
 * -# Bind @p tst1_s and @p tst2_s sockets to wildcard network address and 
 *    a particular port @p P.
 * -# Adjoin @p tst1_s on @p tst1_if and @p tst2_s on @p tst2_if
 *    to @p mcast_addr multicast group.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Check that outgoing interface is not specified for multicast datagrams
 *    (@c IP_MULTICAST_IF socket option value equals @c 0).
 * -# Fill @c IP_MULTICAST_IF option value structure with @p iut_addr,
 *    @p iut_if index or both, depending on @p opt_param value.
 * -# Check that @c IP_MULTICAST_IF option can be set, and successive
 *    @b getsockopt returns the same value.
 * -# Send @p packet_number datagrams from @p iut_s socket to @p mcast_addr.
 * -# Receive them on @p tst1_s. Verify them.
 * -# Check that @p pco_tst2 socket is not readable.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() function on @p iut_s socket with @c IP_MULTICAST_IF
 *    socket option with @a option_value = @p iut_addr2.
 * -# Send @p packet_number datagrams from @p iut_s socket to @p mcast_addr.
 * -# Check that @p pco_tst2 socket is readable, and @p pco_tst1 is not.
 * -# Receive datagrams on @p tst2_s. Verify them.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Set @c IP_MULTICAST_IF socket option value on @p iut_s to wildcard address
 *    (remove any interface previously assigned).
 * -# Check that @b getsockopt() returns wildcard address.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s, @p tst1_s and @p tst2_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_multicast_if"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define CHECK_ADDR_ON_IF(_rpcs, _addr, _if, _addr_on_if)                    \
do {                                                                        \
    char                       addr_str[INET6_ADDRSTRLEN];                  \
    inet_ntop(_addr->sa_family,                                             \
              te_sockaddr_get_netaddr(_addr),                               \
              addr_str, sizeof(addr_str));                                  \
    _addr_on_if = (cfg_get_int32(&inst,                                     \
                                 "/agent:%s/interface:%s/net_addr:%s",      \
                                 _rpcs->ta, _if->if_name,                   \
                                 addr_str) == 0);                           \
} while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut  = NULL;
    rcf_rpc_server *pco_tst1 = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    int             iut_s  = -1;
    int             tst1_s = -1;
    int             tst2_s = -1;

    int             i;

    rpc_socket_domain          domain;

    const struct if_nameindex *tst1_if = NULL;
    const struct if_nameindex *tst2_if = NULL;
    const struct if_nameindex *iut_if1 = NULL;
    const struct if_nameindex *iut_if2 = NULL;
    const struct sockaddr     *iut_addr1 = NULL;
    const struct sockaddr     *iut_addr2 = NULL;
    const struct sockaddr     *tst1_addr = NULL;
    const struct sockaddr     *tst2_addr = NULL;
    const struct sockaddr     *mcast_addr = NULL;
    struct sockaddr_storage    wildcard_addr;
    tarpc_joining_method       method;

    int                        addr_family;
    tarpc_mreqn                addr_storage;
    int                        opt_on = 1;
    socklen_t                  opt_len;

    void                      *iut_buf  = NULL;
    void                      *tst1_buf = NULL;
    void                      *tst2_buf = NULL;
    size_t                     buf_len;
    struct tarpc_mreqn         mreq;
    const char                *opt_param = NULL;
    int32_t                    inst;
    cfg_handle                 rh1 = CFG_HANDLE_INVALID;
    cfg_handle                 rh2 = CFG_HANDLE_INVALID;
    int                        route_prefix;
    int                        packet_number;
    struct sockaddr_storage    from_addr;
    socklen_t                  from_addrlen = sizeof(from_addr);
    te_bool                    addr_found;
    te_bool                    connect_iut;
    te_bool                    sock_readable; 

    mcast_listener_t listener1 = CSAP_INVALID_HANDLE;
    mcast_listener_t listener2 = CSAP_INVALID_HANDLE;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_STRING_PARAM(opt_param);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_MCAST_METHOD(method);

    domain = rpc_socket_domain_by_addr(iut_addr1);
    addr_family = addr_family_rpc2h(domain);
    opt_len = inaddr_get_size_by_domain(domain);

    CHECK_ADDR_ON_IF(pco_iut, iut_addr1, iut_if1, addr_found);

    if (!addr_found)
    {
        route_prefix = te_netaddr_get_size(addr_family) * 8;
    
        if (tapi_cfg_add_route(pco_tst1->ta, addr_family, 
                               te_sockaddr_get_netaddr(iut_addr1),
                               route_prefix, NULL, tst1_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &rh1) < 0)
        {
            TEST_FAIL("Cannot add route on Tester1");
        }
        if (tapi_cfg_add_route(pco_tst2->ta, addr_family, 
                               te_sockaddr_get_netaddr(iut_addr2),
                               route_prefix, NULL, tst2_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &rh2) < 0)
        {
            TEST_FAIL("Cannot add route on Tester2");
        }

        CFG_WAIT_CHANGES;
    }

    /* 
     * Prepare wildcard address: set port part of the address to 
     * the port of 'mcast_addr'.
     */
    memcpy(&wildcard_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));
    
    CHECK_NOT_NULL(iut_buf = sockts_make_buf_dgram(&buf_len));
    tst1_buf = te_make_buf_by_len(buf_len);
    tst2_buf = te_make_buf_by_len(buf_len);
    
    iut_s = rpc_socket(pco_iut, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_setsockopt(pco_tst1, tst1_s, RPC_SO_REUSEADDR, &opt_on);
    rpc_setsockopt(pco_tst2, tst2_s, RPC_SO_REUSEADDR, &opt_on);

    rpc_bind(pco_tst1, tst1_s, SA(&wildcard_addr));
    rpc_bind(pco_tst2, tst2_s, SA(&wildcard_addr));
    
#if 1
    rpc_setsockopt_raw(pco_tst2, tst2_s, RPC_SO_BINDTODEVICE,
                       tst2_if->if_name, IFNAMSIZ);
#endif    
    if (rpc_mcast_join(pco_tst1, tst1_s, mcast_addr, tst1_if->if_index,
                       method))
    {
        TEST_FAIL("Failed to add 'tst1_s' socket to 'mcast_addr' "
                  "multicast group");
    }

    if (rpc_mcast_join(pco_tst2, tst2_s, mcast_addr, tst2_if->if_index,
                       method))
    {
        TEST_FAIL("Failed to add 'tst2_s' socket to 'mcast_addr' "
                  "multicast group");
    }

    memset(&addr_storage, 0, sizeof(addr_storage));
    addr_storage.type = OPT_MREQN;

    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &addr_storage);
    
    if (addr_storage.address != 0)
    {
        char buf[100];

        WARN("Optlen = %d, Default value: %s", opt_len,
             inet_ntop(addr_family, 
                       &addr_storage.address, buf, 100));
        TEST_FAIL("IP_MULTICAST_IF option value is not wildcard address "
                  "by default");
    }
    
    /* Prepare IP_MULTICAST_IF option value */
    memset(&mreq, 0, sizeof(mreq));    
    mreq.type = (opt_param[0] == '{')? OPT_MREQN : OPT_IPADDR;

    if (strstr(opt_param, "addr") != NULL)
        memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr1), opt_len);
    if (strstr(opt_param, "index") != NULL)
        mreq.ifindex = iut_if1->if_index;

    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);

    memset(&addr_storage, 0, sizeof(addr_storage));
    addr_storage.type = OPT_MREQN;
    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &addr_storage);
    
    if (addr_storage.address != mreq.address)
    {
        TEST_FAIL("setsockopt() does not update the value of "
                  "IP_MULTICAST_IF socket option");
    }
    
    if (connect_iut)
    {
        struct sockaddr_storage ss;
        socklen_t               ss_len = sizeof(ss);
        
        rpc_connect(pco_iut, iut_s, mcast_addr);
        rpc_getsockname(pco_iut, iut_s, SA(&ss), &ss_len);
        WARN("connect bound iut_s to %s address",
             inet_ntoa(SIN(&ss)->sin_addr));
    }

    listener1 = mcast_listener_init(pco_iut, iut_if1, mcast_addr, NULL, 0);
    listener2 = mcast_listener_init(pco_iut, iut_if2, mcast_addr, NULL, 0);

    mcast_listen_start(pco_iut, listener1);
    mcast_listen_start(pco_iut, listener2);
    /* Make sure that CSAPs really started (ST-2264) */
    TAPI_WAIT_NETWORK;

    for (i = 0; i < packet_number; i++)
    {
        if (connect_iut)
            RPC_SEND(rc, pco_iut, iut_s, iut_buf, buf_len, 0);
        else
            RPC_SENDTO(rc, pco_iut, iut_s, iut_buf, buf_len, 0, mcast_addr);
        rc = rpc_recvfrom(pco_tst1, tst1_s, tst1_buf, buf_len, 0,
                          SA(&from_addr), &from_addrlen);

        SOCKTS_CHECK_RECV(pco_tst1, iut_buf, tst1_buf, buf_len, rc);
        RPC_CHECK_READABILITY(pco_tst2, tst2_s, FALSE);
 
        if (strcmp(opt_param, "{index}") == 0)
        {
            CHECK_ADDR_ON_IF(pco_iut, SA(&from_addr), iut_if1, addr_found);
            if (!addr_found)
            {
                char addr_str[INET6_ADDRSTRLEN];

                inet_ntop(from_addr.ss_family,
                          te_sockaddr_get_netaddr(SA(&from_addr)),
                          addr_str, sizeof(addr_str));
            
                TEST_VERDICT("Source address not present on iut_if1",
                              addr_str);
            }
        }
        else
        {
            if (!connect_iut &&
                (memcmp(te_sockaddr_get_netaddr(SA(&from_addr)), &mreq.address,
                        sizeof(struct in_addr)) != 0))
            {
                TEST_VERDICT("Source address is not equal IP_MULTICAST_IF value");
            }
        }
    }

    rc = mcast_listen_stop(pco_iut, listener1, NULL);
    if (rc == packet_number)
        RING_VERDICT("All multicast packets were detected by system on "
                     "iut_if1 for the first sending");
    rc = mcast_listen_stop(pco_iut, listener2, NULL);
    if (rc > 0)
        RING_VERDICT("Multicast packets were detected by system on "
                     "iut_if2 for the first sending");

    /* Change interface for outgoing multicast datagrams */
    if (strstr(opt_param, "addr") != NULL)
        memcpy(&mreq.address, te_sockaddr_get_netaddr(iut_addr2),
               sizeof(struct in_addr));
    if (strstr(opt_param, "index") != NULL)
        mreq.ifindex = iut_if2->if_index;

    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);

    mcast_listen_start(pco_iut, listener1);
    mcast_listen_start(pco_iut, listener2);
    /* Make sure that CSAPs really started (ST-2264) */
    TAPI_WAIT_NETWORK;

    for (i = 0; i < packet_number; i++)
    {
        if (connect_iut)
            RPC_SEND(rc, pco_iut, iut_s, iut_buf, buf_len, 0);
        else
            RPC_SENDTO(rc, pco_iut, iut_s, iut_buf, buf_len, 0, mcast_addr);

        RPC_GET_READABILITY(sock_readable, pco_tst2, tst2_s, 1);
        if (connect_iut)
        {
            if (!sock_readable)
            {
                WARN("Connect() bound the iut_s to address on other interface,"
                     " so datagram could not be received on Tester2");
            }
#if 0        
            else
            {
                TEST_VERDICT("Datagram has been transferred despite connect() "
                             "bound iut_s to address on other interface");
            }
#endif        
        }
        else
        {
            rc = rpc_recvfrom(pco_tst2, tst2_s, tst2_buf, buf_len, 0,
                              SA(&from_addr), &from_addrlen);
            SOCKTS_CHECK_RECV(pco_tst2, iut_buf, tst2_buf, buf_len, rc);

            RPC_CHECK_READABILITY(pco_tst1, tst1_s, FALSE);

            if (strcmp(opt_param, "{index}") == 0)
            {
                CHECK_ADDR_ON_IF(pco_iut, SA(&from_addr), iut_if2, addr_found);
                if (!addr_found)
                {
                    TEST_VERDICT("Source address not present on iut_if2");
                }
            }
            else
            {
                if (!connect_iut && 
                    (memcmp(te_sockaddr_get_netaddr(SA(&from_addr)), &mreq.address,
                            sizeof(struct in_addr)) != 0))
                {
                    TEST_VERDICT("Source address is not equal to "
                                 "IP_MULTICAST_IF value");
                }
            }
        }
    }

    rc = mcast_listen_stop(pco_iut, listener1, NULL);
    if (rc > 0)
        RING_VERDICT("Multicast packets were detected by system on "
                     "iut_if1 for the second sending");
    rc = mcast_listen_stop(pco_iut, listener2, NULL);
    if (rc == packet_number)
        RING_VERDICT("All multicast packets were detected by system on "
                     "iut_if2 for the second sending");

    /* Reset IP_MULTICAST_IF option with setting wildcard address */    
    mreq.address = 0;
    mreq.ifindex = 0;

    rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);

    /* Check that the value is really updated */
    memset(&addr_storage, 0, sizeof(addr_storage));
    addr_storage.type = OPT_MREQN;
    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &addr_storage);

    if (addr_storage.address != 0)
    {
        TEST_FAIL("setsockopt() does not update the value of "
                  "IP_MULTICAST_IF socket option to wildcard address");
    }

    if (mcast_leave(pco_tst1, tst1_s, mcast_addr, tst1_if->if_index) != 0 ||
        mcast_leave(pco_tst2, tst2_s, mcast_addr, tst2_if->if_index) != 0)
    {
        TEST_FAIL("Leaving multicast group failed");
    }
    
    TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener1);
    mcast_listener_fini(pco_iut, listener2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (rh1 != CFG_HANDLE_INVALID)
        cfg_del_instance(rh1, FALSE);
    if (rh2 != CFG_HANDLE_INVALID)
        cfg_del_instance(rh2, FALSE);

    free(iut_buf);
    free(tst1_buf);
    free(tst2_buf);
    
    TEST_END;
}

