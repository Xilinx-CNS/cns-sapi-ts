/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Multicasting in IP
 */

/** @page multicast-mcast_src_address Source address for multicasting datagram choice.
 *
 * @objective Test source address setting methods priorities: @b bind()
 *            function, @c IP_MULTICAST_IF socket option, and route
 *            with specified source address.
 *
 * @type Conformance.
 *
 * @param pco_iut               PCO on IUT
 * @param iut_if1               Interface on IUT
 * @param iut_if2               Another interface on IUT
 * @param pco_tst1              PCO on Tester1 to which packets from
 *                              @p pco_iut could be sent through @p iut_if1
 * @param tst1_if               Interface on Tester1
 * @param pco_tst2              PCO on Tester2 to which packets from
 *                              @p pco_iut could be sent through @p iut_if2
 * @param tst2_if               Interface on Tester2
 * @param iut_addr              Address on IUT
 * @param alien_addr            Alien address (which is added on @p iut_if2
 *                              interface)
 * @param mcast_addr            Multicast address
 * @param first_competitor      Method used for @p iut_addr source address
 *                              setting
 * @param second_competitor     Method used for @p alien_addr source address
 *                              setting
 * @param connect_iut           Connect @p iut_s before sending or not
 * @param same_dev              Addresses on the same device are tested or
                                not
 * @param packet_number         Number of datagrams to send for reliability
 * @param join_method           Multicast group joining method
 *
 * @par Scenario:
 *
 * -# Make result forecast:
 *     -# Priorities when determining outgoing interface (on Linux):
 *        @c IP_MULTICAST_IF > @b bind() > route.
 *     -# Priorities when determining source address (on Linux):
 *        @b bind() > @c IP_MULTICAST_IF > route.
 * -# Create datagram sockets: @p iut_s on @p pco_iut
 *    and @p tst1_s on @p pco_tst1. If @p same_dev is @c FALSE,
 *    open @p tst2_s on @p pco_tst2 too.
 * -# Set "competitors" for @p iut_addr and @p alien_addr (@b bind(),
 *    @c IP_MULTICAST_IP or a route with such a source address).
 * -# Make @p tst1_s and, if present, @p tst2_s joined multicast group
 *    with address @p mcast_addr.
 * -# Bind it/them to @p mcast_addr.
 * -# Add a route to @p alien_addr on Tester1, and, if present, on
 *    Tester2. It is necessary, because otherwise tester kernels will
 *    drop the datagram.
 * -# Repeat @p packet_number times:
 *     -# Send a datagram from @p iut_s to @p mcast_addr.
 *     -# Wait 100 milliseconds.
 *     -# Try to receive it on Tester1, and, if present, on Tester2.
 *     -# Check that the result corresponds the forecast.
 * -# Close sockets, delete routes.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/mcast_src_address"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_cfg.h"
#include "mcast_lib.h"
#include "multicast.h"

#define CHECK_TIMEOUT 2000

#define PACKET_NAME_LEN     30

#define METHOD_BIND            1
#define METHOD_ROUTE           2
#define METHOD_IP_MULTICAST_IF 3
#define SRC_ADDR_SETTING_METHODS {"bind", METHOD_BIND}, \
    {"route", METHOD_ROUTE}, \
    {"ip_multicast_if", METHOD_IP_MULTICAST_IF}

#define SET_COMPETITOR(_param, _addr, _if) \
do {                                                                      \
    if (_param == METHOD_BIND)                                            \
    {                                                                     \
        rpc_bind(pco_iut, iut_s, _addr);                                  \
    }                                                                     \
    else if (_param == METHOD_ROUTE)                                      \
    {                                                                     \
        if (tapi_cfg_add_route(pco_iut->ta, addr_family,                  \
                               te_sockaddr_get_netaddr(mcast_addr),       \
                               route_prefix, NULL, _if->if_name,          \
                               te_sockaddr_get_netaddr(_addr),            \
                               0, 0, 0, 0, 0, 0, &rh0) != 0)              \
        {                                                                 \
            TEST_FAIL("Cannot add route to multicast address on IUT");    \
        }                                                                 \
    }                                                                     \
    else if (_param == METHOD_IP_MULTICAST_IF)                            \
    {                                                                     \
        memset(&mreq, 0, sizeof(mreq));                                   \
        mreq.type = OPT_IPADDR;                                           \
        memcpy(&mreq.address, te_sockaddr_get_netaddr(_addr),             \
               sizeof(struct in_addr));                                   \
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_IF, &mreq);       \
    }                                                                     \
    else                                                                  \
    {                                                                     \
        TEST_FAIL("Unknown parameter: %s", _param);                       \
    }                                                                     \
} while (0)

const char *
get_method_name(int method)
{
    static struct param_map_entry map[] = {SRC_ADDR_SETTING_METHODS,
                                           {NULL, 0}};

    struct param_map_entry *p = map;

    while (p->str_val != NULL)
    {
        if (p->num_val == method)
            return p->str_val;
        p++;
    }
    
    return "UNKNOWN";
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;

    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;

    const struct sockaddr      *mcast_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *alien_addr = NULL;
    struct sockaddr_storage     from_addr;
    struct sockaddr_storage     bind_addr;

    rpc_socket_domain           addr_domain;
    rpc_socket_addr_family      addr_family;
    socklen_t                   from_addrlen = sizeof(from_addr);
    int                         route_prefix;
    struct tarpc_mreqn          mreq;

    int                    iut_s = -1;
    int                    tst1_s = -1;
    int                    tst2_s = -1;

    int                    i;

    char                  *sendbuf = NULL;
    char                  *recvbuf = NULL;
    int                    data_len;

    cfg_handle             ah = CFG_HANDLE_INVALID;
    cfg_handle             rh0 = CFG_HANDLE_INVALID;
    cfg_handle             rh1 = CFG_HANDLE_INVALID;
    cfg_handle             rh2 = CFG_HANDLE_INVALID;
    cfg_handle             rh3 = CFG_HANDLE_INVALID;

    int                         packet_number;

    int                         first_competitor;
    int                         second_competitor;

    /* Whether first competitor's source address is expected */
    te_bool                     first_src_addr;
    /* Whether first competitor's outgoing interface is expected */
    te_bool                     first_out_if;

    te_bool                     connect_iut;
    te_bool                     same_dev = TRUE;
    tarpc_joining_method        join_method;

    mcast_listener_t listener1 = CSAP_INVALID_HANDLE;
    mcast_listener_t listener2 = CSAP_INVALID_HANDLE;

    struct sockaddr    *saved_addrs = NULL;
    int                *saved_prefixes = NULL;
    te_bool            *saved_broadcasts = NULL;
    int                 saved_count = 0;
    te_bool             saved_all = FALSE;

    te_bool is_failed = FALSE;

    char packet_name[PACKET_NAME_LEN] = { 0, };

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR_NO_PORT(alien_addr);
    TEST_GET_ADDR(pco_tst1, mcast_addr);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_INT_PARAM(data_len);
    TEST_GET_INT_PARAM(packet_number);
    TEST_GET_ENUM_PARAM(first_competitor, SRC_ADDR_SETTING_METHODS);
    TEST_GET_ENUM_PARAM(second_competitor, SRC_ADDR_SETTING_METHODS);
    TEST_GET_BOOL_PARAM(connect_iut);
    TEST_GET_BOOL_PARAM(same_dev);
    TEST_GET_MCAST_METHOD(join_method);

    CHECK_RC(tapi_cfg_sys_set_int(pco_tst1->ta, 0, NULL,
                                  "net/ipv4/conf:%s/rp_filter",
                                  tst1_if->if_name));
    CHECK_RC(tapi_cfg_sys_set_int(pco_tst1->ta, 0, NULL,
                                  "net/ipv4/conf:all/rp_filter"));

    if (!same_dev)
    {
        TEST_GET_PCO(pco_tst2);
        TEST_GET_IF(tst2_if);
        CHECK_RC(tapi_cfg_sys_set_int(pco_tst2->ta, 0, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      tst2_if->if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_tst2->ta, 0, NULL,
                                      "net/ipv4/conf:all/rp_filter"));
    }

    addr_domain = rpc_socket_domain_by_addr(iut_addr);
    addr_family = addr_family_rpc2h(sockts_domain2family(addr_domain));
    route_prefix = te_netaddr_get_size(addr_family) * 8;

    sendbuf = te_make_buf_by_len(data_len);
    CHECK_NOT_NULL(recvbuf = malloc(data_len));

    te_sockaddr_set_port(SA(alien_addr), te_sockaddr_get_port(iut_addr));

    if (!same_dev)
        CHECK_RC(tapi_cfg_save_del_if_ip4_addresses(pco_iut->ta,
                                                    iut_if2->if_name,
                                                    NULL, FALSE,
                                                    &saved_addrs,
                                                    &saved_prefixes,
                                                    &saved_broadcasts,
                                                    &saved_count));

    saved_all = TRUE;

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if2->if_name,
                                           alien_addr, 24, FALSE, &ah));

    /*
     * Determine whether source address on @p iut_if1 (@p iut_addr) or on
     * @p iut_if2 (@p alien_addr) should be used: bind() has
     * the topmost priority, IP_MULTICAST_IF is the second,
     * route is the last.
     */
    first_src_addr = (first_competitor == METHOD_BIND
                      && second_competitor != first_competitor) ||
                     (first_competitor == METHOD_IP_MULTICAST_IF &&
                      second_competitor == METHOD_ROUTE);

    /*
     * Determine whether @p iut_if1 or @p iut_if2 interface should be used
     * for multicast packets sending: IP_MULTICAST_IF has the topmost
     * priority, bind() is the second, route is the last.
     */
    first_out_if = same_dev ||
                   (first_competitor == METHOD_IP_MULTICAST_IF &&
                    second_competitor != first_competitor) ||
                   (first_competitor == METHOD_BIND &&
                    second_competitor == METHOD_ROUTE);

    /* Use wildcard address with mcast_addr port to bind tester sockets */
    memcpy(&bind_addr, mcast_addr, te_sockaddr_get_size(mcast_addr));
    te_sockaddr_set_wildcard(SA(&bind_addr));

    /* Set up routes on testers' interfaces to @p alien_addr address */

    if (tapi_cfg_add_route(pco_tst1->ta, addr_family,
                           te_sockaddr_get_netaddr(alien_addr),
                           route_prefix, NULL, tst1_if->if_name, NULL,
                           0, 0, 0, 0, 0, 0, &rh1) != 0)
    {
        TEST_FAIL("Cannot add route to IUT on Tester1");
    }

    CFG_WAIT_CHANGES;

    if (!same_dev)
    {
         if (tapi_cfg_add_route(pco_tst2->ta, addr_family,
                               te_sockaddr_get_netaddr(alien_addr),
                               route_prefix, NULL, tst2_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0, &rh2) != 0)
        {
            TEST_FAIL("Cannot add route to IUT on Tester2");
        }

        CFG_WAIT_CHANGES;
    }

    /*
     * Create needed sockets on @p pco_iut, @p pco_tst1 and @p pco_tst2 (if
     * used). Join testers' sockets to multicast group with address
     * @p mcast_addr.
     */

    iut_s = rpc_socket(pco_iut, addr_domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    tst1_s = rpc_socket(pco_tst1, addr_domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    if (rpc_mcast_join(pco_tst1, tst1_s, mcast_addr, tst1_if->if_index,
                       join_method) != 0)
        TEST_VERDICT("Cannot join multicast group on Tester1");

    rpc_bind(pco_tst1, tst1_s, SA(&bind_addr));

    if (!same_dev)
    {
        tst2_s = rpc_socket(pco_tst2, addr_domain, RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
        if (rpc_mcast_join(pco_tst2, tst2_s, mcast_addr, tst2_if->if_index,
                           join_method) != 0)
            TEST_VERDICT("Cannot join multicast group on Tester2");

        rpc_bind(pco_tst2, tst2_s, SA(&bind_addr));
    }

    /*
     * If competitor is @c METHOD_BIND, we @b bind() @p iut_s
     * socket to a given address. If competitor is
     * @c METHOD_IP_MULTICAST_IF, we use @b setsockopt() with
     * this option and mreq.address set to a given address.
     * If competitor is @c METHOD_ROUTE, we add a route to
     * @p mcast_addr on a given iut interface.
     */
    SET_COMPETITOR(first_competitor, iut_addr, iut_if1);
    SET_COMPETITOR(second_competitor, alien_addr, iut_if2);
    CFG_WAIT_CHANGES;

    cfg_tree_print(NULL, 0, "/");

    if (connect_iut)
        rpc_connect(pco_iut, iut_s, mcast_addr);

    listener1 = mcast_listener_init(pco_iut, iut_if1, mcast_addr, NULL, 0);
    mcast_listen_start(pco_iut, listener1);

    if (!same_dev)
    {
        listener2 = mcast_listener_init(pco_iut, iut_if2, mcast_addr,
                                        NULL, 0);
        mcast_listen_start(pco_iut, listener2);
    }

    for (i = 0; i < packet_number; i++)
    {
        if (connect_iut)
            rpc_send(pco_iut, iut_s, sendbuf, data_len, 0);
        else
            rpc_sendto(pco_iut, iut_s, sendbuf, data_len, 0, mcast_addr);
        MSLEEP(100);
    }

    rc = mcast_listen_stop(pco_iut, listener1, NULL);

    if (rc > 0)
    {
        if (rc == packet_number)
            RING_VERDICT("All multicast packets were detected by"
                         " system on iut_if1 interface");
        else if (rc > 1)
            RING_VERDICT("Multicast packets were detected by system on "
                         "iut_if1 interface");
    }

    if (!same_dev)
    {
        rc = mcast_listen_stop(pco_iut, listener2, NULL);
        if (rc > 0)
        {
            if (rc == packet_number)
                RING_VERDICT("All multicast packets were detected by"
                             " system on iut_if2 interface");
            else
                RING_VERDICT("Multicast packets were detected by system on "
                             "iut_if2 interface");
        }
    }

    /* Check whether packets were received by the correct test agent */

    for (i = 0; i < packet_number; i++)
    {
        te_bool         sock_readable;

        snprintf(packet_name, PACKET_NAME_LEN, "the packet %d of %d",
                 i + 1, packet_number);

        memset(&from_addr, 0, sizeof(from_addr));
        RPC_GET_READABILITY(sock_readable, pco_tst1, tst1_s, CHECK_TIMEOUT);

        if (sock_readable)
        {
            RING("First Tester received %s", packet_name);

            rc = rpc_recvfrom(pco_tst1, tst1_s, recvbuf, data_len, 0,
                              SA(&from_addr), &from_addrlen);
            if (rc != data_len || memcmp(sendbuf, recvbuf, rc) != 0)
                TEST_FAIL("Data verification failed");

            if (!same_dev)
            {
                RPC_GET_READABILITY(sock_readable, pco_tst2, tst2_s,
                                    CHECK_TIMEOUT);
                if (sock_readable)
                {
                    RING_VERDICT("Both Testers have received %s",
                                 packet_name);
                    is_failed = TRUE;

                    rc = rpc_recvfrom(pco_tst2, tst2_s, recvbuf, data_len,
                                      0, SA(&from_addr), &from_addrlen);
                    if (rc != data_len || memcmp(sendbuf, recvbuf, rc) != 0)
                        TEST_FAIL("Data verification failed");
                }

                if (!first_out_if)
                {
                    RING_VERDICT("Tester1 received %s instead of Tester2",
                                 packet_name);
                    is_failed = TRUE;
                }
            }
        }
        else if (!same_dev)
        {
            RPC_GET_READABILITY(sock_readable, pco_tst2, tst2_s, CHECK_TIMEOUT);
            if (!sock_readable)
                TEST_VERDICT("No Tester received %s", packet_name);

            RING("Second Tester received %s", packet_name);

            rc = rpc_recvfrom(pco_tst2, tst2_s, recvbuf, data_len, 0,
                              SA(&from_addr), &from_addrlen);

            if (rc != data_len || memcmp(sendbuf, recvbuf, rc) != 0)
                TEST_FAIL("Data verification failed");

            if (first_out_if)
            {
                RING_VERDICT("Tester2 received %s instead of Tester1",
                             packet_name);
                is_failed = TRUE;
            }
        }
        else
            TEST_VERDICT("No Tester received %s", packet_name);

        /* Check whether packets were received from the correct source
         * address */

        te_sockaddr_clear_port(SA(iut_addr));
        te_sockaddr_clear_port(SA(alien_addr));
        te_sockaddr_clear_port(SA(&from_addr));

        if (te_sockaddrcmp(iut_addr, te_sockaddr_get_size(iut_addr),
                           SA(&from_addr), from_addrlen) == 0)
        {
            if (!first_src_addr)
            {
                RING_VERDICT("%s unexpectedly has higher priority than %s "
                             "when determining source address of %s",
                             get_method_name(first_competitor),
                             get_method_name(second_competitor),
                             packet_name);
            }
        }
        else if (te_sockaddrcmp(alien_addr, te_sockaddr_get_size(alien_addr),
                                SA(&from_addr), from_addrlen) == 0)
        {
            if (first_src_addr)
            {
                RING_VERDICT("%s unexpectedly has higher priority than %s "
                             "when determining source address of %s",
                             get_method_name(second_competitor),
                             get_method_name(first_competitor),
                             packet_name);
            }
        }
        else
            TEST_VERDICT("Unknown source address of %s", packet_name);
    }

    if (is_failed)
        TEST_STOP;
    else
        TEST_SUCCESS;

cleanup:
    mcast_listener_fini(pco_iut, listener1);
    if (!same_dev)
        mcast_listener_fini(pco_iut, listener2);

    tapi_cfg_del_route_tmp(pco_tst1->ta, addr_family,
                           te_sockaddr_get_netaddr(alien_addr),
                           route_prefix, NULL, tst1_if->if_name, NULL,
                           0, 0, 0, 0, 0, 0);

    if (!same_dev)
    {
        if (rh2 != CFG_HANDLE_INVALID)
        tapi_cfg_del_route_tmp(pco_tst2->ta, addr_family,
                               te_sockaddr_get_netaddr(alien_addr),
                               route_prefix, NULL, tst2_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0);

        if (rh3 != CFG_HANDLE_INVALID)
        tapi_cfg_del_route_tmp(pco_tst2->ta, addr_family,
                               te_sockaddr_get_netaddr(iut_addr),
                               route_prefix, NULL, tst2_if->if_name, NULL,
                               0, 0, 0, 0, 0, 0);
    }

    cfg_del_instance(ah, FALSE);


    if (rh0 != CFG_HANDLE_INVALID)
    {

        if (second_competitor == METHOD_ROUTE)
            tapi_cfg_del_route_tmp(pco_iut->ta, addr_family,
                                   te_sockaddr_get_netaddr(mcast_addr),
                                   route_prefix, NULL, iut_if2->if_name,
                                   te_sockaddr_get_netaddr(alien_addr),
                                   0, 0, 0, 0, 0, 0);

        if (first_competitor == METHOD_ROUTE)
            tapi_cfg_del_route_tmp(pco_iut->ta, addr_family,
                                   te_sockaddr_get_netaddr(mcast_addr),
                                   route_prefix, NULL, iut_if1->if_name,
                                   te_sockaddr_get_netaddr(iut_addr),
                                   0, 0, 0, 0, 0, 0);
    }


    if (saved_all)
    {
        tapi_cfg_save_del_if_ip4_addresses(pco_iut->ta,
                                           iut_if2->if_name,
                                           NULL, FALSE,
                                           NULL, NULL, NULL, NULL);

        tapi_cfg_restore_if_ip4_addresses(pco_iut->ta, iut_if2->if_name,
                                          saved_addrs, saved_prefixes,
                                          saved_broadcasts, saved_count);
    }

    CFG_WAIT_CHANGES;

    free(saved_addrs);
    free(saved_prefixes);
    free(saved_broadcasts);

    free(sendbuf);
    free(recvbuf);

    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    if (pco_tst2 != NULL)
        CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
