/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-rt_src_based Source based routing
 *
 * @objective Basic usecases for source-based routing with TCP and UDP.
 *
 * @type conformance
 *
 * @param net1                  Tested network
 * @param pco_iut               PCO on IUT
 * @param pco_tst1              PCO on Tester1
 * @param iut_if1               First NIC on IUT
 * @param iut_if2               Second NIC on IUT
 * @param tst1_if               NIC on TST connected with @p iut_if1
 * @param rt_sock_type          Type of sockets used in the test
 * @param iut_bind              Type of IUT socket bind: @c "address" or
 *                              @c "wildcard"
 * @param alien_on_iut1         If parameter is @c TRUE, then alien address
 *                              is connected to @p iut_if1, otherwise
 *                              connected to @p iut_if2.
 * @param iut_addr1             Address on IUT
 * @param tst1_addr             Address on Tester1
 *
 * @par Test sequence:
 *
 * @author Oleg Sadakov <Oleg.Sadakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/rt_src_based"

#include "sockapi-test.h"
#include "tapi_udp.h"
#include "ts_route.h"
#include "onload.h"

/** Specify table id for ip route and ip rule */
#define TABLE       111

/** Determine buffer length for sent data */
#define BUF_LEN     1024

/** TCP connect timeout, in milliseconds. */
#define TCP_CONN_TIMEOUT 2000

/**
 * The number of packets that should be sent in order to ensure that
 * the next packet will be sent through the Onload.
 */
#define UNCOUNTED_UDP_PACKETS   3

/** Type of IUT socket bind */
typedef enum iut_bind_type {
    IUT_BIND_ADDRESS,   /**< Bind to an alien address */
    IUT_BIND_WILDCARD,  /**< Bind to wildcard */
} iut_bind_type;

/**
 * Mapping of argument value to enum @b iut_bind_type
 */
#define IUT_BIND_MAPPING_LIST           \
    { "address",    IUT_BIND_ADDRESS }, \
    { "wildcard",   IUT_BIND_WILDCARD }

/**
 * Get parameter value of type @b iut_bind_type
 *
 * @param var_name_  Name of the variable to get the value of
 *                   @b var_name_ parameter of type @b iut_bind_type
 */
#define TEST_GET_IUT_BIND_PARAM(var_name_)                  \
    TEST_GET_ENUM_PARAM(var_name_, IUT_BIND_MAPPING_LIST)

/**
 * Add the new ip route rule
 *
 * @param ta            TA name
 * @param af            Address family
 * @param dst_addr      Destination address of the route
 * @param prefix        Prefix for @p dst_addr
 * @param gw_addr       Gateway address of the route
 * @param table         Route table ID
 */
static inline void
ip_route_add(const char *ta, int af, const struct sockaddr *dst_addr,
             int prefix, const struct sockaddr *gw_addr, int table)
{
    struct sockaddr_storage dst;

    tapi_sockaddr_clone_exact(dst_addr, &dst);

    CHECK_RC(te_sockaddr_cleanup_to_prefix(SA(&dst), prefix));
    CHECK_RC(tapi_cfg_add_full_route(
                 ta, af,
                 te_sockaddr_get_netaddr(SA(&dst)), prefix,
                 te_sockaddr_get_netaddr(gw_addr), NULL,
                 NULL,
                 0, 0, 0, 0, 0, 0, 0, table, NULL));
}

/**
 * Create and start CSAP
 *
 * @param sock_type     Type of socket
 * @param ta            TA name
 * @param if_name       Interface name
 * @param loc_addr      Local IP address
 * @param rem_addr      Remote IP address
 * @param csap          CSAP handle
 */
static inline void
csap_create_and_start(
        rpc_socket_type sock_type, const char *ta, const char *if_name,
        const struct sockaddr *loc_addr,
        const struct sockaddr *rem_addr,
        csap_handle_t *csap)
{
    if (sock_type == RPC_SOCK_STREAM)
    {
        CHECK_RC(tapi_tcp_ip_eth_csap_create(
                        ta, 0, if_name,
                        TAD_ETH_RECV_ALL | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, loc_addr->sa_family,
                        TAD_SA2ARGS(loc_addr, rem_addr),
                        csap));
    }
    else
    {
         CHECK_RC(tapi_udp_ip_eth_csap_create(
                        ta, 0, if_name,
                        TAD_ETH_RECV_ALL | TAD_ETH_RECV_NO_PROMISC,
                        NULL, NULL, loc_addr->sa_family,
                        TAD_SA2ARGS(loc_addr, rem_addr),
                        csap));
    }

    CHECK_RC(tapi_tad_trrecv_start(ta, 0, *csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));
}

/**
 * Compare address family and IPv4 address
 *
 * @param client        Client address to compare
 * @param expected      Expected address to compare
 */
static inline void
check_client_addr(const struct sockaddr *client,
                  const struct sockaddr *expected)
{
    if (te_sockaddrcmp(client, te_sockaddr_get_size(client),
                       expected, te_sockaddr_get_size(expected)) != 0)
    {
        char *client_str;
        char *expected_str;

        CHECK_RC(te_sockaddr_h2str(client, &client_str));
        CHECK_RC(te_sockaddr_h2str(expected, &expected_str));

        TEST_FAIL("Addresses don't match (client:%s, expected:%s)",
                  client_str, expected_str);
    }
}

/**
 * Send a datagram with random data from @p pco_tx to @p pco_rx
 *
 * @param rt_sock_type  Socket type
 * @param pco_tx        Sending PCO handle
 * @param tx_s          Socket on @pco_tx
 * @param tx_addr       Address on @pco_tx
 * @param pco_rx        Receiving PCO handle
 * @param rx_s          Socket on @pco_rx
 * @param rx_addr       Address on @pco_rx
 * @param tx_buf        Buffer for sending
 * @param rx_buf        Buffer for receiving
 */
static inline void
udp_transmit(
        sockts_socket_type rt_sock_type,
        rcf_rpc_server *pco_tx, int tx_s, const struct sockaddr *tx_addr,
        rcf_rpc_server *pco_rx, int rx_s, const struct sockaddr *rx_addr,
        uint8_t *tx_buf, uint8_t *rx_buf)
{
    ssize_t                   rx_size = 0;
    ssize_t                   tx_size = 0;
    struct sockaddr_storage   from_addr;
    socklen_t                 from_addrlen = sizeof(from_addr);

    te_fill_buf(tx_buf, BUF_LEN);
    memset(rx_buf, 0, BUF_LEN);

    if (rt_sock_type == SOCKTS_SOCK_UDP_NOTCONN)
        tx_size = rpc_sendto(pco_tx, tx_s, tx_buf, BUF_LEN, 0, rx_addr);
    else
        tx_size = rpc_send(pco_tx, tx_s, tx_buf, BUF_LEN, 0);

    if (tx_size != BUF_LEN)
    {
        TEST_FAIL("Only part of the data was sent (%d != %d)",
                  tx_size, BUF_LEN);
    }

    rx_size = rpc_recvfrom(pco_rx, rx_s, rx_buf, BUF_LEN, 0,
                           SA(&from_addr), &from_addrlen);
    if (rx_size != BUF_LEN)
    {
        TEST_FAIL("Only part of the data was received (%d != %d)",
                  rx_size, BUF_LEN);
    }

    if (memcmp(tx_buf, rx_buf, BUF_LEN) != 0)
        TEST_VERDICT("Data verification error");

    check_client_addr(SA(&from_addr), tx_addr);
}

/**
 * Create a TCP connection between two PCO and check the client address
 *
 * @param [in]  pco_tx      Sending PCO handle
 * @param [in]  tx_s        Socket on @pco_tx
 * @param [in]  tx_addr     Address on @pco_tx
 * @param [in]  pco_rx      Receiving PCO handle
 * @param [in]  rx_s        Socket on @pco_rx
 * @param [in]  rx_addr     Address on @pco_rx
 * @param [out] client_s    Socket of the accepted client
 */
static inline void
tcp_prepare(
        rcf_rpc_server *pco_tx, int tx_s, const struct sockaddr *tx_addr,
        rcf_rpc_server *pco_rx, int rx_s, const struct sockaddr *rx_addr,
        int *client_s)
{
    struct sockaddr_storage   from_addr;
    socklen_t                 from_addrlen = sizeof(from_addr);
    int                       rc;

    rpc_listen(pco_rx, rx_s, 1);

    pco_tx->timeout = TCP_CONN_TIMEOUT;
    RPC_AWAIT_ERROR(pco_tx);
    rc = rpc_connect(pco_tx, tx_s, rx_addr);

    if (rc < 0)
        TEST_VERDICT("connect() failed on %s with errno %r",
                     pco_tx->name, RPC_ERRNO(pco_tx));

    *client_s = rpc_accept(pco_rx, rx_s, SA(&from_addr), &from_addrlen);

    check_client_addr(SA(&from_addr), tx_addr);
}

/**
 * Allocate new address and assign it to custom interface
 *
 * @param net_handle    Subnet handle
 * @param pco           PCO handle
 * @param if_name       Interface name
 * @param prefix        Network prefix
 *
 * @return  New address in @p net_handle
 */
static inline struct sockaddr *
add_address(
        cfg_handle net_handle,
        rcf_rpc_server *pco, const char *if_name, int prefix)
{
    struct sockaddr *addr;

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle, NULL, &addr));
    CHECK_RC(tapi_allocate_set_port(pco, addr));
    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                 pco->ta, if_name, addr, prefix, FALSE, NULL));

    return addr;
}

int
main(int argc, char **argv)
{
    tapi_env_net               *net1;

    rcf_rpc_server             *pco_iut;
    rcf_rpc_server             *pco_tst1;

    const struct if_nameindex  *iut_if1;
    const struct if_nameindex  *iut_if2;
    const struct if_nameindex  *tst1_if;

    rpc_socket_type             sock_type;
    iut_bind_type               iut_bind;
    te_bool                     alien_on_iut1;

    const struct sockaddr      *iut_addr1;
    const struct sockaddr      *tst1_addr;

    cfg_handle                  net1_handle;
    cfg_handle                  net2_handle;

    struct sockaddr            *iut_alien_addr;
    struct sockaddr            *tst_alien_addr;

    rpc_socket_domain           domain;
    int                         af = AF_INET;
    int                         pfx;

    te_conf_ip_rule             ip_rule;

    uint8_t                    *tx_buf = NULL;
    uint8_t                    *rx_buf = NULL;

    int                         i;
    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         client_s;

    struct sockaddr_storage     inaddr_any;

    csap_handle_t               csap_iut_out = CSAP_INVALID_HANDLE;
    csap_handle_t               csap_iut_in = CSAP_INVALID_HANDLE;
    csap_handle_t               csap_tst_out = CSAP_INVALID_HANDLE;
    csap_handle_t               csap_tst_in = CSAP_INVALID_HANDLE;

    unsigned int                num_iut_out = 0;
    unsigned int                num_iut_in = 0;
    unsigned int                num_tst_out = 0;
    unsigned int                num_tst_in = 0;

    sockts_socket_type    rt_sock_type;

    te_bool if1_accelerated = FALSE;
    te_bool if2_accelerated = FALSE;

    TEST_START;

    TEST_GET_NET(net1);

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);

    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);

    SOCKTS_GET_RT_SOCK_TYPE(rt_sock_type);
    TEST_GET_IUT_BIND_PARAM(iut_bind);
    TEST_GET_BOOL_PARAM(alien_on_iut1);

    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst1_addr);

    af = iut_addr1->sa_family;
    pfx = (af == AF_INET ? net1->ip4pfx : net1->ip6pfx);
    sock_type = sock_type_sockts2rpc(rt_sock_type);

    if1_accelerated = sockts_if_accelerated(&env, pco_iut->ta,
                                            iut_if1->if_name);
    if2_accelerated = sockts_if_accelerated(&env, pco_iut->ta,
                                            iut_if2->if_name);

    /* Allow replies to ARP request from alien IP address */
    if (af == AF_INET)
    {
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 0, NULL,
                                      "net/ipv4/conf:all/rp_filter"));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 0, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut_if1->if_name));
        CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 0, NULL,
                                      "net/ipv4/conf:%s/rp_filter",
                                      iut_if2->if_name));
    }

    TEST_STEP("Allocate @p iut_alien_addr and assign it to @p iut_if1 "
              "or @p iut_if2 according to @p alien_on_iut1.");

    if (af == AF_INET)
        CHECK_RC(tapi_cfg_alloc_ip4_net(&net1_handle));
    else
        CHECK_RC(tapi_cfg_alloc_ip6_net(&net1_handle));
    iut_alien_addr = add_address(
                net1_handle, pco_iut,
                alien_on_iut1 ? iut_if1->if_name : iut_if2->if_name,
                pfx);

    TEST_STEP("Allocate @p tst_alien_addr from different IP network "
              "and assign it to @p tst1_if.");

    if (af == AF_INET)
        CHECK_RC(tapi_cfg_alloc_ip4_net(&net2_handle));
    else
        CHECK_RC(tapi_cfg_alloc_ip6_net(&net2_handle));

    tst_alien_addr = add_address(net2_handle, pco_tst1,
                                 tst1_if->if_name, pfx);

    domain = rpc_socket_domain_by_addr(tst1_addr);

    TEST_STEP("Prepare source based routing on IUT (from @p iut_alien_addr "
              "to @p tst_alien_addr): "
              "- add route to @p tst_alien_addr via @p tst1_addr "
              "in table @c TABLE; "
              "- add rule with source address = @p iut_alien_addr "
              "to use table @c TABLE.");

    ip_route_add(pco_iut->ta, af, tst_alien_addr, pfx,
                 tst1_addr, TABLE);

    te_conf_ip_rule_init(&ip_rule);
    tapi_sockaddr_clone_exact(iut_alien_addr, &ip_rule.src);
    ip_rule.family = af;
    ip_rule.table = TABLE;
    ip_rule.mask |= TE_IP_RULE_FLAG_SRC | TE_IP_RULE_FLAG_TABLE;
    CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, af, &ip_rule));

    TEST_STEP("Add route to @p iut_alien_addr via @p iut_addr1 "
              "on Tester1.");
    ip_route_add(pco_tst1->ta, af, iut_alien_addr, pfx,
                 iut_addr1, TAPI_RT_TABLE_MAIN);

    CFG_WAIT_CHANGES;

    tx_buf = (uint8_t *)te_make_buf_by_len(BUF_LEN);
    rx_buf = (uint8_t *)te_make_buf_by_len(BUF_LEN);

    TEST_STEP("Create sockets on IUT and Tester, of type defined by "
              "@p rt_sock_type.");
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst1, domain, sock_type, RPC_PROTO_DEF);

    TEST_STEP("Bind IUT socket to @p iut_alien_addr or @c INADDR_ANY "
              "according to @p iut_bind.");

    switch (iut_bind)
    {
        case IUT_BIND_ADDRESS:
            rpc_bind(pco_iut, iut_s, iut_alien_addr);
            break;

        case IUT_BIND_WILDCARD:
            tapi_sockaddr_clone_exact(iut_alien_addr, &inaddr_any);
            te_sockaddr_set_wildcard(SA(&inaddr_any));
            rpc_bind(pco_iut, iut_s, SA(&inaddr_any));
            break;

        default:
            TEST_FAIL("Unknown value of variable iut_bind=%d", iut_bind);
            break;
    }

    TEST_STEP("Bind Tester socket to @p tst_alien_addr.");
    rpc_bind(pco_tst1, tst_s, tst_alien_addr);

    TEST_STEP("Establish connection between sockets, if "
              "required by @p rt_sock_type.");
    switch (rt_sock_type)
    {
        case SOCKTS_SOCK_UDP_NOTCONN:
            /* Nothing to do. */
            break;

        case SOCKTS_SOCK_UDP:
            rpc_connect(pco_iut, iut_s, tst_alien_addr);
            rpc_connect(pco_tst1, tst_s, iut_alien_addr);
            break;

        case SOCKTS_SOCK_TCP_ACTIVE:
            tcp_prepare(pco_iut, iut_s, iut_alien_addr,
                        pco_tst1, tst_s, tst_alien_addr, &client_s);
            break;

        case SOCKTS_SOCK_TCP_PASSIVE_CL:
            tcp_prepare(pco_tst1, tst_s, tst_alien_addr,
                        pco_iut, iut_s, iut_alien_addr, &client_s);
            break;

        default:
            TEST_FAIL("Not supported rt_sock_type value");
    }

    TEST_STEP("If UDP socket is tested, send @c UNCOUNTED_UDP_PACKETS "
              "packets from IUT to ensure that the next packet will be accelerated "
              "by Onload.");
    if (sock_type == RPC_SOCK_DGRAM)
    {
        for (i = 0; i < UNCOUNTED_UDP_PACKETS; i++)
        {
            udp_transmit(rt_sock_type,
                         pco_iut, iut_s, iut_alien_addr,
                         pco_tst1, tst_s, tst_alien_addr,
                         tx_buf, rx_buf);
        }
    }

    TEST_STEP("Create CSAPs to capture packets on @p iut_if1 and @p tst1_if.");

    csap_create_and_start(sock_type, pco_iut->ta, iut_if1->if_name,
                          iut_alien_addr, tst_alien_addr,
                          &csap_iut_out);
    csap_create_and_start(sock_type, pco_iut->ta, iut_if1->if_name,
                          tst_alien_addr, iut_alien_addr,
                          &csap_iut_in);
    csap_create_and_start(sock_type, pco_tst1->ta, tst1_if->if_name,
                          tst_alien_addr, iut_alien_addr,
                          &csap_tst_out);
    csap_create_and_start(sock_type, pco_tst1->ta, tst1_if->if_name,
                          iut_alien_addr, tst_alien_addr,
                          &csap_tst_in);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Send some data with help of sockets.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        if (rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            sockts_test_connection(pco_iut, iut_s,
                                   pco_tst1, client_s);
            rpc_close(pco_tst1, client_s);
        }
        else
        {
            sockts_test_connection(pco_tst1, tst_s,
                                   pco_iut, client_s);
            rpc_close(pco_iut, client_s);
        }
    }
    else
    {
        udp_transmit(rt_sock_type,
                     pco_iut, iut_s, iut_alien_addr,
                     pco_tst1, tst_s, tst_alien_addr,
                     tx_buf, rx_buf);

        udp_transmit(rt_sock_type,
                     pco_tst1, tst_s, tst_alien_addr,
                     pco_iut, iut_s, iut_alien_addr,
                     tx_buf, rx_buf);
    }

    TEST_STEP("Check number of packets captured by CSAPs. All "
              "packets should be captured on @p tst1_if. On "
              "@p iut_if1 packets should be captured only "
              "if traffic is expected to be not accelerated by "
              "Onload.");

    CHECK_RC(rcf_ta_trrecv_stop(
                 pco_iut->ta, 0, csap_iut_out, NULL, NULL, &num_iut_out));
    CHECK_RC(rcf_ta_trrecv_stop(
                 pco_iut->ta, 0, csap_iut_in, NULL, NULL, &num_iut_in));

    CHECK_RC(rcf_ta_trrecv_stop(
                 pco_tst1->ta, 0, csap_tst_out, NULL, NULL, &num_tst_out));
    CHECK_RC(rcf_ta_trrecv_stop(
                 pco_tst1->ta, 0, csap_tst_in, NULL, NULL, &num_tst_in));

    RING("CSAP statistics of captured packets: IUT IN=%u OUT=%u, "
         "TST IN=%u OUT=%u",
         num_iut_in, num_iut_out, num_tst_in, num_tst_out);

    if (num_tst_out == 0)
        ERROR_VERDICT("CSAP didn't catch outgoing packets on Tester1");
    if (num_tst_in == 0)
        ERROR_VERDICT("CSAP didn't catch incoming packets on Tester1");

    /*
     * Connection must be accelerated in 2 cases:
     *  - Both interfaces are Solarflare ones;
     *  - The first interface is Solarflare one and alien address added to
     *    @p iut_if1.
     * Connection is not accelerated in case when alien address is added to
     * non SFC interface or when connection is established using non SFC
     * interface.
     */
    if ((if1_accelerated && if2_accelerated) ||
        (if1_accelerated && alien_on_iut1))
    {
        if (num_iut_out != 0 || num_iut_in != 0)
        {
            ERROR_VERDICT("CSAP caught packets on IUT with "
                          "Onload accelerated connection");
        }
    }
    else
    {
        if (num_iut_in == 0)
        {
            ERROR_VERDICT("CSAP didn't catch incoming packets on IUT with "
                          "non Onload connection");
        }
        if (num_iut_out == 0)
        {
            ERROR_VERDICT("CSAP didn't catch outgoing packets on IUT with "
                          "non Onload connection");
        }
    }

    TEST_SUCCESS;

cleanup:
    free(tx_buf);
    free(rx_buf);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s);

    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap_iut_out));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap_iut_in));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, csap_tst_out));
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst1->ta, 0, csap_tst_in));

    if (af == AF_INET6)
    {
        /*
         * Avoid problems with FAILED neighbor entries on IPv6, see
         * OL bug 9774.
         */
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_iut->ta,
                                                  iut_if1->if_name));
        CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_tst1->ta,
                                                  tst1_if->if_name));
        CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_iut, iut_if1->if_name));
        CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_tst1, tst1_if->if_name));
    }

    TEST_END;
}
