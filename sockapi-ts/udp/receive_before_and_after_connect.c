/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 */

/**
 * @page udp-receive_before_and_after_connect Test UDP receive before and after connect()
 *
 * @objective Check that the socket receives and accelerates everything we
 *            expect
 *
 * @param env      Testing environment:
 *      - @ref arg_types_env.p2p_ip4_ip6
 * @param socket_domain       Socket domain
 *      - @c PF_INET
 *      - @c PF_INET6
 * @param addr_domain         Address domain
 *      - @c PF_INET
 *      - @c PF_INET6
 * @param wildcard            Set wildcard or not
 *      - @c TRUE
 *      - @c FALSE
 * @param connect_addr_domain Connect address domain
 *      - @c PF_INET
 *      - @c PF_INET6
 * @param set_v6only          Set V6_ONLY socket option or not
 *      - @c TRUE
 *      - @c FALSE
 *
 * @par Scenario:
 *
 * @note This test does not implement invalid cases, for example, it does not
 *       make sense to set socket PF_INET and bind it to PF_INET6, or connect to PF_INET6.
 *       Also does not make sence set V6ONLY option after bind or connect,
 *       this case implement in bnbvalue/ipv4_mapped_connect_ipv6.
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/receive_before_and_after_connect"

#include "sockapi-test.h"
#include "tapi_udp.h"

#define NUM_IUT_ADDR 4
#define NUM_TST_ADDR 8
#define NUM_PACKETS 16

/* Each iteration is defined by a set of 4 parameters.
 * Each of these parameters can take 0 or 1
 */
#define BITMASK_ITERATION_0  0x00
#define BITMASK_ITERATION_1  0x01
#define BITMASK_ITERATION_4  0x04
#define BITMASK_ITERATION_5  0x05
#define BITMASK_ITERATION_7  0x07
#define BITMASK_ITERATION_E  0x0E
#define BITMASK_ITERATION_F  0x0F
#define BITMASK_ITERATION_10 0x10
#define BITMASK_ITERATION_11 0x11
#define BITMASK_ITERATION_14 0x14
#define BITMASK_ITERATION_15 0x15
#define BITMASK_ITERATION_17 0x17
#define BITMASK_ITERATION_1E 0x1E
#define BITMASK_ITERATION_1F 0x1F

/* After each iteration, different bitmask results are expected.
 * The bitmask shows which packets have been sent and which have not.
 * Before and after connect expected different bitmask.
 */
#define BITMASK_BEFORE_CONNECT_F    0x0F
#define BITMASK_BEFORE_CONNECT_FF   0xFF
#define BITMASK_BEFORE_CONNECT_F00  0xF00
#define BITMASK_BEFORE_CONNECT_FF00 0xFF00

#define BITMASK_AFTER_CONNECT_1    0x01
#define BITMASK_AFTER_CONNECT_0    0x00
#define BITMASK_AFTER_CONNECT_100  0x100
#define BITMASK_AFTER_CONNECT_1000 0x1000

#define CLONE_IPV4                                                      \
do {                                                                    \
    tapi_sockaddr_clone_exact(tst_addr, &tst_addr_a[0]);                \
    tapi_sockaddr_clone_exact(tst_addr, &tst_addr_a[1]);                \
    te_sockaddr_set_port(SA(&tst_addr_a[1]),                            \
                         te_sockaddr_get_port(tst_addr2));              \
    tapi_sockaddr_clone_exact(tst_addr2, &tst_addr_a[2]);               \
    tapi_sockaddr_clone_exact(tst_addr2, &tst_addr_a[3]);               \
    te_sockaddr_set_port(SA(&tst_addr_a[3]),                            \
                         te_sockaddr_get_port(tst_addr));               \
}while(0)

#define CLONE_IPV6 \
do {                                                                    \
    tapi_sockaddr_clone_exact(tst_addr6, &tst_addr_a[4]);               \
    tapi_sockaddr_clone_exact(tst_addr6, &tst_addr_a[5]);               \
    te_sockaddr_set_port(SA(&tst_addr_a[5]),                            \
                         te_sockaddr_get_port(tst_addr6_2));            \
    tapi_sockaddr_clone_exact(tst_addr6_2, &tst_addr_a[6]);             \
    tapi_sockaddr_clone_exact(tst_addr6_2, &tst_addr_a[7]);             \
    te_sockaddr_set_port(SA(&tst_addr_a[7]),                            \
                         te_sockaddr_get_port(tst_addr6));              \
} while(0)

#define ADD_NEW_ADDR(domain, addr, prefix, handle, pco, _if)            \
do {                                                                    \
    CHECK_RC(tapi_env_allocate_addr(net, addr_family_rpc2h(domain),     \
                                    &addr, NULL));                      \
    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco->ta, _if->if_name,\
                                           addr, prefix,                \
                                           FALSE, &handle));            \
} while(0)

/* Struct which store data about host adddress */
struct host_addr{
    struct sockaddr_storage tst_addr;
    struct sockaddr_storage iut_addr;
    te_bool is_mapped;
};

/* Init and fill struct host_addr.
 * Compose all kinds of valid packets.
 *
 * @param tst_addr     Array of different TST address
 * @param tst_addr_len Length of array TST address
 * @param iut_addr     Array of different IUT address
 * @param iut_addr_len Length of array IUT address
 * @param array        Array of struct
 *
 * @param array        Struct host_addr
 */
static void
gen_host_addr(struct sockaddr_storage *tst_addr,
              int                      tst_addr_len,
              struct sockaddr_storage *iut_addr,
              int                      iut_addr_len,
              struct host_addr        *array)
{
    int              i = 0;
    int              j = 0;
    int              count = 0;
    struct host_addr tmp;

    for (j = 0; j< iut_addr_len; j++)
    {
        for (i = 0; i < tst_addr_len; i++)
        {
            if (tst_addr[i].ss_family != iut_addr[j].ss_family)
                continue;
             tapi_sockaddr_clone_exact(SA(&tst_addr[i]), &tmp.tst_addr);
             tapi_sockaddr_clone_exact(SA(&iut_addr[j]), &tmp.iut_addr);
             memcpy(&array[count], &tmp, sizeof(struct host_addr));
             array[count].is_mapped = FALSE;
             count++;
        }
    }
}

/* Send one packet from TST to IUT
 *
 * @param hosts  packet for send and receive
 * @param pco_iut     RPC server handle
 * @param pco_tst     RPC server handle
 * @param iut_s       IUT socket
 * @param tst_s       TST socket
 * @param tx_buf      Buffer for send
 * @param rx_buf      Biffer for recv
 * @param tx_buf_len  Length tx_buf
 * @param rx_buf_len  Length rx_buf
 *
 * @return TRUE   send and receive packet
 * @return FALSE  not receive
 */
static te_bool
send_one(struct host_addr *hosts,
         rcf_rpc_server   *pco_iut,
         rcf_rpc_server   *pco_tst,
         int               iut_s,
         int              *tst_s,
         char             *tx_buf,
         char             *rx_buf,
         size_t           *tx_buf_len,
         size_t           *rx_buf_len)
{
    te_bool                 readable;
    struct sockaddr_storage tst_addr_from;
    socklen_t               tst_addr_from_len = sizeof(tst_addr_from);

    *tst_s = rpc_socket(pco_tst,
                        rpc_socket_domain_by_addr(SA(&(hosts->tst_addr))),
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, *tst_s, SA(&(hosts->tst_addr)));
    rpc_sendto(pco_tst, *tst_s, tx_buf, *tx_buf_len,
               0, SA(&(hosts->iut_addr)));
    RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
    if (!readable)
    {
        RPC_CLOSE(pco_tst, *tst_s);
        return FALSE;
    }
    rpc_recvfrom(pco_iut, iut_s, rx_buf, *rx_buf_len, 0, SA(&tst_addr_from),
                 &tst_addr_from_len);
    CHECK_BUFS_EQUAL(rx_buf, tx_buf, *tx_buf_len);
    RPC_CLOSE(pco_tst, *tst_s);
    return TRUE;
}

/* Send all packets from array packets, check that packets
 * are accelerated and compose bitmask send status
 *
 * @param hosts       Array of packets to send
 * @param hosts_len   Length array of packets
 * @param pco_iut     RPC server handle
 * @param iut_s       IUT socket
 * @param pco_tst     RPC server handle
 * @param tst_s       TST socket
 * @param tx_buf      Buffer for send
 * @param rx_buf      Biffer for recv
 * @param tx_buf_len  Length tx_buf
 * @param rx_buf_len  Length rx_buf
 * @param csap        CSAP IPv4 handle
 * @param sid         Session IPv4 Id
 * @param csap6       CSAP IPv6 handle
 * @param sid6        Session IPv6 Id
 *
 * @return bitmask
 */
static int
send_all(struct host_addr          *hosts,
         int                        hosts_len,
         rcf_rpc_server            *pco_iut,
         int                        iut_s,
         rcf_rpc_server            *pco_tst,
         int                       *tst_s,
         char                      *tx_buf,
         char                      *rx_buf,
         size_t                    *tx_buf_len,
         size_t                    *rx_buf_len,
         csap_handle_t              csap,
         int                        sid,
         csap_handle_t              csap6,
         int                        sid6)
{
    int               bitmask = 0;
    te_bool           res;
    int               i;
    unsigned  int     received_packets_number;
    te_bool           set_verdict = FALSE;
    rpc_socket_domain domain;
    te_bool           is_ipv4 = FALSE;

    for (i = 0; i < hosts_len; i++)
    {
        res = send_one(&hosts[i], pco_iut, pco_tst, iut_s,
                       tst_s, tx_buf, rx_buf, tx_buf_len, rx_buf_len);
        bitmask |= (res << i );
        domain = rpc_socket_domain_by_addr(SA(&hosts[i].iut_addr));

        if ((domain == RPC_PF_INET6 && hosts[i].is_mapped) ||
            (domain == RPC_PF_INET))
            is_ipv4 = TRUE;
        CHECK_RC(tapi_tad_trrecv_get(pco_iut->ta, is_ipv4 ? sid : sid6,
                                     is_ipv4 ? csap : csap6, NULL,
                                     &received_packets_number));
        if (res && received_packets_number > 0)
            set_verdict = TRUE;
    }

    if (set_verdict)
        RING_VERDICT("CSAP registered data traffic");

    return bitmask;
}

/* Generate verdict dependence on @p bitmask
 *
 * @param bitmask_expected The bitmask that is expected
 *                         in this iteration
 * @param bitmask_recv     The bitmask that is received
 *                         in this iteration
 */
void
get_test_verdict(int bitmask_expected, int bitmask_recv)
{
    int   num_recv_ipv4 = 0;
    int   num_recv_ipv6 = 0;
    int   num_exp_ipv4 = 0;
    int   num_exp_ipv6 = 0;
    int   count = 0;
    for (; bitmask_recv > 0 && bitmask_expected > 0;
         bitmask_recv >>= 1, bitmask_expected >>= 1)
    {
        if (count < NUM_PACKETS / 2)
        {
            if (bitmask_recv & 1)
                num_recv_ipv4++;
            if (bitmask_expected & 1)
                num_exp_ipv4++;
        }
        else
        {
            if (bitmask_recv & 1)
                num_recv_ipv6++;
            if (bitmask_expected & 1)
                num_exp_ipv6++;
        }
        count++;
    }
    if (num_recv_ipv4 > num_exp_ipv4)
        TEST_VERDICT("More IPv4 packets received than expected");
    else
        TEST_VERDICT("Fewer IPv4 packets received than expected");

    if (num_recv_ipv6 > num_exp_ipv6)
        TEST_VERDICT("More IPv6 packets received than expected");
    else
        TEST_VERDICT("Fewer IPv6 packets received than expected");

    TEST_ARTIFACT("Expected %d IPv4 packets and %d IPv6 packets\n "
                  "Received %d IPv4 packets and %d IPv6 packets\n",
                  num_exp_ipv4, num_exp_ipv6, num_recv_ipv4, num_recv_ipv6);

}

/* Compare bitmask from send_all with default value
 *
 * @param bitmask_iteration Bitmask obtained from test param
 * @param bitmask           Bitmask obtained from send_all
 */
static void
check_bitmask(int bitmask_iteration, int bitmask)
{
    switch (bitmask_iteration)
    {
        case BITMASK_ITERATION_0:
            if (bitmask != BITMASK_BEFORE_CONNECT_F)
                get_test_verdict(BITMASK_BEFORE_CONNECT_F, bitmask);
            break;

        case BITMASK_ITERATION_1:
            if (bitmask != BITMASK_BEFORE_CONNECT_FF)
                get_test_verdict(BITMASK_BEFORE_CONNECT_FF, bitmask);
            break;

        case BITMASK_ITERATION_4:
            if (bitmask != BITMASK_BEFORE_CONNECT_F)
                get_test_verdict(BITMASK_BEFORE_CONNECT_F, bitmask);
            break;

        case BITMASK_ITERATION_5:
            if (bitmask != BITMASK_BEFORE_CONNECT_FF)
                get_test_verdict(BITMASK_BEFORE_CONNECT_FF, bitmask);
            break;

        case BITMASK_ITERATION_7:
            if (bitmask != BITMASK_BEFORE_CONNECT_FF00)
                get_test_verdict(BITMASK_BEFORE_CONNECT_FF00, bitmask);
            break;

        case BITMASK_ITERATION_E:
            if (bitmask != BITMASK_BEFORE_CONNECT_F00)
                get_test_verdict(BITMASK_BEFORE_CONNECT_F00, bitmask);
            break;

        case BITMASK_ITERATION_F:
            if (bitmask != BITMASK_BEFORE_CONNECT_FF00)
                get_test_verdict(BITMASK_BEFORE_CONNECT_FF00, bitmask);
            break;

        case BITMASK_ITERATION_10:
            if (bitmask != BITMASK_AFTER_CONNECT_1)
                get_test_verdict(BITMASK_AFTER_CONNECT_1, bitmask);
            break;

        case BITMASK_ITERATION_11:
            if (bitmask != BITMASK_AFTER_CONNECT_1)
                get_test_verdict(BITMASK_AFTER_CONNECT_1, bitmask);
            break;

        case BITMASK_ITERATION_14:
            if (bitmask != BITMASK_AFTER_CONNECT_1)
                get_test_verdict(BITMASK_AFTER_CONNECT_1, bitmask);
            break;

        case BITMASK_ITERATION_15:
            if (bitmask != BITMASK_AFTER_CONNECT_1)
                get_test_verdict(BITMASK_AFTER_CONNECT_1, bitmask);
            break;

        case BITMASK_ITERATION_17:
            if (bitmask != BITMASK_AFTER_CONNECT_0)
                get_test_verdict(BITMASK_AFTER_CONNECT_0, bitmask);
            break;

        case BITMASK_ITERATION_1E:
            if (bitmask != BITMASK_AFTER_CONNECT_100)
                get_test_verdict(BITMASK_AFTER_CONNECT_100, bitmask);
            break;

        case BITMASK_ITERATION_1F:
            if (bitmask != BITMASK_AFTER_CONNECT_1000 &&
                bitmask != BITMASK_AFTER_CONNECT_100)
                get_test_verdict(BITMASK_AFTER_CONNECT_1000, bitmask);
            break;
    }
}

/* Mapped IPv4 field struct to IPv6
 *
 * @param hosts        Structure which to mapped
 * @param num_ip4_addr Number of IP4 addresses
 *
 */
static void
host_addr_ip4_to_ipv6_mapped(struct host_addr *hosts, int num_ip4_addr)
{
    int i;

    for (i = 0; i < num_ip4_addr; i++)
    {
        te_sockaddr_ip4_to_ip6_mapped(SA(&hosts[i].tst_addr));
        te_sockaddr_ip4_to_ip6_mapped(SA(&hosts[i].iut_addr));
        hosts[i].is_mapped = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *iut_addr6 = NULL;
    const struct sockaddr     *tst_addr6 = NULL;
    tapi_env_net              *net = NULL;
    const struct if_nameindex *iut_if = NULL;
    const struct if_nameindex *tst_if = NULL;
    te_bool                    wildcard;
    rpc_socket_domain          socket_domain;
    rpc_socket_domain          addr_domain;
    rpc_socket_domain          connect_addr_domain;
    te_bool                    set_v6only;

    struct sockaddr           *iut_addr2 = NULL;
    struct sockaddr           *iut_addr6_2 = NULL;
    struct sockaddr           *tst_addr2 = NULL;
    struct sockaddr           *tst_addr6_2 = NULL;
    struct sockaddr_storage    iut_addr_bind;
    struct sockaddr_storage    iut_addr_connect;
    struct sockaddr_storage    tst_addr_a[NUM_TST_ADDR];
    struct sockaddr_storage    iut_addr_a[NUM_IUT_ADDR];
    struct host_addr           host_addr_array[NUM_PACKETS];
    cfg_handle                 iut_addr2_handle = CFG_HANDLE_INVALID;
    cfg_handle                 iut_addr6_2_handle = CFG_HANDLE_INVALID;
    cfg_handle                 tst_addr2_handle = CFG_HANDLE_INVALID;
    cfg_handle                 tst_addr6_2_handle = CFG_HANDLE_INVALID;
    int                        iut_s = -1;
    int                        bitmask;
    int                        bitmask_iteration;
    te_bool                    socket_domain_is_ip6;
    te_bool                    addr_domain_is_ip6;
    te_bool                    connect_addr_is_ip6;
    int                        tst_s = -1;
    void                      *tx_buf = NULL;
    void                      *rx_buf = NULL;
    size_t                     tx_buf_len;
    size_t                     rx_buf_len;
    int                        opt_val;
    int                        sid;
    csap_handle_t              csap = CSAP_INVALID_HANDLE;
    int                        sid6;
    csap_handle_t              csap6 = CSAP_INVALID_HANDLE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr6);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, tst_addr6);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(wildcard);
    TEST_GET_DOMAIN(socket_domain);
    TEST_GET_DOMAIN(addr_domain);
    TEST_GET_DOMAIN(connect_addr_domain);
    TEST_GET_BOOL_PARAM(set_v6only);

    socket_domain_is_ip6 = socket_domain == RPC_PF_INET6 ? TRUE : FALSE;
    addr_domain_is_ip6 = addr_domain == RPC_PF_INET6 ? TRUE : FALSE;
    connect_addr_is_ip6 = connect_addr_domain == RPC_PF_INET6 ?
                                                        TRUE : FALSE;
   TEST_STEP("Create CSAP recevier ip4 and ip6 on IUT");
   CHECK_RC(rcf_ta_create_session(pco_iut->ta, &sid));
   CHECK_RC(tapi_udp_ip4_eth_csap_create(pco_iut->ta, sid,
                                         iut_if->if_name,
                                         TAD_ETH_RECV_DEF |
                                         TAD_ETH_RECV_NO_PROMISC,
                                         NULL, NULL, 0, 0,
                                         -1, -1, &csap));
   CHECK_RC(rcf_ta_create_session(pco_iut->ta, &sid6));
   CHECK_RC(tapi_udp_ip6_eth_csap_create(pco_iut->ta, sid6,
                                         iut_if->if_name,
                                         TAD_ETH_RECV_DEF |
                                         TAD_ETH_RECV_NO_PROMISC,
                                         NULL, NULL, 0, 0,
                                         -1, -1, &csap6));

    tx_buf = sockts_make_buf_dgram(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    /* 0 bit in bitmask in responsible for wildcard
     * 1 bit for addr_domain_is_ip6
     * 2 bit for socekt_domain_is_ip6
     * 3 bit for connect_addr_is_ip6
     * 4 bit for before or after connect()
     */
    bitmask_iteration = wildcard | (addr_domain_is_ip6 << 1) |
                        (socket_domain_is_ip6 << 2) | (connect_addr_is_ip6 << 3);

    TEST_STEP("Add new IPv4 address on IUT");
    ADD_NEW_ADDR(RPC_AF_INET, iut_addr2, net->ip4pfx, iut_addr2_handle,
                 pco_iut, iut_if);

    te_sockaddr_set_port(iut_addr2, te_sockaddr_get_port(iut_addr));
    CFG_WAIT_CHANGES;

    TEST_STEP("Add new IPv6 address on IUT");
    ADD_NEW_ADDR(RPC_AF_INET6, iut_addr6_2, net->ip6pfx, iut_addr6_2_handle,
                 pco_iut, iut_if);
    te_sockaddr_set_port(iut_addr6_2, te_sockaddr_get_port(iut_addr6));
    CFG_WAIT_CHANGES;

    tapi_sockaddr_clone_exact(iut_addr, &iut_addr_a[0]);
    tapi_sockaddr_clone_exact(iut_addr2, &iut_addr_a[1]);
    tapi_sockaddr_clone_exact(iut_addr6, &iut_addr_a[2]);
    tapi_sockaddr_clone_exact(iut_addr6_2, &iut_addr_a[3]);

    TEST_STEP("Add new IPv4 address on TST");
    ADD_NEW_ADDR(RPC_AF_INET, tst_addr2, net->ip4pfx, tst_addr2_handle,
                 pco_tst, tst_if);
    TAPI_SET_NEW_PORT(pco_tst, tst_addr2);
    CFG_WAIT_CHANGES;
    CLONE_IPV4;

    TEST_STEP("Add new IPv6 address on TST");
    ADD_NEW_ADDR(RPC_AF_INET6, tst_addr6_2, net->ip6pfx, tst_addr6_2_handle,
                 pco_tst, tst_if);
    TAPI_SET_NEW_PORT(pco_tst, tst_addr6_2);
    CFG_WAIT_CHANGES;
    CLONE_IPV6;

    gen_host_addr(tst_addr_a, NUM_TST_ADDR, iut_addr_a,
                  NUM_IUT_ADDR, host_addr_array);

    if (socket_domain_is_ip6)
       host_addr_ip4_to_ipv6_mapped(host_addr_array, NUM_TST_ADDR);

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, socket_domain,
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    if (set_v6only)
    {
        TEST_STEP("If @p set_v6only set IPV6_V6ONLY socket option.");
        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_IPV6_V6ONLY, &opt_val);
    }

    TEST_STEP("Create struct sockaddr to bind. "
              "Bind @b iut_s to address or wildcard dependence on @p wildcard");
    if (socket_domain_is_ip6 && addr_domain_is_ip6)
        tapi_sockaddr_clone_exact(iut_addr6, &iut_addr_bind);
    else
        tapi_sockaddr_clone_exact(iut_addr, &iut_addr_bind);

    if (wildcard)
        te_sockaddr_set_wildcard(SA(&iut_addr_bind));

    if (socket_domain_is_ip6 && !addr_domain_is_ip6)
        te_sockaddr_ip4_to_ip6_mapped(SA(&iut_addr_bind));
    rpc_bind(pco_iut, iut_s, SA(&iut_addr_bind));

    TEST_STEP("Start CSAP sniffer");
    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, sid, csap, NULL,
                                   TAD_TIMEOUT_INF,
                                   0,
                                   RCF_TRRECV_COUNT));

    CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, sid6, csap6, NULL,
                                   TAD_TIMEOUT_INF,
                                   0,
                                   RCF_TRRECV_COUNT));

    TEST_STEP("Send all packets after bind() and check "
              " that expected packets are received and accelerated");
    bitmask = send_all(host_addr_array, NUM_PACKETS, pco_iut, iut_s, pco_tst,
                       &tst_s, tx_buf, rx_buf, &tx_buf_len, &rx_buf_len,
                       csap, sid, csap6, sid6);

    check_bitmask(bitmask_iteration, bitmask);

    if (!addr_domain_is_ip6 || !connect_addr_is_ip6)
        tapi_sockaddr_clone_exact(SA(&host_addr_array[0].tst_addr),
                                  &iut_addr_connect);
    else if (!wildcard || connect_addr_is_ip6)
        tapi_sockaddr_clone_exact(SA(&host_addr_array[8].tst_addr),
                                  &iut_addr_connect);

    TEST_STEP("Connect IUT socket to TST address");
    rpc_connect(pco_iut, iut_s, SA(&iut_addr_connect));
    bitmask_iteration |= (TRUE << 4);

    TEST_STEP("Send all packets after connect and check "
              " that expected packets are received and accelerated");
    bitmask = send_all(host_addr_array, NUM_PACKETS, pco_iut, iut_s, pco_tst,
                       &tst_s, tx_buf, rx_buf, &tx_buf_len, &rx_buf_len,
                       csap, sid, csap6, sid6);

    check_bitmask(bitmask_iteration, bitmask);

    TEST_STEP("Stop CSAP sniffer");
    CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, sid, csap, NULL,
                                  NULL));
    CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, sid6, csap6, NULL,
                                  NULL));
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (csap != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, sid, csap));
    if (csap6 != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, sid6, csap6));
    free(tx_buf);
    free(rx_buf);
    TEST_END;
}
