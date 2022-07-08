/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Network interface related tests
 */

/** @page ifcfg-if_source_addr_dgram Source address selection by UDP socket when a few local addresses are assigned to the interface
 *
 * @objective Check that the correct source address is used (when there are
 *            a few local addresses) in datagrams in dependence on the
 *            destination address.
 *
 * @type conformance
 *
 * @param pco_iut   PCO on @p IUT
 * @param pco_tst   PCO on @p TESTER
 * @param iut_addr  Network address not assigned to any interface
 * @param tst_addr  Network address not assigned to any interface from the
 *                  same subnetwork as @p iut_addr
 * @param bind_to   Bind address type
 *
 * @par Test sequence:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ifcfg/if_source_addr_dgram"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    tapi_env_net          *net = NULL;
    tapi_env_host         *iut_host = NULL;
    tapi_env_host         *tst_host = NULL;
    sockts_addr_type       bind_to;

    struct sockaddr       *iut_addr2;
    struct sockaddr       *tst_addr2;
    struct sockaddr       *tst_addr_wild = NULL;
    struct sockaddr       *iut_addr_wild = NULL;
    const struct sockaddr *iut_addr_exp = NULL;
    struct sockaddr        peer_addr;
    socklen_t              peer_addrlen = sizeof(peer_addr);
    tapi_cfg_net_assigned  net_handle = {CFG_HANDLE_INVALID, NULL};

    void    *tx_buf = NULL;
    size_t   tx_buflen = 1024;
    void    *rx_buf = NULL;
    size_t   rx_buflen = 1024;

    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_HOST(iut_host);
    TEST_GET_HOST(tst_host);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_ADDR_TYPE(bind_to);

    tx_buf = te_make_buf_by_len(tx_buflen);
    rx_buf = te_make_buf_by_len(rx_buflen);

    TEST_STEP("Assign additional network on IUT and tester interfaces. IUT and "
              "tester have two IP addresses couples now - @b first and @b second.");
    CHECK_RC(tapi_cfg_net_assign_ip(AF_INET, net->cfg_net, &net_handle));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net, iut_host, AF_INET,
                                        &net_handle, &iut_addr2, NULL));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net, tst_host, AF_INET,
                                        &net_handle, &tst_addr2, NULL));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create UDP socket.");
    iut_s = rpc_socket(pco_iut, RPC_AF_INET, SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind it to the @b second IUT address or @c INADDRA_ANY or don't bind "
              "in dependence on @p bind_to.");
    te_sockaddr_set_port(iut_addr2, te_sockaddr_get_port(iut_addr));
    if (bind_to == SOCKTS_ADDR_SPEC)
    {
        rpc_bind(pco_iut, iut_s, iut_addr2);
    }
    else if (bind_to == SOCKTS_ADDR_WILD)
    {
        CHECK_RC(tapi_sockaddr_clone2(iut_addr2, &iut_addr_wild));
        te_sockaddr_set_wildcard(iut_addr_wild);
        rpc_bind(pco_iut, iut_s, iut_addr_wild);
    }

    TEST_STEP("Create and bind tester socket to @c INADDR_ANY.");
    tst_s = rpc_socket(pco_tst, RPC_AF_INET, SOCK_DGRAM, RPC_PROTO_DEF);

    CHECK_RC(tapi_sockaddr_clone2(tst_addr, &tst_addr_wild));
    te_sockaddr_set_wildcard(tst_addr_wild);
    /* Set the same port to @c tst_addr and @c tst_addr2. */
    te_sockaddr_set_port(tst_addr2, te_sockaddr_get_port(tst_addr));

    rpc_bind(pco_tst, tst_s, tst_addr_wild);

    if (bind_to == SOCKTS_ADDR_SPEC)
        iut_addr_exp = iut_addr2;
    else
        iut_addr_exp = iut_addr;

    TEST_STEP("Send a datagram from IUT to the @b first tester IP address. "
              "- Check that datagram source IP address is: "
              "- the @b second if socket was bound to the @b second IP. "
              "- else it is the @b first IP.");
    RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0, tst_addr);
    rc = rpc_recvfrom(pco_tst, tst_s, rx_buf, rx_buflen, 0,
                      &peer_addr, &peer_addrlen);
    if (SIN(&peer_addr)->sin_addr.s_addr != SIN(iut_addr_exp)->sin_addr.s_addr)
        TEST_VERDICT("The first datagram has incorrect source address");
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_buflen, rc);

    TEST_STEP("Send a datagram from IUT to the @b second tester IP address. "
              "- Check that datagram source IP address is the @b second IUT IP.");
    RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, tx_buflen, 0, tst_addr2);
    rc = rpc_recvfrom(pco_tst, tst_s, rx_buf, rx_buflen, 0,
                      &peer_addr, &peer_addrlen);
    if (SIN(&peer_addr)->sin_addr.s_addr != SIN(iut_addr2)->sin_addr.s_addr)
        TEST_VERDICT("The second datagram has incorrect source address");
    SOCKTS_CHECK_RECV(pco_tst, tx_buf, rx_buf, tx_buflen, rc);

    TEST_STEP("Send a datagram from tester to IUT, check data.");
    if (bind_to == SOCKTS_ADDR_NONE)
    {
        struct sockaddr_storage bind_addr;
        socklen_t               bind_addrlen = sizeof(bind_addr);

        rpc_getsockname(pco_iut, iut_s, SA(&bind_addr), &bind_addrlen);
        te_sockaddr_set_port(iut_addr2,
                             te_sockaddr_get_port(SA(&bind_addr)));
    }

    sockts_test_udp_sendto(pco_tst, tst_s, pco_iut, iut_s, iut_addr2);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
