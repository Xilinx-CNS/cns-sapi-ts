/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* (c) Copyright 2023 OKTET Labs Ltd. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 * 
 * $Id$
 */

/** @page tcp-tcp_loopback Testing of TCP connection between sockets on the same host
 *
 * @objective Check that we can connect two TCP sockets created on the
 *            same host no matter which addresses on which interfaces
 *            they are bound to.
 *
 * @type conformance
 *
 * @param pco_iut                 PCO on IUT
 * @param iut_addr1               Address on SFC interface
 * @param iut_addr2               Address on other interface
 * @param server_addr             Which address server TCP
 *                                socket should be bound to
 *                                (address on SFC interface,
 *                                 on other interface, loopback
 *                                 address or wildcard address)
 * @param client_addr             Which address client TCP
 *                                socket should be bound to
 *                                (the same options as for @p server_addr
 *                                 excepting wildcard address or not
 *                                 bind it at all) 
 * @param connect_addr            Which address client TCP socket
 *                                should be connected to
 *                                (the same options as for @p server_addr)
 * @param accept_first            Whether @b accept() should be called
 *                                before @b connect or not.
 * @param ef_tcp_server_loopback  Value to be set for environment
 *                                variable @c EF_TCP_SERVER_LOOPBACK
 * @param ef_tcp_client_loopback  Value to be set for environment
 *                                variable @c EF_TCP_CLIENT_LOOPBACK
 * @param v6only                  If @c TRUE, enable @c IPV6_V6ONLY option
 * 
 * @par Test sequence:
 *
 * -# If @p ef_tcp_[server|client]_loopback is not "none",
 *    set corresponding environment variable(s).
 * -# Create socket @p iut_s on @p pco_iut, bind it to an address
 *    selected according to @p server_addr parameter, call
 *    @b listen() on it.
 * -# Create child process @p pco_tst.
 * -# Create socket @p tst_s on @p pco_tst, bind it to an address
 *    selected according to @p client_addr if required.
 * -# If @p accept_first, call blocking @b accept() on @pco_iut.
 * -# @b connect() @p tst_s to an address selected according to
 *    @p connect_addr.
 * -# Call @b accept() on @p iut_s to obtain @p acc_s socket on
 *    @p pco_iut.
 * -# Check that we can transmit data through established TCP
 *    connection.
 * -# Check whether we can see TCP packets on loopback interface
 *    via CSAP.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tcp/tcp_loopback"

#include "sockapi-test.h"
#include "tapi_tcp.h"

#define BUF_SIZE 4096

#define LOCAL_ADDRS \
    {"SFC_ADDR", SFC_IF_ADDR},    \
    {"OTH_ADDR", OTHER_IF_ADDR},  \
    {"LO_ADDR", LOOPBACK_ADDR},   \
    {"OTH_LO_ADDR", OTHER_LOOP_ADDR},   \
    {"WILD_ADDR", WILDCARD_ADDR}, \
    {"WILD_IP4MAPPED_ADDR", WILDCARD_IP4MAPPED_ADDR}, \
    {"NO_ADDR", NO_ADDR}

enum {
    SFC_IF_ADDR = 1,
    OTHER_IF_ADDR,
    LOOPBACK_ADDR,
    OTHER_LOOP_ADDR,
    WILDCARD_ADDR,
    WILDCARD_IP4MAPPED_ADDR,
    NO_ADDR
};

#define LOOPBACK_USERS \
    {"ROOT_LISTEN", ROOT_LISTEN}, \
    {"ROOT_CONN", ROOT_CONN},     \
    {"ROOT_BOTH", ROOT_BOTH},     \
    {"SAME_USERS", SAME_USERS},   \
    {"DIFF_USERS", DIFF_USERS}

enum {
    ROOT_LISTEN = 1,
    ROOT_CONN,
    ROOT_BOTH,
    SAME_USERS,
    DIFF_USERS
};

#if HAVE_PWD_H
#include <pwd.h>
#endif

#define SET_CHECK_USER_BY_ID(_pco, _id) \
do {                                            \
    rpc_setuid(_pco, _id);                      \
    if (rpc_getuid(_pco) != _id)                \
        TEST_FAIL("User ID change failed");     \
} while (0)

int
main(int argc, char *argv[])
{
    int         server_addr = 0;
    int         client_addr = 0;
    int         connect_addr = 0;
    int         loopback_users = 0;
    int         iut_s = -1;
    int         tst_s = -1;
    int         acc_s = -1;
    uint16_t    iut_port;
    te_bool     v6only;

    uint8_t     tx_buf[BUF_SIZE];
    uint8_t     rx_buf[BUF_SIZE];

    int             sid;
    unsigned int    received_packets_number = 0;
    csap_handle_t   csap = CSAP_INVALID_HANDLE;

    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;
    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *iut_addr1 = NULL;
    const struct sockaddr   *iut_addr2 = NULL;
    const struct sockaddr   *iut_addr_wild = NULL;
    struct sockaddr_storage  tst_addr;
    struct sockaddr_storage  addr_to_conn;
    struct sockaddr_storage  loopback_addr;
    struct sockaddr_storage  other_loop_addr;
    struct sockaddr_storage  wildcard_addr;
    struct sockaddr_storage  wildcard_ip4mapped_addr;

    const struct if_nameindex *iut_if = NULL;

    te_bool                  accept_first = FALSE;
    int                      ef_tcp_client_loopback;
    int                      ef_tcp_server_loopback;
    cfg_handle               ef_name_h = CFG_HANDLE_INVALID;
    char                    *old_ef_name = NULL;
    cfg_val_type             val_type = CVT_STRING;

    te_bool                  is_failed = FALSE;

    struct passwd           *passwd = getpwuid(getuid());

    te_bool                  restart_pco = FALSE;
    te_bool                  ipv4_vs_ipv6 = FALSE;

    te_bool                  diff_user = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ENUM_PARAM(server_addr, LOCAL_ADDRS);
    TEST_GET_ENUM_PARAM(client_addr, LOCAL_ADDRS);
    TEST_GET_ENUM_PARAM(connect_addr, LOCAL_ADDRS);
    TEST_GET_BOOL_PARAM(accept_first);
    TEST_GET_INT_PARAM(ef_tcp_server_loopback);
    TEST_GET_INT_PARAM(ef_tcp_client_loopback);
    TEST_GET_ENUM_PARAM(loopback_users, LOOPBACK_USERS);
    TEST_GET_BOOL_PARAM(v6only);

    if (server_addr == OTHER_IF_ADDR ||
        client_addr == OTHER_IF_ADDR ||
        connect_addr == OTHER_IF_ADDR)
    {
        TEST_GET_ADDR(pco_iut, iut_addr2);
    }

    /*
     * iut_addr_wild is presented only in environment with mixed IPv4
     * and IPv6 addresses, and is intented to test the case: IPv6 wildcard
     * server with IPv4 client connecting to it.
     * iut_addr_wild has always AF_INET6 family.
     */
    iut_addr_wild = tapi_env_get_addr(&env, "iut_addr_wild", NULL);

    if ((iut_addr1->sa_family != AF_INET) &&
        (server_addr == OTHER_LOOP_ADDR ||
         client_addr == OTHER_LOOP_ADDR ||
         connect_addr == OTHER_LOOP_ADDR))
    {
        TEST_FAIL("Invalid iteration - there is only one loopback "
                  "address in IPv6");
    }

    te_fill_buf(tx_buf, BUF_SIZE);
    memset(rx_buf, 0, BUF_SIZE);

    SA(&loopback_addr)->sa_family = SA(iut_addr1)->sa_family;
    te_sockaddr_set_loopback(SA(&loopback_addr));
    SA(&other_loop_addr)->sa_family = SA(iut_addr1)->sa_family;
    te_sockaddr_set_loopback(SA(&other_loop_addr));
    /* Set unusual loopback address */
    SIN(&other_loop_addr)->sin_addr.s_addr =
        htonl(ntohl(SIN(&other_loop_addr)->sin_addr.s_addr) + 10);

    if (iut_addr_wild != NULL)
    {
        if (iut_addr_wild->sa_family != AF_INET6)
        {
            TEST_FAIL("Invalid testing environment, 'iut_addr_wild' "
                      "must have AF_INET6 family.");
        }
        tapi_sockaddr_clone_exact(iut_addr_wild, &wildcard_addr);
        ipv4_vs_ipv6 = TRUE;
    }
    else
    {
        SA(&wildcard_addr)->sa_family = SA(iut_addr1)->sa_family;
        te_sockaddr_set_wildcard(SA(&wildcard_addr));
    }

    wildcard_ip4mapped_addr.ss_family = AF_INET;
    te_sockaddr_set_wildcard(SA(&wildcard_ip4mapped_addr));
    te_sockaddr_ip4_to_ip6_mapped(SA(&wildcard_ip4mapped_addr));

    if (ef_tcp_server_loopback != -1)
    {
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_SERVER_LOOPBACK",
                                     ef_tcp_server_loopback, TRUE, FALSE));
        restart_pco = TRUE;
    }

    if (ef_tcp_client_loopback != -1)
    {
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_CLIENT_LOOPBACK",
                                     ef_tcp_client_loopback, TRUE, FALSE));
        restart_pco = TRUE;
    }

    if (restart_pco && cfg_find_fmt(&ef_name_h, "/agent:%s/env:EF_NAME",
                                    pco_iut->ta) == 0)
    {
        CHECK_RC(cfg_get_instance(ef_name_h, &val_type, &old_ef_name));
        if (strcmp(old_ef_name, "") != 0)
            CHECK_RC(cfg_set_instance(ef_name_h, CVT_STRING,
                                      "te_tcp_loopback"));
    }

    if (restart_pco)
    {
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
        CHECK_RC(rcf_rpc_server_restart(pco_tst));
    }

    CHECK_RC(rcf_ta_create_session(pco_iut->ta, &sid));
    rc = tapi_tcp_ip_eth_csap_create(pco_iut->ta, sid, iut_if->if_name,
                                     TAD_ETH_RECV_HOST |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     NULL, NULL, iut_addr1->sa_family,
                                     TAD_SA2ARGS(NULL, NULL), &csap);

    switch (loopback_users)
    {
        case ROOT_LISTEN:
            SET_CHECK_USER_BY_ID(pco_tst, passwd->pw_uid);
            break;

        case ROOT_CONN:
            SET_CHECK_USER_BY_ID(pco_iut, passwd->pw_uid);
            break;

        case SAME_USERS:
            SET_CHECK_USER_BY_ID(pco_iut, passwd->pw_uid);
            SET_CHECK_USER_BY_ID(pco_tst, passwd->pw_uid);
            break;

        case DIFF_USERS:
            CHECK_RC(tapi_cfg_add_new_user(pco_iut->ta, SOCKTS_DEF_UID));
            diff_user = TRUE;
            SET_CHECK_USER_BY_ID(pco_tst, SOCKTS_DEF_UID);
            SET_CHECK_USER_BY_ID(pco_iut, passwd->pw_uid);
            break;

        default:
            break;
    }

    switch (server_addr)
    {
        case SFC_IF_ADDR:
            iut_addr = iut_addr1;
            iut_port = te_sockaddr_get_port(iut_addr1);
            break;

        case OTHER_IF_ADDR:
            iut_addr = iut_addr2;
            iut_port = te_sockaddr_get_port(iut_addr2);
            break;

        case LOOPBACK_ADDR:
            CHECK_RC(tapi_allocate_port_htons(pco_iut, &iut_port));
            iut_addr = SA(&loopback_addr);
            break;

        case OTHER_LOOP_ADDR:
            CHECK_RC(tapi_allocate_port_htons(pco_iut, &iut_port));
            iut_addr = SA(&other_loop_addr);
            break;

        case WILDCARD_ADDR:
            CHECK_RC(tapi_allocate_port_htons(pco_iut, &iut_port));
            iut_addr = SA(&wildcard_addr);
            break;

        case WILDCARD_IP4MAPPED_ADDR:
            CHECK_RC(tapi_allocate_port_htons(pco_iut, &iut_port));
            iut_addr = SA(&wildcard_ip4mapped_addr);
            break;

        default:
            break;
    }

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr1),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (v6only)
        rpc_setsockopt_int(pco_iut, iut_s, RPC_IPV6_V6ONLY, 1);

    te_sockaddr_set_port(SA(&wildcard_addr), iut_port);
    te_sockaddr_set_port(SA(&wildcard_ip4mapped_addr), iut_port);
    te_sockaddr_set_port(SA(&loopback_addr), iut_port);
    te_sockaddr_set_port(SA(&other_loop_addr), iut_port);
    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

    switch (client_addr)
    {
        case SFC_IF_ADDR:
            tapi_sockaddr_clone_exact(iut_addr1, &tst_addr);
            break;

        case OTHER_IF_ADDR:
            tapi_sockaddr_clone_exact(iut_addr2, &tst_addr);
            break;

        case LOOPBACK_ADDR:
            tapi_sockaddr_clone_exact(SA(&loopback_addr), &tst_addr);
            break;

        case OTHER_LOOP_ADDR:
            tapi_sockaddr_clone_exact(SA(&other_loop_addr), &tst_addr);
            break;

        default:
            break;
    }

    if (client_addr != NO_ADDR)
    {
        te_sockaddr_set_port(SA(&tst_addr), 0);
        rpc_bind(pco_tst, tst_s, SA(&tst_addr));
    }

    switch (connect_addr)
    {
        case SFC_IF_ADDR:
            tapi_sockaddr_clone_exact(iut_addr1, &addr_to_conn);
            break;

        case OTHER_IF_ADDR:
            tapi_sockaddr_clone_exact(iut_addr2, &addr_to_conn);
            break;

        case LOOPBACK_ADDR:
            tapi_sockaddr_clone_exact(SA(&loopback_addr), &addr_to_conn);
            break;

        case OTHER_LOOP_ADDR:
            tapi_sockaddr_clone_exact(SA(&other_loop_addr), &addr_to_conn);
            break;

        case WILDCARD_ADDR:
            if (ipv4_vs_ipv6)
            {
                wildcard_addr.ss_family = AF_INET;
                te_sockaddr_set_wildcard(SA(&wildcard_addr));
            }
            tapi_sockaddr_clone_exact(SA(&wildcard_addr), &addr_to_conn);
            break;

        default:
            break;
    }

    te_sockaddr_set_port(SA(&addr_to_conn), iut_port);

    if (accept_first)
    {
        pco_iut->op = RCF_RPC_CALL;
        rpc_accept(pco_iut, iut_s, NULL, NULL);
    }

    if (v6only)
        RPC_AWAIT_ERROR(pco_tst);

    rc = rpc_connect(pco_tst, tst_s, SA(&addr_to_conn));

    if (v6only)
    {
        if (rc == 0)
        {
            TEST_VERDICT("Connect from IPv4 client with V6ONLY option "
                         "enabled on server unexpectedly succeed");
        }
        else
        {
            CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED, "Connect from IPv4 "
                            "client with V6ONLY option enabled on server "
                            "failed, but");
            TEST_SUCCESS;
        }
    }

    acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

    rc = tapi_tad_trrecv_start(pco_iut->ta, sid, csap, NULL,
                               TAD_TIMEOUT_INF,
                               0,
                               RCF_TRRECV_PACKETS);
    if (rc != 0)
        TEST_FAIL("Failed to start receiving on the CSAP, rc = %X, "
                  "csap id %d", rc, csap);

    rpc_send(pco_iut, acc_s, tx_buf, BUF_SIZE, 0);
    rc = rpc_recv(pco_tst, tst_s, rx_buf, BUF_SIZE, 0);
    if (rc != BUF_SIZE)
    {
        RING_VERDICT("recv() on pco_tst returned %d bytes "
                     "instead of %d", rc, BUF_SIZE);
        is_failed = TRUE;
    }
    else if (memcmp(tx_buf, rx_buf, BUF_SIZE) != 0)
    {
        RING_VERDICT("Wrong data was received on pco_tst");
        is_failed = TRUE;
    }

    memset(rx_buf, 0, BUF_SIZE);

    rpc_send(pco_tst, tst_s, tx_buf, BUF_SIZE, 0);
    rc = rpc_recv(pco_iut, acc_s, rx_buf, BUF_SIZE, 0);
    if (rc != BUF_SIZE)
    {
        RING_VERDICT("recv() on pco_iut returned %d bytes "
                     "instead of %d", rc, BUF_SIZE);
        is_failed = TRUE;
    }
    else if (memcmp(tx_buf, rx_buf, BUF_SIZE) != 0)
    {
        RING_VERDICT("Wrong data was received on pco_iut");
        is_failed = TRUE;
    }

    if (tapi_tad_trrecv_stop(pco_iut->ta, sid, csap, NULL,
                             &received_packets_number))
        TEST_FAIL("Failed to receive packets");

    RING("Received packets number %d", received_packets_number);
    if (received_packets_number > 0)
        RING_VERDICT("CSAP registered data traffic on the loopback "
                     "interface");

    if (is_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_iut->ta, sid, csap))
        ERROR("Failed to destroy CSAP");

    if (diff_user)
    {
        /* Restart to rollback user ID. */
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_tst));
        CLEANUP_CHECK_RC(tapi_cfg_del_user(pco_tst->ta, SOCKTS_DEF_UID));
    }

    /* This test changes environment variables and does not roll them back.
     * So we need to disable reuse_pco mode in order not to affect next
     * test. */
    tapi_no_reuse_pco_disable_once();

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
