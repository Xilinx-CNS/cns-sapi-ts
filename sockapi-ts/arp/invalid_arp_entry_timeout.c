/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * ARP table
 */

/** @page arp-invalid_arp_entry_timeout Invalid ARP entries are not reinforced by socket operations
 *
 * @objective Check that establishing TCP connection or sending/receiving
 *            UDP packets will not reinforce invalid ARP entry.
 *
 * @type conformance
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on TESTER
 * @param iut_if          Network interface on IUT
 * @param iut_lladdr      Hardware address of @p iut_if interface
 * @param iut_addr        IP address of @p iut_if interface
 * @param tst_if          Network interface on TESTER
 * @param tst_lladdr      Hardware address of @p tst_if interface
 * @param tst_addr        IP address of @p tst_if interface
 * @param alien_link_addr MAC address not assigned to any host
 * @param sock_type       Socket type (@c SOCK_STREAM or @c SOCK_DGRAM)
 * @param active          If @c TRUE, in case of TCP initiate connection
 *                        from IUT, in case of UDP send packets from IUT.
 *                        Otherwise initiate connection from Tester for
 *                        TCP or send packets from Tester for UDP.
 * @param call_connect    Whether to call @b connect() on IUT (makes sense
 *                        only for UDP).
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME "arp/invalid_arp_entry_timeout"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "te_ethernet.h"
#include "tapi_route_gw.h"

/**
 * How long to wait until incorrect ARP entry times out,
 * in milliseconds.
 */
#define ARP_CHECK_TIMEOUT       (4 * 60 * 1000)

/**
 * The number of attempts to skip DELAY state
 */
#define ARP_DELAY_WAIT_MAX 3


/**
 * Time in seconds to skip DELAY state before REACHABLE.
 */
#define ARP_DELAY_TIMEOUT 2

/**
 * Check that there is a correct ARP entry for
 * a given address.
 *
 * @param ta              Test Agent name
 * @param if_name         Interface name
 * @param net_addr        Network address
 * @param exp_mac_addr    Expected MAC address
 */
static void
check_arp_entry(const char *ta,
                const char *if_name,
                const struct sockaddr *net_addr,
                const uint8_t *exp_mac_addr)
{
    te_errno rc;

    uint8_t                 mac_addr[ETHER_ADDR_LEN];
    te_bool                 is_static;
    cs_neigh_entry_state    state;
    int                     i;

    for (i = 0; i <= ARP_DELAY_WAIT_MAX; i++)
    {
        rc = tapi_cfg_get_neigh_entry(ta, if_name, net_addr,
                                    mac_addr, &is_static, &state);

        if (rc == 0)
        {
            if (memcmp(mac_addr, exp_mac_addr, sizeof(mac_addr)) != 0)
            {
                TEST_VERDICT("ARP entry does not contain correct MAC");
            }
            else if (is_static)
            {
                TEST_VERDICT("ARP entry is static, not dynamic");
            }
            else if (i != ARP_DELAY_WAIT_MAX && state == CS_NEIGH_DELAY)
            {
                VSLEEP(ARP_DELAY_TIMEOUT, "Wait some time to skip DELAY state.");
            }
            else if (state != CS_NEIGH_REACHABLE)
            {
                TEST_VERDICT("ARP entry has unexpected state %s",
                             cs_neigh_entry_state2str(state));
            }
            else
            {
                break;
            }
        }
        else
        {
            if (rc == TE_RC(TE_CS, TE_ENOENT))
                TEST_VERDICT("Correct ARP entry did not appear");
            else
                TEST_VERDICT("tapi_cfg_get_neigh_entry() failed returning %r",
                            rc);
        }
    }
}

/**
 * Check that libc function returns non-negative value; otherwise
 * fail the test with an error message.
 *
 * @param expr_       Libc function call.
 */
#define CHECK_LIBC_RC(expr_) \
{                                                         \
    int rc_;                                              \
                                                          \
    rc_ = (expr_);                                        \
                                                          \
    if (rc_ < 0)                                          \
    {                                                     \
        TEST_FAIL("line %d: %s failed with errno %r",     \
                  __LINE__, # expr_,                      \
                  TE_RC(TE_TAPI, te_rc_os2te(errno)));    \
    }                                                     \
}

/**
 * Fail the test if too much time passed since we started
 * waiting for incorrect ARP entry timing out.
 *
 * @param start_time_     Moment when we started checking.
 */
#define CHECK_ARP_TIMEOUT(start_time_) \
    do {                                                              \
        struct timeval current_time_;                                 \
                                                                      \
        CHECK_LIBC_RC(gettimeofday(&current_time_, NULL));            \
        if (TE_US2MS(TIMEVAL_SUB(current_time_,                       \
                                 start_time_)) > ARP_CHECK_TIMEOUT)   \
        {                                                             \
            TEST_VERDICT("Incorrect ARP entry survived "              \
                         "for too much time");                        \
        }                                                             \
    } while (0)

/**
 * Check that sending UDP packets does not prevent
 * incorrect ARP entry from timing out.
 *
 * @param pco_iut       RPC server on IUT
 * @param iut_s         IUT socket
 * @param pco_tst       RPC server on Tester
 * @param tst_s         Tester socket
 * @param tst_addr      Network address to which
 *                      Tester socket is bound
 * @param call_connect  Whether connect() should be called
 *                      for IUT socket
 */
static void
check_udp_send(rcf_rpc_server *pco_iut, int iut_s,
               rcf_rpc_server *pco_tst, int tst_s,
               const struct sockaddr *tst_addr,
               te_bool call_connect)
{
    te_errno  rc;
    char      send_buf[SOCKTS_MSG_DGRAM_MAX];
    char      recv_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t    send_len;
    te_bool   readable = FALSE;

    struct timeval start_time;

    if (call_connect)
        rpc_connect(pco_iut, iut_s, tst_addr);

    CHECK_LIBC_RC(gettimeofday(&start_time, NULL));

    while (TRUE)
    {
        send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
        te_fill_buf(send_buf, send_len);

        if (call_connect)
            rpc_send(pco_iut, iut_s, send_buf, send_len, 0);
        else
            rpc_sendto(pco_iut, iut_s, send_buf, send_len, 0, tst_addr);

        TAPI_WAIT_NETWORK;

        RPC_GET_READABILITY(readable, pco_tst, tst_s, 0);
        if (readable)
        {
            rc = rpc_recv(pco_tst, tst_s, recv_buf,
                          SOCKTS_MSG_DGRAM_MAX, 0);
            SOCKTS_CHECK_RECV(pco_tst, send_buf, recv_buf,
                              send_len, rc);

            break;
        }

        CHECK_ARP_TIMEOUT(start_time);
    }
}

/**
 * Check that receiving UDP packets does not prevent
 * incorrect ARP entry from timing out.
 *
 * @param pco_iut       RPC server on IUT
 * @param iut_s         IUT socket
 * @param pco_tst       RPC server on Tester
 * @param tst_s         Tester socket
 * @param tst_addr      Network address to which
 *                      Tester socket is bound
 * @param if_name       IUT interface name
 * @param exp_mac       Correct MAC for Tester address
 * @param call_connect  Whether connect() should be called
 *                      for IUT socket
 */
static void
check_udp_receive(rcf_rpc_server *pco_iut, int iut_s,
                  rcf_rpc_server *pco_tst, int tst_s,
                  const struct sockaddr *tst_addr,
                  const char *if_name,
                  const uint8_t *exp_mac,
                  te_bool call_connect)
{
    char    send_buf[SOCKTS_MSG_DGRAM_MAX];
    char    recv_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t  send_len;

    struct timeval start_time;

    te_errno                rc;
    uint8_t                 mac_addr[ETHER_ADDR_LEN];
    te_bool                 is_static;
    cs_neigh_entry_state    state;
    te_bool                 readable = FALSE;
    te_bool                 first_iut_send = TRUE;

    CHECK_LIBC_RC(gettimeofday(&start_time, NULL));

    while (TRUE)
    {
        send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
        te_fill_buf(send_buf, send_len);

        rpc_send(pco_tst, tst_s, send_buf, send_len, 0);

        TAPI_WAIT_NETWORK;

        rc = rpc_recv(pco_iut, iut_s, recv_buf,
                      SOCKTS_MSG_DGRAM_MAX, 0);
        SOCKTS_CHECK_RECV(pco_iut, send_buf, recv_buf,
                          send_len, rc);

        rc = tapi_cfg_get_neigh_entry(pco_iut->ta, if_name, tst_addr,
                                      mac_addr, &is_static, &state);

        if ((rc == 0 &&
             memcmp(mac_addr, exp_mac, sizeof(mac_addr)) == 0) ||
            rc == TE_RC(TE_CS, TE_ENOENT))
            break;
        else if (rc != 0)
            TEST_VERDICT("tapi_cfg_get_neigh_entry() failed returning %r",
                         rc);

        /*
         * It seems on Linux ARP entry may be in STALE state for an
         * indefinite amount of time until something provokes ARP
         * resolution. After that it for some time will send ARP
         * requests with incorrect MAC address, which will not be
         * answered; and finally ARP entry will be removed.
         */

        if (state == CS_NEIGH_STALE && first_iut_send)
        {
            if (call_connect)
            {
                rpc_connect(pco_iut, iut_s, tst_addr);
                rpc_send(pco_iut, iut_s, send_buf, send_len, 0);
            }
            else
            {
                rpc_sendto(pco_iut, iut_s, send_buf, send_len, 0, tst_addr);
            }

            first_iut_send = FALSE;

            TAPI_WAIT_NETWORK;
            RPC_GET_READABILITY(readable, pco_tst, tst_s, 0);
            if (readable)
                break;
        }

        CHECK_ARP_TIMEOUT(start_time);
    }

    /*
     * This is done to make sure that correct ARP entry will appear
     * in the table.
     */

    if (!readable)
    {
        if (call_connect)
        {
            if (first_iut_send)
                rpc_connect(pco_iut, iut_s, tst_addr);
            rpc_send(pco_iut, iut_s, send_buf, send_len, 0);
        }
        else
        {
            rpc_sendto(pco_iut, iut_s, send_buf, send_len, 0, tst_addr);
        }

        TAPI_WAIT_NETWORK;

        RPC_GET_READABILITY(readable, pco_tst, tst_s, 0);
        if (!readable)
            TEST_VERDICT("Cannot receive a packet on Tester after "
                         "ARP entry timed out");
    }

    rc = rpc_recv(pco_tst, tst_s, recv_buf,
                  SOCKTS_MSG_DGRAM_MAX, 0);
    SOCKTS_CHECK_RECV(pco_tst, send_buf, recv_buf,
                      send_len, rc);
}

/**
 * Check that TCP connection can be established despite incorrect
 * ARP entry (which should be replaced with correct one eventually).
 *
 * @param rpcs        RPC server handle
 * @param s           Socket
 * @param addr        Network address to connect to
 */
static void
check_tcp_connect(rcf_rpc_server *rpcs, int s,
                  const struct sockaddr *addr)
{
    struct timeval start_time;
    te_errno       rc;

    CHECK_LIBC_RC(gettimeofday(&start_time, NULL));

    while (TRUE)
    {
        rpcs->timeout = ARP_CHECK_TIMEOUT;
        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_connect(rpcs, s, addr);

        if (rc >= 0)
            break;
        else if (RPC_ERRNO(rpcs) != RPC_ETIMEDOUT)
            TEST_VERDICT("connect() failed with unexpected errno %r",
                         RPC_ERRNO(rpcs));

        CHECK_ARP_TIMEOUT(start_time);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server  *pco_iut = NULL;
    rcf_rpc_server  *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;
    const struct sockaddr  *alien_link_addr = NULL;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *tst_if = NULL;

    int iut_s = -1;
    int tst_s = -1;

    rpc_socket_type   sock_type;
    te_bool           active;
    te_bool           call_connect;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(call_connect);

    TEST_STEP("Delete @p tst_addr ARP table entry on IUT.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                      tst_addr));

    TEST_STEP("Delete @p iut_addr ARP table entry on Tester.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      iut_addr));

    TEST_STEP("Add static ARP table entry for @p iut_addr on Tester "
              "to avoid ARP resolution activities from it.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, CVT_HW_ADDR(iut_lladdr), TRUE));

    TEST_STEP("Add dynamic ARP table entry for @p tst_addr with incorrect "
              "@p alien_link_addr on IUT.");
    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_link_addr), FALSE));

    CFG_WAIT_CHANGES;

    TEST_STEP("Create a pair of sockets of type @p sock_type on IUT and Tester.");

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Perform socket operation according to @p sock_type, @p active "
              "and @p call_connect until it succeeds (for TCP connection "
              "establishment), or until a packet sent from IUT can be received "
              "on Tester (for UDP socket).");

    if (sock_type == RPC_SOCK_STREAM)
    {
        if (active)
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

            check_tcp_connect(pco_iut, iut_s, tst_addr);
        }
        else
        {
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);

            check_tcp_connect(pco_tst, tst_s, iut_addr);
        }
    }
    else
    {
        rpc_connect(pco_tst, tst_s, iut_addr);

        if (active)
        {
            check_udp_send(pco_iut, iut_s, pco_tst, tst_s,
                           tst_addr, call_connect);
        }
        else
        {
            check_udp_receive(pco_iut, iut_s, pco_tst, tst_s,
                              tst_addr, iut_if->if_name,
                              (uint8_t *)tst_lladdr->sa_data,
                              call_connect);
        }
    }

    TEST_STEP("Check that now correct ARP table entry for @p tst_addr "
              "can be found on IUT.");
    check_arp_entry(pco_iut->ta, iut_if->if_name, tst_addr,
                    (uint8_t *)tst_lladdr->sa_data);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
