/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_lacp_slave_up SO_REUSEPORT and changing state of LACP aggregation slaves
 *
 * @objective Check that if sockets are bound with @c SO_REUSEPORT to an
 *            address on LACP aggregation interface, they can accept
 *            connection or receive data if and only if it goes through
 *            a slave which is currently up.
 *
 *
 * @type use case
 *
 * @param pco_iut         PCO on IUT
 * @param pco_tst         PCO on Tester
 * @param iut_if1         The first network interface on IUT
 * @param iut_if2         The second network interface on IUT
 * @param tst1_if         The first network interface on Tester
 * @param tst2_if         The second network interface on Tester
 * @param team            If @c TRUE, check teaming; otherwise check
 *                        bonding.
 * @param first_slave     If @c TRUE, change state of the first slave;
 *                        otherwise change state of the second slave.
 * @param sock_first      If @c TRUE, create an IUT socket before
 *                        bringing one of the slave interfaces down;
 *                        otherwise create it after that.
 * @param sock_type       @c SOCK_STREAM or @c SOCK_DGRAM.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_lacp_slave_up"

#include "sockapi-test.h"
#include "reuseport.h"
#include "te_ethernet.h"
#include "tapi_cfg_aggr.h"
#include "sockapi-ts_net_conns.h"

/** Number of connections to open. */
#define CONNS_NUM 10

/**
 * Configure bonding/teaming device.
 *
 * @param rpcs            RPC server handle.
 * @param team            If @c TRUE, configure teaming,
 *                        otherwise bonding.
 * @param aggr_if_name    Where to save configured interface name.
 * @param slave1_if_name  Name of the first slave interface.
 * @param slave2_if_name  Name of the second slave interface.
 * @param net_handle      Network from which to allocate IP address.
 * @param net_prefix      Network prefix length.
 * @param addr            Where to save IP address assigned to the
 *                        configured interface.
 * @param addr_handle     Where to save configuration handle of
 *                        the assigned IP address.
 */
static void
configure_lacp(rcf_rpc_server *rpcs,
               te_bool team,
               char **aggr_if_name,
               const char *slave1_if_name,
               const char *slave2_if_name,
               cfg_handle net_handle,
               unsigned int net_prefix,
               struct sockaddr_storage *addr,
               cfg_handle *addr_handle)
{
    struct sockaddr *addr_aux = NULL;

    const char *mode = (team ? "team4" : "bond4");

    CHECK_RC(tapi_cfg_aggr_create_bond(rpcs->ta, "test_bond",
                                       aggr_if_name, mode));

    /*
     * On some hosts (like bifur with 3.10.0-514.26.2.el7.x86_64)
     * it is important to bring teaming device down before
     * adding slaves to it, or it will not work.
     */
    if (team)
        CHECK_RC(tapi_cfg_base_if_down(rpcs->ta, *aggr_if_name));

    CHECK_RC(tapi_cfg_aggr_bond_enslave(rpcs->ta, "test_bond",
                                        slave1_if_name));
    CHECK_RC(tapi_cfg_aggr_bond_enslave(rpcs->ta, "test_bond",
                                        slave2_if_name));

    CHECK_RC(tapi_cfg_alloc_net_addr(net_handle,
                                     addr_handle,
                                     &addr_aux));
    CHECK_RC(tapi_sockaddr_clone(rpcs, addr_aux,
                                 addr));
    free(addr_aux);

    CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                        rpcs->ta, *aggr_if_name,
                                        SA(addr),
                                        net_prefix,
                                        TRUE, NULL));

    if (!team)
        CHECK_RC(tapi_cfg_base_if_down(rpcs->ta, *aggr_if_name));
    CHECK_RC(tapi_cfg_base_if_up(rpcs->ta, *aggr_if_name));
}

/**
 * List of possible slave interfaces states.
 */
typedef enum {
    NO_SLAVES_DOWN = 0,   /**< Both slaves are up. */
    FIRST_SLAVE_DOWN,     /**< The first slave is down. */
    SECOND_SLAVE_DOWN,    /**< The second slave is down. */
} bond_slaves_state;

/** Will be set to TRUE if the testing failed. */
static te_bool test_failed = FALSE;

/**
 * Check that sockets bound to bonding/teaming interface
 * can accept connections or send data only via slaves which
 * are up.
 *
 * @param pco_iut           RPC server on IUT.
 * @param pco_tst           RPC server on Tester.
 * @param sock_type         @c SOCK_STREAM or @c SOCK_DGRAM.
 * @param iut_test_s1       The first socket on IUT bound to
 *                          @p iut_addr.
 * @param iut_test_s2       The second socket on IUT bound to
 *                          @p iut_addr.
 * @param tst_csap1         Handle of CSAP capturing packets
 *                          sent via the first slave on Tester.
 * @param tst_csap2         Handle of CSAP capturing packets
 *                          sent via the second slave on Tester.
 * @param iut_addr          IP address assigned to bonding/teaming
 *                          interface on IUT.
 * @param tst_addr          IP address assigned to bonding/teaming
 *                          interface on Tester.
 * @param state             State of bonding/teaming slaves.
 * @param err_msg           A string to print in verdicts.
 */
static void
check_lacp(rcf_rpc_server *pco_iut,
           rcf_rpc_server *pco_tst,
           rpc_socket_type sock_type,
           int iut_test_s1,
           int iut_test_s2,
           csap_handle_t tst_csap1,
           csap_handle_t tst_csap2,
           const struct sockaddr *iut_addr,
           struct sockaddr *tst_addr,
           bond_slaves_state state,
           const char *err_msg)
{
    int i;
    int iut_s = -1;
    int tst_s = -1;
    int iut_test_s = -1;

    unsigned int pkts1_num;
    unsigned int pkts2_num;
    te_bool      slave1_traffic = FALSE;
    te_bool      slave2_traffic = FALSE;
    te_bool      readable = FALSE;
    te_bool      wrong_received = FALSE;
    te_bool      not_received1 = FALSE;
    te_bool      not_received2 = FALSE;

    char      send_buf[SOCKTS_MSG_DGRAM_MAX];
    char      recv_buf[SOCKTS_MSG_DGRAM_MAX];
    ssize_t   rc;

    /*
     * In the loop a socket is created on Tester, each time
     * bound to a new port. It is assumed that choice of
     * a slave interface through which to send data depends on
     * port number. Currently TE sets xmit_hash_policy to
     * 1 (layer3+4) for LACP bond (and similar parameter for
     * LACP team), so this assumption should be correct.
     *
     * The loop is repeated until some packets are sent
     * through both Tester interfaces, or until @c CONNS_NUM
     * iterations were executed.
     */

    for (i = 0; i < CONNS_NUM; i++)
    {
        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tst_csap1, NULL,
                                       TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_COUNT));

        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, tst_csap2, NULL,
                                       TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_COUNT));

        CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr));

        tst_s = rpc_socket(pco_tst,
                           rpc_socket_domain_by_addr(iut_addr),
                           sock_type, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_s, tst_addr);

        if (sock_type == RPC_SOCK_STREAM)
        {
            rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);
            RPC_AWAIT_ERROR(pco_tst);
            rc = rpc_connect(pco_tst, tst_s, iut_addr);
            if (rc < 0 && RPC_ERRNO(pco_tst) != RPC_EINPROGRESS)
                TEST_VERDICT("Nonblocking connect() reported "
                             "unexpected error %r", RPC_ERRNO(pco_tst));
        }
        else
        {
            te_fill_buf(send_buf, sizeof(send_buf));
            rpc_connect(pco_tst, tst_s, iut_addr);
            rpc_send(pco_tst, tst_s, send_buf, sizeof(send_buf), 0);
        }

        RPC_GET_READABILITY(readable, pco_iut, iut_test_s1,
                            TAPI_WAIT_NETWORK_DELAY);
        if (readable)
        {
            iut_test_s = iut_test_s1;
        }
        else
        {
            RPC_GET_READABILITY(readable, pco_iut, iut_test_s2, 0);
            if (readable)
                iut_test_s = iut_test_s2;
        }

        if (readable)
        {
            if (sock_type == RPC_SOCK_STREAM)
            {
                iut_s = rpc_accept(pco_iut, iut_test_s, NULL, NULL);
                RPC_CLOSE(pco_iut, iut_s);
            }
            else
            {
                rc = rpc_recv(pco_iut, iut_test_s,
                              recv_buf, sizeof(recv_buf), 0);
                SOCKTS_CHECK_RECV(pco_iut, send_buf, recv_buf,
                                  sizeof(send_buf), rc);
            }
        }

        RPC_CLOSE(pco_tst, tst_s);

        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0,
                                      tst_csap1, NULL, &pkts1_num));

        CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0,
                                      tst_csap2, NULL, &pkts2_num));

        if (pkts1_num > 0 && pkts2_num > 0)
            TEST_VERDICT("%s: traffic over both slaves was detected",
                         err_msg);
        else if (pkts1_num == 0 && pkts2_num == 0)
            TEST_VERDICT("%s: no traffic over slaves was detected",
                         err_msg);

        if (readable)
        {
            if ((pkts1_num > 0 && state == FIRST_SLAVE_DOWN) ||
                (pkts2_num > 0 && state == SECOND_SLAVE_DOWN))
            {
                if (!wrong_received)
                {
                    ERROR_VERDICT("%s: connection check succeeded for "
                                  "the slave which is down", err_msg);
                    wrong_received = TRUE;
                    test_failed = TRUE;
                }
            }
        }
        else
        {
            if ((pkts1_num > 0 && state != FIRST_SLAVE_DOWN) ||
                (pkts2_num > 0 && state != SECOND_SLAVE_DOWN))
            {
                if ((pkts1_num > 0 && !not_received1) ||
                    (pkts2_num > 0 && !not_received2))
                {
                    ERROR_VERDICT("%s: connection check failed for "
                                  "the %s slave which is up", err_msg,
                                  (pkts1_num > 0 ? "first" : "second"));

                    if (pkts1_num > 0)
                        not_received1 = TRUE;
                    else
                        not_received2 = TRUE;

                    test_failed = TRUE;
                }
            }
        }

        if (pkts1_num > 0)
            slave1_traffic = TRUE;

        if (pkts2_num > 0)
            slave2_traffic = TRUE;

        if (slave1_traffic && slave2_traffic)
            break;
    }

    if (!slave1_traffic || !slave2_traffic)
        TEST_VERDICT("%s: no traffic was detected over one of the slaves "
                     "after many attempts to provoke it",
                     err_msg);
}

/**
 * Create two sockets on IUT, set SO_REUSEPORT for them
 * and bind them to the same IP address and port.
 *
 * @param rpcs          RPC server handle.
 * @param sock_type     Socket type.
 * @param bind_address  IP address and port to which to bind sockets.
 * @param s1            Where to save descriptor of the first socket.
 * @param s2            Where to save descriptor of the second socket.
 */
static void
create_iut_sockets(rcf_rpc_server *rpcs,
                   rpc_socket_type sock_type,
                   struct sockaddr *bind_addr,
                   int *s1, int *s2)
{
    *s1 = reuseport_create_bind_socket(rpcs, sock_type,
                                       bind_addr, TRUE);
    *s2 = reuseport_create_bind_socket(rpcs, sock_type,
                                       bind_addr, TRUE);

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(rpcs, *s1, SOCKTS_BACKLOG_DEF);
        rpc_listen(rpcs, *s2, SOCKTS_BACKLOG_DEF);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if1 = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct if_nameindex  *tst1_if = NULL;
    const struct if_nameindex  *tst2_if = NULL;

    char                       *iut_if_name = NULL;
    char                       *tst_if_name = NULL;
    struct sockaddr_storage     iut_addr;
    struct sockaddr_storage     tst_addr;
    cfg_handle                  iut_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  tst_addr_handle = CFG_HANDLE_INVALID;
    cfg_handle                  net_handle = CFG_HANDLE_INVALID;
    unsigned int                net_prefix = 0;

    csap_handle_t   tst_csap1 = CSAP_INVALID_HANDLE;
    csap_handle_t   tst_csap2 = CSAP_INVALID_HANDLE;

    int iut_test_s1 = -1;
    int iut_test_s2 = -1;

    te_bool           team;
    te_bool           first_slave;
    te_bool           sock_first;
    rpc_socket_type   sock_type;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if1);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst1_if);
    TEST_GET_IF(tst2_if);
    TEST_GET_BOOL_PARAM(team);
    TEST_GET_BOOL_PARAM(first_slave);
    TEST_GET_BOOL_PARAM(sock_first);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Create LACP bond interfaces @b iut_if_name on IUT and "
              "@b tst_if_name on Tester, choosing bonding/teaming according "
              "to @p team. "
              "Add @p iut_if1, @p iut_if2 as slaves to @b iut_if_name. "
              "Add @p tst1_if, @p tst2_if as slaves to @b tst_if_name. "
              "Allocate IP addresses @b iut_addr and @b tst_addr from a new "
              "network, assign @b iut_addr to @b iut_if_name and @b tst_addr to "
              "@b tst_if_name.");

    sockts_allocate_network(&net_handle, &net_prefix, AF_INET);

    configure_lacp(pco_iut, team, &iut_if_name,
                   iut_if1->if_name,
                   iut_if2->if_name,
                   net_handle, net_prefix, &iut_addr,
                   &iut_addr_handle);

    configure_lacp(pco_tst, team, &tst_if_name,
                   tst1_if->if_name,
                   tst2_if->if_name,
                   net_handle, net_prefix, &tst_addr,
                   &tst_addr_handle);

    CFG_WAIT_CHANGES;

    tapi_rpc_provoke_arp_resolution(pco_tst, SA(&iut_addr));

    TEST_STEP("Create a CSAP @b tst_csap1 on @p tst1_if; create a CSAP "
              "@b tst_csap2 on @p tst2_if. The CSAPs should listen for "
              "IP packets sent to @b iut_addr.");

    CHECK_RC(tapi_ip4_eth_csap_create(
                                  pco_tst->ta, 0, tst1_if->if_name,
                                  TAD_ETH_RECV_OUT |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  NULL, NULL,
                                  SIN(&iut_addr)->sin_addr.s_addr, 0,
                                  (sock_type == RPC_SOCK_STREAM ?
                                            IPPROTO_TCP : IPPROTO_UDP),
                                  &tst_csap1));

    CHECK_RC(tapi_ip4_eth_csap_create(
                                  pco_tst->ta, 0, tst2_if->if_name,
                                  TAD_ETH_RECV_OUT |
                                  TAD_ETH_RECV_NO_PROMISC,
                                  NULL, NULL,
                                  SIN(&iut_addr)->sin_addr.s_addr, 0,
                                  (sock_type == RPC_SOCK_STREAM ?
                                            IPPROTO_TCP : IPPROTO_UDP),
                                  &tst_csap2));

    TEST_STEP("If @p sock_first is @c TRUE, create two sockets of type "
              "@p sock_type on IUT, set @c SO_REUSEPORT for them and bind them "
              "to the same address @b iut_addr. For TCP sockets call listen(). "
              "After that check that connections can be accepted (or data "
              "received) via both IUT slave interfaces.");

    if (sock_first)
    {
        create_iut_sockets(pco_iut, sock_type, SA(&iut_addr),
                           &iut_test_s1, &iut_test_s2);

        check_lacp(pco_iut, pco_tst, sock_type,
                   iut_test_s1, iut_test_s2,
                   tst_csap1, tst_csap2,
                   SA(&iut_addr), SA(&tst_addr),
                   NO_SLAVES_DOWN, "The initial check");
    }

    TEST_STEP("If @p first_slave is @c TRUE, bring down @p iut_if1, "
              "else bring down @p iut_if2.");
    CHECK_RC(tapi_cfg_base_if_down(pco_iut->ta,
                                   (first_slave ? iut_if1->if_name :
                                                  iut_if2->if_name)));

    TEST_STEP("If @p sock_first is @c FALSE, create two sockets of type "
              "@p sock_type on IUT, set @c SO_REUSEPORT for them and bind them "
              "to the same address @b iut_addr. For TCP sockets call listen().");

    if (!sock_first)
    {
        create_iut_sockets(pco_iut, sock_type, SA(&iut_addr),
                           &iut_test_s1, &iut_test_s2);
    }

     TEST_STEP("Check that connections can be accepted (or data "
               "received) only via the IUT slave interface which is up.");
    check_lacp(pco_iut, pco_tst, sock_type,
               iut_test_s1, iut_test_s2,
               tst_csap1, tst_csap2,
               SA(&iut_addr), SA(&tst_addr),
               (first_slave ? FIRST_SLAVE_DOWN : SECOND_SLAVE_DOWN),
               "The check after bringing a slave down");

    TEST_STEP("Bring up IUT interface which was brought down previously.");
    CHECK_RC(tapi_cfg_base_if_up(pco_iut->ta,
                                 (first_slave ? iut_if1->if_name :
                                                iut_if2->if_name)));

     TEST_STEP("Check that connections can be accepted (or data "
               "received) via both IUT slave interfaces.");
    check_lacp(pco_iut, pco_tst, sock_type,
               iut_test_s1, iut_test_s2,
               tst_csap1, tst_csap2,
               SA(&iut_addr), SA(&tst_addr),
               NO_SLAVES_DOWN,
               "The final check");

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    if (tst_csap1 != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, tst_csap1));
    if (tst_csap2 != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, tst_csap2));

    if (iut_if_name != NULL)
    {
        CLEANUP_CHECK_RC(tapi_cfg_aggr_destroy_bond(
                                            pco_iut->ta, "test_bond"));
        free(iut_if_name);
    }

    if (tst_if_name != NULL)
    {
        CLEANUP_CHECK_RC(tapi_cfg_aggr_destroy_bond(
                                            pco_tst->ta, "test_bond"));
        free(tst_if_name);
    }

    CLEANUP_RPC_CLOSE(pco_iut, iut_test_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_test_s2);

    CLEANUP_CHECK_RC(tapi_cfg_free_entry(&iut_addr_handle));
    CLEANUP_CHECK_RC(tapi_cfg_free_entry(&tst_addr_handle));
    CLEANUP_CHECK_RC(tapi_cfg_free_entry(&net_handle));

    TEST_END;
}
