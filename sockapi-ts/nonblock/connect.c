/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * NONBLOCK Requests
 *
 * $Id$
 */

/** @page nonblock-connect Using of connect() function with enabled FIONBIO or NONBLOCK request
 *
 * @objective Check that @c FIONBIO / @c O_NONBLOCK request affects on
 *            connect() function called on @c SOCK_STREAM socket.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on TESTER
 * @param pco_gw         PCO on host in the tested network that is able
 *                       to forward incoming packets (router)
 * @param gw_exists      If @c TRUE pco_gw exists in evnironment. If @c
 *                       FALSE pco_gw does not exist in environment.
 * @param nonblock_func  Function used to set nonblocking state to socket
 *                       ("fcntl", "ioctl")
 *
 * @par Test sequence:
 * -# If @p gw_exists parameter is @c TRUE enable forwarding on the host
 *    with @p pco_gw;
 * -# If @p gw_exists parameter is @c TRUE establish routing on the hosts
 *    with @p pco_iut and @p pco_tst to reach each other via @p gw_iut_addr
 *    and @p gw_tst_addr addresses;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Bind @p tst_s socket to a local address - @p tst_addr.
 * -# Call @b listen() on @p tst_s socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() or @b fcntl() on @p iut_s socket to set nonblock state.
 * -# If @p gw_exists parameter is @c TRUE add a new static ARP entry on
 *    the host with @p pco_tst to direct traffic to @p gw_tst_addr network
 *    address to alien link-layer address;
 * -# Call @b connect() on @p iut_s socket using @p tst_addr as the peer
 *    address.
 * -# Check that the function returns @c -1 and sets @b errno to
 *    @c EINPROGRESS.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p gw_exists parameter is @c TRUE delete static ARP entry on the
 *    host with @p pco_tst to disable directing traffic to @p gw_tst_addr
 *    network address to alien link-layer address;
 * -# Call @b connect() on @b iut_s socket once again.
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b connect() @b on iut_s socket once again.
 * -# Check that the function returns @c -1 and sets @b errno to @c EISCONN.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s and @p tst_s sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "nonblock/connect"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_route_gw.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    rcf_rpc_server    *pco_gw = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;
    const void              *alien_link_addr = NULL;
    const struct sockaddr   *gw_iut_addr = NULL;
    const struct sockaddr   *gw_tst_addr = NULL;

    const struct if_nameindex  *tst_if = NULL;

    te_bool                  bind_iut;
    te_bool                  gw_exists;

    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_BOOL_PARAM(gw_exists);
    if (gw_exists)
    {
        TEST_GET_PCO(pco_gw);

        TEST_GET_IF(tst_if);

        TEST_GET_ADDR_NO_PORT(gw_iut_addr);
        TEST_GET_ADDR_NO_PORT(gw_tst_addr);
        TEST_GET_LINK_ADDR(alien_link_addr);
    }

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);

    if (bind_iut)
        iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_STREAM,
                                           RPC_IPPROTO_TCP, TRUE, FALSE,
                                           iut_addr);
    else
        iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    /* Turn on nonblocking state on 'iut_s' socket */
    set_sock_non_block(pco_iut, iut_s, nonblock_func == FCNTL_SET_FDFLAG, TRUE);


    if (gw_exists)
    {
        /* Turn on forwarding on router host */
        CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                      "net/ipv4/ip_forward"));

        /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw_iut_addr' */
        if (tapi_cfg_add_route_via_gw(pco_iut->ta,
                tst_addr->sa_family,
                te_sockaddr_get_netaddr(tst_addr),
                te_netaddr_get_size(tst_addr->sa_family) * 8,
                te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
        {
            TEST_FAIL("Cannot add route to the dst");
        }
        /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw_tst_addr' */
        if (tapi_cfg_add_route_via_gw(pco_tst->ta,
                iut_addr->sa_family,
                te_sockaddr_get_netaddr(iut_addr),
                te_netaddr_get_size(iut_addr->sa_family) * 8,
                te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
        {
            TEST_FAIL("Cannot add route to the src");
        }

        CFG_WAIT_CHANGES;

        /* Add static ARP entry to prevent connection establishment */
        CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                                 gw_tst_addr, CVT_HW_ADDR(alien_link_addr),
                                 TRUE));
        CFG_WAIT_CHANGES;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);

    if (rc != -1)
    {
        RING_VERDICT("connect() called on the socket with nonblock state "
                     "enabled returns %d, but it is expected to "
                     "return -1", rc);
    }
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EINPROGRESS,
                "connect() called on the socket with nonblock state "
                "enabled returns -1, but");

    if (gw_exists)
    {
        /* Delete static ARP entry */
        CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                          gw_tst_addr));
        CFG_WAIT_CHANGES;
    }

    /*
     * Sleep a while to become more confident that connection is
     * established
     */
    SLEEP(5);

    /* Call connect once more */
    do {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s, tst_addr);
        if (rc == 0)
        {
            static te_bool got_zero = FALSE;

            if (got_zero)
            {
                TEST_FAIL("connect() called on the socket with nonblock "
                          "state returned 0 more than once");
            }
            else
            {
                RING_VERDICT("connect() called the second time on "
                             "the socket with nonblock state set "
                             "returned 0");
            }
            got_zero = TRUE;
        }
        else
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
                "connect() called the third time on the socket with "
                "nonblock state request enabled returns -1, but");
        }
    } while (rc == 0);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
