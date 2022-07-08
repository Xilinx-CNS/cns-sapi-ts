/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionbio_connect_send Using of connect() function with enabled FIONBIO request 
 *
 * @objective Check that @c FIONBIO request affects on connect() function
 *            called on @c SOCK_STREAM socket.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param pco_iut        PCO on IUT
 * @param pco_tst        PCO on TESTER
 *
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# Bind @p tst_s socket to a local address - @p tst_addr.
 * -# Call @b listen() on @p tst_s socket.
 * -# Create ARP entry on @p pco_tst so that packets destined to
 *    @p pco_iut goes to some fake MAC address and are not captured
 *    by @p pco_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() on @p iut_s socket enabling @c FIONBIO.
 * -# Call @b connect() on @p iut_s socket using @p tst_addr as the peer 
 *    address.
 * -# Check that the function returns @c -1 and sets @b errno to
 *    @c EINPROGRESS.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b send() on @p iut_s.
 * -# Call @b connect() on @p tst_s socket once again.
 * -# Check that the function returns @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b connect() @b on tst_s socket once again.
 * -# Check that the function returns @c -1 and sets @b errno to @c EISCONN.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s and @p tst_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionbio_connect_send"

#include "sockapi-test.h"
#include "tapi_cfg.h"

#define IUT_L5


#ifndef IUT_L5
#define ENABLE_CONNECTION \
    do {                                                                 \
        if (tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,       \
                                     iut_addr) != 0)                     \
        {                                                                \
            TEST_FAIL("Cannot delete ARP entry");                        \
        }                                                                \
        arp_entry_added = FALSE;                                         \
    } while (0)

#else
#define ENABLE_CONNECTION \
    do {                                                             \
        if (tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,   \
                                     gw_addr) != 0)                  \
        {                                                            \
            TEST_FAIL("Cannot delete ARP entry");                    \
        }                                                            \
        arp_entry_added = FALSE;                                     \
        if (tapi_cfg_del_route_via_gw(pco_tst->ta,                   \
                    addr_family_rpc2h(sockts_domain2family(domain)), \
                    te_sockaddr_get_netaddr(iut_addr),               \
                    te_netaddr_get_size(addr_family_rpc2h(           \
                            sockts_domain2family(domain))) * 8,      \
                    te_sockaddr_get_netaddr(SIN(&gw_addr))) != 0)    \
        {                                                            \
            TEST_FAIL("Cannot delete route ");                       \
        }                                                            \
        route_added = FALSE;                                         \
    } while (0)

#endif

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    int                tst_s = -1;

    const struct if_nameindex *tst_if = NULL;

    const struct sockaddr   *iut_addr;
    const struct sockaddr   *tst_addr;
    te_bool                  bind_iut;
    const void              *alien_link_addr;
    int                      req_val;

    void                    *tx_buf = NULL;
    void                    *rx_buf = NULL;
    size_t                   buf_len;

    te_bool                  arp_entry_added = FALSE;


#ifdef IUT_L5
    struct sockaddr_in       gw_addr;
    te_bool                  route_added = FALSE;
#endif

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(bind_iut);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(tst_if);
    
#ifdef IUT_L5
    memset(&gw_addr, 0, sizeof(gw_addr));
    gw_addr.sin_family = AF_INET;
    gw_addr.sin_addr.s_addr = inet_addr("192.168.140.33");
#endif
    
    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    
    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
 
    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);
    
    if (bind_iut)
    {
        rpc_bind(pco_iut, iut_s, iut_addr);
    }

    /* Turn on FIONBIO request on 'iut_s' socket */
    req_val = TRUE;
 
    rpc_ioctl(pco_iut, iut_s, RPC_FIONBIO, &req_val);

    /* 
     * Create a static ARP entry on pco_tst so that any packets 
     * destined to pco_iut go to some fake MAC address, so they are
     * lost from pco_tst point of view.
     */
#ifndef IUT_L5
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             iut_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    arp_entry_added = TRUE;
#else
    /* 
     * Add route on 'pco_tst': 'dst_addr' via gateway 'gw_addr' 
     */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(SIN(&gw_addr))) != 0)
    {
        TEST_FAIL("Cannot add route");
    }
    route_added = TRUE;
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             gw_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    arp_entry_added = TRUE;
#endif
    CFG_WAIT_CHANGES;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc != -1)
    {
        TEST_FAIL("connect() called on the socket with FIONBIO ioctl() "
                  "request enabled returns %d, but it is expected to "
                  "return -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EINPROGRESS,
            "connect() called on the socket with FIONBIO ioctl() "
            "request enabled returns -1, but");

    /*
     * Send some data from the socket: in postponed mode because the 
     * socket is not connected yet - it has not received SYN/ACK due to
     * ARP entry added on pco_tst.
     */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    if (rc != -1)
    {
        TEST_FAIL("send() returns %d sending data in nonblocking mode, "
                  "but it is expected to return -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN,
            "send() returns -1 sending data in nonblocking mode, but");

    /* 
     * Delete ARP entry so that connection can be established and the data
     * sent from the socket 
     */
    ENABLE_CONNECTION;
    
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
#if 0
    if (rc != 0)
    {
        TEST_FAIL("connect() called on the socket with FIONBIO ioctl() "
                  "the second time returns %d, but it is expected to "
                  "return 0", rc);
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (rc != -1)
    {
        TEST_FAIL("connect() called the third time on the socket with "
                  "FIONBIO ioctl() request enabled returns %d, but "
                  "it is expected to return -1", rc);
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
            "connect() called the third time on the socket with "
            "FIONBIO ioctl() request enabled returns -1, but");
#endif
    SLEEP(10);
    /* Check that the data arrives */
    RPC_CHECK_READABILITY(pco_tst, tst_s, TRUE);
    
    rc = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0);
    if ((size_t)rc != buf_len)
    {
        TEST_FAIL("Not all the data is delivered: "
                  "received %d bytes, expected %d bytes",
                  rc, buf_len);
    }
    if (memcmp(tx_buf, rx_buf, buf_len) != 0)
    {
        TEST_FAIL("The data in tx_buf and rx_buf are different");
    }
    
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

#ifndef IUT_L5
    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, iut_addr) != 0)
    {
        ERROR("Cannot delete ARP entry");
        result = EXIT_FAILURE;
    }
#else
    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw_addr) != 0)
    {
        ERROR("Cannot delete ARP entry");
        result = EXIT_FAILURE;
    }
    if (route_added)
    {
        if (tapi_cfg_del_route_via_gw(pco_tst->ta,
                addr_family_rpc2h(sockts_domain2family(domain)),
                te_sockaddr_get_netaddr(iut_addr),
                te_netaddr_get_size(addr_family_rpc2h(
                    sockts_domain2family(domain))) * 8,
                te_sockaddr_get_netaddr(SIN(&gw_addr))) != 0)
        {
            ERROR("Cannot delete route");
            result = EXIT_FAILURE;
        }
    }
#endif

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}

