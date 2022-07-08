/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-dontroute Usage of SO_DONTROUTE socket option
 *
 * @objective Check that if a @c SO_DONTROUTE option is switched on 
 *            for a socket of type @c SOCK_DGRAM, it is forbidden to send 
 *            any datagrams via a gateway, but permitted only to directly
 *            connected hosts.
 *
 * @type conformance
 *
 * @reference @ref STEVENS
 *
 * @param pco_iut       PCO on IUT, see @ref sockopts_dontroute_1 "note 1"
 * @param iut1_addr     Network address of @p pco_iut that is not
 *                      directly accessible from @p pco_tst1
 * @param pco_tst1      PCO on TESTER1, see @ref sockopts_dontroute_1 "note 1"
 * @param tst1_addr     Network address of @p pco_tst1 that is not 
 *                      directly accessible from @p pco_iut
 * @param pco_tst2      PCO on TESTER2 (@p pco_iut and @p pco_tst2
 *                      reside on the same subnetwork)
 * @param gw_iut1_addr  Network address of a gateway through that 
 *                      @p pco_iut can reach @p tst1_addr address
 * @param gw_tst1_addr  Network address of a gateway through that
 *                      @p pco_tst1 can reach @p iut1_addr address
 *
 * @note
 *     - @anchor sockopts_dontroute_1
 *       @p pco_iut and @p pco_tst1 can communicate only via gateway.
 *     .
 * @htmlonly

  <pre>

                        +----------------+
                        | [gw_tst1_addr] |----- { [tst1_addr] pco_tst1 }
  +--------------+      |       GW       |
  |          if1+|------| [gw_iut1_addr] |
  |  [iut1_addr] |      +----------------+
  |     IUT      |
  |  [iut2_addr] |
  |          if2+|------ { pco_tst2 }
  +--------------+

  </pre>

  @endhtmlonly
 *
 *
 * @par Test sequence:
 *
 * -# Create a buffer @p tx_buf of @p buf_len bytes;
 * -# Create a buffer @p rx_buf of @p buf_len bytes;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Add route on @p pco_iut host to @p tst1_addr via gateway specifying
 *    @p gw_iut1_addr;
 * -# Add back route on @p pco_tst1 host to @p iut1_addr via gateway 
 *    specifying @p gw_tst1_addr;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create @p iut_s socket of type @c SOCK_DGRAM on @p pco_iut;
 * -# Create @p tst1_s socket of type @c SOCK_DGRAM on @p pco_tst1;
 * -# Create @p tst2_s socket of type @c SOCK_DGRAM on @p pco_tst2;
 * -# Bind @p tst1_s socket to @p tst1_addr network address and port @p P;
 * -# Bind @p tst2_s socket to a local address;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p iut_s socket to get initial value of the
 *    option;
 * -# Check that the function returns @c 0 and the option is disabled;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send @p tx_buf buffer from @p iut_s socket to @p tst1_addr 
 *    network address and port @p P with @b sendto() function;
 * -# Call @b recv(@p tst1_s, @p rx_buf, @p buf_len, @c 0);
 * -# Check that the content of @p tx_buf and @p buf_len bytes 
 *    of @p rx_buf are the same (data successfully delivered);
 * -# Send @p tx_buf buffer from @p iut_s socket to @p tst2_s socket; 
 * -# Call @b recv(@p tst2_s, @p rx_buf, @p buf_len, @c 0);
 * -# Check that the content of @p tx_buf and @p buf_len bytes 
 *    of @p rx_buf are the same (data successfully delivered);
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p iut_s with @c SO_DONTROUTE enabling 
 *    this option;
 * -# Call @b getsockopt() on @p iut_s socket;
 * -# Check that the function returns @c 0 and the option value is 1;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Send @p tx_buf buffer from @p iut_s socket to @p tst1_addr network 
 *    address and port @p P with @b sendto() function;
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c ENETUNREACH;
 * -# Send @p tx_buf buffer from @p iut_s socket to @p tst2_s socket;
 * -# Call @b recv(@p tst2_s, @p rx_buf, @p buf_len, @c 0);
 * -# Check that the content of @p tx_buf and @p buf_len bytes
 *    of @p rx_buf are the same (data successfully delivered);
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p iut_s with @c SO_DONTROUTE disabling 
 *    this option;
 * -# Send @p tx_buf buffer from @p iut_s socket to @p tst1_addr network 
 *    address and port @p P with @b sendto() function;
 * -# Call @b recv(@p tst1_s, @p rx_buf, @p buf_len, @c 0);
 * -# Check that the function returns @p buf_len and fills in the first 
 *    @p buf_len bytes of @p rx_buf with data containing in @p tx_buf;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Delete added routes;
 * -# Delete @p rx_buf, and @p tx_buf buffers;
 * -# Close @p tst1_s, @p tst2_s and @p iut_s sockets.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/dontroute"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_gw = NULL;
    rcf_rpc_server         *pco_tst1 = NULL;
    rcf_rpc_server         *pco_tst2 = NULL;
    const struct sockaddr  *iut1_addr;
    const struct sockaddr  *tst1_addr;
    const struct sockaddr  *tst2_addr;
    const struct sockaddr  *gw_iut1_addr;
    const struct sockaddr  *gw_tst1_addr;
    
    int         iut_s = -1;
    int         tst1_s = -1;
    int         tst2_s = -1;
    void       *tx_buf = NULL;
    void       *rx_buf = NULL;
    size_t      buf_len;
    int         opt_val;
    te_bool     route1_added = FALSE;
    te_bool     route2_added = FALSE;
    
    rpc_socket_domain domain;
            
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);

    TEST_GET_ADDR(pco_iut, iut1_addr);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    TEST_GET_ADDR_NO_PORT(gw_iut1_addr);
    TEST_GET_ADDR_NO_PORT(gw_tst1_addr);

    domain = rpc_socket_domain_by_addr(iut1_addr);

    CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&buf_len));
    rx_buf = te_make_buf_by_len(buf_len);


    /* Add route on 'pco_iut': 'tst1_addr' via gateway 'gw_iut1_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta, 
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_iut1_addr)) != 0)
    {
        TEST_FAIL("Cannot add route on 'pco_iut': 'tst1_addr' via "
                  "gateway 'gw_iut1_addr'");
    }
    route1_added = TRUE;
    /* Add route on 'pco_tst1': 'iut1_addr' via gateway 'gw_tst1_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst1->ta, 
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut1_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_tst1_addr)) != 0)
    {
        TEST_FAIL("Cannot add route on 'pco_tst1': 'iut1_addr' via "
                  "gateway 'gw_tst1_addr'");
    }
    route2_added = TRUE;
    /* Turn on forwarding on router host */
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));
    CFG_WAIT_CHANGES;


    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst1_s = rpc_socket(pco_tst1, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    tst2_s = rpc_socket(pco_tst2, domain, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst1, tst1_s, tst1_addr);
    rpc_bind(pco_tst2, tst2_s, tst2_addr);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_DONTROUTE, &opt_val);
    if (opt_val != 0)
    {
        WARN("SO_DONTROUTE socket option is enabled by default");

        opt_val = 0;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_DONTROUTE, &opt_val);
    }

    /*
     * Check the ability to transfer data between 'iut_s' and 'tst_s_'
     * sockets.
     *
     * @param tst_                   RPC server
     * @param tst_s_                 Socket descriptor on tst_
     * @param should_be_delivered_   Whether we expect the data is delivered
     *                               to 'tst_s_' from 'iut_s'
     */
#define CHECK_DATA_TRANSFER(tst_, tst_s_, should_be_delivered_) \
    do {                                                                \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                   \
        rc = rpc_sendto(pco_iut, iut_s, tx_buf, buf_len, 0,             \
                        tst_ ## _addr);                                 \
        if (should_be_delivered_ == TRUE)                               \
        {                                                               \
            rc = rpc_recv(pco_ ## tst_, tst_s_, rx_buf, buf_len, 0);    \
            if (rc != (int)buf_len)                                     \
            {                                                           \
                TEST_FAIL("'" #tst_s_ "' socket receives unexpected "   \
                          "number of bytes from 'iut_s' socket");       \
            }                                                           \
            if (memcmp(tx_buf, rx_buf, buf_len) != 0)                   \
            {                                                           \
                TEST_FAIL("The content of 'tx_buf' and "                \
                          "'rx_buf' are different");                    \
            }                                                           \
            /*                                                          \
             * Check that the is no more data to read                   \
             * on 'tst_s_' socket                                       \
             */                                                         \
            RPC_CHECK_READABILITY(pco_ ## tst_, tst_s_, FALSE);         \
        }                                                               \
        else                                                            \
        {                                                               \
            if (rc != -1)                                               \
            {                                                           \
                TEST_FAIL("sendto() returns %d, but it is expected to"  \
                          " return -1, because SO_DONTROUTE socket "    \
                          "option is enabled and destination can be "   \
                          "accessible only via gateway", rc);           \
            }                                                           \
            CHECK_RPC_ERRNO(pco_iut, RPC_ENETUNREACH,                   \
                    "sendto() returns -1");                             \
        }                                                               \
    } while (0)

    CHECK_DATA_TRANSFER(tst1, tst1_s, TRUE);
    CHECK_DATA_TRANSFER(tst2, tst2_s, TRUE);
    
    /* Enable SO_DONTROUTE option on 'iut_s' socket */
    opt_val = 1;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_DONTROUTE, &opt_val);
    /*
     * Set different value to the 'opt_val' to ensure that
     * it is updated by getsockopt()
     */
    opt_val = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_DONTROUTE, &opt_val);
    if (opt_val == 0)
    {
        TEST_FAIL("The value of SO_DONTROUTE socket option is not updated "
                  "by setsockopt() function");
    }
    else if (opt_val != 1)
    {
        RING_VERDICT("Enabled SO_DONTROUTE socket option is equal to %d",
                     opt_val);
    }
    
    /* 
     * 'tst1_s' is accessible only via the gateway, so that no data 
     * is delivered to it.
     */
    CHECK_DATA_TRANSFER(tst1, tst1_s, FALSE);
    /* 'tst2_s' is directly accessible, so that data successfully delivered */
    CHECK_DATA_TRANSFER(tst2, tst2_s, TRUE);
    
    
    /* Disable SO_DONTROUTE option on 'iut_s' socket */
    opt_val = 0;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_DONTROUTE, &opt_val);
    
    CHECK_DATA_TRANSFER(tst1, tst1_s, TRUE);
    CHECK_DATA_TRANSFER(tst2, tst2_s, TRUE);

    TEST_SUCCESS;

#undef CHECK_DATA_TRANSFER

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst1, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst2, tst2_s);

    if (route1_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst1_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_iut1_addr)) != 0)
    {
        ERROR("Cannot delete route on 'pco_iut': 'tst1_addr' via "
              "gateway 'gw_iut1_addr'");
        result = EXIT_FAILURE;
    }
    if (route2_added &&
        tapi_cfg_del_route_via_gw(pco_tst1->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut1_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw_tst1_addr)) != 0)
    {
        ERROR("Cannot delete route on 'pco_tst1': 'iut1_addr' via "
              "gateway 'gw_tst1_addr'");
        result = EXIT_FAILURE;
    }

    free(tx_buf);
    free(rx_buf);

    TEST_END;
}

