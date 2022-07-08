/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_cork_nodelay TCP_CORK and TCP_NODELAY behaviour
 *
 * @objective Checking behaviour of the TCP_CORK and TCP_NODELAY socket
 *            option called on the same socket in different orders.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of the @c SOCK_STREAM type on @p pco_iut;
 * -# Retrieve default value of TCP_CORK option by means of
 *    @b getsockopt();
 * -# If TCP_CORK option is enabled turn it @c OFF;
 * -# Retrieve default value of TCP_NODELAY option by means of
 *    @b getsockopt();
 * -# If TCP_NODELAY option is enabled turn it @c OFF;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Turn TCP_NODELAY mode on @p iut_s socket @c ON by means of
 *    @b setsockopt();
 * -# Check that TCP_NODELAY option is enabled;
 * -# Turn TCP_CORK mode on @p iut_s socket @c ON by means of
 *    @b setsockopt();
 * -# Check that @b setsockopt() returns @c 0 and TCP_CORK is set
 *    @c ON;
 * -# Check that TCP_NODELAY option is still @c ON;
 * -# Turn TCP_CORK option @c OFF and check, that TCP_NODELAY is still @c ON;
 * -# Turn @c OFF TCP_NODELAY and turn @c ON the TCP_CORK;
 * -# Turn TCP_NODELAY @c ON and check, that TCP_CORK is still turned
 *    @c ON;
 * -# Turn @c ON TCP_CORK and turn @c OFF the TCP_NODELAY;
 * -# Create @p tst_s socket of the @c SOCK_STREAM type on @p pco_tst;
 * -# Bind @p iut_s to the @p iut_addr on the @p pco_iut;
 * -# Bind @p tst_s to the @p tst_addr on the @p pco_tst;
 * -# Call @b listen() on the @p tst_s;
 * -# Call @b connect(iut_s, tst_addr);
 * -# Call @b accept on the @p tst_s to obtain @p acc_s;
 * -# Get the MTU of the interface the @p iut_s socket is binded to;
 *  
 * -# Send three packets of size MTU / 3 each from @p iut_s to the
 *    @p acc_s;
 * -# Receive all data that arrived on the @p acc_s and check, that it
 *    was transferred correctly;
 * -# Call @b iomux_call() on the @p acc_s socket to check, that it is not
 *    readable;
 * -# Enable TCP_NODELAY on the @p iut_s socket using @b setsockopt();
 * -# Check, that @p acc_s is readable and receive the remainging data;
 * -# Check, that all data was transferred correctly;
 *
 * -# Check, that both TCP_NODELAY and TCP_CORK are turned @c ON;
 * -# Send three packets of size MTU / 3 each from @p iut_s to the
 *    @p acc_s;
 * -# Receive all data that arrived on the @p acc_s and check, that it
 *    was transferred correctly;
 * -# Call @b iomux_call() on the @p acc_s socket to check, that it is not
 *    readable;
 * -# Enable TCP_NODELAY on the @p iut_s socket using @b setsockopt();
 * -# Check, that @p acc_s is readable and receive the remainging data;
 * -# Check, that all data was transferred correctly;
 *
 * -# Close created sockets.
 *  
 * @note
 * -# Test checks the behaviour of the TCP_CORK and TCP_NODELAY socket
 *    options which is documented in man 7 tcp;
 * -# Linux has timer for the TCP_CORK socket option. So, when it expires
 *    all unsent data will be send to the TST side;
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_cork_nodelay"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

#include "conf_api.h"
#include "tapi_rpc.h"

#include "tapi_test.h"
#include "tapi_ip4.h"
#include "tapi_udp.h"
#include "tapi_tcp.h"

#include "ndn_eth.h"
#include "ndn_ipstack.h"

#include "iomux.h"

#define TST_SET_MODE_WITH_CHECKING(_opt, _optval, _opt2, _optval2) \
    do {                                                        \
        int optval = (_optval);                                 \
                                                                \
        RPC_AWAIT_IUT_ERROR(pco_iut);                           \
        rc = rpc_setsockopt(pco_iut, iut_s, _opt, &optval); \
        if (rc != 0)                                            \
        {                                                       \
            TEST_VERDICT("Failed to set %s to %d when %s is "   \
                         "set to %d", sockopt_rpc2str(_opt),    \
                         optval, sockopt_rpc2str(_opt2),        \
                         (_optval2));                           \
        }                                                       \
        optval = 0;                                             \
        rpc_getsockopt(pco_iut, iut_s, _opt, &optval);          \
        if (optval != _optval)                                  \
            TEST_FAIL("It's impossible to turn "#_opt" %s",     \
                      _optval ? "ON" : "OFF");                  \
    } while (0)

#define TST_BUF_LEN 15000

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr     *tst_addr = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    
    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    acc_s = -1;

    int                    optval;
    int                    mtu;

    char                   tx_buf[TST_BUF_LEN];
    char                   rx_buf[TST_BUF_LEN];
    int                    buf_len;
    int                    bytes_received;
    int                    remaining_bytes;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    /* TCP_CORK default value */
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_CORK, &optval);
    RING("Default value for TCP_CORK mode is %s",
          optval ? "ON" : "OFF");

    if (optval)
        TST_SET_MODE_WITH_CHECKING(RPC_TCP_CORK, 0, RPC_TCP_NODELAY, 0);

    /* TCP_NODELAY default */
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval);
    RING("Default value for TCP_NODELAY mode is %s",
         optval ? "ON" : "OFF");

    if (optval)
        TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 0, RPC_TCP_CORK, 0);

    /* Check that CORK overwrites NODELAY */
    TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 1, RPC_TCP_CORK, 0);
    TST_SET_MODE_WITH_CHECKING(RPC_TCP_CORK, 1, RPC_TCP_NODELAY, 1);
    
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval);
    RING_VERDICT("TCP_NODELAY socket option value after setting "
                 "TCP_CORK is %s", optval ? "ON" : "OFF");

    /* Unsetting TCP_CORK should not affect the TCP_NODELAY */
    TST_SET_MODE_WITH_CHECKING(RPC_TCP_CORK, 0, RPC_TCP_NODELAY, optval);

    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval);
    RING_VERDICT("TCP_NODELAY socket option value after unsetting "
                 "TCP_CORK is %s", optval ? "ON" : "OFF");

    TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 0, RPC_TCP_CORK, 0);

    /* TCP_NODELAY should not unset TCP_CORK */
    TST_SET_MODE_WITH_CHECKING(RPC_TCP_CORK, 1, RPC_TCP_NODELAY, 0);
    TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 1, RPC_TCP_CORK, 1);
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_CORK, &optval);
    RING_VERDICT("TCP_CORK socket option value after setting "
                 "TCP_NODELAY is %s", optval ? "ON" : "OFF");

    TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 0, RPC_TCP_CORK, optval);
    TST_SET_MODE_WITH_CHECKING(RPC_TCP_CORK, 1, RPC_TCP_NODELAY, 0);

    /* 
     * Checking, that setting TCP_NODELAY with TCP_CORK already set
     * flushes the buffer of the socket.
     * The check is for level 5 only, on linux it will fail, as linux
     * has the timer for TCP_CORK socket option.
     */
    /* Setup the connection between IUT and TST */
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr);
    rpc_bind(pco_tst, tst_s, tst_addr);

    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    /*
     * The TCP_CORK should not affect SYN packets
     */
    rpc_connect(pco_iut, iut_s, tst_addr);
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
    
    /* Connection between iut_s and acc_s is established */

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (rpc_getsockopt(pco_iut, iut_s, RPC_IP_MTU, &mtu) != 0)
    {
        TEST_VERDICT("getsockopt(IP_MTU) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    buf_len = mtu / 3;
    te_fill_buf(tx_buf, mtu);
    rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    rpc_send(pco_iut, iut_s, tx_buf + buf_len, buf_len, 0);
    rpc_send(pco_iut, iut_s, tx_buf + 2 * buf_len, buf_len, 0);

    sleep(1);
    /* on linux the rest of the test works incorrect */
    bytes_received = rpc_recv(pco_tst, acc_s, rx_buf, TST_BUF_LEN, 0);
    RING("%d bytes received on the TST size", bytes_received);
    if (strncmp(tx_buf, rx_buf, bytes_received) != 0)
    {
        TEST_FAIL("Wrong data is received on the TST side");
    }
    
    rc = iomux_call_default_simple(pco_tst, acc_s, EVT_RD, NULL, 2000);
    if (rc != 0)
    {
        WARN("All arrived data on the TST size is received");
    }

    TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 1, RPC_TCP_CORK, 1);

    rc = iomux_call_default_simple(pco_tst, acc_s, EVT_RD, NULL, 2000);
    if (rc != 1)
    {
        TEST_VERDICT("Data is not received on the TST side");
    }
    
    remaining_bytes = rpc_recv(pco_tst, acc_s, rx_buf + bytes_received, 
                               TST_BUF_LEN, 0);
    RING("The rest %d bytes received on the TST size", remaining_bytes);
    if (bytes_received + remaining_bytes != mtu)
    {
        TEST_FAIL("Wrong number of bytes received");
    }
    if (strcmp(tx_buf + bytes_received, rx_buf + bytes_received) != 0)
    {
        TEST_FAIL("Wrong data received");
    }

    /* Checking, that TCP_CORK has more priority, than TCP_NODELAY */
    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_CORK, &optval);
    if (optval != 1)
        TEST_FAIL("Unexpected behaviour");

    optval = 0;
    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_NODELAY, &optval);
    if (optval != 1)
        TEST_FAIL("Unexpected behaviour");
    
    rpc_send(pco_iut, iut_s, tx_buf, buf_len, 0);
    rpc_send(pco_iut, iut_s, tx_buf + buf_len, buf_len, 0);
    rpc_send(pco_iut, iut_s, tx_buf + 2 * buf_len, buf_len, 0);

    sleep(1);
    bytes_received = rpc_recv(pco_tst, acc_s, rx_buf, TST_BUF_LEN, 0);
    RING("%d bytes received on the TST size", bytes_received);
    if (strncmp(tx_buf, rx_buf, bytes_received) != 0)
    {
        TEST_FAIL("Wrong data is received on the TST side");
    }
    
    rc = iomux_call_default_simple(pco_tst, acc_s, EVT_RD, NULL, 2000);
    if (rc != 0)
    {
        WARN("All arrived data on the TST size is received");
    }

    TST_SET_MODE_WITH_CHECKING(RPC_TCP_NODELAY, 1, RPC_TCP_CORK, 1);

    rc = iomux_call_default_simple(pco_tst, acc_s, EVT_RD, NULL, 2000);
    if (rc != 1)
    {
        TEST_FAIL("Data is not received on the TST side");
    }
    
    remaining_bytes = rpc_recv(pco_tst, acc_s, rx_buf + bytes_received, 
                               TST_BUF_LEN, 0);
    RING("The rest %d bytes received on the TST size", remaining_bytes);
    if (bytes_received + remaining_bytes != mtu)
    {
        TEST_FAIL("Wrong number of bytes received");
    }
    if (strcmp(tx_buf + bytes_received, rx_buf + bytes_received) != 0)
    {
        TEST_FAIL("Wrong data received");
    }
    
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    TEST_END;
}
