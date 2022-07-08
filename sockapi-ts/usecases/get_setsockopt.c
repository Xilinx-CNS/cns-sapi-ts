/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 */

/** @page usecases-get_setsockopt The getsockopt()/setsockopt() operations on BSD compatible sockets
 *
 * @objective Test on reliability of @b getsockopt()/setsockopt() operations
 *            on BSD compatible sockets.
 *
 * @type use case
 *
 * @param env   Testing environment:
 *                  - @ref arg_types_env_peer2peer
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 *                  - @ref arg_types_env_p2p_ip6
 *                  - @ref arg_types_env_peer2peer_tst
 *                  - @ref arg_types_env_peer2peer_lo
 *
 * @par Scenario:
 * -# Create connected @c SOCK_STREAM sockets on @p pco_iut and @p pco_tst.
 * -# Call @b setsockopt (@c SO_OOBINLINE) on the @p pco_iut socket
 *    to turn on.
 * -# Call @b iomux_call(@c EVT_RD | @c EVT_PRI) on the @p pco_iut socket.
 * -# Call @b send() on @p pco_tst socket with @e out-of-band flag
 *    (length of the buffer is greater than zero).
 * -# Check that iomux_call() returns both @c EVT_RD and @c EVT_PRI events
 *    for the @p pco_iut socket. 
 * -# Check by means of @c SIOCATMARK that @e out-of-band data marker 
 *    is not set @p pco_iut socket, since only the last byte is
 *    considered as @e out-of-band.
 * -# Call @b recv() on the @p pco_iut socket.
 * -# Check that only ordinary data returned (no @e out-of-band data).
 * -# Check @p out-of-band data existence in receive buffer of @p pco_iut
 *    socket by means of @b ioctl (@c SIOCATMARK).
 * -# @b recv() @p out-of-band data on the @p pco_iut socket.
 * -# Check @e out-of-band data obtained by @b recv() on the @p pco_iut socket.
 * -# Call @b send() on @p pco_tst socket without @e out-of-band flag
 *    (length of the buffer is greater than zero).
 * -# Check that @e out-of-band marker is clear, since @c SO_OOBINLINE
 *    option is set, data which have just been read were in-line and
 *    marker was shifted.
 * -# @b recv() ordinary data on the @p pco_iut socket.
 * -# Call @b getsockopt (@c SO_OOBINLINE) on the @p pco_iut socket
 *    and check that option is turned on.
 * -# Call @b setsockopt (@c SO_OOBINLINE) on the @p pco_iut socket
 *    to turn off.
 * -# Call @b getsockopt (@c SO_OOBINLINE) on the @p pco_iut socket
 *    and check that option is turned off.
 * -# Close created sockets on the both sides.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "usecases/get_setsockopt"

#include "sockapi-test.h"
#include "iomux.h"


#define TST_SENDRECV_FLAGS    0
#define TST_OPTION_ON         1
#define TST_OPTION_OFF        !TST_OPTION_ON


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             tst_s = -1;
    int             iut_s = -1;
    void           *tx_buf = NULL;
    size_t          tx_buf_len;
    void           *rx_buf = NULL;
    size_t          rx_buf_len;
    int             optval;
    int             ioctl_ret = 0;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    iomux_evt               evt, exp_evt, unexp_evt;
    iomux_call_type         default_iomux = iomux_call_get_default();
    te_bool                 use_select;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    tx_buf = sockts_make_buf_stream(&tx_buf_len);
    rx_buf = te_make_buf_min(tx_buf_len, &rx_buf_len);

    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &tst_s, &iut_s);


    optval = TST_OPTION_ON;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);

    use_select = (default_iomux == IC_SELECT || default_iomux == IC_PSELECT) ?
                 TRUE : FALSE;
    evt = exp_evt = EVT_RD | (use_select ? EVT_EXC : EVT_PRI);

    pco_iut->op = RCF_RPC_CALL;
    iomux_call_default_simple(pco_iut, iut_s, evt, NULL, -1);
    TAPI_WAIT_NETWORK;

    RPC_SEND(rc, pco_tst, tst_s, tx_buf, tx_buf_len, RPC_MSG_OOB);

    pco_iut->op = RCF_RPC_WAIT;
    rc = iomux_call_default_simple(pco_iut, iut_s, evt, &evt, -1);

    unexp_evt = evt & ~exp_evt;
    if (unexp_evt)
        TEST_FAIL("iomux_call() %s unexpected event(s)",
                  iomux_event_rpc2str(unexp_evt));

    if (!(evt & EVT_RD))
        TEST_VERDICT("iomux_call() did not mark the socket as readable");

    if (use_select)
    {
        if (!(evt & EVT_EXC))
            TEST_FAIL("iomux_call() did not set EVT_EXC event");
    }
    else
    {
        if (!(evt & EVT_PRI))
            TEST_FAIL("iomux_call() did not set EVT_PRI event");
    }

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &ioctl_ret);
    if (ioctl_ret)
        TEST_FAIL("RPC ioctl(SIOCATMARK): unexpected "
                  "out-of-band data observed");

    rc = rpc_recv_gen(pco_iut, iut_s, rx_buf,
                      tx_buf_len, TST_SENDRECV_FLAGS, rx_buf_len);

    if (rc < (int)tx_buf_len - 1)
    {
        TEST_FAIL("Only part of normal data received");
    }

    if (rc == (int)tx_buf_len)
        TEST_FAIL("recv() returned both usual and OOB data in one call");
    if (memcmp(tx_buf, rx_buf, rc))
        TEST_FAIL("Invalid normal data received");

    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &ioctl_ret);
    if (!ioctl_ret)
        TEST_FAIL("RPC ioctl(SIOCATMARK): no out-of-band data observed");

    rc = rpc_recv(pco_iut, iut_s, rx_buf, tx_buf_len, TST_SENDRECV_FLAGS);
    if (rc != 1)
        TEST_FAIL("Out-of-band data not received");

    if (memcmp(tx_buf + (tx_buf_len - 1), rx_buf, 1))
        TEST_FAIL("Invalid out-of-band data received");

    /*
     * OOB mark must not be reset until at least one byte of
     * normal data is read from the socket.
     */
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCATMARK, &ioctl_ret);
    if (ioctl_ret)
        TEST_FAIL("RPC ioctl(SIOCATMARK): out-of-band data flag "
                  "is not clear");

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
    if (!optval)
        TEST_FAIL("Invalid SO_OOBINLINE value returned: expected ON");

    optval = TST_OPTION_OFF;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_OOBINLINE, &optval);
    if (optval)
        TEST_FAIL("Invalid SO_OOBINLINE value returned: expected OFF");
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    free(tx_buf);
    free(rx_buf);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
