/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_conn Exec robustness for connected sockets
 *
 * @objective Check that connected socket is inherited during @b execve()
 *            call, that data received and transmitted correctly.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_tst
 *              - @ref arg_types_env_peer2peer_lo
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 *
 * @par Scenario:
 *
 * -# Create network connection of sockets of @p sock_type, obtain sockets
 *    @p iut_s and @p tst_s on @p pco_iut and @p pco_tst respectively.
 * -# Perform sockts_get_socket_state() routine for @p pco_iut, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED. 
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Perform sockts_get_socket_state() routine for @p pco_iut, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p iut_s.
 * -# Catch sent data by @b recv() on @p tst_s. 
 * -# Check that received data has same length as was sent. 
 * -# @b send() data from @p tst_s.
 * -# Change image of process @p pco_iut by @b execve() call.
 * -# Catch sent data by @b recv() on @p iut_s. 
 * -# Check that received data is the same as was sent. 
 * -# @b close() all sockets.
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_conn"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    int                     iut_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_socket_type         sock_type; 

    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_dgram(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    /*
     * Scenario
     */ 

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED); 

    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED); 

    RPC_SEND(rc, pco_iut, iut_s, tx_buf, buf_len, 0);

    rc = rpc_recv(pco_tst, tst_s, rx_buf, buf_len, 0); 

    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("tst_s received bytes differ then was sent from pco_iut"); 
    }


    RPC_SEND(rc, pco_tst, tst_s, tx_buf, buf_len, 0); 

    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    RPC_CHECK_READABILITY(pco_iut, iut_s, TRUE); 

    rc = rpc_recv(pco_iut, iut_s, rx_buf, buf_len, 0); 
    if ((unsigned)rc != buf_len)
    { 
        TEST_FAIL("iut_s received differ length then was sent from pco_tst"); 
    }

    if (memcmp(tx_buf, rx_buf, buf_len) != 0)
    {
        TEST_FAIL("iut_s received differ data then was sent from pco_tst");
    } 

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s); 
    CLEANUP_RPC_CLOSE(pco_tst, tst_s); 

    TEST_END;
}
