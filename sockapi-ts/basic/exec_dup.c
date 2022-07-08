/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_dup Socket duplication and exec.
 *
 * @objective Check that dup'ed socket works after execve().
 *
 * @type Conformance, compatibility
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *              - @ref arg_types_env_peer2peer_fake
 *
 * @par Scenario:
 *
 * -# Create a TCP connection between @p sock_iut on @p pco_iut and
 *    @p sock_tst on @p pco_tst.
 * -# Call @b dup() on @p sock_iut to get @p sock_dup.
 * -# Call exec() on rpc-server
 * -# @b send() data from @p sock_dup.
 * -# Catch sent data by @b recv() on @p sock_tst on @p pco_tst. 
 * -# Close both @p sock_dup and @p sock_iut.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# @b close() all sockets, including listening socket.
 * -# Destroy process @b iut_child;
 *
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_dup"

#include <fcntl.h>
#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    void                   *tx_buf = NULL;
    void                   *rx_buf = NULL;
    size_t                  buf_len;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     sock_iut = -1;
    int                     sock_tst = -1;
    int                     sock_dup = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;


    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    CHECK_NOT_NULL((tx_buf = sockts_make_buf_stream(&buf_len)));
    rx_buf = te_make_buf_by_len(buf_len);

    /*
     * Scenario
     */ 

    /* Establish connection */
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                        tst_addr, iut_addr, &sock_tst, &sock_iut);

    /* Dup & exec*/
    sock_dup = rpc_fcntl(pco_iut, sock_iut, RPC_F_DUPFD, 0);
    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    /* Check that connection is alive */
    buf_len = rpc_send(pco_iut, sock_dup, rx_buf, buf_len, 0); 
    rc = rpc_recv(pco_tst, sock_tst, tx_buf, buf_len, 0);
    if ((unsigned)rc != buf_len)
    {
        TEST_FAIL("sock_tst received on TST has different length than sent");
    }
    rpc_close(pco_iut, sock_iut);
    rpc_close(pco_iut, sock_dup);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, sock_tst); 

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
