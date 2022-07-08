/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-fork_kill Use of the connection after parent's death
 *
 * @objective Check that connection may be used after parent finishing/killing.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param act_child If @c TRUE child acts after @b fork(), parent tracks;
 *                  else parent acts after @b fork(), child tracks.
 * @param method    Determines what exactly to do creating new process:
 *                  - inherit: means just calling @b fork().
 * @param kill      If @c TRUE, parent process should be killed;
 *                  otherwise it should be finished in usual way.
 *
 * @pre Sockets @p iut_s and @p tst_s are connected.
 *
 * @par Scenario:
 *
 * -# Send/receive data via @p iut_s and @p tst_s.
 * -# Create child process @p pco_child and @p child_s according to
 *    @p method.
 * -# Send/receive data via @p iut_s and @p tst_s.
 * -# Send/receive data via @p child_s and @p tst_s.
 * -# If @p kill is @c TRUE, kill @p pco_iut. Otherwise just finish it.
 * -# Send/receive data via @p child_s and @p tst_s.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/fork_kill"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_child = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const char             *method;
    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    rpc_socket_type         sock_type;
    te_bool                 kill;
    
    rpc_socket_domain       domain;
    int                     iut_s = -1;
    int                     child_s = -1;
    int                     tst_s = -1;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(method);
    TEST_GET_BOOL_PARAM(kill);

    domain = rpc_socket_domain_by_addr(iut_addr);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    rpc_create_child_process_socket(method, pco_iut, iut_s, domain,
                                    sock_type, &iut_child, &child_s);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
    sockts_test_connection(iut_child, child_s, pco_tst, tst_s);

    if (kill)
    {
        rpc_kill(iut_child, rpc_getpid(pco_iut), RPC_SIGKILL);
        /* 
         * Do not restart pco_iut in the case of kill - for 
         * processes which do not respond, the whole group is killed
         * by rcfpch. Postpone restarting until cleanup.
         */
    }
    else 
    {
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }
    
    sockts_test_connection(iut_child, child_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    if (kill)
        rcf_rpc_server_restart(pco_iut);
    
    TEST_END;
}
