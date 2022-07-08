/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-exec_fork_multiple Robustness after calling of the multiple exec()/fork() procedures
 *
 * @objective Check that connected socket is inherited during multiple @b exec()
 *            and @b fork()/exec() calls that data received and transmitted
 *            correctly.
 *
 * @type Conformance, compatibility
 *
 * @reference @ref STEVENS Section 4.7
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param method1   Determines what exactly to do creating the first new
 *                  process:
 *                  - inherit: means just calling @b fork().
 * @param method2   Determines what exactly to do creating other child
 *                  processes:
 *                  - inherit: means just calling @b fork().
 *
 * @par Scenario:
 *
 * -# Create network connection of sockets of @p sock_type by means of
 *    @c GEN_CONNECTION, obtain sockets @p iut_s on @p pco_iut and
 *    @p tst_s on @p pco_tst.
 * -# Perform @c CHECK_SOCKET_STATE for @p pco_iut, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# Change image of process @p pco_iut by means of @b execve() call.
 * -# Perform @c CHECK_SOCKET_STATE for @p pco_iut, @p iut_s.
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED.
 *  \n @htmlonly &nbsp; @endhtmlonly
 * -# @b send() data from @p iut_s.
 * -# Catch sent data by @b recv() on @p tst_s.
 * -# Check that received data has same length as was sent.
 * -# @b send() data from @p tst_s.
 * -# Change image of process @p pco_iut by means of @b execve() call.
 * -# Catch sent data by @b recv() on @p iut_s.
 * -# Check that received data is the same as was sent.
 * -# Split process @p iut_child1 from @p pco_iut with @b fork().
 * -# Split process @p iut_child2 from @p pco_chld1 with @b fork().
 * -# Perform @c CHECK_SOCKET_STATE for @p iut_s on: @p pco_iut,
 *  @p iut_child1 and @p iut_child2.
 * -# Check that obtained state of @p iut_s is @c STATE_CONNECTED
 *    in all cases.
 * -# @b send() data from @p tst_s.
 * -# Catch sent data by @b recv() on @p iut_child1.
 * -# Check that received data are the same as was sent.
 * -# @b send() data from @p tst_s.
 * -# Catch sent data by @b recv() on @p iut_child2.
 * -# Check that received data are the same as was sent.
 * -# @b close() all sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/exec_fork_multiple"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *iut_child1 = NULL;
    rcf_rpc_server         *iut_child2 = NULL;
    rcf_rpc_server         *iut_child3 = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const char             *method1;
    const char             *method2;
    rpc_socket_domain       domain;

    int                     iut_s = -1;
    int                     child1_s = -1;
    int                     child2_s = -1;
    int                     child3_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    rpc_socket_type         sock_type;
    

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(method1);
    TEST_GET_STRING_PARAM(method2);

    domain = rpc_socket_domain_by_addr(iut_addr);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);

    rpc_create_child_process_socket(method1, pco_iut, iut_s, domain,
                                    sock_type, &iut_child1, &child1_s);
    rpc_create_child_process_socket(method2, iut_child1, child1_s, domain,
                                    sock_type, &iut_child2, &child2_s);
    rpc_create_child_process_socket(method2, pco_iut, iut_s, domain,
                                    sock_type, &iut_child3, &child3_s);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
    sockts_test_connection(iut_child1, child1_s, pco_tst, tst_s);
    sockts_test_connection(iut_child2, child2_s, pco_tst, tst_s);
    sockts_test_connection(iut_child3, child3_s, pco_tst, tst_s);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (iut_child1 == pco_iut)
        CLEANUP_RPC_CLOSE(pco_iut, child1_s);
    if (iut_child2 == pco_iut)
        CLEANUP_RPC_CLOSE(pco_iut, child2_s);
    if (iut_child3 == pco_iut)
        CLEANUP_RPC_CLOSE(pco_iut, child3_s);
    
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
