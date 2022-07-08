/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-ef_fork_netif @c EF_FORK_NETIF and it's interaction with @b fork() call
 *
 * @objective Check that changing @c EF_FORK_NETIF environment variable
 *            changes stack creation behaviour in parent and child
 *            processes after @b fork(). 
 *
 * @param pco_iut       PCO on IUT
 * @param sock_type     Type of socket used in the test
 * @param ef_fork_netif The value of @c EF_FORK_NETIF environment variable
 *
 * @par Scenario:
 *
 * -# Set @c EF_FORK_NETIF variable according to @p ef_fork_netif.
 * -# Create @p sock_type socket.
 * -# Call @b fork().
 * -# Create two socket: one in parent process one in child.
 * -# Check stacks id for each socket are correct according to
 *    @p ef_fork_netif.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/ef_fork_netif"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut      = NULL;
    rcf_rpc_server *pco_iut_fork = NULL;

    const char  *ef_fork_netif_val;
    char        *old_val = NULL;

    cfg_handle          ef_fork_netif_handle = CFG_HANDLE_INVALID;
    rpc_socket_type     sock_type = RPC_SOCK_UNKNOWN;

    int s1;
    int s2;
    int s3;

    tarpc_onload_stat ostat1;
    tarpc_onload_stat ostat2;
    tarpc_onload_stat ostat3;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(ef_fork_netif_val);
    TEST_GET_SOCK_TYPE(sock_type);

    ef_fork_netif_handle = sockts_set_env(pco_iut, "EF_FORK_NETIF",
                                          ef_fork_netif_val,
                                          &old_val);

    s1 = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    CHECK_RC(rcf_rpc_server_fork(pco_iut, "pco_iut_fork", &pco_iut_fork));

    s2 = rpc_socket(pco_iut, RPC_PF_INET, sock_type, RPC_PROTO_DEF);
    s3 = rpc_socket(pco_iut_fork, RPC_PF_INET, sock_type, RPC_PROTO_DEF);

    rpc_onload_fd_stat(pco_iut, s1, &ostat1);
    rpc_onload_fd_stat(pco_iut, s2, &ostat2);
    rpc_onload_fd_stat(pco_iut_fork, s3, &ostat3);

    if (!((atoi(ef_fork_netif_val) == 0 &&
           ostat1.stack_id == ostat2.stack_id &&
           ostat2.stack_id == ostat3.stack_id) ||
          (atoi(ef_fork_netif_val) == 1 &&
           ostat1.stack_id == ostat2.stack_id &&
           ostat2.stack_id != ostat3.stack_id) ||
          (atoi(ef_fork_netif_val) == 2 &&
           ostat1.stack_id == ostat3.stack_id &&
           ostat2.stack_id != ostat3.stack_id) ||
          (atoi(ef_fork_netif_val) == 3 &&
           ostat1.stack_id != ostat2.stack_id &&
           ostat2.stack_id != ostat3.stack_id &&
           ostat1.stack_id != ostat3.stack_id)))
        TEST_FAIL("Incorrect behaviour for EF_FORK_NETIF=%s",
                  ef_fork_netif_val);

    TEST_SUCCESS;

cleanup:
    rcf_rpc_server_destroy(pco_iut_fork);

    CLEANUP_CHECK_RC(sockts_restore_env(pco_iut, ef_fork_netif_handle,
                                        old_val));

    TEST_END;
}
