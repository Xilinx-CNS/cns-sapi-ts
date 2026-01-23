/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_uids Port sharing by different users
 *
 * @objective  Try to share address and port with SO_REUSEPOR by different
 *             users.
 *
 * @param pco_iut1       First PCO on IUT.
 * @param pco_iut2       Second PCO on IUT.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_uids"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut1 = NULL;
    rcf_rpc_server *pco_iut2 = NULL;
    const struct sockaddr *iut_addr = NULL;
    rpc_socket_type sock_type;
    int sock1 = -1;
    int sock2 = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut1);
    TEST_GET_PCO(pco_iut2);
    TEST_GET_ADDR(pco_iut1, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);

    TEST_STEP("Set different user ID to one of IUT processes with @p pco_iut2.");
    sockts_server_change_uid(pco_iut2);

    TEST_STEP("Open sockets on both IUT processes.");
    sock1 = rpc_socket(pco_iut1, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    sock2 = rpc_socket(pco_iut2, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set SO_REUSEPORT for the both sockets.");
    rpc_setsockopt_int(pco_iut1, sock1, RPC_SO_REUSEPORT, 1);
    rpc_setsockopt_int(pco_iut2, sock2, RPC_SO_REUSEPORT, 1);

    TEST_STEP("Bind one of sockets.");
    rpc_bind(pco_iut1, sock1, iut_addr);

    TEST_STEP("Try to bind the second socket. It must fail with errno "
              "EADDRINUSE.");
    RPC_AWAIT_IUT_ERROR(pco_iut2);
    rc = rpc_bind(pco_iut2, sock2, iut_addr);
    if (rc == 0)
        TEST_VERDICT("Second bind unexpectedly succeeded");

    if (RPC_ERRNO(pco_iut2) != RPC_EADDRINUSE)
        TEST_VERDICT("Second bind failed with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut2)));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut1, sock1);
    CLEANUP_RPC_CLOSE(pco_iut2, sock2);

    TEST_END;
}
