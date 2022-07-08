/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_connect Connect twice to one address from reused address
 *
 * @objective  Try to connect to exactly same address:port twice from
 *             reusing with SO_REUSEPORT address.
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param sock_type     Socket type
 * @param server        Determines is the TCP socket server or client
 * @param wildcard      If @c TRUE, bind IUT sockets to INADDR_ANY
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_connect"

#include "sockapi-test.h"
#include "reuseport.h"
int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_aux = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr_storage iut_bind_addr;

    rpc_socket_type   sock_type;
    te_bool           server = FALSE;
    te_bool           wildcard = FALSE;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int tst_s1 = -1;
    int tst_s2 = -1;
    int acc_s  = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(server);
    TEST_GET_BOOL_PARAM(wildcard);

    tapi_sockaddr_clone_exact(iut_addr, &iut_bind_addr);
    if (wildcard)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    TEST_STEP("Create two tcp sockets couples, set SO_REUSEPORT for both IUT and "
              "tester sockets.");
    iut_s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);
    tst_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        sock_type, RPC_PROTO_DEF);

    rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_REUSEPORT, 1);
    rpc_setsockopt_int(pco_tst, tst_s1, RPC_SO_REUSEPORT, 1);

    rpc_bind(pco_iut, iut_s1, SA(&iut_bind_addr));
    rpc_bind(pco_tst, tst_s1, tst_addr);

    iut_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                        sock_type, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                        sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set SO_REUSEPORT for both sockets and bind them to the same addreses "
              "as previous sockets couple.");
    rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEPORT, 1);
    rpc_bind(pco_iut, iut_s2, SA(&iut_bind_addr));

    rpc_setsockopt_int(pco_tst, tst_s2, RPC_SO_REUSEPORT, 1);
    rpc_bind(pco_tst, tst_s2, tst_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_STEP("Try to establish connection for TCP sockets. If @p server is "
                  "@c TRUE than IUT is server. connect() should fail with errno "
                  "@c EADDRNOTAVAIL.");
        if (server)
        {
            rpc_listen(pco_iut, iut_s1, 1);
            rpc_listen(pco_iut, iut_s2, 1);

            rpc_fcntl(pco_iut, iut_s1, RPC_F_SETFL, RPC_O_NONBLOCK);
            rpc_fcntl(pco_iut, iut_s2, RPC_F_SETFL, RPC_O_NONBLOCK);

            rpc_connect(pco_tst, tst_s1, iut_addr);

            TAPI_WAIT_NETWORK;

            if ((acc_s = reuseport_try_accept(pco_iut, iut_s1)) < 0)
            {
                acc_s = reuseport_try_accept(pco_iut, iut_s2);
                if (acc_s < 0)
                    TEST_VERDICT("Neither of listeners accepted connection");
            }

            RPC_AWAIT_IUT_ERROR(pco_tst);
            rc = rpc_connect(pco_tst, tst_s2, iut_addr);
            pco_aux = pco_tst;
        }
        else
        {
            pco_aux = pco_iut;
            rpc_listen(pco_tst, tst_s1, 1);
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s1, tst_addr);

            if (rc == 0)
            {
                rpc_listen(pco_tst, tst_s2, 1);
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = rpc_connect(pco_iut, iut_s2, tst_addr);
            }
        }

        if (rc != 0)
        {
            if (RPC_ERRNO(pco_aux) == RPC_EADDRNOTAVAIL)
                TEST_SUCCESS;
            TEST_VERDICT("connect() failed with unexpected errno: %s",
                         te_rc_err2str(RPC_ERRNO(pco_aux)));
        }
        TEST_VERDICT("connect() unexpectedly succeeded");
    }
    else
    {
        TEST_STEP("Just call connect() for both IUT and tester sockets if "
                  "@p sock_type is @c SOCK_DGRAM.");
        rpc_connect(pco_iut, iut_s1, tst_addr);
        rpc_connect(pco_tst, tst_s1, iut_addr);
        rpc_connect(pco_iut, iut_s2, tst_addr);
        rpc_connect(pco_tst, tst_s2, iut_addr);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    /* Avoid sockets in TIME_WAIT state on IUT, see ST-2451. */
    TAPI_WAIT_NETWORK;

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    TEST_END;
}
