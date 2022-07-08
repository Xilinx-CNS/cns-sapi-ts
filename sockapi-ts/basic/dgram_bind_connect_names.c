/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Advanced usage of basic Socket API
 */

/** @page basic-dgram_bind_connect_names Bind UDP socket to loopback address and try to connect to unicast address
 *
 * @objective Bind UDP socket to loopback address and try to connect to unicast address
 *
 * @type conformance
 *
 * @param env   Private environment where IUT and tester are located on two
 *              different hosts which are connected directly using @b SFC
 *              NICs. @c INADDR_LOOPBACK address is issued for IUT.
 *
 * @par Test sequence:
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 */

#define TE_TEST_NAME    "basic/dgram_bind_connect_names"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *localhost = NULL;
    const struct sockaddr  *remote = NULL;

    struct sockaddr_storage name;
    socklen_t               namelen = sizeof(name);

    int                     iut_s = -1;

    /* Preambule */
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, localhost);
    TEST_GET_ADDR(pco_tst, remote);

    te_sockaddr_set_port(SA(localhost), 0);

    TEST_STEP("Create @c SOCK_DGRAM socket @b iut_s on @p pco_iut.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(localhost),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @b iut_s to @p localhost :@c 0.");
    rpc_bind(pco_iut, iut_s, localhost);

    TEST_STEP("Call @b getsockname() on @b iut_s and check that "
              "the function returns address "
              "@p localhost (not considering port number).");
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp_no_ports(localhost, te_sockaddr_get_size(localhost),
                                SA(&name), namelen))
    {
        ERROR("getsockname() returned address %s, expected one is %s",
              te_sockaddr_get_ipstr(SA(&name)),
              te_sockaddr_get_ipstr(localhost));
        TEST_VERDICT("getsockname() before connect() returned unexpected "
                     "address for bound IUT socket");
    }

    TEST_STEP("Connect @b iut_s to @p remote, check that "
              "@b connect() returns @c -1 and errno is set to "
              "@c EADDRNOTAVAIL or @c EINVAL.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s, remote);
    if (rc != -1)
    {
        RING_VERDICT("datagram socket is bound to loopback, "
                     "but connect() to non-local address returns OK");
    }
    else if (RPC_ERRNO(pco_iut) == RPC_EINVAL)
    {
        /* Acceptable behaviour */
        RING_VERDICT("connect() to remote address of the socket bound "
                     "to localhost address failed with errno EINVAL");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EADDRNOTAVAIL,
                        "connect() returned -1, but");
    }

    TEST_STEP("Call @b getsockname() on @b iut_s and check that "
              "the function returns address "
              "@p localhost (not considering port number).");
    namelen = sizeof(name);
    rpc_getsockname(pco_iut, iut_s, SA(&name), &namelen);
    if (te_sockaddrcmp_no_ports(localhost, te_sockaddr_get_size(localhost),
                                 SA(&name), namelen))
    {
        ERROR("getsockname() returned address %s, expected one is %s",
              te_sockaddr_get_ipstr(SA(&name)),
              te_sockaddr_get_ipstr(localhost));
        TEST_VERDICT("getsockname() after connect() returned unexpected "
                     "address for bound IUT socket");
    }

    TEST_STEP("Call @b getpeername() on @b iut_s and check "
              "that it returned @c -1 and @p errno on @p pco_iut "
              "is set to @c ENOTCONN.");
    namelen = sizeof(name);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getpeername(pco_iut, iut_s, SA(&name), &namelen);
    if (rc != -1)
    {
        RING_VERDICT("getpeername() succeeded");
        if (te_sockaddrcmp(SA(&name), namelen, remote,
                           te_sockaddr_get_size(remote)))
            TEST_VERDICT("getpeername() returns unexpected address");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                        "getpeername() returned -1, but");
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
