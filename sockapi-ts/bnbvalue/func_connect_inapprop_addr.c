/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_connect_inapprop_addr Using wildcard address and zero port in connect() function with connection-oriented sockets
 *
 * @objective Check that @b connect() reports an error when it is used
 *            with peer address that contains wildcard network address
 *            or zero port with connection-oriented sockets.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env            Testing environment:
 *                         - @ref arg_types_env_peer2peer
 *                         - @ref arg_types_env_peer2peer_ipv6
 * @param port_wildcard  If @c TRUE, connect() to an address with zero port
 * @param addr_wildcard  If @c TRUE, connect() to wildcard address
 *
 * @note
 * -# @anchor bnbvalue_func_connect_inapprop_addr_1
 *    This step is oriented on Linux behaviour - it tries to establish
 *    a connection with the peer endpoint using specified IP address
 *    and port 0. On FreeBSD the function sets
 *    @b errno to @c EADDRNOTAVAIL without establishing any connections;
 * -# @anchor bnbvalue_func_connect_inapprop_addr_2
 *    This step is oriented on FreeBSD and Linux behaviour, but Linux
 *    tries to establish a connection with the peer endpoint using
 *    specified port number and the same IP address as it is bound to.
 *    FreeBSD does not send anything from its interfaces.
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_connect_inapprop_addr"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *wild_addr;
    struct sockaddr_storage dst_addr;
    int                     iut_socket = -1;
    te_bool                 port_wildcard;
    te_bool                 addr_wildcard;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_BOOL_PARAM(port_wildcard);
    TEST_GET_BOOL_PARAM(addr_wildcard);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, wild_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_STEP("Create @b iut_s socket of type @c SOCK_STREAM on @b pco_iut.");
    iut_socket = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);

    TEST_STEP("Prepare @b dst_addr address for test connect.");
    tapi_sockaddr_clone_exact(addr_wildcard ? wild_addr : tst_addr, &dst_addr);

    TEST_STEP("Set port to @c 0 in @b dst_addr if @p port_wildcard is "
              "@c TRUE.");
    if (port_wildcard)
    {
        te_sockaddr_clear_port(SA(&dst_addr));
    }

    TEST_STEP("Call @b connect() to connect @b iut_s socket to the prepared "
              "address.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_socket, SA(&dst_addr));

    TEST_STEP("Check that the function returns @c -1 and sets @b errno to "
              "@c ECONNREFUSED. "
              "See @ref bnbvalue_func_connect_inapprop_addr_1 \"note 1\".");
    if (rc != -1)
    {
        TEST_FAIL("connect() to %s returned %d instead of -1",
                  te_sockaddr2str(SA(&dst_addr)), rc);
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_ECONNREFUSED,
                    "connect() returned -1");


    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_socket);

    TEST_END;
}
