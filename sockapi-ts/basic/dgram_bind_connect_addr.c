/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-dgram_bind_connect_addr connect() behavior in different combination of local and destination address/port on UDP sockets
 *
 * @objective Check @b connect() behavior on socket of @c SOCK_DGRAM type after
 *            @b bind() with following combinations:
 *             - local address       - INADDR_ANY, loopback, unicast;
 *             - local port          - 0, any valid port;
 *             - destination address - INADDR_ANY, loopback,
 *                                     unicast local, unicast peer;
 *             - destination port    - 0, any valid port.
 *
 * @type Conformance, compatibility
 *
 * @param env         Testing environments:
 *                    - @ref arg_types_env_peer2peer_2addr;
 *                    - @ref arg_types_env_peer2peer_2addr_lo;
 *                    - @ref arg_types_env_peer2peer_2addr_ipv6;
 *                    - @ref arg_types_env_peer2peer_2addr_lo_ipv6.
 * @param local_addr  IP address used for binding:
 *                    - any: @c INADDR_ANY
 *                    - loopback: @c INADDR_LOOPBACK
 *                    - local: a local IP address
 * @param local_port  Use any valid port in bind() if @c TRUE, else port
 *                    is @c 0.
 * @param dst_port    Use any valid port in connect() if @c TRUE, else port
 *                    is @c 0.
 * @param dst_addr    IP address used in connect():
 *                    - any: @c INADDR_ANY
 *                    - loopback: @c INADDR_LOOPBACK
 *                    - local: a local IP address
 *                    - remote: a correct remote IP address
 *
 * @par Scenario
 *
 * @author Igor Vasiliev <Igor Vasiliev@oktetlabs.ru>
 */


#define TE_LOG_LEVEL  (TE_LL_ERROR | TE_LL_WARN | TE_LL_RING | TE_LL_INFO)

#define TE_TEST_NAME  "basic/dgram_bind_connect_addr"

#include "sockapi-test.h"
#include "tapi_cfg.h"

int
main(int argc, char *argv[])
{
    te_bool                 local_port;
    const char             *local_addr;
    te_bool                 dst_port;
    const char             *dst_addr;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;

    int                     iut_s = -1;

    const struct sockaddr  *iut_addr1;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr1;

    struct sockaddr_storage l_addr;
    struct sockaddr_storage d_addr;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_STRING_PARAM(local_addr);
    TEST_GET_BOOL_PARAM(local_port);
    TEST_GET_STRING_PARAM(dst_addr);
    TEST_GET_BOOL_PARAM(dst_port);

    TEST_STEP("Prepare local and destination addresses according to input"
              "test parameters;");
    memcpy(&l_addr, iut_addr1, te_sockaddr_get_size(iut_addr1));
    memcpy(&d_addr, tst_addr1, te_sockaddr_get_size(tst_addr1));

    /* Prepare local address to bind socket */
    if (strcmp(local_addr, "any") == 0)
        te_sockaddr_set_wildcard(SA(&l_addr));
    else if (strcmp(local_addr, "loopback") == 0)
        te_sockaddr_set_loopback(SA(&l_addr));
    else if (strcmp(local_addr, "local") != 0)
        TEST_FAIL("Unexpected type of local address passed as parameter");

    if (local_port == FALSE)
        te_sockaddr_set_port(SA(&l_addr), 0);

    /* Prepare remote address to connect socket */
    if (strcmp(dst_addr, "local") == 0)
        memcpy(&d_addr, iut_addr2, te_sockaddr_get_size(iut_addr2));
    else if (strcmp(dst_addr, "any") == 0)
        te_sockaddr_set_wildcard(SA(&d_addr));
    else if (strcmp(dst_addr, "loopback") == 0)
        te_sockaddr_set_loopback(SA(&d_addr));
    else if (strcmp(dst_addr, "remote") != 0)
        TEST_FAIL("Unexpected type of destination address passed as "
                  "parameter");

    if (dst_port == FALSE)
        te_sockaddr_set_port(SA(&d_addr), 0);

    INFO("Test params: SRC - (%s,%d); DST - (%s,%d)",
         local_addr, ntohs(te_sockaddr_get_port(SA(&l_addr))),
         dst_addr, ntohs(te_sockaddr_get_port(SA(&d_addr))));

    TEST_STEP("Create socket @b iut_s of @c SOCK_DGRAM type on @p pco_iut;");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Bind @b iut_s to the local address;");
    rpc_bind(pco_iut, iut_s, SA(&l_addr));

    RPC_AWAIT_IUT_ERROR(pco_iut);


    TEST_STEP("Connect @b iut_s to the destination address;");
    rc = rpc_connect(pco_iut, iut_s, SA(&d_addr));

    TEST_STEP("Check @b connect() call return value. If @p local_addr is "
              "loopback and @p dst_addr is remote we expect that @b connect() "
              "call fails with @c EINVAL");
    if ((strcmp(local_addr,"loopback") == 0) &&
        (strcmp(dst_addr,"remote") == 0))
    {
        if (rc != -1)
        {
            TEST_VERDICT("connect() to the foreign host should return -1 "
                         "instead of %d, because socket bound to the "
                         "'loopback'", (int)rc);
        }
        if (RPC_ERRNO(pco_iut) == RPC_EINVAL)
        {
            /* Really expected result */
        }
        else
        {
            TEST_VERDICT("connect() failed with unexpected errno %s "
                         "instead of EINVAL",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        TEST_SUCCESS;
    }

    if (rc == -1)
    {
        TEST_VERDICT("connect() unexpectedly failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TEST_SUCCESS;

cleanup:
    TEST_STEP("Close created socket.");
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
