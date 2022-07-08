/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-connections_on_aliases Creation of the several connections on aliases
 *
 * @objective Check a possibility of creation of the several connections on
 *            separate addresses (aliases) of the same network interface and
 *            correct network interaction.
 *
 * @type Conformance, compatibility
 *
 *
 * @param env   Private set of environments:
 *               - similar to @ref arg_types_env_peer2peer but both IUT and
 *              Tester have by three IP addresses issued;
 *               - similar to @ref arg_types_env_peer2peer_lo but both IUT and
 *              Tester have by three IP addresses issued.
 *               - similar to @ref arg_types_env_peer2peer_ipv6 but both IUT and
 *              Tester have by three IP addresses issued;
 *               - similar to @ref arg_types_env_peer2peer_lo_ipv6 but both IUT and
 *              Tester have by three IP addresses issued.
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param diff_port All addresses use the same port if @c TRUE,
 *                  else - different.
 *
 * @par Scenario:
 *
 * -# Create connection of the @p sock_type type between socket @p iut1_s
 *    on @p pco_iut and @p tst1_s of the @p sock_type type by means of
 *    @p GEN_CONNECTION using @p alias1 @p tst1_addr as endpoints addresses;
 * -# Create connection of the @p sock_type type between socket @p iut2_s
 *    on @p pco_iut and @p tst2_s of the @p sock_type type by means of
 *    @p GEN_CONNECTION using @p alias2 @p tst2_addr as endpoints addresses;
 * -# Create connection of the @p sock_type type between socket @p iut3_s
 *    on @p pco_iut and @p tst3_s of the @p sock_type type by means of
 *    @p GEN_CONNECTION using @p alias3 @p tst3_addr as endpoints addresses;
 * -# Check correctness of the local/remote addresses by means of
 *    @b getsockname()/getpeername();
 * -# Prepare three buffers by means of @b te_make_buf();
 * -# Send prepared data from @p pco_tst to @p pco_iut using the created
 *    connections.
 * -# Check correctness of the data received on the @p pco_iut by means of
 *    @p CHECK_RECV.
 * -# @b close() created sockets.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/connections_on_aliases"

#include "sockapi-test.h"

#define DATA_BULK 100


int
main(int argc, char *argv[])
{
    rpc_socket_type     sock_type;
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    int                 iut1_s = -1;
    int                 iut2_s = -1;
    int                 iut3_s = -1;
    int                 tst1_s = -1;
    int                 tst2_s = -1;
    int                 tst3_s = -1;

    const struct sockaddr *alias1;
    const struct sockaddr *alias2;
    const struct sockaddr *alias3;

    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;
    const struct sockaddr *tst3_addr;

    struct sockaddr_storage     retaddr1;
    socklen_t                   retaddr1_len;
    struct sockaddr_storage     retaddr2;
    socklen_t                   retaddr2_len;

    ssize_t                s_len1;
    ssize_t                s_len2;
    ssize_t                s_len3;
    ssize_t                r_len1;
    ssize_t                r_len2;
    ssize_t                r_len3;
    size_t                 len1;
    size_t                 len2;
    size_t                 len3;

    te_bool                diff_port;

    char                  *tx_buf1 = NULL;
    char                  *tx_buf2 = NULL;
    char                  *tx_buf3 = NULL;
    unsigned char          r_buf1[DATA_BULK];
    unsigned char          r_buf2[DATA_BULK];
    unsigned char          r_buf3[DATA_BULK];


    /* Test preambule */
    TEST_START;    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(diff_port);

    TEST_GET_ADDR(pco_iut, alias1);
    TEST_GET_ADDR(pco_iut, alias2);
    TEST_GET_ADDR(pco_iut, alias3);

    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_ADDR(pco_tst, tst3_addr);


    if (diff_port)
    {
        SIN(alias2)->sin_port = SIN(alias1)->sin_port;
        SIN(alias3)->sin_port = SIN(alias1)->sin_port;
    }

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   alias1, tst1_addr, &iut1_s, &tst1_s);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   alias2, tst2_addr, &iut2_s, &tst2_s);

    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   alias3, tst3_addr, &iut3_s, &tst3_s);

    retaddr1_len = sizeof(retaddr1);
    rpc_getsockname(pco_iut, iut1_s, SA(&retaddr1), &retaddr1_len);

    retaddr2_len = sizeof(retaddr2);
    rpc_getpeername(pco_tst, tst1_s, SA(&retaddr2), &retaddr2_len);

    if ((te_sockaddrcmp(SA(&retaddr1), retaddr1_len, alias1,
                        te_sockaddr_get_size(alias1)) != 0) ||
        (te_sockaddrcmp(SA(&retaddr2), retaddr2_len, alias1,
                        te_sockaddr_get_size(alias1)) != 0))
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr1_len = sizeof(retaddr1);
    rpc_getsockname(pco_iut, iut2_s, SA(&retaddr1), &retaddr1_len);

    retaddr2_len = sizeof(retaddr2);
    rpc_getpeername(pco_tst, tst2_s, SA(&retaddr2), &retaddr2_len);

    if ((te_sockaddrcmp(SA(&retaddr1), retaddr1_len, alias2,
                        te_sockaddr_get_size(alias2)) != 0) ||
        (te_sockaddrcmp(SA(&retaddr2), retaddr2_len, alias2,
                        te_sockaddr_get_size(alias2)) != 0))
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr1_len = sizeof(retaddr1);
    rpc_getsockname(pco_iut, iut3_s, SA(&retaddr1), &retaddr1_len);

    retaddr2_len = sizeof(retaddr2);
    rpc_getpeername(pco_tst, tst3_s, SA(&retaddr2), &retaddr2_len);

    if ((te_sockaddrcmp(SA(&retaddr1), retaddr1_len, alias3,
                        te_sockaddr_get_size(alias3)) != 0) ||
        (te_sockaddrcmp(SA(&retaddr2), retaddr2_len, alias3,
                        te_sockaddr_get_size(alias3)) != 0))
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr1_len = sizeof(retaddr1);
    rpc_getsockname(pco_tst, tst1_s, SA(&retaddr1), &retaddr1_len);

    retaddr2_len = sizeof(retaddr2);
    rpc_getpeername(pco_iut, iut1_s, SA(&retaddr2), &retaddr2_len);

    if ((te_sockaddrcmp(SA(&retaddr1), retaddr1_len, tst1_addr,
                        te_sockaddr_get_size(tst1_addr)) != 0) ||
        (te_sockaddrcmp(SA(&retaddr2), retaddr2_len, tst1_addr,
                        te_sockaddr_get_size(tst1_addr) ) != 0))
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr1_len = sizeof(retaddr1);
    rpc_getsockname(pco_tst, tst2_s, SA(&retaddr1), &retaddr1_len);

    retaddr2_len = sizeof(retaddr2);
    rpc_getpeername(pco_iut, iut2_s, SA(&retaddr2), &retaddr2_len);

    if ((te_sockaddrcmp(SA(&retaddr1), retaddr1_len, tst2_addr,
                        te_sockaddr_get_size(tst2_addr)) != 0) ||
        (te_sockaddrcmp(SA(&retaddr2), retaddr2_len, tst2_addr,
                        te_sockaddr_get_size(tst2_addr)) != 0))
    {
        TEST_FAIL("Incorrect address");
    }

    retaddr1_len = sizeof(retaddr1);
    rpc_getsockname(pco_tst, tst3_s, SA(&retaddr1), &retaddr1_len);

    retaddr2_len = sizeof(retaddr2);
    rpc_getpeername(pco_iut, iut3_s, SA(&retaddr2), &retaddr2_len);

    if ((te_sockaddrcmp(SA(&retaddr1), retaddr1_len, tst3_addr,
                        te_sockaddr_get_size(tst3_addr)) != 0) ||
        (te_sockaddrcmp(SA(&retaddr2), retaddr2_len, tst3_addr,
                        te_sockaddr_get_size(tst3_addr)) != 0))
    {
        TEST_FAIL("Incorrect address");
    }

    if ((tx_buf1 = te_make_buf(1, DATA_BULK, &len1)) == NULL)
        TEST_STOP;

    if ((tx_buf2 = te_make_buf(1, DATA_BULK, &len2)) == NULL)
        TEST_STOP;

    if ((tx_buf3 = te_make_buf(1, DATA_BULK, &len3)) == NULL)
        TEST_STOP;

    RPC_SEND(s_len1, pco_tst, tst1_s, tx_buf1, len1, 0);
    RPC_SEND(s_len2, pco_tst, tst2_s, tx_buf2, len2, 0);
    RPC_SEND(s_len3, pco_tst, tst3_s, tx_buf3, len3, 0);

    r_len1 = rpc_recv(pco_iut, iut1_s, r_buf1, len1, 0);
    if (r_len1 != (ssize_t)s_len1)
        TEST_FAIL("Received only %d bytes instead of %d", r_len1, sizeof(tx_buf1));

    r_len2 = rpc_recv(pco_iut, iut2_s, r_buf2, len2, 0);
    if (s_len2 != (ssize_t)r_len2)
        TEST_FAIL("Received only %d bytes instead of %d", s_len2, DATA_BULK);

    r_len3 = rpc_recv(pco_iut, iut3_s, r_buf3, len3, 0);
    if (s_len3 != (ssize_t)r_len3)
        TEST_FAIL("Received only %d bytes instead of %d", s_len3, DATA_BULK);

    if (memcmp(tx_buf1, r_buf1, r_len1) != 0 ||
        memcmp(tx_buf2, r_buf2, r_len2) != 0 ||
        memcmp(tx_buf3, r_buf3, r_len3) != 0)
        TEST_FAIL("Recieved data wasn't correct");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut1_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut2_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut3_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst2_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst3_s);
    free(tx_buf1);
    free(tx_buf2);
    free(tx_buf3);

    TEST_END;
}
