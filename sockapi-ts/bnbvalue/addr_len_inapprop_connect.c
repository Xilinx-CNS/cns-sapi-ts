/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_connect Using inappropriate address length value in connect() function
 *
 * @objective The test deals with @b connect() function. It checks that
 *            Socket API functions take into account the value passed in
 *            @a address_len parameter, and report an appropriate error if
 *            it is incorrect.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *                  - @ref arg_types_env_p2p_ip6ip4mapped
 * @param sock_type Socket type used in the test:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param len_val   Length of @a address_len field:
 *                  - small: 4 bytes;
 *                  - big: the length value is greater than address size, but
 *                  lesser then double address size;
 *                  - large: the length value is greater than double address
 *                  size.
 *
 * @par Scenario:
 * -# Create @p tst_s socket of type @p sock_type on @p pco_tst.
 * -# Create @p iut_s socket of type @p sock_type on @p pco_iut.
 * -# @b bind() @p tst_s socket to a local address.
 * -# @b bind() @p iut_s socket to a local address.
 * -# If @p sock_type parameter equals to @c SOCK_STREAM,
 *    call @b listen() on  @p tst_s socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b connect() to connect @p iut_s to @p tst_s passing @a address_len
 *    parameter equals to something that is less than size of an appropriate
 *    @c sockaddr structure.
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 * -# Call @p func_conn to connect @p iut_s socket to @p tst_s socket passing 
 *    @a address_len parameter equals to something that is more than size of 
 *    an appropriate @c sockaddr structure.
 * -# Check that the function returns @c 0.
 *    See @ref bnbvalue_addr_len_inapprop_connect_1 "note 1".
 * -# Close @p tst_s, and @p iut_s sockets.
 *
 * @note
 * -# @anchor bnbvalue_addr_len_inapprop_connect_1
 *    On FreeBSD systems it is not allowed for @c PF_INET sockets to pass
 *    @a address_len anything but @c sizeof(sockaddr_in).
 *    Functions return @c -1 and set @b errno to @c EINVAL;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_inapprop_connect"

#include "sockapi-test.h"

#define MAX_BUF_LEN 300

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL; 
    rcf_rpc_server *pco_tst = NULL;

    rpc_socket_type   sock_type;

    const struct sockaddr *iut_addr;
    int                    iut_s = -1;

    const struct sockaddr *tst_addr;
    int                    tst_s = -1;

    struct sockaddr        *addr = NULL;
    tarpc_sa               *rpc_sa = NULL;

    tarpc_ssize_t           sockaddr_size = 0;

    const char             *len_val;

    uint8_t addr_buf[MAX_BUF_LEN];
    socklen_t addrbuf_len = sizeof(struct sockaddr_storage);

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(len_val);

    /*
     * Preambule.
     */

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_bind(pco_iut, iut_s, iut_addr);

    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    }

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(tst_addr, &rpc_sa));
    rpc_sa->flags &= ~TARPC_SA_LEN_AUTO;

    sockaddr_size = rpc_get_sizeof(pco_iut,
                        addr_family_sockaddr_str(rpc_sa->sa_family));

    if (strcmp(len_val, "small") == 0)
        rpc_sa->len = 4; /* Check address length 4 */
    else if (strcmp(len_val, "big") == 0)
        rpc_sa->len = sockaddr_size + rand_range(1, sockaddr_size);
    else if (strcmp(len_val, "large") == 0)
    {
        memset(addr_buf, 0, MAX_BUF_LEN);
        addrbuf_len += rand_range(1, addrbuf_len);
        memcpy(addr_buf, tst_addr, te_sockaddr_get_size(tst_addr));
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect_raw(pco_iut, iut_s, (struct sockaddr *)addr_buf,
                             addrbuf_len);
    }
    else
    {
        TEST_FAIL("Incorrect value of 'len_val'.");
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(len_val, "large") != 0)
    {
        rc = rpc_connect(pco_iut, iut_s, addr);
    }

    if (rc == -1)
    {
        if (strcmp(len_val, "big") == 0)
            TEST_VERDICT("connect() called with %s 'len_val' parameter "
                         "failed with errno %s", len_val,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        else
            CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                            "connect() called with %s 'len_val' parameter "
                            "returned -1", len_val);
    }
    else if (strcmp(len_val, "big") != 0)
        TEST_VERDICT("connect() called with %s 'len_val' parameter "
                     "returned success instead of expected failure(-1)",
                     len_val);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(addr);

    TEST_END;
}
