/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_sendto Using inappropriate address length value in sendto() function
 *
 * @objective The test deals with @b sendto() function. It
 *            checks that Socket API functions take into account the value
 *            passed in @a address_len parameter, and report an appropriate
 *            error if it is incorrect.
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
 * @param connect   @c TRUE or @c FALSE.
 *                  Value @c FALSE iterate only with @p sock_type = @c SOCK_DGRAM.
 * @param len_val   Length of @a address_len field:
 *                  - small: 4 bytes;
 *                  - big: the length value is greater than address size, but
 *                  lesser then double address size;
 *                  - large: the length value is greater than double address
 *                  size.
 *
 * @note
 * -# @anchor bnbvalue_addr_len_inapprop_sendto_1
 *    On FreeBSD systems it is not allowed for @c PF_INET sockets to pass
 *    @a address_len anything but @c sizeof(sockaddr_in).
 *    Functions return @c -1 and set @b errno to @c EINVAL;
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_inapprop_sendto"

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

    te_bool           connect;

    unsigned char          *buffer = NULL;
    size_t                  buffer_len;

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
    TEST_GET_BOOL_PARAM(connect);
    TEST_GET_STRING_PARAM(len_val);

    buffer = sockts_make_buf_dgram(&buffer_len);
    CHECK_NOT_NULL(buffer);

    /*
     * Preambule.
     */
    TEST_STEP("Create @b iut_s socket of type @p sock_type on @p pco_iut "
              "and bind it to @p iut_addr");
    iut_s = rpc_create_and_bind_socket(pco_iut, sock_type, RPC_PROTO_DEF,
                                       TRUE, FALSE, SA(iut_addr));
    if (iut_s < 0)
    {
        TEST_FAIL("Cannot create 'iut_s' socket of type %s",
                  socktype_rpc2str(sock_type));
    }

    TEST_STEP("Create @b tst_s socket of type @p sock_type on @p pco_tst "
              "and bind it to @p tst_addr");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("If @p sock_type parameter equals to @c SOCK_STREAM,"
              "call @b listen() on @b tst_s socket.");
    if (sock_type == RPC_SOCK_STREAM)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    }

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(tst_addr, &rpc_sa));

    TEST_STEP("If @p connect is @c TRUE, call @b connect() on @b iut_s socket "
              "to connect to tst_addr.");
    if (connect)
    {
        rpc_connect(pco_iut, iut_s, addr);
    }

    rpc_sa->flags &= ~TARPC_SA_LEN_AUTO;
    sockaddr_size = rpc_get_sizeof(pco_iut,
                        addr_family_sockaddr_str(rpc_sa->sa_family));

    TEST_STEP("If @p len_val is 'small' set @a address_len parameter "
              "to @c 4. If @p len_val is 'big' set @a address_len parameter "
              "to something between size of @c sockaddr structure and double "
              "@c sockaddr size. If @p len_val is 'large' set "
              "@a address_len parameter to value greather than double "
              "@c sockaddr size.");
    TEST_STEP("Call @b sendto() on @b iut_s socket sending some data towards "
              "@b tst_s socket.");
    if (strcmp(len_val, "small") == 0)
        rpc_sa->len = 4; /* Check address length 4 */
    else if (strcmp(len_val, "big") == 0)
        rpc_sa->len = sockaddr_size + rand_range(1, sockaddr_size);
    else if (strcmp(len_val, "large") == 0)
    {
        memset(addr_buf, 0, MAX_BUF_LEN);
        addrbuf_len += rand_range(1, addrbuf_len);
        memcpy(addr_buf, tst_addr, sizeof(*tst_addr));
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_sendto_raw(pco_iut, iut_s, buffer, buffer_len, 0,
                            (struct sockaddr *)addr_buf, addrbuf_len);
    }
    else
        TEST_FAIL("Incorrect value of 'len_val'");


    if (strcmp(len_val, "large") != 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_sendto(pco_iut, iut_s, buffer, buffer_len, 0, addr);
    }

    TEST_STEP("If @p len_val is 'big' check that the function returns size of "
              "sent data. See @ref bnbvalue_addr_len_inapprop_sendto_1 "
              "\"note 1\".");
    if (strcmp(len_val, "big") == 0)
    {
        if ((size_t)rc != buffer_len)
        {
            TEST_VERDICT("sendto() called with 'big' 'len_val' "
                         "parameter %s with errno %s",
                         rc == -1 ? "failed" : "returned incorrect "
                         "value", errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        else
            TEST_SUCCESS;
    }

    TEST_STEP("If @p len_val is 'small' or 'large' check that the function "
              "returns @c -1 and sets @b errno to @c EINVAL.");
    if (rc != -1)
    {
        if (rc == (int)buffer_len)
        {
            TEST_VERDICT("sendto() called with %s 'len_val' "
                         "parameter returned success instead of "
                         "expected failure(-1)", len_val);
        }
        else
        {
            TEST_VERDICT("sendto() called with %s 'len_val' parameter "
                         "returned strange result instead of expected "
                         "failure(-1)", len_val);
        }
    }
    else
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                        "sendto() called with %s 'len_val' parameter "
                        "returned -1", len_val);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(addr);

    TEST_END;
}
