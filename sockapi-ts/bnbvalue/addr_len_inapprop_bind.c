/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-addr_len_inapprop_bind Using inappropriate address length value in bind() function
 *
 * @objective The test deals with @b bind() function. It checks that Socket
 *            API functions take into account the value passed in
 *            @a address_len parameter, and report an appropriate error if
 *            it is incorrect.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_iut_ucast
 *                  - @ref arg_types_env_iut_ucast_ipv6
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
 * -# Create @p iut_s socket of type @p sock_type on @p pco_iut.
 * -# @b bind() @p iut_s socket to a local address passing @a address_len
 *    parameter according to @p len_val:
 *    - if @p len_val is @c small then @a address_len should be equals to
 *      something that is less than size of an appropriate @c sockaddr
 *      structure (for @c PF_INET domain it should be less than
 *      @c sizeof(struct sockaddr_in)).
 *    - if @p len_val is @c big then @a address_len should be equals to
 *      something that is more than size of an appropriate @c sockaddr
 *      structure (for @c PF_INET domain it should be less than
 *      @c sizeof(struct sockaddr_in)) but less then
 *      @c sizeof(struct sockaddr_storage).
 *    - if @p len_val is @c large then @a address_len should be equals to
 *      something that is more than @c sizeof(struct sockaddr_storage).
 * -# Check that the function returns @c -1 and sets @b errno to @c EINVAL.
 *    See @ref bnbvalue_addr_len_inapprop_bind_1 "note 1".
 * -# Close @p iut_s socket.
 *
 * @note
 * -# @anchor bnbvalue_addr_len_inapprop_bind_1
 *    On FreeBSD systems it is not allowed for @c PF_INET sockets to pass
 *    @a address_len anything but @c sizeof(sockaddr_in).
 *    Functions return @c -1 and set @b errno to @c EINVAL;
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/addr_len_inapprop_bind"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    rpc_socket_type   sock_type;

    const struct sockaddr *iut_addr;
    int                    iut_s = -1;

    struct sockaddr        *addr = NULL;
    tarpc_sa               *rpc_sa = NULL;

    const char             *len_val;
    socklen_t               length;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(len_val);

    /*
     * Preambule.
     */

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    CHECK_NOT_NULL(addr = sockaddr_to_te_af(iut_addr, &rpc_sa));

    if (strcmp(len_val, "small") == 0)
        length = 4; /* Check address length 4 */
    else if (strcmp(len_val, "big") == 0)
    {
        length = rpc_get_sizeof(pco_iut,
            addr_family_sockaddr_str(rpc_sa->sa_family));
        length += rand_range(1, length);
    }
    else if (strcmp(len_val, "large") == 0)
        length = sizeof(struct sockaddr_storage) +
                      rand_range(1, sizeof(struct sockaddr_storage));

    RPC_AWAIT_IUT_ERROR(pco_iut);

    if ((rc = rpc_bind_len(pco_iut, iut_s, addr, length)) == -1)
    {
        if (strcmp(len_val, "big") == 0)
            TEST_VERDICT("bind() called with addr_length parameter more "
                         "than sizeof(struct sockaddr_) failed with "
                         "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
        else
            CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                            "bind() called with addr_length parameter %s "
                            "returned -1",
                            (strcmp(len_val, "large") == 0) ?
                                "more than sizeof(struct sockaddr_storage)" :
                                "less than sizeof(struct sockaddr_)");
    }
    else if (strcmp(len_val, "big") != 0)
    {
            TEST_VERDICT("bind() called with %s addr_length parameter "
                         "returned success instead of expected "
                         "failure(-1)", len_val);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(addr);

    TEST_END;
}
