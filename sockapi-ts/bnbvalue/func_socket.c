/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_socket Passing inappropriate parameters to socket() function
 *
 * @objective Check that @b socket() function correctly handles values of
 *            @a domain, @a type and @a protocol parameters and
 *            sets @b errno variable in appropriate way.
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_iut_only
 * @param domain        Socket domain.
 * @param sock_type     Socket type used in the test.
 * @param proto         Protocol used in the test.
 * @param exp_errno     Expected value of @b errno parameter.
 *
 * @par Scenario:
 *
 * -# Call @b socket(@a domain, @a type, @a proto);
 * -# Check that the function returns @c -1 and sets @b errno to @p
 *    exp_errno;
 *
 * @table_start
 * @row_start
 *     @entry_start @a domain @entry_end
 *     @entry_start @a type @entry_end
 *     @entry_start @a protocol @entry_end
 *     @entry_start @b errno @entry_end
 *     @entry_start note @entry_end
 * @row_end
 * @row_start
 *     @entry_start @p unknown_domain @entry_end
 *     @entry_start @c SOCK_STREAM @entry_end
 *     @entry_start @c 0 @entry_end
 *     @entry_start @c EAFNOSUPPORT @entry_end
 *     @entry_start &nbsp; @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c AF_INET @entry_end
 *     @entry_start @p unsupported_type @entry_end
 *     @entry_start @c 0 @entry_end
 *     @entry_start @c EPROTOTYPE @entry_end
 *     @entry_start See @ref bnbvalue_func_socket_1 "note 1" @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c AF_INET @entry_end
 *     @entry_start @p unknown_type @entry_end
 *     @entry_start @c 0 @entry_end
 *     @entry_start @c EPROTOTYPE @entry_end
 *     @entry_start See @ref bnbvalue_func_socket_2 "note 2" @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c AF_INET @entry_end
 *     @entry_start @c SOCK_DGRAM @entry_end
 *     @entry_start @p unknown_proto @entry_end
 *     @entry_start @c EPROTONOSUPPORT @entry_end
 *     @entry_start See @ref bnbvalue_func_socket_3 "note 3" @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c AF_INET @entry_end
 *     @entry_start @c SOCK_STREAM @entry_end
 *     @entry_start @p unknown_proto @entry_end
 *     @entry_start @c EPROTONOSUPPORT @entry_end
 *     @entry_start See @ref bnbvalue_func_socket_3 "note 3" @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c AF_INET @entry_end
 *     @entry_start @c SOCK_DGRAM @entry_end
 *     @entry_start @c IPPROTO_TCP @entry_end
 *     @entry_start @c EPROTONOSUPPORT @entry_end
 *     @entry_start See @ref bnbvalue_func_socket_3 "note 3" @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c AF_INET @entry_end
 *     @entry_start @c SOCK_STREAM @entry_end
 *     @entry_start @c IPPROTO_UDP @entry_end
 *     @entry_start @c EPROTONOSUPPORT @entry_end
 *     @entry_start See @ref bnbvalue_func_socket_3 "note 3" @entry_end
 * @row_end
 *
 * @table_end
 *
 * @note
 * -# @anchor bnbvalue_func_socket_1
 *    The value of @b errno is based on @ref XNS5, but on Linux @b errno is
 *    set to @c ESOCKTNOSUPPORT;
 * -# @anchor bnbvalue_func_socket_2
 *    The value of @b errno is based on @ref XNS5, but on Linux @b errno is
 *    set to @c EINVAL;
 * -# @anchor bnbvalue_func_socket_3
 *    The value of @b errno is based on @ref XNS5 and FreeBSD, but on Linux
 *    @b errno is set to @c ESOCKTNOSUPPORT;
 *
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_socket"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;

    rpc_socket_type    sock_type;
    rpc_socket_proto   proto;
    rpc_errno          exp_errno;
    
    rpc_socket_domain  domain;

    /* Preambule */
    TEST_START;
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_PROTOCOL(proto);
    TEST_GET_ERRNO_PARAM(exp_errno);
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    iut_s = rpc_socket(pco_iut, domain, sock_type, proto);

    if (iut_s != -1)
    {
        TEST_VERDICT("socket(%s, %s, %s) is expected to return -1, "
                     "but it %s", domain_rpc2str(domain),
                     socktype_rpc2str(sock_type), proto_rpc2str(proto),
                     iut_s >= 0 ? "passed" : "failed unexpectedly");
    }
        
    CHECK_RPC_ERRNO(pco_iut, exp_errno, "socket(%s, %s, %s) returns -1, but",
                    domain_rpc2str(domain), socktype_rpc2str(sock_type),
                    proto_rpc2str(proto));

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
