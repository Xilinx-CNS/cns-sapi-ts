/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_setsockopt Inappropriate usage of setsockopt() function
 *
 * @objective Check the behaviour of @b setsockopt() function with
 *            different combinations of @a option_value and @a option_length
 *            parameters
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param domain       Domain used for the test (@c PF_INET, or smth.)
 * @param type         Type of socket used in the test
 * @param opt_name     Option name used in the test
 * @param opt_buffer   @c FALSE if @c NULL or @c TRUE in case of the
 *                     real buffer passed as the value of @a option_value
 *                     parameter
 * @param opt_len      value of @a option_length parameter
 * @param pco_iut      PCO on IUT
 *
 * @note If @p opt_buffer parameter is TRUE, @p opt_len is allowed to be
 * only zero.
 * 
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @p type
 *    on @b pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Map @p opt_name to socket @p level via rpc_sockopt2level() routine;
 * -# If @p opt_buffer is TRUE, set @p opt_val to some real buffer,
 *    otherwise set it to @c NULL;
 * -# Call @b setsockopt(@p iut_s, @p level, @p opt_name,
 *                       @p opt_val, @p opt_len);
 * -# If @p opt_len is not zero, suggest that the @p opt_len is short and,
 *    check that the function returns @c -1 and sets @b errno to @c EINVAL;
 * -# If @p opt_len is not zero, check that the function returns @c -1 and 
 *    sets @b errno to @c EFAULT;
 * -# If @p opt_len is zero, check that the function returns @c -1 and 
 *    sets @b errno to @c EINVAL;
 * -# Close @p iut_s socket.
 *
 * @note
 *     Some options does not support SET operation, so that this test
 *     should not be used for such options.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME              "bnbvalue/func_setsockopt"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;
    rpc_socket_type    type;
    rpc_socklevel      level;
    rpc_sockopt        opt_name;
    te_bool            opt_buffer;
    int                opt_val_buf[10] = { 0, };
    int               *opt_val = opt_val_buf;
    int                opt_len;
    rpc_socket_domain  domain;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(type);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_BOOL_PARAM(opt_buffer);
    TEST_GET_INT_PARAM(opt_len);
    TEST_GET_DOMAIN(domain);

    level = rpc_sockopt2level(opt_name);

    if (!opt_buffer)
    {
        opt_val = NULL;
    }

    iut_s = rpc_socket(pco_iut, domain, type, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_gen(pco_iut, iut_s, level, opt_name, NULL,
                            opt_val, opt_len,
                            opt_val == NULL ? 0 : sizeof(opt_val_buf));
    if (rc != -1)
    {
        ERROR("setsockopt(..., %s, %s, %x, %d) returns %d instead of -1",
              socklevel_rpc2str(level), sockopt_rpc2str(opt_name),
              opt_val, opt_len, rc);
        TEST_VERDICT("setsockopt() with level %s optname %s "
                     "and optlen %d returns %d instead of -1",
                     socklevel_rpc2str(level),
                     sockopt_rpc2str(opt_name),
                     opt_len, rc);
    }
    
    if ((RPC_ERRNO(pco_iut) == RPC_ENOPROTOOPT))
    {
        TEST_VERDICT("%s option is unknown at level %s, setsockopt() failed,"
                     " errno=%s",
                     sockopt_rpc2str(opt_name), socklevel_rpc2str(level),
                     errno_rpc2str(RPC_ENOPROTOOPT));
    }

    if (opt_buffer && (opt_len != 0))
    {
        /* Suppose, opt_len should be too short for the option */
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "setsockopt(%s, %s, %d) "
                        "returns -1, but",
                        sockopt_rpc2str(opt_name), 
                        opt_val == NULL ? "(nil)" : "(not nil)",
                        opt_len);
    }
    else if (opt_len == 0 && opt_buffer)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL, "setsockopt(%s, %s, %d) "
                        "returns -1, but",
                        sockopt_rpc2str(opt_name), 
                        opt_val == NULL ? "(nil)" : "(not nil)",
                        opt_len);
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT, "setsockopt(%s, %s, %d) "
                        "returns -1, but",
                        sockopt_rpc2str(opt_name), 
                        opt_val == NULL ? "(nil)" : "(not nil)",
                        opt_len);
    }
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
