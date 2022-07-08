/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_sockopt_level_name Usage of getsockopt() and setsockopt() functions with unknown level and option name
 *
 * @objective Check that @b getsockopt() and @b setsockopt() functions 
 *            correctly handle passing unknown @a level parameter and 
 *            unsupported option name;
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param domain        Domain used for the test (@c PF_INET, or smth.)
 * @param type          Type of socket used in the test
 * @param func          Function used in the test (@b getsockopt(), or 
 *                      @b setsockopt())
 * @param level         Option level value used in the test
 * @param opt_name      Option name used in the test
 * @param exp_errno     Expected value of @b errno parameter
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @p type
 *    on @b pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b func (@p iut_s, @p level, @p opt_name, ...);
 * -# Check that the function returns @c -1 and sets @b errno to @p
 *    exp_errno;
 * @table_start
 * @row_start
 *     @entry_start @a level @entry_end
 *     @entry_start @a opt_name @entry_end
 *     @entry_start @b errno @entry_end
 * @row_end
 * @row_start
 *     @entry_start @p unknown_level @entry_end
 *     @entry_start @c SO_OOBINLINE @entry_end
 *     @entry_start @c EINVAL @entry_end
 * @row_end
 * @row_start
 *     @entry_start @c SOL_SOCKET @entry_end
 *     @entry_start @p unknown_opt_name @entry_end
 *     @entry_start @c ENOPROTOOPT @entry_end
 * @row_end
 * -# Close @p iut_s socket.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_sockopt_level_name"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;
    rpc_socket_type    type;
    const char        *func;
    rpc_socklevel      level;
    rpc_sockopt        opt_name;
    int                opt_val = 0;

    rpc_errno          exp_errno;
    te_bool            unknown_func = TRUE;
    
    rpc_socket_domain  domain;
 
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(type);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_SOCKLEVEL(level);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_DOMAIN(domain);
    
    TEST_GET_ERRNO_PARAM(exp_errno);
    
    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, type, RPC_PROTO_DEF);

#define CHECK_FUNCTION(func_name_, func_, params...) \
    do {                                                    \
        if (strcmp(func, #func_name_) == 0)                 \
        {                                                   \
            unknown_func = FALSE;                           \
            RPC_AWAIT_IUT_ERROR(pco_iut);                   \
            rc = rpc_ ## func_(pco_iut, params);            \
                                                            \
            if (rc != -1)                                   \
            {                                               \
                TEST_FAIL(# func_name_ "(%s, %s) "          \
                          "returns %d instead of -1",       \
                          socklevel_rpc2str(level),         \
                          sockopt_rpc2str(opt_name), rc);   \
            }                                               \
        }                                                   \
    } while (0)

    CHECK_FUNCTION(getsockopt, getsockopt_gen, iut_s, level, opt_name,
                   &opt_val, NULL, NULL, 0);
    CHECK_FUNCTION(setsockopt, setsockopt_gen, iut_s, level, opt_name,
                   &opt_val, NULL, 0, 0);

    if (unknown_func)
    {
        TEST_FAIL("Incorrect value of 'func' parameter. "
                  "Supported values are: { setsockopt, getsockopt }");
    }

    CHECK_RPC_ERRNO(pco_iut, exp_errno, "%s(%s, %s) returns -1, but",
                    func, socklevel_rpc2str(level), sockopt_rpc2str(opt_name));
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
