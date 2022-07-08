/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_getsockopt Inappropriate usage of getsockopt() function
 *
 * @objective Check the behaviour of @b getsockopt() function with
 *            different combinations of @a option_value and @a option_length
 *            parameters
 *
 * @type conformance, robustness
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param domain        Domain used for the test (@c PF_INET, or smth.)
 * @param type          Type of socket used in the test
 * @param opt_name      Option name used in the test
 * @param opt_buffer    @c FALSE if @c NULL or @c TRUE in case of the
 *                      real buffer passed as the value of @a option_value
 *                      parameter
 * @param len_buffer    @c FALSE if @c NULL or @c TRUE in case of the
 *                      real buffer passed as the value of @a option_length
 *                      parameter
 * @param opt_len_val   Value of @a option_length parameter
 * @param buf_rlen      Real length of buffer passed to @b getsockopt()
 *                      
 * @param pco_iut       PCO on IUT
 *
 * @par Scenario:
 * -# Create @p iut_s socket from @p domain domain of type @p type
 *    on @b pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Map @p opt_name to socket @p level via rpc_sockopt2level() routine;
 * -# If @p opt_buffer is TRUE, set @p opt_val to some real buffer,
 *    otherwise set it to @c NULL;
 * -# If @p len_buffer is FALSE, set @p opt_len to @c NULL, otherwise
 *    set it to the location of 'socklen_t' filled in with @p opt_len_len;
 * -# Call @b getsockopt(@p iut_s, @p level, @p opt_name,
 *                       @p opt_val, @p opt_len);
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Check return code and returned option length.
 *
 * @note
 *     Some options does not support SET operation, so that this test
 *     should not be used for such options.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_getsockopt"

#include "sockapi-test.h"

#define MAX_OPT_VAL_BUF 1024

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;
    rpc_socket_type    type;
    rpc_socklevel      level;
    rpc_sockopt        opt_name;
    te_bool            opt_buffer;
    te_bool            len_buffer;
    char               opt_val_buf[MAX_OPT_VAL_BUF] = { 0, };
    int               *opt_val = (int *)opt_val_buf;
    socklen_t          opt_len_val_orig = 0;
    socklen_t          opt_len_val = 0;
    socklen_t          buf_rlen = 0;
    socklen_t         *opt_len = NULL;

    rpc_socket_domain domain;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(type);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_BOOL_PARAM(opt_buffer);
    TEST_GET_BOOL_PARAM(len_buffer);
    TEST_GET_DOMAIN(domain);

    level = rpc_sockopt2level(opt_name);

    if (!opt_buffer)
    {
        opt_val = NULL;
    }

    if (len_buffer)
    {
        TEST_GET_INT_PARAM(opt_len_val);
        TEST_GET_INT_PARAM(buf_rlen);

        /* Remember original opt_len value */
        opt_len_val_orig = opt_len_val;

        opt_len = &opt_len_val;
    }
    else
        buf_rlen = sizeof(opt_val_buf);

    iut_s = rpc_socket(pco_iut, domain, type, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt_gen(pco_iut, iut_s, level, opt_name, NULL,
                            opt_val, opt_len,
                            (opt_val == NULL) ? 0 : buf_rlen);

    if ((rc != 0) && (RPC_ERRNO(pco_iut) == RPC_ENOPROTOOPT))
    {
        TEST_VERDICT("%s option is unknown at level %s, getsockopt() failed,"
                     " errno=%s",
                     sockopt_rpc2str(opt_name), socklevel_rpc2str(level),
                     errno_rpc2str(RPC_ENOPROTOOPT));
    }

    if (len_buffer && opt_buffer && (opt_len_val_orig != 0))
    {
        if (rc != 0)
        {
            if (RPC_ERRNO(pco_iut) == RPC_EINVAL)
            {
                RING_VERDICT("getsockopt(%s, %s) failed due to incorrect optlen "
                             "and returned %d, errno=%s",
                             socklevel_rpc2str(level), sockopt_rpc2str(opt_name),
                             rc, errno_rpc2str(RPC_EINVAL));
                TEST_SUCCESS;
            }
            else
            {
                TEST_VERDICT("getsockopt(%s, %s) failed and returned %d, errno=%s",
                             socklevel_rpc2str(level), sockopt_rpc2str(opt_name),
                             rc, errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }

        if (opt_len_val != opt_len_val_orig)
        {
            if (opt_len_val < opt_len_val_orig)
            {
                RING_VERDICT("getsockopt(%s) has reduced opt_len and "
                             "returned no error", sockopt_rpc2str(opt_name));
            }

            if (opt_len_val > opt_len_val_orig)
            {
                RING_VERDICT("getsockopt(%s) has increased opt_len and "
                             "returned no error", sockopt_rpc2str(opt_name));
            }
        }
        else
        {
            RING_VERDICT("getsockopt(%s) has not changed opt_len and "
                         "returned no error", sockopt_rpc2str(opt_name));
        }
        TEST_SUCCESS;
    }
    
    if (len_buffer && opt_len_val_orig == 0)
    {
        if (rc != 0)
        {
            TEST_VERDICT("getsockopt(%s) with zero option length value "
                         "failed with errno %s",
                         sockopt_rpc2str(opt_name),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }
    else if (opt_buffer || !len_buffer)
    {
        if (rc == 0)
            TEST_FAIL("option length value was changed unexpectedly");
        CHECK_RPC_ERRNO(pco_iut, RPC_EFAULT, "getsockopt(%s) with %s "
                        "option value buffer and %s length value buffer "
                        "returns -1, but", sockopt_rpc2str(opt_name),
                        opt_buffer ? "non-NULL" : "NULL",
                        len_buffer ? "non-NULL" : "NULL");
    }
 
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
