/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-func_sockopt_boolean Checking for boolean socket options setting
 *
 * @objective Check that any boolean socket option can be processed correctly
 *            when a variable different integer type is used for passing option
 *            value.
 *
 * @type conformance
 *
 * @param domain        Domain used for the test (@c PF_INET, or smth.) 
 * @param pco_iut       PCO on IUT
 * @param optname       Option to be tested
 * @param optlevel      Level where option can be used
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param exp_errno     If it's set to expected errno then
 *                      second part of the test is admitted
 *
 * @par Test sequence:
 * -# Create a socket @p iut_s with @p sock_type type on @p pco_iut;
 * -# Check a possibility to retrieve default value of @p optname
 *    socket option by means of @b getsockopt();
 * -# Check a possibility to turn @p optname socket option off
 *    by means of @b setsockopt();
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Carry out the following checks if @p exp_errno does not
 *    set to some error code;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Enable socket option using integer value equal to 1. Get applied
 *    value using @b getsockopt(). Retrived value should always be
 *    returned when @e enabled state is expected. @c 0 option value
 *    corresponds to @e disabled state.
 * -# Sequentially call @b setsockopt() and @b getsockopt() for
 *    checking influence different integer value on result.
 *    The following should be used as a set value and as an expected
 *    retrieved one:
 *        - set to: -1, 0, 1, 256, (64K - 1), 64K, 0x100000000;
 *        - appropriate retrived value: enabled, disabled, enabled,
 *          enabled, enabled, enabled, enabled;
 * -# Close @p iut_s.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_sockopt_boolean"

#include "sockapi-test.h"

#define TST_OPTVAL_LEN  16

#define CHECK_GETSOCKOPT(_tmpl, _expect) \
    do {                                                          \
        memset(opt_val, _tmpl, TST_OPTVAL_LEN);                   \
        opt_len = TST_OPTVAL_LEN;                                 \
        opt_val[0] = 0xFF; opt_val[1] = 0xFF;                     \
        opt_val[2] = 0xFF; opt_val[3] = 0xFF;                     \
        RPC_AWAIT_IUT_ERROR(pco_iut);                             \
        rc = rpc_getsockopt_raw(pco_iut, iut_s, opt_name, opt_val,\
                           &opt_len);                             \
        if (rc != 0)                                                   \
        {                                                         \
            RING_VERDICT("getsockopt() return %s",                \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));      \
            break;                                                \
        }                                                         \
        if (opt_len != sizeof(int))                               \
            TEST_FAIL("Unexpected (%d) option length returned",   \
                       opt_len);                                  \
        rpc_raw2integer(pco_iut, opt_val, sizeof(int));           \
        if (*((int *)opt_val) != _expect)                         \
            TEST_FAIL("It's expected to get %d instead %d",       \
                      _expect, *((int *)opt_val));                \
        for (i = sizeof(int); i < TST_OPTVAL_LEN; i++)            \
        {                                                         \
            if (opt_val[i] != _tmpl)                              \
            {                                                     \
                WARN("getsockopt() affects more than "            \
                     "sizeof(int) bytes");                        \
                break;                                            \
            }                                                     \
        }                                                         \
    } while (0)

int
main(int argc, char *argv[])
{
    rpc_socket_type        sock_type;
    rcf_rpc_server        *pco_iut = NULL;

    int                    iut_s = -1;

    rpc_sockopt            opt_name;
    uint8_t                opt_val[TST_OPTVAL_LEN];
    int                    enabled;
    socklen_t              opt_len;
    socklen_t              cfg_opt_len;
    rpc_errno              exp_errno;

    rpc_socket_domain domain;
    int               i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ERRNO_PARAM(exp_errno);
    TEST_GET_INT_PARAM(opt_len);
    TEST_GET_DOMAIN(domain);

    cfg_opt_len = opt_len;

    /* Scenario */
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    /*
     * First part of test is carried out in any case.
     */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_len = cfg_opt_len;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt(pco_iut, iut_s, opt_name, opt_val);

    if (exp_errno != 0)
    {
        if (rc != -1)
            TEST_FAIL("getsockopt() returns %d instead -1", rc);
        CHECK_RPC_ERRNO(pco_iut, exp_errno,
                       "getsockopt() called with incorrect parameter, "
                       "returns -1, but");
    }
    else
    {
        if (rc == -1)
        {
            TEST_VERDICT("getsockopt(%s) for %s socket failed with "
                         "errno %s",
                         sockopt_rpc2str(opt_name),
                         socktype_rpc2str(sock_type),
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        RING("Default value for %s is %d",
             sockopt_rpc2str(opt_name), *opt_val);
    }

    /* Turn checked option OFF */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_len = cfg_opt_len;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);

    if (exp_errno != 0)
    {
        if (rc != -1)
            TEST_FAIL("setsockopt() returns %d instead -1", rc);
        CHECK_RPC_ERRNO(pco_iut, exp_errno,
                       "setsockopt() called with incorrect parameter, "
                       "returns -1, but");
    }
    else if (rc == -1)
    {
        TEST_VERDICT("setsockopt(%s) to zero value (length %d) for %s "
                     "socket failed with errno %s",
                     sockopt_rpc2str(opt_name), opt_len,
                     socktype_rpc2str(sock_type),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (exp_errno != 0)
        TEST_SUCCESS;

    /*
     * Second part of test is carried out for configurations
     * with successful expected results only.
     */
    *(int *)opt_val = 1;
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    rpc_getsockopt(pco_iut, iut_s, opt_name, &enabled);
    if (enabled != 1)
        RING_VERDICT("%s option value in enabled state is %d",
                     sockopt_rpc2str(opt_name), enabled);

    /* opt_val = -1 */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_len = cfg_opt_len;
    memset(opt_val, 0xFF, cfg_opt_len);
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc != 0)
    {
        RING_VERDICT("setsockopts(-1) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, enabled);

    /* opt_val = 0 */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_len = cfg_opt_len;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc != 0)
    {
        RING_VERDICT("setsockopts(0) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, 0);

    /* opt_val = 1 */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_val[0] = 0x1;
    opt_len = cfg_opt_len;
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc != 0)
    {
        RING_VERDICT("setsockopts(1) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, enabled);

    /* opt_val = 256 */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_val[1] = 0x1;
    opt_len = cfg_opt_len;
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc != 0)
    {
        RING_VERDICT("setsockopts(256) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, enabled);

    /* opt_val = 64K-1 */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_val[0] = opt_val[1] = 0xFF;
    opt_len = cfg_opt_len;
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc !=0 )
    {
        RING_VERDICT("setsockopts(64K-1) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, enabled);

    /* opt_val = 64K */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_val[2] = 1;
    opt_len = cfg_opt_len;
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc != 0)
    {
        RING_VERDICT("setsockopts(64K) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, enabled);

    /* opt_val = 0x100000000 */
    memset(opt_val, 0, TST_OPTVAL_LEN);
    opt_val[4] = 0x1;
    opt_len = cfg_opt_len;
    rpc_integer2raw(pco_iut, *(int *)opt_val, opt_val, sizeof(int));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, opt_name, opt_val, opt_len);
    if (rc != 0)
    {
        RING_VERDICT("setsockopts(0x100000000) return %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    CHECK_GETSOCKOPT(0xFF, 0);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
