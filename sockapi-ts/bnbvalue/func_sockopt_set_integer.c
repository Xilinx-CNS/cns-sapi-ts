/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-func_sockopt_set_integer Checking for setting of integer socket options
 *
 * @objective Check that any integer socket option can be processed correctly
 *            when a variable of different integer type (byte, int32,
 *            or anything else) is used for passing to set option value.
 *
 * @type conformance
 *
 * @param domain        Domain used for the test (@c PF_INET, or smth.) 
 * @param pco_iut       PCO on IUT
 * @param optname       Option to be tested
 *                      (SO_PRIORITY, SO_RCVBUF, SO_RCVLOWAT, SO_SNDBUF,
 *                       SO_TYPE, IP_MULTICAST_TTL, IP_TOS, IP_TTL,
 *                       IP_MTU_DISCOVER, IPV6_MULTICAST_HOPS,
 *                       IPV6_UNICAST_HOPS, TCP_MAXSEG, TCP_KEEPIDLE,
 *                       TCP_KEEPINTVL, TCP_KEEPCNT, TCP_DEFER_ACCEPT)
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param opt_val       Value of Option (may be -1, 0, in range, out of range)
 * @param opt_len       Option Length (1,2,3,4,5,8,9)
 *
 * @par Test sequence:
 * -# Map @p opt_name to socket @p optlevel via rpc_sockopt2level() routine;
 * -# Create a socket @p iut_s with @p sock_type type on @p pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Form the buffer @p opt_buf of size @p opt_len and fill it randomly.
 * -# If @p opt len < @c sizeof(int), put the type-casted to char
 *    @p opt_val value to the first byte of the buffer, else put @p opt_val
 *    value to the first 4 bytes of the buffer.
 * -# Call @b setsockopt() on @p optname option with @p opt_buf and @p opt_len
 * -# If exp_errno != 0, compare errno with exp_errno and success the test.
 * -# Call getsockopt() with optlen=sizeof(int) optlen and check that
 *    returned value is the same as @p opt_val.
 * -# Close @p iut_s.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_sockopt_set_integer"

#include "sockapi-test.h"

#define MAX_OPT_BUF_SIZE    32

void
fill_random_buf(u_char *buf, int len)
{
    int i;

    srand(time(NULL));
    for (i = 0; i < len; i++)
        buf[i] = rand() & 0xff;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    int                iut_s = -1;
    rpc_socket_type    sock_type;
    rpc_socklevel      opt_level;
    rpc_sockopt        opt_name;
    char               opt_buf[MAX_OPT_BUF_SIZE];
    int                opt_val;
    int                opt_len;
    int                cmp_opt_val = 0;
    int                cmp_opt_len;
    rpc_socket_domain  domain;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_INT_PARAM(opt_val);
    TEST_GET_INT_PARAM(opt_len);
    TEST_GET_DOMAIN(domain);

    opt_level = rpc_sockopt2level(opt_name);

    fill_random_buf((u_char *)opt_buf, MAX_OPT_BUF_SIZE);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    if ((socklen_t)opt_len < sizeof(int))
    {
        if (opt_val > 128)
        {
            ERROR("Using invalid parameters. opt_val=%d "
                  "does not fit to char", opt_val);
            TEST_FAIL("Option value does not fit to char");
        }
        opt_buf[0] = (char)opt_val;
        rpc_integer2raw(pco_iut, *(char *)opt_buf, (uint8_t *)opt_buf,
                        sizeof(char));
    }
    else
    {
        memcpy(opt_buf, &opt_val, sizeof(int));
        rpc_integer2raw(pco_iut, *(int *)opt_buf, (uint8_t *)opt_buf,
                        sizeof(int));
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_gen(pco_iut, iut_s, opt_level, opt_name, NULL,
                            opt_buf, (socklen_t)opt_len, MAX_OPT_BUF_SIZE);
    if (rc != 0)
    {
        TEST_VERDICT("setsockopt() failed with errno=%s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    /*
     * SO_SNDBUFFORCE/SO_RCVBUFFORCE can only be used with
     * setsockopt().
     */
    opt_name = sockts_fix_get_opt(opt_name);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    cmp_opt_len = sizeof(cmp_opt_val);
    rc = rpc_getsockopt_gen(pco_iut, iut_s, opt_level, opt_name,
                            NULL, &cmp_opt_val,
                            (socklen_t *)&cmp_opt_len,
                            (socklen_t)sizeof(cmp_opt_val));

    if (rc != 0)
    {
        TEST_VERDICT("getsockopt() failed with errno=%s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    rpc_raw2integer(pco_iut, (uint8_t *)&cmp_opt_val, cmp_opt_len);
    
    if ((cmp_opt_val != opt_val) &&
        !((opt_len < (int)sizeof(int)) &&
          ((char)cmp_opt_val == opt_buf[0])))
    {
        ERROR("getsockopt(optname=%s) returns opt_val=%d instead of "
              "%d set by setsockopt()", sockopt_rpc2str(opt_name),
              cmp_opt_val, opt_val);
        TEST_VERDICT("getsockopt() returns different option value "
                     "than was set by setsockopt()");
    }
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
