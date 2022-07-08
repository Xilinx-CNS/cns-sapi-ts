/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-func_sockopt_get_integer Checking for getting of integer socket options
 *
 * @objective Check that any integer socket option can be processed correctly
 *            when a variable of different integer type (byte, int32,
 *            or anything else) is used for passing to get option value.
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
 * @param opt_val       Value of Option (must fit in range)
 * @param opt_len       Option Length (1,2,3,4,5,8,4K)
 * @param exp_opt_val   Expected option value from getsockopt()
 * @param exp_errno     Expected ERRNO
 *
 * @par Test sequence:
 * -# Map @p opt_name to socket @p optlevel via rpc_sockopt2level() routine;
 * -# Create a socket @p iut_s with @p sock_type type on @p pco_iut;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p optname option with @p opt_val
 *    and @p len = @c sizeof(int);
 * -# Form the buffer @p opt_buf of size @p opt_len
 * -# Fill the buffer by random values.
 * -# Call getsockopt() with the @p opt_buf and @p opt_len.
 * -# If exp_errno != 0, compare errno with exp_errno and success the test.
 * -# If @p opt_len < @c sizeof(int) then check that
 *   - the first byte of @p opt_buf contains the same value as @p exp_opt_val,
 *   - the rest part of the @p opt_buf hasn't been changed by getsockopt(),
 *   - getsockopt() call changed @p opt_len parameter to sizeof(char).
 * -# Else (If @p opt_len >= @c sizeof(int)) check that
 *   - the first 4 bytes of @p opt_buf contain the same integer value
 *     as @p exp_opt_val,
 *   - the rest part of the @p opt_buf hasn't been changed by getsockopt(),
 *   - getsockopt() call changed @p opt_len parameter to sizeof(int).
 * -# Close @p iut_s.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_sockopt_get_integer"

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
    char               orig_opt_buf[MAX_OPT_BUF_SIZE];
    int                opt_len;
    int                orig_opt_len;
    int                cmp_opt_val = 0;
    socklen_t          cmp_opt_len;
    rpc_socket_domain  domain;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_INT_PARAM(opt_len);
    TEST_GET_DOMAIN(domain);

    opt_level = rpc_sockopt2level(opt_name);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    /* Try to get sockopt value with integer option value (always should work) */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    cmp_opt_len = sizeof(cmp_opt_val);
    rc = rpc_getsockopt_gen(pco_iut, iut_s, opt_level, opt_name,
                            NULL, &cmp_opt_val,
                            &cmp_opt_len,
                            (socklen_t)sizeof(cmp_opt_val));
    if (rc != 0)
    {
        if (RPC_ERRNO(pco_iut) == RPC_ENOPROTOOPT)
        {
            TEST_VERDICT("getsockopt(opt_name=%s) is unsupported",
                         sockopt_rpc2str(opt_name));
        }
        TEST_VERDICT("first getsockopt(opt_name=%s) failed with rc=%d, errno=%s",
                     sockopt_rpc2str(opt_name), rc,
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    rpc_raw2integer(pco_iut, (uint8_t *)&cmp_opt_val, cmp_opt_len);

    /* Handle the case when cmp_opt_val is reduced to sizeof(char) */
    if (cmp_opt_len < sizeof(cmp_opt_val))
        cmp_opt_val = *(u_char *)(&cmp_opt_val);

    RING("getsockopt(opt_name=%s) returns opt_val=%d",
         sockopt_rpc2str(opt_name), cmp_opt_val);

    /*
     * Fill the opt_buf buffer with random values and 
     * make the copy for comparison
     */
    fill_random_buf((u_char *)opt_buf, MAX_OPT_BUF_SIZE);
    memcpy(orig_opt_buf, opt_buf, MAX_OPT_BUF_SIZE);

    orig_opt_len = opt_len;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt_gen(pco_iut, iut_s, opt_level, opt_name, NULL,
                            opt_buf, (socklen_t *)&opt_len,
                            MAX_OPT_BUF_SIZE);

    if (memcmp(&orig_opt_buf[orig_opt_len], &opt_buf[orig_opt_len],
        MAX_OPT_BUF_SIZE - orig_opt_len) != 0)
    {
        ERROR_VERDICT("getsockopt() has corrupted unallocated memory");
    }

    rpc_raw2integer(pco_iut, (uint8_t *)opt_buf, opt_len);

    if (orig_opt_len != opt_len)
    {
        if (orig_opt_len > opt_len)
        {
            if (opt_len == sizeof(char))
            {
                RING_VERDICT("getsockopt(opt_name=%s) has reduced opt_len "
                             "to sizeof(char)", sockopt_rpc2str(opt_name));
            }
            else if (opt_len == sizeof(int))
            {
                RING_VERDICT("getsockopt(opt_name=%s) has reduced opt_len "
                             "to sizeof(int)", sockopt_rpc2str(opt_name));
            }
            else
            {
                RING_VERDICT("getsockopt(opt_name=%s) has reduced opt_len "
                             "to %d bytes", sockopt_rpc2str(opt_name),
                             opt_len);
            }
        }
        else
        {
            if (opt_len == sizeof(char))
            {
                RING_VERDICT("getsockopt(opt_name=%s) has increased opt_len "
                             "to sizeof(char)", sockopt_rpc2str(opt_name));
            }
            else if (opt_len == sizeof(int))
            {
                RING_VERDICT("getsockopt(opt_name=%s) has increased opt_len "
                             "to sizeof(int)", sockopt_rpc2str(opt_name));
            }
            else
            {
                RING_VERDICT("getsockopt(opt_name=%s) has increased opt_len "
                             "to %d bytes", sockopt_rpc2str(opt_name),
                             opt_len);
            }
        }
    }

    if (rc != 0)
    {
        TEST_VERDICT("getsockopt(opt_name=%s, opt_len=%d) "
                     "failed with rc=%d, errno=%s",
                     sockopt_rpc2str(opt_name), orig_opt_len, rc,
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    if (opt_len <= 0)
    {
        TEST_VERDICT("getsockopt() has not returned any option value");
    }

    if ((socklen_t)opt_len < sizeof(int))
    {
        /* Compare (char) opt_val */
        char opt_val_char = *(char *)opt_buf;

        if (memcmp(&cmp_opt_val, opt_buf, opt_len) != 0)
        {
            ERROR("getsockopt(opt_name=%s, opt_len=%d) "
                  "returned (char) opt_val=%d instead of %d",
                  sockopt_rpc2str(opt_name), orig_opt_len,
                  (int)opt_val_char, cmp_opt_val);

            if ((char)cmp_opt_val != cmp_opt_val)
            {
                TEST_VERDICT("Using opt_len < sizeof(int) affects the result"
                             " of opt_val returned by getsockopt()");
            }
            else
            {
                TEST_VERDICT("opt_val returned by the second getsockopt() "
                             "call is not equal to opt_val returned by the "
                             "first call");
            }
        }
    }
    else
    {
        /* Compare (int) opt_val */
        int opt_val_int = *(int *)opt_buf;

        if (opt_val_int != cmp_opt_val)
        {
            ERROR("getsockopt(opt_name=%s, opt_len=%d) "
                  "returned (char) opt_val=%d instead of %d",
                  sockopt_rpc2str(opt_name), orig_opt_len,
                  opt_val_int, cmp_opt_val);

            if (opt_len > orig_opt_len)
            {
                TEST_VERDICT("Using opt_len < sizeof(int) affects the result"
                             " of opt_val returned by getsockopt()");
            }
            else
            {
                TEST_VERDICT("opt_val returned by the second getsockopt() "
                             "call is not equal to opt_val returned by the "
                             "first call");
            }
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
