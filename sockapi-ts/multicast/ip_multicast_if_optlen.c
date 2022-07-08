/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-ip_multicast_if_optlen Test IP_MULTICAST_IF socket option with different optlen values
 *
 * @objective Check that IP_MULTICAST_IF socket option accepts and correctly
 *            proceeds arguments of different lengths.
 * 
 * @type Conformance.
 *
 * @param pco_iut           PCO on IUT
 * @param iut_addr          IUT address
 * @param iut_if            Interface on IUT
 * @param optlen            Length ot the option argument
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 * -# Open datagram socket @p iut_s on @p pco_iut.
 * -# Call @b getsockopt() with optlen = @c sizeof(@c struct @c in_addr)
 *    and check the returned value.
 * -# Call @b getsockopt() for @c IP_MULTICAST_IF option with buffer
 *    of the same length as used in next @b setsockopt(). Check
 *    length returned by the function and, if length is greater than
 *    @c sizeof(@c struct @c in_addr) returned local (interface)
 *    IP address.
 * -# Call @b setsockopt() for @c IP_MULTICAST_IF option:
 *     -# If @p optlen is @c null-zero, @a option_value is @c NULL and
 *        @a option_len is @c 0;
 *     -# If @p optlen is @c zero, @a option_value is not @c NULL and
 *        @a option_len is @c 0;
 *     -# If @p optlen is @c zero-in_addr, @a option_value is a pointer
 *        to @c struct @c in_addr structure with @p iut_addr and
 *        @a option_len is greater than zero and less than
 *        @c sizeof(@c struct @c in_addr);
 *     -# If @p optlen is @c in_addr, @a option_value is a pointer
 *        to @c struct @c in_addr structure with @p iut_addr and
 *        @a option_len is equal to @c sizeof(@c struct @c in_addr);
 *     -# If @p optlen is @c in_addr-ip_mreqn, @a option_value is a pointer
 *        to @c struct @c ip_mreqn structure with @p iut_addr as
 *        interface address and @c INADDR_ANY as multicast address and
 *        @a option_len is greater than @c sizeof(@c struct @c in_addr) and
 *        less than @c sizeof(@c struct @c ip_mreqn);
 *     -# If @p optlen is @c ip_mreqn, @a option_value is a pointer
 *        to @c struct @c ip_mreqn structure with @p iut_addr as
 *        interface address, @c INADDR_ANY as multicast address and
 *        @p iut_if interface index, @a option_len is equal to
 *        @c sizeof(@c struct @c ip_mreqn);
 *     -# If @p optlen is @c ip_mreqn-, @a option_value is a pointer
 *        to @c struct @c ip_mreqn structure with @p iut_addr as
 *        interface address, @c INADDR_ANY as multicast address and
 *        @p iut_if interface index, @a option_len is greater than
 *        @c sizeof(@c struct @c ip_mreqn);
 *     .
 *     Check that function returns @c 0.
 * -# Call @b getsockopt() with optlen = @c sizeof(@c struct @c in_addr)
 *    and check the returned value.
 * -# Close @p iut_s.
 *                 
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME "multicast/ip_multicast_if_optlen"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    const struct sockaddr     *iut_addr = NULL;
    int                        iut_s = -1;
    const char                *optlen;
    socklen_t                  real_optlen;
    const struct if_nameindex *iut_if = NULL;
    struct tarpc_mreqn         param;
    enum option_type           opttype;
    void                      *optval = NULL;
    void                      *raw_optval = NULL;
    void                      *good_raw_optval = NULL;
    socklen_t                  raw_optlen;
    socklen_t                  raw_roptlen;
    te_bool                    exact_len = FALSE;
    te_bool                    short_optlen = FALSE;
    const char                *descr = NULL;
    struct in_addr             addr;

    sockts_socket_func  sock_func;
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_STRING_PARAM(optlen);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    iut_s = sockts_socket(sock_func, pco_iut,
                          RPC_PF_INET, RPC_SOCK_DGRAM,
                          RPC_IPPROTO_UDP);

    /* Get the default option value */
    raw_roptlen = rpc_get_sizeof(pco_iut, "struct ip_mreqn");
    real_optlen = raw_roptlen;
    memset(&param, 0, sizeof(param));
    param.type = OPT_MREQN;
    optval = &param;
    good_raw_optval = te_make_buf_by_len(raw_roptlen);
    rpc_getsockopt_gen(pco_iut, iut_s, RPC_SOL_IP, RPC_IP_MULTICAST_IF,
                       optval, good_raw_optval, &real_optlen, raw_roptlen);

    memset(&addr, 0, sizeof(addr));
    if (memcmp(&param.address, &addr, sizeof(addr)) ||
        (param.type == OPT_MREQN && param.ifindex != -1))
    {
        WARN_VERDICT("Unexpected default value for IP_MULTICAST_IF");
    }

    /* Prepare for getsockopt */
    memset(&param, 0, sizeof(param));
    if (strcmp(optlen, "null-zero") == 0)
    {
        optval = NULL;
        raw_optlen = raw_roptlen = 0;
        raw_optval = NULL;
        exact_len = TRUE;
        short_optlen = TRUE;
        descr = "NULL option value pointer and zero option length";
    }
    else if (strcmp(optlen, "zero") == 0)
    {
        optval = NULL;
        raw_roptlen = rpc_get_sizeof(pco_iut, "struct in_addr");
        raw_optlen = 0;
        raw_optval = te_make_buf_by_len(raw_roptlen);
        exact_len = TRUE;
        short_optlen = TRUE;
        descr = "not-NULL option value pointer and zero option length";
    }
    else if (strcmp(optlen, "zero-in_addr") == 0)
    {
        optval = NULL;
        raw_roptlen = rpc_get_sizeof(pco_iut, "struct in_addr");
        raw_optlen = rand_range(1, raw_roptlen - 1);
        raw_optval = te_make_buf_by_len(raw_roptlen);
        short_optlen = TRUE;
        descr = "option length greater than zero and less than "
                "sizeof(struct in_addr)";
    }
    else if (strcmp(optlen, "in_addr") == 0)
    {
        param.type = OPT_IPADDR;
        optval = &param;
        raw_optlen = raw_roptlen = 0;
        raw_optval = NULL;
        exact_len = TRUE;
        descr = "option length equal to sizeof(struct in_addr)";
    }
    else if (strcmp(optlen, "in_addr-ip_mreq") == 0)
    {
        param.type = OPT_IPADDR;
        optval = &param;
        raw_roptlen = rpc_get_sizeof(pco_iut, "struct ip_mreq") -
                      rpc_get_sizeof(pco_iut, "struct in_addr");
        raw_optlen = rand_range(1, raw_roptlen - 1);
        raw_optval = te_make_buf_by_len(raw_roptlen);
        descr = "option length greater than sizeof(struct in_addr) and "
                "less than sizeof(struct ip_mreq)";
    }
    else if (strcmp(optlen, "ip_mreq-ip_mreqn") == 0)
    {
        param.type = OPT_MREQ;
        optval = &param;
        raw_roptlen = rpc_get_sizeof(pco_iut, "struct ip_mreqn") -
                      rpc_get_sizeof(pco_iut, "struct ip_mreq");
        raw_optlen = rand_range(1, raw_roptlen - 1);
        raw_optval = te_make_buf_by_len(raw_roptlen);
        descr = "option length greater than sizeof(struct ip_mreq) and "
                "less than sizeof(struct ip_mreqn)";
    }
    else if (strcmp(optlen, "ip_mreqn") == 0)
    {
        param.type = OPT_MREQN;
        optval = &param;
        raw_optlen = raw_roptlen = 0;
        raw_optval = NULL;
        exact_len = TRUE;
        descr = "option length equal to sizeof(struct ip_mreqn)";
    }
    else if (strcmp(optlen, "ip_mreqn-") == 0)
    {
        param.type = OPT_MREQN;
        optval = &param;
        raw_optlen = raw_roptlen = rand_range(1, 10);
        raw_optval = te_make_buf_by_len(raw_roptlen);
        descr = "option length greater than sizeof(struct ip_mreqn)";
    }
    else
    {
        TEST_FAIL("Unsupported 'optlen' parameter '%s'", optlen);
    }

    /* Getsockopt with specified optlen */
    real_optlen = raw_optlen;
    rc = rpc_getsockopt_gen(pco_iut, iut_s, RPC_SOL_IP, RPC_IP_MULTICAST_IF,
                            optval, raw_optval, &real_optlen, raw_roptlen);
   
    if (rc != 0)
    {
        TEST_VERDICT("getsockopt(IP_MULTICAST_IF) with %s failed "
                     "with errno %s", descr,
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    memset(&addr, 0, sizeof(addr));
    if ((strcmp(optlen, "null-zero") == 0) ||
        (strcmp(optlen, "zero") == 0) ||
        (strcmp(optlen, "zero-in_addr") == 0))
    {
        if (real_optlen != raw_optlen)
            TEST_VERDICT("Unexpected option length %d is returned",
                         real_optlen);
        if (memcmp(&addr, raw_optval, real_optlen) != 0)
            TEST_VERDICT("Unexpected value returned by "
                         "getsockopt(IP_MULTICAST_IF) with too short "
                         "option buffer length");
    }
    else if ((strcmp(optlen, "in_addr") == 0) ||
             (strcmp(optlen, "in_addr-ip_mreq") == 0) ||
             (strcmp(optlen, "ip_mreq-ip_mreqn") == 0))
    {
        if (strcmp(optlen, "ip_mreq-ip_mreqn") == 0)
        {
            if (param.type == OPT_IPADDR)
                WARN_VERDICT("getsockopt(IP_MULTICAST_IF) with sufficient "
                             "space for 'struct ip_mreq' returns "
                             "'struct in_addr'");
            else if (param.type != OPT_MREQ)
                TEST_VERDICT("Unexpected type %d of returned "
                             "IP_MULTICAST_IF option value for"
                             " 'struct ip_mreq'", param.type);
        }
        else if (param.type != OPT_IPADDR)
            TEST_VERDICT("Unexpected type %d of returned IP_MULTICAST_IF "
                         "option value", param.type);
        if (real_optlen != raw_optlen)
            TEST_VERDICT("Unexpected option length %d is returned",
                         real_optlen);
        if (memcmp(&param.address, &addr, sizeof(addr)) != 0)
            TEST_VERDICT("Obtained option value is not INADDR_ANY");
    }
    else if ((strcmp(optlen, "ip_mreqn") == 0) ||
             (strcmp(optlen, "ip_mreqn-") == 0))
    {
        if (param.type == OPT_MREQN)
        {
            /* Exactly as set */
            if (param.ifindex != -1)
            {
                TEST_VERDICT("getsockopt(IP_MULTICAST_IF) has returned "
                             "unexpected interface index");
            }
        }
        else if (param.type == OPT_IPADDR)
        {
            WARN_VERDICT("getsockopt(IP_MULTICAST_IF) with sufficient "
                         "space for 'struct ip_mreqn' returns "
                         "'struct in_addr'");
        }
        else
        {
            TEST_VERDICT("Unexpected type %d of returned IP_MULTICAST_IF "
                         "option value", param.type);
        }
        if (real_optlen != raw_optlen)
            TEST_VERDICT("Unexpected option length is returned");
        if (memcmp(&param.address, &addr, sizeof(addr)) != 0)
            TEST_VERDICT("Obtained option value is not INADDR_ANY");
    }
    else
    {
        assert(FALSE);
    }

    /* Setsockopt with specified optlen */
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(optlen, "in_addr") == 0 ||
        strcmp(optlen, "in_addr-ip_mreq") == 0)
        param.type = OPT_IPADDR;
    if (strcmp(optlen, "ip_mreq-ip_mreqn") == 0)
        param.type = OPT_MREQ;
    if (strcmp(optlen, "ip_mreqn") == 0 ||
             strcmp(optlen, "ip_mreqn-") == 0)
        param.type = OPT_MREQN;

    opttype = param.type;
    memset(&param, 0, sizeof(param));
    param.type = opttype;
    memcpy(&addr, &SIN(iut_addr)->sin_addr, sizeof(addr));
    memcpy(&param.address, &addr, sizeof(addr));
    param.ifindex = iut_if->if_index;
    te_fill_buf(raw_optval, raw_roptlen);
    WARN("raw_optlen=%d", raw_optlen);

    rc = rpc_setsockopt_gen(pco_iut, iut_s, RPC_SOL_IP, RPC_IP_MULTICAST_IF,
                            optval, raw_optval, raw_optlen, raw_roptlen);

    /* For short_optlen we accept both -1(EINVAL) and 0, because both
     * are sensible. */
    if (rc != 0 && !(short_optlen && RPC_ERRNO(pco_iut) == RPC_EINVAL))
    {
        if (exact_len)
        {
            TEST_VERDICT("setsockopt(IP_MULTICAST_IF) with %s failed "
                         "with errno %s", descr,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        else
        {
            WARN_VERDICT("setsockopt(IP_MULTICAST_IF) with %s failed "
                         "with errno %s", descr,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }
    if (short_optlen || rc != 0)
        memset(&addr, 0, sizeof(addr));

    raw_roptlen = rpc_get_sizeof(pco_iut, "struct in_addr");
    real_optlen = raw_roptlen;
    memset(&param, 0, sizeof(param));
    param.type = OPT_IPADDR;
    optval = &param;
    te_fill_buf(good_raw_optval, raw_roptlen);
    rpc_getsockopt_gen(pco_iut, iut_s, RPC_SOL_IP, RPC_IP_MULTICAST_IF,
                       optval, good_raw_optval, &real_optlen, raw_roptlen);

    if (param.type != OPT_IPADDR || 
        memcmp(&param.address, &addr, sizeof(addr)) != 0)
    {
        TEST_VERDICT("Obtained option value does not match set one");
    }

    TEST_SUCCESS;

cleanup:    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(raw_optval);
    free(good_raw_optval);

    TEST_END;
}
