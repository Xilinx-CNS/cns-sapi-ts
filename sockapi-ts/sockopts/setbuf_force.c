/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-setbuf_force Usage of SO_SNDBUFFORCE/SO_RCVBUFFORCE options
 *
 * @objective Check that SO_SNDBUFFORCE/SO_RCVBUFFORCE options can be
 *            used to set socket buffer sizes to values higher than
 *            those defined by wmem_max/rmem_max.
 *
 * @type conformance
 *
 * @param domain        Socket domain.
 * @param sock_type     Socket type.
 * @param opt_name      Option to test
 *                      - @c SO_SNDBUFFORCE
 *                      - @c SO_RCVBUFFORCE
 *
 * @reference MAN 7 socket
 *
 * @par Test sequence:
 *
 */

#define TE_TEST_NAME  "sockopts/setbuf_force"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rpc_socket_type     sock_type;
    rpc_socket_domain   domain;
    int                 iut_s = -1;
    rpc_sockopt         opt_name;
    rpc_sockopt         opt_base;
    int                 buf_max;
    int                 buf_max_d;
    int                 set_val;
    int                 got_val;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_DOMAIN(domain);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_SOCKOPT(opt_name);

    TEST_STEP("Set @b buf_max to value from wmem_max (for @c SO_SNDBUFFORCE) "
              "or rmem_max (for @c SO_RCVBUFFORCE). Let @b opt_base be "
              "@c SO_SNDBUF if @p opt_name is @c SO_SNDBUFFORCE, or "
              "@c SO_RCVBUF if @p opt_name is @c SO_RCVBUFFORCE.");

    switch (opt_name)
    {
        case RPC_SO_SNDBUFFORCE:
            opt_base = RPC_SO_SNDBUF;
            CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &buf_max,
                                             "net/core/wmem_max"));
            break;

        case RPC_SO_RCVBUFFORCE:
            opt_base = RPC_SO_RCVBUF;
            CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &buf_max,
                                             "net/core/rmem_max"));
            break;

        default:
            TEST_FAIL("Unknown opt_name value");
    }

    /*
     * setsockopt() on Linux sets SO_SNDBUF/SO_RCVBUF to two times
     * the value passed to it, so that actual limit is @b buf_max * 2.
     */
    buf_max_d = buf_max * 2;
    RING("System maximum for %s is %d * 2 = %d",
         sockopt_rpc2str(opt_base), buf_max, buf_max_d);

    TEST_STEP("Create a socket on IUT according to @p domain and @p sock_type.");

    iut_s = rpc_socket(pco_iut, sockts_domain2family(domain),
                       sock_type, RPC_PROTO_DEF);

    set_val = buf_max + 1;

    TEST_STEP("Call setsockopt() to set @b opt_base to @b buf_max + 1.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, opt_base, set_val);
    if (rc < 0)
        TEST_VERDICT("setsockopt(%s) unexpectedly failed with errno %r",
                     sockopt_rpc2str(opt_base), RPC_ERRNO(pco_iut));

    TEST_STEP("Check that getsockopt(@b opt_base) returns value no larger than "
              "@b buf_max * 2.");

    rpc_getsockopt(pco_iut, iut_s, opt_base, &got_val);
    if (got_val > buf_max_d)
        ERROR_VERDICT("setsockopt(%s) allowed to set value bigger "
                      "than system maximum", sockopt_rpc2str(opt_base));

    TEST_STEP("Call setsockopt() to set @p opt_name to @b buf_max + 1.");
    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, opt_name, set_val);
    if (rc < 0)
        TEST_VERDICT("setsockopt(%s) unexpectedly failed with errno %r",
                     sockopt_rpc2str(opt_name), RPC_ERRNO(pco_iut));

    TEST_STEP("Check that now getsockopt(@b opt_base) returns value larger "
              "than @b buf_max * 2.");
    rpc_getsockopt(pco_iut, iut_s, opt_base, &got_val);
    if (got_val <= buf_max_d)
        TEST_VERDICT("setsockopt(%s) did not allow to set value bigger "
                     "than system maximum", sockopt_rpc2str(opt_name));

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
