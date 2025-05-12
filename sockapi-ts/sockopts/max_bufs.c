/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-max_bufs Using of native system wide maximums for receive and send buffers
 *
 * @objective Check that values that can be set with socket options
 *            @c SO_RCVBUF and @c SO_SNDBUF are limited by the system
 *            wide maximums @b rmem_max and @b wmem_max.
 *
 * @type conformance
 *
 * @param env                 Testing environment:
 *                            - @ref arg_types_env_iut_ucast
 *                            - @ref arg_types_env_iut_ucast_ipv6
 * @param sock_type           Socket type:
 *                            - @c SOCK_DGRAM
 *                            - @c SOCK_STREAM
 * @param check_sndbuf        If @c TRUE, check @c SO_SNDBUF, else check
 *                            @c SO_RCVBUF
 * @param max_value_change    How to change system-wide maximum:
 *                            - @c none (do not change)
 *                            - @c increase
 *                            - @c decrease
 * @param small_tcp_bufs      If @c TRUE, decrease @c tcp_rmem[2] /
 *                            @c tcp_wmem[2] to be less than buffer size
 *
 * @par Test sequence:
 *
 * @note
 *      @b setsockopt() sets value of @c SO_SNDBUF or @c SO_RCVBUF
 *      to doubled option value passed to it, and system wide
 *      maximum buffer size values restrict values passed to
 *      @b setsockopt() (so values returned by @b getsockopt() can be
 *      twice as much as system wide maximum values).
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/max_bufs"

#include "sockapi-test.h"
#include "tapi_cfg.h"

/*
 * If it is requested to change maximum value, it is multiplied or
 * divided by this number.
 */
#define CHANGE_COEFF 1.5

/**< Possible values of "max_value_change" parameter */
typedef enum {
    MAX_CHANGE_NONE,        /**< No change */
    MAX_CHANGE_INCREASE,    /**< Increase the maximum */
    MAX_CHANGE_DECREASE     /**< Decrease the maximum */
} max_change_type;

/**
 * List of values of "max_value_change" parameter for
 * TEST_GET_ENUM_PARAM()
 */
#define MAX_CHANGE_TYPES \
    { "none", MAX_CHANGE_NONE },          \
    { "increase", MAX_CHANGE_INCREASE },  \
    { "decrease", MAX_CHANGE_DECREASE }

/**
 * Set socket buffer to the given value with setsockopt() and
 * retrieve it with getsockopt().
 *
 * @param rpcs        RPC server.
 * @param s           Socket FD.
 * @param opt         Socket option specifying the buffer:
 *                    - RPC_SO_SNDBUF
 *                    - RPC_SO_RCVBUF
 * @param set_val     Value to set.
 * @param got_val     Where to save obtained value.
 * @param err_msg     String to print in verdicts.
 * @param ...         Format arguments for "err_msg".
 */
static void
set_sock_buf(rcf_rpc_server *rpcs, int s, rpc_sockopt opt,
             int set_val, int *got_val, const char *err_msg, ...)
{
    int rc;
    te_string stage = TE_STRING_INIT_STATIC(1024);
    va_list ap;

    va_start(ap, err_msg);
    rc = te_string_append_va(&stage, err_msg, ap);
    va_end(ap);
    if (rc != 0)
        TEST_FAIL("%s(): failed to construct stage string", __FUNCTION__);

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_setsockopt_int(rpcs, s, opt, set_val);
    if (rc < 0)
    {
        TEST_VERDICT("%s: setsockopt() failed unexpectedly with "
                     "error %r", stage.ptr, RPC_ERRNO(rpcs));
    }

    rpc_getsockopt(rpcs, s, opt, got_val);
}

/**
 * Set socket buffer size to a given value, retrieve the resulting
 * value with getsockopt(), check that it is within the system-wide
 * maximum.
 *
 * @param rpcs        RPC server.
 * @param s           Socket FD.
 * @param opt         Socket option specifying the buffer:
 *                    - RPC_SO_SNDBUF
 *                    - RPC_SO_RCVBUF
 * @param set_val     Value to set.
 * @param max_val     System-wide maximum.
 * @param failed      Will be set to TRUE in case of failure.
 */
static void
set_check_buf(rcf_rpc_server *rpcs, int s, rpc_sockopt opt,
              int set_val, int max_val, te_bool *failed)
{
    int exp_val;
    int got_val;
    const char *set_descr;
    const char *got_descr;

    int fixed_set_val;
    int fixed_max_val;

    if (set_val < max_val)
        set_descr = "less than maximum";
    else if (set_val > max_val)
        set_descr = "more than maximum";
    else
        set_descr = "maximum";

    fixed_set_val = set_val * 2;
    fixed_max_val = max_val * 2;
    exp_val = MIN(fixed_set_val, fixed_max_val);

    set_sock_buf(rpcs, s, opt, set_val, &got_val,
                 "Setting the buffer size to %s", set_descr);

    if (got_val == set_val || got_val == max_val)
    {
        RING_VERDICT("When setting the buffer size to %s "
                     "value, retrieved value was not multiplied "
                     "by two", set_descr);
        exp_val /= 2;
        fixed_set_val /= 2;
        fixed_max_val /= 2;
    }

    if (got_val != exp_val)
    {
        ERROR("Expected value is %d, obtained value is %d",
              exp_val, got_val);

        if (got_val == fixed_set_val)
            got_descr = "the (fixed) set value";
        else if (got_val == fixed_max_val)
            got_descr = "the (fixed) maximum value";
        else
            got_descr = "an unanticipated value";

        ERROR_VERDICT("After setting the buffer size to %s "
                      "value, the returned size is unexpectedly set to %s",
                      set_descr, got_descr);
        *failed = TRUE;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const struct sockaddr *iut_addr = NULL;
    int iut_s = -1;

    rpc_socket_type sock_type;
    te_bool check_sndbuf;
    te_bool small_tcp_bufs;
    max_change_type max_value_change;

    const char *max_conf_path;
    int orig_buf_max;
    int buf_max;
    int new_buf_max;
    rpc_sockopt opt;
    int val;
    char *dyn_tcp_buf_max_conf_path;
    int dyn_tcp_buf_max;
    int orig_dyn_tcp_buf_max;
    int new_dyn_tcp_buf_max;

    te_bool test_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(check_sndbuf);
    TEST_GET_BOOL_PARAM(small_tcp_bufs);
    TEST_GET_ENUM_PARAM(max_value_change, MAX_CHANGE_TYPES);

    if (sock_type != RPC_SOCK_STREAM && small_tcp_bufs)
        TEST_SKIP("Small TCP buffers can be tested only for SOCK_STREAM");

    if (check_sndbuf)
    {
        max_conf_path = "net/core/wmem_max";
        opt = RPC_SO_SNDBUF;
        dyn_tcp_buf_max_conf_path = "net/ipv4/tcp_wmem:2";
    }
    else
    {
        max_conf_path = "net/core/rmem_max";
        opt = RPC_SO_RCVBUF;
        dyn_tcp_buf_max_conf_path = "net/ipv4/tcp_rmem:2";
    }

    TEST_STEP("Obtain the current value of system-wide maximum "
              "related to send (if @p check_sendbuf is @c TRUE) or "
              "to receive buffer size.");
    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &buf_max,
                                     max_conf_path));

    TEST_STEP("If required, change the system-wide maximum according "
              "to @p max_value_change.");
    if (max_value_change != MAX_CHANGE_NONE)
    {
        if (max_value_change == MAX_CHANGE_INCREASE)
            new_buf_max = buf_max * CHANGE_COEFF;
        else
            new_buf_max = buf_max / CHANGE_COEFF;

        RING("Changing %s from %d to %d", max_conf_path,
             buf_max, new_buf_max);
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, new_buf_max, NULL,
                                         max_conf_path));
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
        orig_buf_max = buf_max;
        buf_max = new_buf_max;
    }

    if (small_tcp_bufs)
    {
        /*
         * TCP tcp_wmem and tcp_rmem are used for dymanic TCP buffers
         * adjustment and do not limit SO_SNDBUF/SO_RCVBUF according to
         * Linux manual. Therefore we reduce these values to be less
         * than buf_max.
         */
        TEST_STEP("Obtain @p tcp_wmem[2] / @p tcp_rmem[2] to see if we need "
                  "to reduce it if it is greater than buffer max.");
        CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &dyn_tcp_buf_max,
                                         dyn_tcp_buf_max_conf_path));
        orig_dyn_tcp_buf_max = dyn_tcp_buf_max;
        if (buf_max <= dyn_tcp_buf_max)
        {
            new_dyn_tcp_buf_max = buf_max / 2;

            RING("Changing %s from %d to %d", dyn_tcp_buf_max_conf_path,
                 dyn_tcp_buf_max, new_dyn_tcp_buf_max);
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, new_dyn_tcp_buf_max,
                                             NULL,
                                             dyn_tcp_buf_max_conf_path));
            CHECK_RC(rcf_rpc_server_restart(pco_iut));
            dyn_tcp_buf_max = new_dyn_tcp_buf_max;
        }
    }

    RING("System-wide maximum is %d (if doubled: %d)", buf_max,
         buf_max * 2);

    TEST_STEP("Create a socket of type @p sock_type on IUT.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Check that the current size of the related socket buffer "
              "is within the system-wide maximum.");

    rpc_getsockopt(pco_iut, iut_s, opt, &val);
    if (val > buf_max * 2)
        TEST_VERDICT("Initial size of the socket buffer is too big");

    TEST_STEP("Check that if the socket buffer size is set to the maximum "
              "allowed value, @b getsockopt() reports it to be double of "
              "that size.");
    set_check_buf(pco_iut, iut_s, opt, buf_max, buf_max, &test_failed);

    TEST_STEP("Check that if the socket buffer size is set to more than "
              "the maximum allowed value, @b getsockopt() reports it to be "
              "double of the maximum allowed value.");
    set_check_buf(pco_iut, iut_s, opt, buf_max + 1, buf_max, &test_failed);

    TEST_STEP("Check that if the socket buffer size is set to less than "
              "the maximum allowed value, @b getsockopt() reports it to be "
              "double of the set value.");
    set_check_buf(pco_iut, iut_s, opt, buf_max - 1, buf_max, &test_failed);

    if (test_failed)
        TEST_STOP;

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (max_value_change != MAX_CHANGE_NONE)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, orig_buf_max,
                                                 NULL, max_conf_path));
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }
    if (small_tcp_bufs && dyn_tcp_buf_max != orig_dyn_tcp_buf_max)
    {
        CLEANUP_CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta,
                                                 orig_dyn_tcp_buf_max, NULL,
                                                 dyn_tcp_buf_max_conf_path));
        CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }

    TEST_END;
}
