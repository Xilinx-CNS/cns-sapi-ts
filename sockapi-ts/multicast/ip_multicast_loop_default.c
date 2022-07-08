/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Multicasting in IP
 *
 * $Id$
 */

/** @page multicast-ip_multicast_loop_default Default value for IP_MULTICAST_LOOP option.
 *
 * @objective Check that default value of IP_MULTICAST_LOOP option matches
 *            to the specified one, previously set env variable which
 *            potentially can give effect.
 *
 * @type Conformance.
 *
 * @param pco_iut           PCO on IUT
 * @param expected_value    Expected value of the option
 * @param env_option        Envaronment variable name
 * @param env_option_value  Envaronment variable value
 * @param sock_func         Socket creation function
 *
 * @par Scenario:
 *
 * -# Set env @p env_option with value @p env_option_value
 * -# Create a datagram socket @p iut_s on @p pco_iut.
 * -# Get the value of @c IP_MULTICAST_LOOP option.
 * -# if it equals to @p expected_value, test is passed.
 *    Otherwise test is failed.
 *     
 * @author Ivan Soloducha <Ivan.Soloducha@oktetlabs.ru>
 */

#define TE_TEST_NAME  "multicast/ip_multicast_loop_default"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    int                    iut_s = -1;
    int                    expected_value;
    int                    opt_value;
    int                    env_option_value;
    const char            *env_option;
    sockts_socket_func     sock_func;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(expected_value);
    TEST_GET_INT_PARAM(env_option_value);
    TEST_GET_STRING_PARAM(env_option);
    SOCKTS_GET_SOCK_FUNC(sock_func);

    if (strcmp(env_option, "none") != 0)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, env_option,
                                     env_option_value, TRUE, TRUE));

    iut_s = sockts_socket(sock_func, pco_iut, RPC_AF_INET,
                          RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);

    rpc_getsockopt(pco_iut, iut_s, RPC_IP_MULTICAST_LOOP, &opt_value);

    if (opt_value != expected_value)
        TEST_FAIL("Obtained value does not match to expected one");
    
    TEST_SUCCESS;

cleanup:    
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (strcmp(env_option, "none") != 0)
        CLEANUP_CHECK_RC(tapi_sh_env_unset(pco_iut, env_option, TRUE,
                                           TRUE));

    TEST_END;
}
