/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue used to enable or disable timestamps for a group of iterations.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/timestamps_prologue"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut;
    te_bool         enable_timestamps;

    int             iut_ts_val;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(enable_timestamps);

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &iut_ts_val,
                                     "net/ipv4/tcp_timestamps"));
    CHECK_RC(cfg_add_instance_str("/local:/iut_orig_ts_state:",
                                  NULL, CFG_VAL(INTEGER, iut_ts_val)));

    if (enable_timestamps)
    {
        if (!iut_ts_val)
        {
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, NULL,
                                             "net/ipv4/tcp_timestamps"));
            CHECK_RC(rcf_rpc_server_restart(pco_iut));
        }
    }
    else
    {
        if (iut_ts_val)
        {
            CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 0, NULL,
                                             "net/ipv4/tcp_timestamps"));
            CHECK_RC(rcf_rpc_server_restart(pco_iut));
        }
    }

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
