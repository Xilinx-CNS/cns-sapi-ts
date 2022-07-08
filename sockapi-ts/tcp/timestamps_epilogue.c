/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Epilogue used to restore original IUT timestamps state
 * after timestamps_prologue.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/timestamps_epilogue"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut;
    cfg_val_type    inst_type;
    int             iut_ts_orig_val;
    int             iut_ts_val;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_iut->ta, &iut_ts_val,
                                     "net/ipv4/tcp_timestamps"));

    inst_type = CVT_INTEGER;
    CHECK_RC(cfg_get_instance_str(&inst_type, &iut_ts_orig_val,
                                  "/local:/iut_orig_ts_state:"));
    CHECK_RC(cfg_del_instance_fmt(FALSE, "/local:/iut_orig_ts_state:"));

    if (iut_ts_val != iut_ts_orig_val)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, iut_ts_orig_val, NULL,
                                         "net/ipv4/tcp_timestamps"));
        CHECK_RC(rcf_rpc_server_restart(pco_iut));
    }


    TEST_SUCCESS;

cleanup:

    TEST_END;
}
