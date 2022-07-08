/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Epilogue for timestamps package
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#define TE_TEST_NAME "timestamps/prologue"

#include "sockapi-test.h"
#include "tapi_sfptpd.h"
#include "tapi_ntpd.h"
#include "onload.h"
#include "lib-ts_netns.h"
#include "lib-ts_timestamps.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    cfg_handle      handle;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    if (!tapi_onload_lib_exists(pco_iut->ta))
        TEST_SUCCESS;

    libts_timestamps_disable_sfptpd(pco_iut);

    if (cfg_find_fmt(&handle, "/agent:%s/env:EF_TIMESTAMPING_REPORTING",
                     pco_iut->ta) == RPC_EOK)
        CHECK_RC(cfg_del_instance(handle, 1));

    if (!tapi_getenv_bool("EF_RX_TIMESTAMPING") &&
        cfg_find_fmt(&handle, "/agent:%s/env:EF_RX_TIMESTAMPING",
                     pco_iut->ta) == RPC_EOK)
        CHECK_RC(cfg_del_instance(handle, 1));

    if (!tapi_getenv_bool("EF_TX_TIMESTAMPING") &&
        cfg_find_fmt(&handle, "/agent:%s/env:EF_TX_TIMESTAMPING",
                     pco_iut->ta) == RPC_EOK)
        CHECK_RC(cfg_del_instance(handle, 1));

    sockts_recreate_onload_stack(pco_iut);
    rcf_rpc_server_restart(pco_iut);

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
