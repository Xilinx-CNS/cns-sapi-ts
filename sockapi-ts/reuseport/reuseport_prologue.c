/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue for testing Onload clustering and SO_REUSEPORT option
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "reuseport/reuseport_prologue"

#include "sockapi-test.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             ef_cluster_size;
    int             scalable_filters_enable;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(ef_cluster_size);
    TEST_GET_INT_PARAM(scalable_filters_enable);

    if (scalable_filters_enable != 0)
    {
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_SCALABLE_FILTERS_ENABLE",
                                     scalable_filters_enable, TRUE, FALSE));
    }

    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                 ef_cluster_size, TRUE, FALSE));

    sockts_recreate_onload_stack(pco_iut);
    rcf_rpc_server_restart(pco_iut);

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
