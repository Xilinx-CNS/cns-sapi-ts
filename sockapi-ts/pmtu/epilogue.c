/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * PMTU Test Package epilogue
 * 
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 *
 * $Id$
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "pmtu/epilogue"

#include "sockapi-test.h"
#include "tapi_cfg_vtund.h"
#include "tapi_cfg.h"
#include "conf_api.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    rcf_rpc_server         *pco_gw = NULL;

    te_saved_mtus       iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus       tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);
    te_saved_mtus       gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_gw);

    CHECK_RC(tapi_retrieve_saved_mtus(pco_iut->ta, "iut_mtus", &iut_mtus));
    CHECK_RC(tapi_retrieve_saved_mtus(pco_tst->ta, "tst_mtus", &tst_mtus));
    CHECK_RC(tapi_retrieve_saved_mtus(pco_gw->ta, "gw_mtus", &gw_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2_rollback(&iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2_rollback(&tst_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2_rollback(&gw_mtus));

    sleep(2);
    CHECK_RC(rc = cfg_synchronize("/:", TRUE));

    TEST_SUCCESS;

cleanup:

    TEST_END;
}

