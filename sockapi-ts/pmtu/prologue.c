/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * PMTU Test Package prologue
 *
 * $Id$
 */

/** @page pmtu-prologue PMTU Test Package prologue
 *
 * @objective Convert existing network model to model required for PMTU
 *            testing.
 *
 * @param mtu           MTU to set on all interfaces
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "pmtu/prologue"

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

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *gw_iut_if = NULL;
    const struct if_nameindex  *gw_tst_if = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct sockaddr      *gw_iut_addr = NULL;
    const struct sockaddr      *gw_tst_addr = NULL;

    int             mtu;

    te_saved_mtus       iut_mtus = LIST_HEAD_INITIALIZER(iut_mtus);
    te_saved_mtus       tst_mtus = LIST_HEAD_INITIALIZER(tst_mtus);
    te_saved_mtus       gw_mtus = LIST_HEAD_INITIALIZER(gw_mtus);

    TEST_START;
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(gw_iut_if);
    TEST_GET_IF(gw_tst_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_gw, gw_iut_addr);
    TEST_GET_ADDR(pco_gw, gw_tst_addr);

    TEST_GET_INT_PARAM(mtu);

    /* Check the first net capabilities */
    CHECK_RC(tapi_set_if_mtu_smart2(pco_iut->ta, iut_if->if_name,
                                    mtu, &iut_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_iut_if->if_name,
                                    mtu, &gw_mtus));
    /* Check the second net capabilities */
    CHECK_RC(tapi_set_if_mtu_smart2(pco_gw->ta, gw_tst_if->if_name,
                                    mtu, &gw_mtus));
    CHECK_RC(tapi_set_if_mtu_smart2(pco_tst->ta, tst_if->if_name,
                                    mtu, &tst_mtus));

    if (!tapi_stored_mtus_exist(pco_iut->ta, "iut_mtus"))
    {
        CHECK_RC(tapi_store_saved_mtus(pco_iut->ta, "iut_mtus", &iut_mtus));
        CHECK_RC(tapi_store_saved_mtus(pco_tst->ta, "tst_mtus", &tst_mtus));
        CHECK_RC(tapi_store_saved_mtus(pco_gw->ta, "gw_mtus", &gw_mtus));
    }

    /* Turn on forwarding on router host */
    if (gw_iut_addr->sa_family == AF_INET)
        CHECK_RC(tapi_cfg_base_ipv4_fw(pco_gw->ta, TRUE));
    else if (gw_iut_addr->sa_family == AF_INET6)
        CHECK_RC(tapi_cfg_base_ipv6_fw(pco_gw->ta, TRUE));

    CHECK_RC(rc = cfg_synchronize("/:", TRUE));

    CHECK_RC(rc = cfg_tree_print(NULL, TE_LL_RING, "/:"));

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
