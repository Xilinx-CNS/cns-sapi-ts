/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-prologue Routing package prologue
 *
 * @objective Configure tested hosts for routing tests.
 *
 * @param env   Testing environment:
 *      - @ref arg_types_env_iut_only
 *
 * @par Scenario:
 *
 * @author Andrey Dmtirov <Andrey.Dmtirov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/prologue"

#include "sockapi-test.h"
#include "tapi_namespaces.h"
#include "tapi_host_ns.h"
#include "sockapi-ts_cns.h"
#include "ts_route.h"

/*
 * Callback function to set rp_filter value to an interface.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param opaque    Opaque user data (unused)
 */
static te_errno
set_rp_filter_cb(const char *ta, const char *ifname, void *opaque)
{
    UNUSED(opaque);

    return tapi_cfg_sys_set_int(ta, 0, NULL, "net/ipv4/conf:%s/rp_filter",
                                ifname);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    TEST_STEP("If --ool=netns_calico was specified, configure Calico-style "
              "namespace.");
    sockts_cns_setup(pco_iut->ta);

    TEST_STEP("Set /proc/sys/net/ipv4/conf/<interface>/rp_filter to @c 0 on all "
              "interfaces which are grabbed by IUT test agent.");
    CHECK_RC(tapi_host_ns_if_ta_iter(pco_iut->ta, set_rp_filter_cb, NULL));
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_SUCCESS;
cleanup:
    TEST_END;
}
