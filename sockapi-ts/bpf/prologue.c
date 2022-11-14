/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * BPF/XDP
 *
 * @author Damir Mansurov <dnman@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "bpf/prologue"

#include "sockapi-test.h"
#include "sockapi-ts_bpf.h"

static void set_ef_xdp_mode_compatible(rcf_rpc_server *rpcs)
{
    sockts_set_env_gen(rpcs, "EF_XDP_MODE",
                       "compatible", NULL, FALSE);
    sockts_recreate_onload_stack(rpcs);
    CHECK_RC(rcf_rpc_server_restart(rpcs));
}

static void set_cplane_track_xdp(rcf_rpc_server *rpcs)
{
    te_errno       cfg_errno;

    RPC_AWAIT_IUT_ERROR(rpcs);
    cfg_errno = cfg_set_instance_fmt(CFG_VAL(STRING, "Y"),
                                     "/agent:%s/module:onload/parameter:cplane_track_xdp",
                                     rpcs->ta);

    if (cfg_errno != 0 && TE_RC_GET_ERROR(cfg_errno) != TE_ENOENT)
    {
        TEST_FAIL("Unexpected errno during setting of cplane_track_xdp");
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_used = NULL;
    const struct if_nameindex  *iut_if = NULL;
    char netns_ifname[IF_NAMESIZE];
    char netns_agt[RCF_MAX_NAME];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);

    if (sockts_not_pure_netns_used())
    {
        CHECK_RC(sockts_find_parent_netns(pco_iut, iut_if->if_name,
                                          netns_agt, netns_ifname));

        CHECK_RC(rcf_rpc_server_create(netns_agt, "rpc_used_nets",
                                       &pco_used));
    }
    else
    {
        pco_used = pco_iut;
    }

    TEST_STEP("Make xdp object files from sources on agent.");
    CHECK_RC(sockts_bpf_build_all(pco_used));

    TEST_STEP("Increase @b RLIMIT_MEMLOCK up to @c SOCKTS_BPF_RLIMITS_MEMLOCK "
              "value.");
    sockts_bpf_set_rlim_memlock(pco_used,
                                (uint64_t)SOCKTS_BPF_RLIMITS_MEMLOCK);

    TEST_STEP("Set @b cplane_track_xdp to @c Y");
    set_cplane_track_xdp(pco_used);

    TEST_STEP("Set @n EF_XDP_MODE to @c compatible");
    set_ef_xdp_mode_compatible(pco_iut);

    if (sockts_not_pure_netns_used())
    {
        CHECK_RC(rcf_rpc_server_destroy(pco_used));
    }

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
