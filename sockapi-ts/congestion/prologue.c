/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * Congestion testing
 */

/** @page congestion-prologue Congestion package prologue
 *
 * @objective Configure tested hosts for congestion tests.
 *
 * @param env   Testing environment:
 *      - @ref arg_types_env_peer2peer
 *
 * @par Scenario:
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "congestion/prologue"

#include "sockapi-test.h"
#include "onload.h"
#include "ts_congestion.h"
#include "tapi_cfg_qdisc.h"
#include "tapi_cfg_tbf.h"
#include "tapi_cfg_netem.h"
#include "sockapi-ts_bpf.h"

/** Size of a delayed frame used in congestion tests. */
#define TC_DELAY_FRAME_SIZE "1514"

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *tst_if = NULL;
    tapi_env_net               *net = NULL;

    char *ct_btlnck_veth1_name = NULL;
    char *ct_recv_veth1_name = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_if);
    TEST_GET_NET(net);

    CHECK_NOT_NULL(ct_btlnck_veth1_name =
                        sockts_ct_param_get("bottleneck_first_veth_name"));
    CHECK_NOT_NULL(ct_recv_veth1_name =
                        sockts_ct_param_get("receiver_first_veth_name"));

    CHECK_RC(tapi_onload_copy_sapi_ts_script(pco_iut, PATH_TO_TE_ONLOAD));

    TEST_STEP("Configure 2 pairs of VETHs, 2 Linux bridges and network namespace "
              "on @b Tester. First VETHs pair is bottleneck where traffic will "
              "be shaped. Second VETHs pair is for connection to namespace. "
              "Bridges are needed to make link between @b tst_if and interface "
              "in namespace.");
    sockts_ct_tst_net_setup(pco_tst->ta, tst_if->if_name, net);

    TEST_STEP("Use tc qdisc tbf to shape traffic on the bottleneck. "
              "Rate is @c CT_BTLNCK_TBF_DEFAULT_RATE, "
              "burst is @c CT_BTLNCK_TBF_DEFAULT_BURST and limit is "
              "@c CT_BTLNCK_TBF_DEFAULT_LIMIT.");
    CHECK_RC(tapi_cfg_qdisc_set_kind(pco_tst->ta, ct_btlnck_veth1_name,
                                     TAPI_CFG_QDISC_KIND_TBF));
    sockts_ct_set_btlnck_tbf_params(pco_tst->ta,
                                    CT_BTLNCK_TBF_DEFAULT_RATE,
                                    CT_BTLNCK_TBF_DEFAULT_BURST,
                                    CT_BTLNCK_TBF_DEFAULT_LIMIT);

    TEST_STEP("Use tc qdisc netem on @p receiver_first_veth_name interface to "
              "control RTT of packets. Default delay is "
              "@c CT_RECEIVER_NETEM_DEFAULT_DELAY_MS");
    CHECK_RC(tapi_cfg_qdisc_set_kind(pco_tst->ta, ct_recv_veth1_name,
                                     TAPI_CFG_QDISC_KIND_NETEM));
    CHECK_RC(tapi_cfg_netem_set_delay(pco_tst->ta, ct_recv_veth1_name,
                                      TE_MS2US(CT_RECEIVER_NETEM_DEFAULT_DELAY_MS)));
    CHECK_RC(tapi_cfg_qdisc_enable(pco_tst->ta, ct_recv_veth1_name));

    TEST_STEP("Build stimuli BPF programs on Tester");
    rpc_setenv(pco_tst, "TC_DELAY_FRAME_SIZE", TC_DELAY_FRAME_SIZE, 1);
    CHECK_RC(sockts_bpf_build_stimuli(pco_tst));

    TEST_STEP("Increase @b RLIMIT_MEMLOCK up to @c SOCKTS_BPF_RLIMITS_MEMLOCK "
              "value on TST.");
    sockts_bpf_set_rlim_memlock(pco_tst,
                                (unsigned int)SOCKTS_BPF_RLIMITS_MEMLOCK);

    TEST_SUCCESS;

cleanup:
    free(ct_btlnck_veth1_name);
    free(ct_recv_veth1_name);
    TEST_END;
}
