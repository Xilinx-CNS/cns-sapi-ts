/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * Congestion testing
 */

/** @page congestion-epilogue Congestion package epilogue
 *
 * @objective Restore configuration after running congestion tests.
 *
 * @param env   Testing environment:
 *      - @ref arg_types_env_peer2peer
 *
 * @par Scenario:
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#define TE_TEST_NAME    "congestion/epilogue"

#include "sockapi-test.h"
#include "ts_congestion.h"
#include "tapi_cfg_qdisc.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    char *ct_btlnck_veth1_name = NULL;
    char *ct_recv_veth2_name = NULL;
    char *ct_ns_agent_name = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    CHECK_NOT_NULL(ct_btlnck_veth1_name =
                        sockts_ct_param_get("bottleneck_first_veth_name"));
    CHECK_NOT_NULL(ct_ns_agent_name = sockts_ct_param_get("ns_agent_name"));
    CHECK_NOT_NULL(ct_recv_veth2_name =
                        sockts_ct_param_get("receiver_second_veth_name"));

    tapi_cfg_qdisc_disable(pco_tst->ta, ct_btlnck_veth1_name);
    tapi_cfg_qdisc_disable(ct_ns_agent_name, ct_recv_veth2_name);

    sockts_ct_tst_net_cleanup(pco_tst->ta);

    TEST_SUCCESS;

cleanup:
    free(ct_btlnck_veth1_name);
    free(ct_recv_veth2_name);
    free(ct_ns_agent_name);
    TEST_END;
}

