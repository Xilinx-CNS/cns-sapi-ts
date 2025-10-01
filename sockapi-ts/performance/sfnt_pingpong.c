/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 */

/**
 * @page performance-sfnt_pingpong_test Performance testing
 *
 * @objective Measure performance with sfnt-pingpong
 *
 * @param env       Testing environment:
 *        -@ref arg_types_env_peer2peer
 *        -@ref arg_types_env_peer2peer_ipv6
 * @param proto Transport protocol:
 *        - @c IPPROTO_TCP
 *        - @c IPPROTO_UDP
 * @param sizes List of message size:
 *        - 1, 1400, 1500
 * @param muxer Type of iomux call:
 *        - none
 *        - poll
 *        - select
 *        - epoll
 * @param spin Non-blocking calls or not:
 *        - @c True
 *        - @c False
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */
#define TE_TEST_NAME  "performance/sfnt_pingpong"

#include "sockapi-test.h"
#include "tapi_sfnt_pingpong.h"
#include "tapi_job.h"
#include "tapi_job_factory_rpc.h"
#include "te_vector.h"
#include "te_mi_log.h"
#include "onload.h"

/** Default maximum time per message size (sec). */
#define TIME_PER_MSG 3
/**
 * Additional delay in seconds to wait sfnt-pingpong output.
 * This value was chosen empirically.
 * with value 1,2 and 10 there was unexpected fail.
 */
#define EXTRA_TIME_TO_WAIT 15

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rpc_socket_proto       proto;
    tapi_sfnt_pp_muxer     muxer;
    int                   *sizes = NULL;
    int                    sizes_len;
    te_bool                spin;

    tapi_job_factory_t        *cl_factory = NULL;
    tapi_job_factory_t        *sv_factory = NULL;
    tapi_sfnt_pp_opt           opt;
    tapi_sfnt_pp_app_client_t *client;
    tapi_sfnt_pp_app_server_t *server;
    tapi_sfnt_pp_report       *report;
    int                        i;
    te_vec                     vec = TE_VEC_INIT(int);
    te_string                  res = TE_STRING_INIT;

    tapi_job_wrapper_t    *wrap;
    /*
     * For understanding why `2` see tapi_sfnt_pp_client_add_sched_param
     * description.
     */
    tapi_job_sched_param sched_param[2];
    tapi_job_sched_affinity_param af;
    int cpu_mask[] = {1};
    /* This value should match to cpu_mask value */
    const char *ef_periodic_timer_cpu = "1";

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_PROTOCOL(proto);
    TEST_GET_INT_LIST_PARAM(sizes, sizes_len);
    TEST_GET_SFNT_PP_MUXER(muxer);
    TEST_GET_BOOL_PARAM(spin);

    te_vec_append_array(&vec, sizes, sizes_len);

    opt = tapi_sfnt_pp_opt_default_opt;
    opt.proto = proto_rpc2h(proto);
    opt.server = tst_addr;
    opt.ipversion = tst_addr->sa_family;
    opt.muxer = muxer;
    opt.sizes = &vec;
    opt.spin = spin;

    tapi_job_factory_rpc_create(pco_iut, &cl_factory);
    tapi_job_factory_rpc_create(pco_tst, &sv_factory);

    /* Kill zombie stacks now to avoid killing them at stack creation moment.
     * It takes time, and sfnt-pingpong is sensitive to execution time.
     * See bug 12215.*/
    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create client and server of sfnt-pingpong");
    CHECK_RC(tapi_sfnt_pp_create(cl_factory, sv_factory,
                                 &opt,  &client, &server));

    if (tapi_onload_lib_exists(pco_iut->ta))
    {
        char *tool = PATH_TO_TE_ONLOAD;
        const char *tool_argv[2] = {
            PATH_TO_TE_ONLOAD,
            NULL
        };
        CHECK_RC(tapi_sfnt_pp_client_wrapper_add(client, tool, tool_argv,
                                        TAPI_JOB_WRAPPER_PRIORITY_DEFAULT,
                                        &wrap));
    }

    rpc_setenv(pco_iut, "EF_PERIODIC_TIMER_CPU", ef_periodic_timer_cpu, 1);

    af.cpu_ids = cpu_mask;
    af.cpu_ids_len = TE_ARRAY_LEN(cpu_mask);

    sched_param[0].type = TAPI_JOB_SCHED_AFFINITY;
    sched_param[0].data = &af;

    sched_param[1].type = TAPI_JOB_SCHED_END;

    CHECK_RC(tapi_sfnt_pp_client_add_sched_param(client, sched_param));

    TEST_STEP("Start client and start server");
    CHECK_RC(tapi_sfnt_pp_start_server(server));
    TEST_SUBSTEP("Wait for a while before connecting "
                 "to allow the server to start.");
    TAPI_WAIT_NETWORK;
    CHECK_RC(tapi_sfnt_pp_start_client(client));

    TEST_STEP("Wait for sfnt-pingpong client completion.");
    CHECK_RC(tapi_sfnt_pp_wait_client(client,
                    TE_SEC2MS(TIME_PER_MSG * sizes_len + EXTRA_TIME_TO_WAIT)));

    TEST_STEP("Wait for sfnt-pingpong server completion.");
    CHECK_RC(tapi_sfnt_pp_wait_server(
                server, TAPI_WAIT_NETWORK_DELAY));

    TEST_STEP("Get report");
    CHECK_RC(tapi_sfnt_pp_get_report(client, &report));

    te_string_append(&res, "size      mean      min       median    max       "
                    "ile       stddev\n");
    for (i = 0; i < sizes_len; i++)
    {
        te_string_append(&res, "%-10d%-10d%-10d%-10d%-10d%-10d%-10d\n",
                         report[i].size, report[i].mean, report[i].min,
                         report[i].median, report[i].max, report[i].percentile,
                         report[i].stddev);
    }
    TEST_ARTIFACT("%s", res.ptr);

    for (i = 0; i < sizes_len; i++)
        tapi_sfnt_pp_mi_report(&report[i]);

    TEST_SUCCESS;

cleanup:
    CHECK_RC(tapi_sfnt_pp_kill_client(client, SIGTERM));
    CHECK_RC(tapi_sfnt_pp_destroy_client(client));
    CHECK_RC(tapi_sfnt_pp_destroy_server(server));
    te_string_free(&res);
    te_vec_free(&vec);
    TEST_END;
}
