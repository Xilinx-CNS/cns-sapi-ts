/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 */

/** @page performance-netperf_test Performance testing
 *
 * @objective Measure performance with netperf
 *
 * @par Test sequence:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */
#define TE_TEST_NAME  "performance/netperf"

#include "sockapi-test.h"
#include "tapi_netperf.h"
#include "tapi_job.h"
#include "tapi_job_factory_rpc.h"
#include "onload.h"

/* Duration of the test in seconds. */
#define TEST_DURATION 60
/** Send and receive socket buffer size */
#define SOCK_BUF_SIZE 65536

#define TEST_NAME_MAP_LIST \
    {"tcp_stream", TAPI_NETPERF_TEST_TCP_STREAM}, \
    {"udp_stream", TAPI_NETPERF_TEST_UDP_STREAM}, \
    {"tcp_maerts", TAPI_NETPERF_TEST_TCP_MAERTS}, \
    {"tcp_rr", TAPI_NETPERF_TEST_TCP_RR},         \
    {"udp_rr", TAPI_NETPERF_TEST_UDP_RR}

const char *
test_name_enum2str(tapi_netperf_test_name test_name)
{
    switch (test_name)
    {
        case TAPI_NETPERF_TEST_TCP_STREAM:
            return "tcp_stream";

        case TAPI_NETPERF_TEST_UDP_STREAM:
            return "udp_stream";

        case TAPI_NETPERF_TEST_TCP_MAERTS:
            return "tcp_maerts";

        case TAPI_NETPERF_TEST_TCP_RR:
            return "tcp_rr";

        case TAPI_NETPERF_TEST_UDP_RR:
            return "udp_rr";

        default:
            return NULL;
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    tapi_job_factory_t    *netperf_factory = NULL;
    tapi_job_factory_t    *netserver_factory = NULL;

    tapi_job_wrapper_t    *wrap;
    /*
     * For understanding why `2` see tapi_netperf_client_add_sched_param
     * description.
     */
    tapi_job_sched_param sched_param[2];
    tapi_job_sched_affinity_param af;
    int cpu_mask[] = {1};
    /* This value should match to cpu_mask value */
    const char *ef_periodic_timer_cpu = "1";

    tapi_netperf_opt           opt;
    tapi_netperf_app_client_t *netperf;
    tapi_netperf_app_server_t *netserver;
    tapi_netperf_report        report;
    tapi_netperf_test_name     test_name;

    int      port = -1;
    uint32_t duration = TEST_DURATION;
    int32_t  payload;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ENUM_PARAM(test_name, TEST_NAME_MAP_LIST);
    TEST_GET_INT_PARAM(payload);

    opt = tapi_netperf_default_opt;
    opt.test_name = test_name;
    opt.dst_host = tst_addr;
    opt.src_host = iut_addr;
    opt.duration = duration;
    opt.port = port;
    opt.ipversion = tst_addr->sa_family;

    switch (test_name)
    {
        case TAPI_NETPERF_TEST_TCP_MAERTS:
            opt.test_opt.stream.buffer_send = payload;
            opt.test_opt.stream.buffer_recv = payload;
            opt.test_opt.stream.remote_sock_buf = SOCK_BUF_SIZE;
            opt.test_opt.type = TAPI_NETPERF_TYPE_STREAM;
            break;
        case TAPI_NETPERF_TEST_TCP_STREAM:
            opt.test_opt.stream.buffer_send = payload;
            opt.test_opt.stream.buffer_recv = payload;
            opt.test_opt.stream.local_sock_buf = SOCK_BUF_SIZE;
            opt.test_opt.type = TAPI_NETPERF_TYPE_STREAM;
            break;
        case TAPI_NETPERF_TEST_UDP_STREAM:
            opt.test_opt.stream.buffer_send = payload;
            opt.test_opt.stream.buffer_recv = payload;
            opt.test_opt.type = TAPI_NETPERF_TYPE_STREAM;
            break;

        case TAPI_NETPERF_TEST_UDP_RR:
        case TAPI_NETPERF_TEST_TCP_RR:
            opt.test_opt.rr.request_size = payload;
            opt.test_opt.rr.response_size = payload;
            opt.test_opt.type = TAPI_NETPERF_TYPE_RR;
            break;
    }

    tapi_job_factory_rpc_create(pco_iut, &netperf_factory);
    tapi_job_factory_rpc_create(pco_tst, &netserver_factory);

    TEST_STEP("Create netperf and netserver.");
    CHECK_RC(tapi_netperf_create(netperf_factory, netserver_factory, &opt,
                                 &netperf, &netserver));

    if (tapi_onload_lib_exists(pco_iut->ta))
    {
        char *tool = PATH_TO_TE_ONLOAD;
        const char *tool_argv[2] = {
            PATH_TO_TE_ONLOAD,
            NULL
        };
        CHECK_RC(tapi_netperf_client_wrapper_add(netperf, tool, tool_argv,
                                        TAPI_JOB_WRAPPER_PRIORITY_DEFAULT,
                                        &wrap));
    }

    rpc_setenv(pco_iut, "EF_PERIODIC_TIMER_CPU", ef_periodic_timer_cpu, 1);

    af.cpu_ids = &cpu_mask;
    af.cpu_ids_len = TE_ARRAY_LEN(cpu_mask);

    sched_param[0].type = TAPI_JOB_SCHED_AFFINITY;
    sched_param[0].data = &af;

    sched_param[1].type = TAPI_JOB_SCHED_END;

    CHECK_RC(tapi_netperf_client_add_sched_param(netperf, sched_param));

    TEST_STEP("Start netperf and netserver.");
    CHECK_RC(tapi_netperf_start_server(netserver));
    /* ST-2384: Looks like netserver sometimes starts slowly, so let's add
     * bigger timeout than TAPI_WAIT_NETWORK. */
    SLEEP(1);
    CHECK_RC(tapi_netperf_start_client(netperf));

    TEST_STEP("Wait for netperf completion.");
    CHECK_RC(tapi_netperf_wait_client(netperf,
                                      TE_SEC2MS(duration + pco_iut->def_timeout)));

    TEST_STEP("Get netperf report.");
    CHECK_RC(tapi_netperf_get_report(netperf, &report));

    switch (report.tst_type)
    {
        case TAPI_NETPERF_TYPE_STREAM:
            TEST_ARTIFACT("test_name = %s, payload = %d, throughput tx = %lf 10^6bits/sec, "
                          "throughput rx = %lf 10^6bits/sec", test_name_enum2str(test_name),
                          payload ,report.stream.mbps_send,
                          report.stream.mbps_recv);
            break;

        case TAPI_NETPERF_TYPE_RR:
            TEST_ARTIFACT("test_name = %s, payload = %d, transactions per second = %lf",
                          test_name_enum2str(test_name), payload,
                          report.rr.trps);
            break;
    }

    tapi_netperf_mi_report(&report);

    TEST_SUCCESS;

cleanup:
    CHECK_RC(tapi_netperf_kill_server(netserver, SIGTERM));
    CHECK_RC(tapi_netperf_destroy_client(netperf));
    CHECK_RC(tapi_netperf_destroy_server(netserver));
    tapi_job_factory_destroy(netperf_factory);
    tapi_job_factory_destroy(netserver_factory);
    TEST_END;
}
