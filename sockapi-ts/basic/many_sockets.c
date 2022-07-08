/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-many_sockets  Create a very large sockets number
 *
 * @objective  Create a very large sockets number to test large values of
 *             Onload limits EF_MAX_ENDPOINTS and RLIMIT_NOFILE.
 *
 * @type reliability
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer
 *              - @ref arg_types_env_peer2peer_ipv6
 * @param accept        Create sockets using accept() call if @c TRUE.
 * @param one_stack     Share stack between processes if @c TRUE.
 * @param proc_num      Processes number:
 *                      - 1
 *                      - 10
 * @param ef_max_endpoints  Set the value to Onload @c EF_MAX_ENDPOINTS:
 *                          - 65536
 * @param ef_fdtable_size   Set the value to Onload @c EF_FDTABLE_SIZE:
 *                          - 25000
 * @param ef_max_rx_packets Set the value to Onload @c EF_MAX_RX_PACKETS and
 *                          (the value + @c 10000) to EF_MAX_PACKETS:
 *                          - 500000
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/many_sockets"

#include "sockapi-test.h"
#include "onload.h"

/**
 * Minimum value for /proc/sys/net/netfilter/nf_conntrack_max.
 *
 * This test may fail with errors like "nf_conntrack: table full,
 * dropping packet" in log if this parameter has too small value.
 * The given value is the default one on a few hosts I've checked
 * (except for a rhel7 host with 4Gb memory).
 */
#define MIN_CONNTRACK_MAX 262144

/* Allowed precesion. */
#define PRECISION 0.01

/* Sockets context. */
typedef struct socket_ctx {
    struct sockaddr *addr; /**< Bounded address */
    rcf_rpc_server *rpcs;  /**< RPC server */
    int s;                 /**< Socket descriptor */
    rpc_ptr handle;        /**< Socket array handle */
} socket_ctx;

/**
 * Destroy spawned processes
 * 
 * @param cs     Sockets context
 * @param num    Processes number
 * @param delay  Wait delay before closing listening socket
 */
static void
clean_proc(socket_ctx *cs, int num, te_bool delay, int req_num)
{
    int i;

    if (cs == NULL)
        return;

    for (i = 0; i < num; i++)
    {
        if (cs[i].rpcs == NULL)
            return;

        rpc_many_close(cs[i].rpcs, cs[i].handle, req_num);
        if (cs[i].s != -1)
        {
            if (delay)
                SLEEP(2);
            rpc_close(cs[i].rpcs, cs[i].s);
        }

        rcf_rpc_server_destroy(cs[i].rpcs);
    }
}

/**
 * Check whether /proc/sys/net/netfilter/nf_conntrack_max is big enough;
 * increase it if it is not.
 *
 * @param ta        Test Agent name.
 */
static void
check_fix_nf_conntrack_max(const char *ta)
{
    int cur_val;
    te_errno rc;

    rc = tapi_cfg_sys_ns_get_int(ta, &cur_val,
                                 "net/netfilter/nf_conntrack_max");
    if (rc != 0)
    {
        WARN("Failed to get the value of nf_conntrack_max on TA %s "
             "(rc=%r), perhaps it is not supported", ta, rc);
        return;
    }

    if (cur_val < MIN_CONNTRACK_MAX)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(ta, MIN_CONNTRACK_MAX, NULL,
                                         "net/netfilter/nf_conntrack_max"));
    }
}

int
main(int argc, char *argv[])
{
    const struct sockaddr   *iut_addr = NULL;
    const struct sockaddr   *tst_addr = NULL;
    struct sockaddr_storage *addr = NULL;
    rcf_rpc_server          *pco_iut = NULL;
    rcf_rpc_server          *pco_tst = NULL;

    te_bool one_stack;
    te_bool accept;
    int     ef_max_endpoints;
    int     ef_fdtable_size;
    int     ef_max_rx_packets;
    int     proc_num;

    socket_ctx *iut_s = NULL;
    socket_ctx *tst_s = NULL;
    int num;
    int req_num;
    int total;
    int i;

    rpc_socket_domain domain;
    te_bool onload = FALSE;
    char    proc_name[32] = {0,};
    int     rlimit;
    float   precision = PRECISION;
    char   *tx_buf = NULL;
    size_t  buf_len;
    int     loglevel;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(ef_max_endpoints);
    TEST_GET_INT_PARAM(ef_fdtable_size);
    TEST_GET_INT_PARAM(ef_max_rx_packets);
    TEST_GET_INT_PARAM(proc_num);
    TEST_GET_BOOL_PARAM(accept);
    TEST_GET_BOOL_PARAM(one_stack);

    if (proc_num < 1)
        TEST_FAIL("Wrong argument proc_num %d, it must be more 0",
                  proc_num);

    check_fix_nf_conntrack_max(pco_iut->ta);
    check_fix_nf_conntrack_max(pco_tst->ta);
    CFG_WAIT_CHANGES;

    num = ef_max_endpoints + 50;
    tx_buf = sockts_make_buf_stream(&buf_len);

    domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Set stack name if @p one_stack is @c TRUE.");
    if (one_stack)
        CHECK_RC(tapi_sh_env_set(pco_iut, "EF_NAME", "foo", FALSE, FALSE));

    TEST_STEP("Increase packets queue limits.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MAX_PACKETS",
                                 ef_max_rx_packets + 10000, TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MAX_RX_PACKETS",
                                 ef_max_rx_packets, TRUE, FALSE));

    TEST_STEP("Set EF_MAX_ENDPOINTS and EF_FDTABLE_SIZE envs in dependence on the "
              "test parameters.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_MAX_ENDPOINTS",
                                 ef_max_endpoints, TRUE, FALSE));
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_FDTABLE_SIZE",
                                 ef_fdtable_size, TRUE, TRUE));

    TEST_STEP("Increase RLIMIT_NOFILE for tester to make possible creating "
              "a lot of sockets.");
    rlimit = ef_fdtable_size + 100;
    sockts_inc_rlimit(pco_tst, RPC_RLIMIT_NOFILE, rlimit);

    addr = te_calloc_fill(sizeof(*addr), proc_num, 0);
    iut_s = te_calloc_fill(sizeof(*iut_s), proc_num, 0);
    tst_s = te_calloc_fill(sizeof(*tst_s), proc_num, 0);
    for (i = 0; i < proc_num; i++)
    {
        iut_s[i].s = -1;
        tst_s[i].s = -1;
    }

    TEST_STEP("Create aux processes independence on @p rpco_num.");
    for (i = 0; i < proc_num; i++)
    {
        snprintf(proc_name, sizeof(proc_name), "pco_iut_%d", i);
        CHECK_RC(rcf_rpc_server_fork(pco_iut, proc_name, &iut_s[i].rpcs));

        TEST_STEP("Increase RLIMIT_NOFILE for new IUT processes.");
        sockts_inc_rlimit(iut_s[i].rpcs, RPC_RLIMIT_NOFILE, rlimit);

        if (accept)
        {
            int val = 1;

            snprintf(proc_name, sizeof(proc_name), "pco_tst_%d", i);
            CHECK_RC(rcf_rpc_server_fork(pco_tst, proc_name, &tst_s[i].rpcs));

            TEST_STEP("Create listener sockets if @p accept is @c TRUE.");
            iut_s[i].s = rpc_socket(iut_s[i].rpcs, domain, RPC_SOCK_STREAM,
                                    RPC_PROTO_DEF);
            CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, addr + i));
            iut_s[i].addr = SA(addr + i);
            rpc_bind(iut_s[i].rpcs, iut_s[i].s, iut_s[i].addr);
            if (1) /* if send_count > 1 */
            {
                rpc_setsockopt(iut_s[i].rpcs, iut_s[i].s,
                               RPC_TCP_NODELAY, &val);
            }
            rpc_listen(iut_s[i].rpcs, iut_s[i].s, -1);
        }
    }

    req_num = num / proc_num;

    total = 0;
    TEST_STEP("For each process create requested number of sockets with socket() "
              "or accept() in dependence on iteration. Sockets creation part is "
              "moved to RPC to decrease the execution time.");
    for (i = 0; i < proc_num; i++)
    {
        if (!accept)
        {
            total += rpc_many_socket(iut_s[i].rpcs, domain, req_num,
                                     &iut_s[i].handle);
            RING("Process %d sockets number %d", i, total);
            continue;
        }
        
        iut_s[i].rpcs->timeout =  100000;
        iut_s[i].rpcs->op = RCF_RPC_CALL;
        rpc_many_accept(iut_s[i].rpcs, iut_s[i].s, req_num, 1, 128, NULL,
                        NULL, &iut_s[i].handle);

        tst_s[i].rpcs->timeout =  300000;
        RPC_AWAIT_IUT_ERROR(tst_s[i].rpcs);
        rpc_many_connect(tst_s[i].rpcs, iut_s[i].addr, req_num, 1, 128, NULL,
                         NULL, &tst_s[i].handle);

        total += rpc_many_accept(iut_s[i].rpcs, iut_s[i].s, req_num, 1, 128,
                                 NULL, NULL, &iut_s[i].handle);

        RING("Process %d sockets number %d", i, total);
    }

    RING("Sockets number %d/%d/ %d/%d/%d", total, num,
         ef_max_endpoints, ef_fdtable_size, proc_num);

    /* Statistics
    SLEEP(5);
    rpc_system(pco_iut, "te_onload_stdump tcp_stats");
    rpc_system(pco_iut, "te_onload_stdump more_stats");
    rpc_system(pco_iut, "te_onload_stdump tcp_ext_stats");
    rpc_system(pco_iut, "te_onload_stdump all");
    SLEEP(5);
    */

    if (tapi_onload_lib_exists(pco_iut->ta) &&
        tapi_onload_is_onload_fd(iut_s[i - 1].rpcs, iut_s[i - 1].s))
    {
        onload = TRUE;
        TEST_STEP("For Onload fd table size is limited by EF_FDTABLE_SIZE.");
        rlimit = ef_fdtable_size;
    }

    if (rlimit * proc_num > ef_max_endpoints)
    {
        if (onload && one_stack)
            rlimit = ef_max_endpoints;
        else
            rlimit = num;
    }

    if (total < rlimit - rlimit * precision)
    {
        ERROR_VERDICT("Sockets limit was not achieved");

        /* ST-2361: print statistics */
        if (tapi_onload_lib_exists(pco_iut->ta))
            rpc_system(pco_iut, "te_onload_stdump lots");

        TEST_STOP;
    }
    if (total > rlimit)
        TEST_VERDICT("Sockets limit was exceeded");

    TEST_SUCCESS;

cleanup:
    /** Disable logging because it is rather verbose on Siena, perhaps
     * solving bug 47579 can help to avoid this. */
    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

    clean_proc(tst_s, proc_num, FALSE, req_num);
    TAPI_WAIT_NETWORK;
    clean_proc(iut_s, proc_num, TRUE, req_num);
    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);

    free(addr);
    free(iut_s);
    free(tst_s);
    free(tx_buf);

    TEST_END;
}
