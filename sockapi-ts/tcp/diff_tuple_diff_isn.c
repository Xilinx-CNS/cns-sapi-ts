/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * TCP tests
 */

/** @page tcp-diff_tuple_diff_isn TCP ISN selection for TCP connections with different addresses/ports
 *
 * @objective Check that for TCP connections with different addresses/ports
 *            substantially different TCP ISNs are selected.
 *
 * @param env               Testing environment:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_ipv6
 * @param client_diff       How different should be addresses/ports of
 *                          client TCP sockets:
 *                          - @c none: no difference
 *                          - @c addr: addresses are different
 *                          - @c port: ports are different
 *                          - @c no_bind: do not bind sockets
 * @param server_diff       How different should be addresses/ports of
 *                          server TCP sockets:
 *                          - @c none: no difference (the single listener
 *                                     is used)
 *                          - @c addr: addresses are different
 *                          - @c port: ports are different
 * @param active            If @c TRUE, connections should be established
 *                          actively from IUT; otherwise they should be
 *                          established passively.
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/diff_tuple_diff_isn"

#include "sockapi-test.h"

#include "tapi_tcp.h"
#include "tcp_isn_check.h"

/** How many connections to establish */
#define TEST_CONNS_NUM 100

/** Difference between TCP ISNs considered as small. */
#define ISN_SMALL_DIFF ((1LLU << 32) / 200.0)

/**
 * Number of iterations in a loop computing
 * maximum probable number of connections
 * having close ISN value.
 */
#define MAX_METRIC_RUNS 100000

/** Kinds of bound address/port difference between TCP sockets */
typedef enum test_addr_diff {
    TEST_ADDR_DIFF_NONE,      /**< No difference */
    TEST_ADDR_DIFF_ADDR,      /**< Addresses are different */
    TEST_ADDR_DIFF_PORT,      /**< Ports are different */
    TEST_ADDR_DIFF_NO_BIND,   /**< Sockets are not bound before
                                   connect() */
} test_addr_diff;

/**
 * List for TEST_GET_ENUM_PARAM() to obtain argument of test_addr_diff
 * type
 */
#define TEST_ADDR_DIFF \
    { "none",           TEST_ADDR_DIFF_NONE },      \
    { "addr",           TEST_ADDR_DIFF_ADDR },      \
    { "port",           TEST_ADDR_DIFF_PORT },      \
    { "no_bind",        TEST_ADDR_DIFF_NO_BIND }

/** Structure describing TCP connection */
typedef struct test_conn {
    struct sockaddr_storage   iut_addr;       /**< IP address and port
                                                   on IUT */
    struct sockaddr_storage   tst_addr;       /**< IP address and port
                                                   on Tester */
    int                       iut_s;          /**< Connected socket on
                                                   IUT */
    int                       tst_s;          /**< Connected socket on
                                                   Tester */
    int                       listener;       /**< Listener socket on
                                                   Tester */

    uint32_t                  isn;            /**< TCP ISN */
    te_bool                   isn_captured;   /**< Will be set to TRUE
                                                   if ISN is captured */

    /*
     * Auxiliary variables for marking connections
     * whose ISN values are similar.
     */
    unsigned int              cur_mark;
    unsigned int              max_mark;

    /*
     * Auxiliary variables for storing configuration handles
     * of added addresses.
     */
    cfg_handle                iut_addr_entry_hndl;
    cfg_handle                iut_addr_hndl;
    cfg_handle                tst_addr_entry_hndl;
    cfg_handle                tst_addr_hndl;
} test_conn;

/** Type of argument passed to CSAP callback */
typedef struct iut_pkts_data {
    test_conn      *conns;      /**< Array of connections descriptions */
    unsigned int    conns_num;  /**< Number of connections */
    te_bool         failed;     /**< Will be set to TRUE if packets
                                     processing failed */
} iut_pkts_data;

/**
 * CSAP callback for processing packets sent from IUT.
 *
 * @param pkt             TCP packet.
 * @param user_data       Pointer to iut_pkts_data structure.
 */
static void
iut_pkts_handler(asn_value *pkt, void *user_data)
{
    iut_pkts_data *data = (iut_pkts_data *)user_data;

    uint32_t flags;
    uint32_t seqn;

    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    unsigned int            i;
    te_errno                rc;

    if (data->failed)
        goto cleanup;

    rc = asn_read_uint32(pkt, &flags,
                         "pdus.0.#tcp.flags");
    if (rc != 0)
    {
        ERROR("Failed to get TCP flags: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if (~flags & TCP_SYN_FLAG)
        goto cleanup;

    rc = sockts_get_addrs_from_tcp_asn(pkt, &src_addr, &dst_addr);
    if (rc != 0)
    {
        ERROR("Failed to obtain source/destination addresses: %r",
              rc);
        data->failed = TRUE;
        goto cleanup;
    }

    rc = asn_read_uint32(pkt, &seqn,
                         "pdus.0.#tcp.seqn");
    if (rc != 0)
    {
        ERROR("Failed to get SEQN: %r", rc);
        data->failed = TRUE;
        goto cleanup;
    }

    for (i = 0; i < data->conns_num; i++)
    {
        if (tapi_sockaddr_cmp(SA(&src_addr),
                              SA(&data->conns[i].iut_addr)) == 0 &&
            tapi_sockaddr_cmp(SA(&dst_addr),
                              SA(&data->conns[i].tst_addr)) == 0)
        {
            if (data->conns[i].isn_captured)
            {
                RING("SYN retransmit was captured");
                if (data->conns[i].isn != seqn)
                {
                    ERROR("SYN retransmit has different SEQN");
                    data->failed = TRUE;
                    goto cleanup;
                }
            }
            else
            {
                data->conns[i].isn = seqn;
                data->conns[i].isn_captured = TRUE;
            }
            break;
        }
    }

cleanup:

    asn_free_value(pkt);
}

/**
 * Construct address/port for a new TCP socket according to
 * test_addr_diff value. Assign new IP address to network
 * interface if necessary.
 *
 * @param addr_diff         How an address should be different
 *                          from an address to which other
 *                          sockets are bound.
 * @param rpcs              RPC server handle.
 * @param base_addr         Address/port obtained from environment.
 * @param net               Network to which addresses should belong.
 * @param if_name           Network interface name.
 * @param new_addr          Where to save the address/port for a new socket.
 * @param handle_entry      Where to save configuration handle for entry
 *                          in a pool of addresses (if new address is
 *                          allocated).
 * @param handle_addr       Where to save configuration handle for an
 *                          address assigned to network interface
 *                          (if new address is allocated).
 */
static void
construct_addr(test_addr_diff addr_diff,
               rcf_rpc_server *rpcs, const struct sockaddr *base_addr,
               tapi_env_net *net, const char *if_name,
               struct sockaddr_storage *new_addr,
               cfg_handle *handle_entry, cfg_handle *handle_addr)
{
    struct sockaddr *addr_aux = NULL;
    int              af = base_addr->sa_family;

    switch (addr_diff)
    {
        case TEST_ADDR_DIFF_NO_BIND:
        case TEST_ADDR_DIFF_NONE:
            tapi_sockaddr_clone_exact(base_addr, new_addr);
            break;

        case TEST_ADDR_DIFF_PORT:
            CHECK_RC(tapi_sockaddr_clone(rpcs, base_addr, new_addr));
            break;

        case TEST_ADDR_DIFF_ADDR:

            CHECK_RC(tapi_cfg_alloc_net_addr((af == AF_INET ? net->ip4net :
                                                              net->ip6net),
                                             handle_entry, &addr_aux));
            tapi_sockaddr_clone_exact(addr_aux, new_addr);
            free(addr_aux);

            te_sockaddr_set_port(SA(new_addr),
                                 te_sockaddr_get_port(base_addr));

            CHECK_RC(tapi_cfg_base_if_add_net_addr(
                                rpcs->ta, if_name,
                                SA(new_addr),
                                (af == AF_INET ? net->ip4pfx : net->ip6pfx),
                                FALSE,
                                handle_addr));

            break;

        default:
            break;
    }

}

/**
 * Obtain metric of how ISNs of connections are similar to each other.
 * It is computed as a maximum number of connections with ISNs close
 * to ISN of some connection.
 *
 * @param conns       Array of connections descriptions.
 * @param conns_num   Number of connections.
 */
static unsigned int
get_isn_diff_metric(test_conn *conns, unsigned int conns_num)
{
    unsigned int  i;
    unsigned int  j;
    unsigned int  small_dst_count;
    uint32_t      isn_diff;
    uint32_t      min_isn;
    uint32_t      max_isn;
    double        metric;

    for (i = 0; i < conns_num; i++)
    {
        conns[i].cur_mark = 0;
        conns[i].max_mark = 0;
    }

    metric = 0;
    for (i = 0; i < conns_num; i++)
    {
        small_dst_count = 1;
        assert(conns[i].isn_captured);

        conns[i].cur_mark = i + 1;
        for (j = 0; j < conns_num; j++)
        {
            if (i == j)
                continue;

            min_isn = MIN(conns[i].isn, conns[j].isn);
            max_isn = MAX(conns[i].isn, conns[j].isn);
            if (max_isn - min_isn > (1LLU << 31))
                isn_diff = (1LLU << 32) - max_isn + min_isn;
            else
                isn_diff = max_isn - min_isn;

            if ((double)isn_diff <= ISN_SMALL_DIFF)
            {
                small_dst_count++;
                conns[j].cur_mark = i + 1;
            }
        }

        if (metric < small_dst_count)
        {
            metric = small_dst_count;
            for (j = 0; j < conns_num; j++)
            {
                if (conns[j].cur_mark == i + 1)
                    conns[j].max_mark = metric;
            }
        }
    }

    return metric;
}

/**
 * Compute maximum probable value which get_isn_diff_metric() can return
 * in case of random distribution of ISNs. To do so, this function
 * repeatedly creates a sequence of random ISNs and computes metric
 * for them, saving maximum value of metric.
 *
 * @param conns_num         Number of connections.
 * @param max_attempts      How many times to compute metric before
 *                          returning maximum value.
 *
 * @return Maximum probable metric.
 */
static unsigned int
compute_max_probable_metric(unsigned int conns_num,
                            unsigned int max_attempts)
{
    test_conn    *conns;
    unsigned int  i;
    unsigned int  j;
    unsigned int  metric;
    unsigned int  metric_max = 0;

    /*
     * This was computed with help of this function - it
     * takes about 10 seconds so let's return precomputed
     * value for known values of arguments.
     */
    if (max_attempts == 100000 && conns_num == 100 &&
        ISN_SMALL_DIFF == ((1LLU << 32) / 200.0))
        return 12;

    srand48(rand());

    conns = TE_ALLOC(conns_num * sizeof(test_conn));
    for (i = 0; i < max_attempts; i++)
    {
        for (j = 0; j < conns_num; j++)
        {
            conns[j].isn_captured = TRUE;
            conns[j].isn = drand48() * (double)(1LLU << 32);
        }

        metric = get_isn_diff_metric(conns, conns_num);
        if (metric > metric_max)
            metric_max = metric;
    }

    free(conns);

    return metric_max;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    tapi_env_net               *net = NULL;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    const struct if_nameindex  *tst_if = NULL;
    const struct if_nameindex  *iut_if = NULL;

    const struct sockaddr  *iut_lladdr = NULL;
    const struct sockaddr  *tst_lladdr = NULL;

    test_addr_diff          client_diff;
    test_addr_diff          server_diff;
    te_bool                 active;

    test_conn               conns[TEST_CONNS_NUM];
    te_bool                 conns_initialized = FALSE;
    csap_handle_t           recv_csap = CSAP_INVALID_HANDLE;
    unsigned int            i;
    int                     af;
    rpc_socket_domain       domain;

    tapi_tad_trrecv_cb_data cb_data;
    iut_pkts_data           pkts_data;
    unsigned int            diff_metric;
    unsigned int            max_diff_metric;
    te_string               str = TE_STRING_INIT_STATIC(10000);

    rcf_rpc_server         *rpcs_srv = NULL;
    rcf_rpc_server         *rpcs_clnt = NULL;
    int                    *clnt_s = NULL;
    int                    *acc_s = NULL;
    int                    *listener = NULL;
    struct sockaddr        *srv_addr = NULL;
    struct sockaddr        *clnt_addr = NULL;
    socklen_t               addr_len;
    int                     old_isn_passive = 0;
    te_bool                 isn_passive_existed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ENUM_PARAM(client_diff, TEST_ADDR_DIFF);
    TEST_GET_ENUM_PARAM(server_diff, TEST_ADDR_DIFF);
    TEST_GET_BOOL_PARAM(active);

    TEST_STEP("If @p active is @c FALSE, set @c EF_TCP_ISN_INCLUDE_PASSIVE "
              "environment variable to @c 1 on IUT.");
    if (!active)
    {
        CHECK_RC(tapi_sh_env_save_set_int(pco_iut,
                                          "EF_TCP_ISN_INCLUDE_PASSIVE",
                                          1, TRUE, &isn_passive_existed,
                                          &old_isn_passive));
    }

    TEST_STEP("Configure CSAP on Tester to capture packets sent from "
              "IUT.");

    CHECK_RC(tapi_tcp_ip_eth_csap_create(
                                     pco_tst->ta, 0, tst_if->if_name,
                                     TAD_ETH_RECV_DEF |
                                     TAD_ETH_RECV_NO_PROMISC,
                                     (const uint8_t *)tst_lladdr->sa_data,
                                     (const uint8_t *)iut_lladdr->sa_data,
                                     tst_addr->sa_family, NULL, NULL,
                                     -1, -1, &recv_csap));

    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0,
                                   recv_csap, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS));

    af = iut_addr->sa_family;
    domain = rpc_socket_domain_by_af(af);

    memset(conns, 0, sizeof(test_conn) * TEST_CONNS_NUM);
    for (i = 0; i < TEST_CONNS_NUM; i++)
    {
        conns[i].iut_addr_entry_hndl = CFG_HANDLE_INVALID;
        conns[i].iut_addr_hndl = CFG_HANDLE_INVALID;
        conns[i].tst_addr_entry_hndl = CFG_HANDLE_INVALID;
        conns[i].tst_addr_hndl = CFG_HANDLE_INVALID;
        conns[i].iut_s = -1;
        conns[i].tst_s = -1;
        conns[i].listener = -1;
    }
    conns_initialized = TRUE;

    TEST_STEP("If required by @p server_diff and @p client_diff, "
              "assign additional IP addresses on IUT or Tester.");

    for (i = 0; i < TEST_CONNS_NUM; i++)
    {
        construct_addr((active ? client_diff : server_diff),
                       pco_iut, iut_addr,
                       net, iut_if->if_name,
                       &conns[i].iut_addr,
                       &conns[i].iut_addr_entry_hndl,
                       &conns[i].iut_addr_hndl);

        construct_addr((active ? server_diff : client_diff),
                       pco_tst, tst_addr,
                       net, tst_if->if_name,
                       &conns[i].tst_addr,
                       &conns[i].tst_addr_entry_hndl,
                       &conns[i].tst_addr_hndl);
    }

    CFG_WAIT_CHANGES;

    if (active)
    {
        rpcs_srv = pco_tst;
        rpcs_clnt = pco_iut;
    }
    else
    {
        rpcs_clnt = pco_tst;
        rpcs_srv = pco_iut;
    }

    TEST_STEP("Establish many connections between IUT and Tester, "
              "actively or passively from IUT as specified by @p active, "
              "choosing addresses for sockets according to @p client_diff "
              "and @p server_diff.");

    for (i = 0; i < TEST_CONNS_NUM; i++)
    {
        if (active)
        {
            srv_addr = SA(&conns[i].tst_addr);
            clnt_addr = SA(&conns[i].iut_addr);
            clnt_s = &conns[i].iut_s;
            acc_s = &conns[i].tst_s;
        }
        else
        {
            srv_addr = SA(&conns[i].iut_addr);
            clnt_addr = SA(&conns[i].tst_addr);
            clnt_s = &conns[i].tst_s;
            acc_s = &conns[i].iut_s;
        }

        if (i == 0 || server_diff != TEST_ADDR_DIFF_NONE)
        {
            conns[i].listener = rpc_socket(rpcs_srv, domain,
                                           RPC_SOCK_STREAM,
                                           RPC_PROTO_DEF);
            rpc_bind(rpcs_srv, conns[i].listener, srv_addr);
            rpc_listen(rpcs_srv, conns[i].listener, SOCKTS_BACKLOG_DEF);
            listener = &conns[i].listener;
        }
        else
        {
            listener = &conns[0].listener;
        }

        *clnt_s = rpc_socket(rpcs_clnt, domain, RPC_SOCK_STREAM,
                             RPC_PROTO_DEF);
        if (client_diff == TEST_ADDR_DIFF_NONE)
        {
            rpc_setsockopt_int(rpcs_clnt, *clnt_s, RPC_SO_REUSEADDR, 1);
        }
        if (client_diff != TEST_ADDR_DIFF_NO_BIND)
        {
            rpc_bind(rpcs_clnt, *clnt_s, clnt_addr);
        }

        rpc_connect(rpcs_clnt, *clnt_s, srv_addr);

        /*
         * Address is taken here because it may be not known if
         * not bound sockets are tested.
         */
        addr_len = te_sockaddr_get_size(clnt_addr);
        *acc_s = rpc_accept(rpcs_srv, *listener, clnt_addr, &addr_len);
    }

    memset(&pkts_data, 0, sizeof(pkts_data));
    memset(&cb_data, 0, sizeof(cb_data));
    pkts_data.conns = conns;
    pkts_data.conns_num = TEST_CONNS_NUM;
    cb_data.callback = &iut_pkts_handler;
    cb_data.user_data = &pkts_data;

    TEST_STEP("Check that established connections have ISNs spread "
              "over all possible ISN values (rather than being close "
              "to each other).");

    rcf_tr_op_log(FALSE);
    CHECK_RC(tapi_tad_trrecv_stop(pco_tst->ta, 0,
                                  recv_csap, &cb_data, NULL));
    if (pkts_data.failed)
        TEST_STOP;

    for (i = 0; i < TEST_CONNS_NUM; i++)
    {
        if (!conns[i].isn_captured)
            TEST_VERDICT("For some connections ISN was not captured");

        te_string_append(&str, "conns[%u].ISN = %u\n", i, conns[i].isn);
    }
    RING("Obtained ISNs:\n%s", str.ptr);

    max_diff_metric = compute_max_probable_metric(TEST_CONNS_NUM,
                                                  MAX_METRIC_RUNS);
    RING("Maximum probable number of connections with close ISN values: %u",
         max_diff_metric);

    diff_metric = get_isn_diff_metric(conns, TEST_CONNS_NUM);
    RING("%u connections have close values of ISN", diff_metric);
    te_string_reset(&str);
    for (i = 0; i < TEST_CONNS_NUM; i++)
    {
        if (conns[i].max_mark == diff_metric)
            te_string_append(&str, "conns[%u].ISN = %u\n", i, conns[i].isn);
    }
    RING("The longest list of connections with close ISN values:\n%s",
         str.ptr);

    if (diff_metric > max_diff_metric)
        TEST_VERDICT("Too many connections have close values of ISN");

    TEST_SUCCESS;

cleanup:

    if (conns_initialized)
    {
        for (i = 0; i < TEST_CONNS_NUM; i++)
        {
            CLEANUP_RPC_CLOSE(pco_tst, conns[i].tst_s);
            CLEANUP_RPC_CLOSE(active ? pco_tst : pco_iut,
                              conns[i].listener);
            CLEANUP_RPC_CLOSE(pco_iut, conns[i].iut_s);

            if (conns[i].iut_addr_hndl != CFG_HANDLE_INVALID)
            {
                CLEANUP_CHECK_RC(cfg_del_instance(conns[i].iut_addr_hndl,
                                                  FALSE));
            }
            if (conns[i].tst_addr_hndl != CFG_HANDLE_INVALID)
            {
                CLEANUP_CHECK_RC(cfg_del_instance(conns[i].tst_addr_hndl,
                                                  FALSE));
            }

            if (conns[i].iut_addr_entry_hndl != CFG_HANDLE_INVALID)
            {
                CLEANUP_CHECK_RC(tapi_cfg_free_entry(
                                      &conns[i].iut_addr_entry_hndl));
            }

            if (conns[i].tst_addr_entry_hndl != CFG_HANDLE_INVALID)
            {
                CLEANUP_CHECK_RC(tapi_cfg_free_entry(
                                      &conns[i].tst_addr_entry_hndl));
            }
        }
    }

    if (recv_csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, recv_csap));

    if (!active)
    {
        CHECK_RC(tapi_sh_env_rollback_int(pco_iut,
                                          "EF_TCP_ISN_INCLUDE_PASSIVE",
                                          isn_passive_existed,
                                          old_isn_passive, TRUE));
    }

    TEST_END;
}
