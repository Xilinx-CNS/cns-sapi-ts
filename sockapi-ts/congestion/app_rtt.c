/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Congestion testing
 */

/**
 * @page congestion-app_rtt Test the congestion algorithm in a managed network
 *
 * @objective Check behavior of congestion algorithm in a managed network that
 *            has bottleneck with limited throughput.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer
 * @param limit             Limit of tc qdisc tbf on the bottleneck interface
 *                          in bytes:
 *                          - @c 15000
 *                          - @c 50000
 *                          - @c 100000
 *                          - @c 150000
 * @param rate              Rate of tc qdisc tbf on the bottleneck interface
 *                          in Mb/s:
 *                          - @c 10
 *                          - @c 40
 * @param delay             Delay for tc qdisc netem on the receiver interface
 *                          in milliseconds:
 *                          - @c 0
 *                          - @c 5
 *                          - @c 50
 * @param chunk_size        Chunk size parameter for ol-apprtt application
 *                          in bytes:
 *                          - @c 150000
 * @param set_ts            Control "tcp_timestamps" option
 *                          - @c FALSE - disable the option
 *                          - @c TRUE - enable the option
 * @param set_sack          Control "tcp_sack" option
 *                          - @c FALSE - disable the option
 *                          - @c TRUE - enable the option
 * @param set_dsack         Control "tcp_dsack" option
 *                          - @c FALSE - disable the option
 *                          - @c TRUE - enable the option
 * @param stimulus          Type of tested congestion stimulus:
 *                          - @c none - don't test stimulus
 *                          - @c slow_start - test slow start stimulus only
 *                          - @c drop - drop @p stimulus_param packets
 *                          - @c duplicate - duplicate one packet
 *                                           @p stimulus_param times
 *                          - @c delay - delay one packet for @p stimulus_param
 *                                       packets
 * @param stimulus_param    Parameter value for @p stimulus if it isn't @c none
 *                          or @c slow_start:
 *                          - @c 1
 *                          - @c 10
 *                          - @c 20
 *
 * @par Scenario:
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "congestion/app_rtt"

#include "sockapi-test.h"
#include "ts_congestion.h"
#include "tapi_cfg_qdisc.h"
#include "tapi_cfg_tbf.h"
#include "sockapi-ts_apprtt.h"
#include "sockapi-ts_stats.h"
#include "sockapi-ts_pcap.h"
#include "tapi_sniffer.h"
#include "te_ethernet.h"
#include "onload.h"
#include "te_mi_log.h"
#include "tapi_bpf_stim.h"

/**
 * Duration of the test in seconds. It should be quite big (over 30 seconds),
 * to get enough RTT samples, hence calculate more accurate statistics.
 * Espesially it is evident for "stimulus=!slow_start" iterations, where we
 * skip the first @ref slow_start_in_chunks RTT samples.
 */
#define CT_APPRTT_DURATION_SEC 45

/**
 * The condition of a big stimuli parameter value which means heavy link
 * damaging. It is used to adjust some test parameters.
 */
#define CT_AGGRESSIVE_STIMULUS (stimulus_param >= 20)

/**
 * Acceptable difference in percent between mean and median RTT values
 * for iterations with high stimulus parameter value.
 */
#define CT_AGGR_STIM_MEAN 25

/**
 * Extra timeout (in seconds) to wait for sender to send all the pushed data
 * during @ref CT_APPRTT_DURATION_SEC time, for cases when the traffic speed
 * is too low. Usually it is needed for "stimulus_param>=20" iterations.
 * See ST-2512.
 */
#define CT_APPRTT_EXTRA_TIMEOUT 600

/** Condition under which to use extra timeout. */
#define CT_APPRTT_EXTRA_TIMEOUT_COND CT_AGGRESSIVE_STIMULUS

/** Length of TCP header with options containing timestamp. */
#define CT_TCP_HDR_WITH_TS_LEN 32

/**
 * Sniffer shanphot length for one packet.
 * '1' stands for ol-apprtt server answer.
 */
#define CT_SNIFFER_SNAPLEN \
    (ETHER_HDR_LEN + SOCKTS_IPV4_HDR_LEN + CT_TCP_HDR_WITH_TS_LEN + 1)

/**
 * Percentage that sets the width of the range with valid RTT values
 * in percents.
 */
#define CT_VALID_RANGE_WIDTH 5

/**
 * Structure to keep all test artifacts and acceptable values for these
 * artifacts.
*/
typedef struct sockts_ct_stats {
    /**< Mean value. */
    int mean;
    /**< Median value. */
    int median;
    /**< Percent of values that are out of the acceptable range. */
    double out_of_range;
    /**< Number of TCP retransmissons. */
    int retrans_num;
} sockts_ct_stats;

/** Special value for acceptable values to don't check the statistic. */
#define CT_DONT_CHECK_STAT -1

/** Maximum bottleneck buffer size in bytes for small buffers. */
#define CT_SMALL_BUFF_MAX 30000

/** Default bottleneck rate in Mb/s. */
#define CT_DEFAULT_RATE 10

/** Indexes for types of acceptable values. */
typedef enum {
    CT_NORMAL_BUF_ID, /* Default acceptable values */
    CT_SMALL_BUF_ID,  /* Acceptable values if tbf::limit <= CT_SMALL_BUFF_MAX */
    CT_SLOW_START_ID, /* Acceptable values for stimulus=slow_start */
    CT_SLOW_START_NOSACK_ID, /* Acceptable values for stimulus=slow_start and
                                disabled SACK. */
    CT_HIGH_RATE_ID,  /* Acceptable values if tbf::rate > CT_DEFAULT_RATE */
} accept_vals_ids;

/**
 * The test measures different statistics and sets the maximum acceptable
 * values for them to get PASS/FAIL result.
 * Map with these acceptable values which depend on the type of iteration.
 */
static const sockts_ct_stats acc_vals_map[] =
{
    [CT_NORMAL_BUF_ID] = {
        /* Don't check median value */
        .median         = CT_DONT_CHECK_STAT,
        /* Maximum acceptable difference between mean and median values
         * in percent
         */
        .mean           = 10,
        /* Maximum acceptable percentage of RTT values that are out of 5% range
         * from median
         */
        .out_of_range   = 25,
        /* Maximum acceptable number of TCP retransmissoins. Depends on
         * @ref CT_APPRTT_DURATION_SEC */
        .retrans_num    = 225
    },
    [CT_SMALL_BUF_ID] = {
        .median         = CT_DONT_CHECK_STAT,
        .mean           = 20,
        .out_of_range   = 50,
        .retrans_num    = 1050
    },
    [CT_SLOW_START_ID] = {
        .median         = CT_DONT_CHECK_STAT,
        .mean           = 20,
        .out_of_range   = 50,
        .retrans_num    = 50
    },
    [CT_SLOW_START_NOSACK_ID] = {
        .median         = CT_DONT_CHECK_STAT,
        .mean           = 50,
        /*
         * Deltas of RTT values are too big at slow start phase without SACK.
         * So the number of RTT values which differ from median more than 5%
         * is too big and may exceed 90%. There is no much sence to check it.
         */
        .out_of_range   = CT_DONT_CHECK_STAT,
        .retrans_num    = 100
    },
    [CT_HIGH_RATE_ID] = {
        .median         = CT_DONT_CHECK_STAT,
        .mean           = 10,
        .out_of_range   = 25,
        .retrans_num    = 375
    },
};

/** Slow start timeout in seconds */
#define CT_SLOW_START_TIMEOUT 7
/**
 * Timeout for reation on stimulus in seconds
 * (depends on @c CT_APPRTT_DURATION_SEC)
 */
#define CT_REACTION_TIMEOUT 3
/**
 * The number of times we trigger a stimulus in seconds
 * (depends on @c CT_APPRTT_DURATION_SEC)
 */
#define CT_STIM_NUM 7

/**
 * Set a /proc/sys/net/ipv4/ option on IUT according to @p set parameter.
 * Print the option value in case of using a default value.
 *
 * @param[in]  pco_iut  IUT RPC server.
 * @param[in]  option   Option name.
 * @param[in]  set      Option value.
 * @param[out] restart  Whether to restart IUT RPC server.
 */
static void
set_sys_option_bool(rcf_rpc_server *pco_iut, const char *option, te_bool3 set,
                    te_bool *restart)
{
    if (set != TE_BOOL3_ANY)
    {
        CHECK_RC(sockts_cfg_sys_ipv4_set_int(pco_iut->ta, option,
                                             set == TE_BOOL3_TRUE ? 1 : 0,
                                             restart));
    }
    else
    {
        int optval;

        CHECK_RC(sockts_cfg_sys_ipv4_get_int(pco_iut->ta, option, &optval));
        RING("Default value of \"%s\" option is %u.", option, optval);
    }
}

/**
 * Set the capture length and add a sniffer.
 *
 * @param pco_tst           RPC server handle.
 * @param tst_if            Interface for the sniffer.
 *
 * @return Sniffer handler or NULL in case of error.
 */
static tapi_sniffer_id *
sockts_ct_add_sniffer(rcf_rpc_server *pco_tst, const struct if_nameindex *tst_if)
{
    te_errno rc;

    rc = tapi_sniffer_common_snaplen_set(pco_tst->ta, CT_SNIFFER_SNAPLEN);
    if (rc != 0)
    {
        ERROR("Failed to set capture length for sniffer, rc = %r", rc);
        return NULL;
    }

    return tapi_sniffer_add(pco_tst->ta, tst_if->if_name, NULL, "tcp", TRUE);
}

/**
 * Get TCP retransmissions for chunks from pcap file for one direction of
 * connection.
 *
 * @param[in]   sniff           Sniffer handler.
 * @param[in]   ns_addr         Destination address to choose TCP connection and
 *                              direction.
 * @param[in]   chunk_size      Chunk size.
 * @param[out]  retrans         Pointer to array with TCP retansmissions.
 * @param[out]  retrans_size    Pointer to @p retrans size.
 *
 * @note Array with retransmission values @p retrans is allocated in this
 *       function and must be freed after use.
 *
 * @return Status code.
 */
static te_errno
sockts_ct_get_retrans_from_pcap(tapi_sniffer_id *sniff,
                                struct sockaddr *ns_addr,
                                unsigned int chunk_size,
                                int **retrans,
                                unsigned int *retrans_size)
{
    char *caps_path = getenv("TE_SNIFF_LOG_DIR");
    char pcap_file[1024];

    if (caps_path == NULL || strlen(caps_path) == 0)
    {
        ERROR("There is no path to pcap files.");
        return TE_EINVAL;
    }

    RING("File with captured packets: %s_%s_%d_%s.pcap", sniff->ta,
         sniff->ifname, sniff->ssn, sniff->snifname);
    snprintf(pcap_file, sizeof(pcap_file), "%s/%s_%s_%d_%s.pcap", caps_path,
             sniff->ta, sniff->ifname, sniff->ssn, sniff->snifname);
    return sockts_pcap_get_retrans(pcap_file, ns_addr, chunk_size, retrans,
                                   retrans_size);
}

/**
 * Get statistic from app level RTT values and number of TCP retransmissons,
 * print them as artifacts and compare them with acceptable values.
 *
 * @param[in]   rtt_vals        Vector with app level RTT values.
 * @param[in]   retrans_num     Number of TCP retransmissons.
 * @param[in]   acceptable_vals Acceptable values but median value should be
 *                              the difference between it and mean value in
 *                              percentage (@c CT_DONT_CHECK_STAT can be set to
 *                              don't check the statistic).
 * @param[out]  vals            Calculated statistic values.
 * @param[out]  test_failed     @c TRUE if there are unacceptable values.
 *
 * @return Status code.
 */
static te_errno
sockts_ct_get_and_process_stats(te_vec *rtt_vals,
                                int retrans_num,
                                sockts_ct_stats *acceptable_vals,
                                sockts_ct_stats *vals,
                                te_bool *test_failed)
{
    te_errno rc = 0;
    sockts_stats_int rtt_stats;
    double mean_diff;
    unsigned int out_range_num;
    double out_range_percent;

    rc = sockts_stats_int_get(rtt_vals, &rtt_stats);
    if (rc != 0)
        TEST_FAIL("Failed to get app level RTT statistics");

    TEST_ARTIFACT("Median app level RTT = %d us", rtt_stats.median);

    mean_diff = 100 * (((rtt_stats.median > rtt_stats.mean) ?
                  (rtt_stats.median - rtt_stats.mean) :
                  (rtt_stats.mean - rtt_stats.median)) / (double)rtt_stats.median);
    TEST_ARTIFACT("Mean app level RTT = %d us, it is %s than median value by "
                  "%.2f%%", rtt_stats.mean, (rtt_stats.mean > rtt_stats.median) ?
                  "greater" : "lower", mean_diff);
    RING("Maximum acceptable difference between mean and median is %d",
         acceptable_vals->mean);

    out_range_num = sockts_stats_int_out_of_range_num(rtt_vals,
                                                      rtt_stats.median,
                                                      CT_VALID_RANGE_WIDTH,
                                                      NULL, NULL);
    out_range_percent = 100 * out_range_num / (double)te_vec_size(rtt_vals);
    TEST_ARTIFACT("Number of RTT values that are out of %d%% range from median "
                  "= %.2f%%", CT_VALID_RANGE_WIDTH, out_range_percent);
    RING("Maximum acceptable percentage of RTT values that are out of range is %f",
         acceptable_vals->out_of_range);

    TEST_ARTIFACT("Number of TCP retransmissions = %d", retrans_num);
    RING("Maximum acceptable number of TCP retransmissions is %d",
         acceptable_vals->retrans_num);

    if (acceptable_vals->median != CT_DONT_CHECK_STAT &&
        rtt_stats.median > acceptable_vals->median)
    {
        *test_failed = TRUE;
        ERROR_VERDICT("The median of app level RTT values is more than "
                      "acceptable.");
    }
    if (acceptable_vals->mean != CT_DONT_CHECK_STAT &&
        mean_diff > acceptable_vals->mean)
    {
        *test_failed = TRUE;
        ERROR_VERDICT("The difference between mean and median app level "
                      "RTT values is more than acceptable.");
    }
    if (acceptable_vals->out_of_range != CT_DONT_CHECK_STAT &&
        out_range_percent > acceptable_vals->out_of_range)
    {
        *test_failed = TRUE;
        ERROR_VERDICT("The number of RTT values that are out of %d%% range from "
                      "median is more than acceptable.", CT_VALID_RANGE_WIDTH);
    }
    if (acceptable_vals->retrans_num != CT_DONT_CHECK_STAT &&
        retrans_num > acceptable_vals->retrans_num)
    {
        *test_failed = TRUE;
        ERROR_VERDICT("The number of TCP retransmissions is more than "
                      "acceptable.");
    }

    if (vals != NULL)
    {
        vals->mean = rtt_stats.mean;
        vals->median = rtt_stats.median;
        vals->out_of_range = out_range_percent;
        vals->retrans_num = retrans_num;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server                 *pco_iut = NULL;
    rcf_rpc_server                 *pco_tst = NULL;
    rcf_rpc_server                 *pco_ns = NULL;
    tapi_env_net                   *net = NULL;
    struct sockaddr                *ns_addr = NULL;
    const struct if_nameindex      *tst_if = NULL;

    sockts_apprtt_handle           *ol_app_rtt = NULL;
    sockts_apprtt_client_options    client_opts;
    sockts_apprtt_server_options    server_opts;
    te_bool                         test_failed = FALSE;

    te_vec rtt_values_for_stats = TE_VEC_INIT(int);
    te_vec rtt_values = {0};
    int *rtt_val;
    int chunk_size;
    int limit;
    int delay;
    int rate;
    te_bool3 set_ts;
    te_bool3 set_sack;
    te_bool3 set_dsack;

    sockts_ct_stats acceptable_vals;
    sockts_ct_stats stats;
    accept_vals_ids acc_vals_id;

    tapi_sniffer_id    *sniff = NULL;
    te_bool             restart_pco = FALSE;

    tapi_bpf_stim_hdl  *handle = NULL;
    unsigned int        stimulus;
    int                 stimulus_param;
    int                 i;
    unsigned int        slow_start_in_chunks = 0;
    sockts_stats_int    rtt_stats;
    te_bool             slow_start_stim = FALSE;
    int                 retrans_num = 0;
    int                *retrans = NULL;
    unsigned int        retrans_size;
    int timeout_s;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net);
    TEST_GET_INT_PARAM(limit);
    TEST_GET_INT_PARAM(chunk_size);
    TEST_GET_INT_PARAM(delay);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL3_PARAM(set_ts);
    TEST_GET_BOOL3_PARAM(set_sack);
    TEST_GET_BOOL3_PARAM(set_dsack);
    TEST_GET_CT_STIMULUS_PARAM(stimulus);
    TEST_GET_INT_PARAM(stimulus_param);
    TEST_GET_INT_PARAM(rate);

    TEST_STEP("Set TCP options");
    TEST_SUBSTEP("Set \"tcp_timestamps\" option according to @p set_ts");
    set_sys_option_bool(pco_iut, "tcp_timestamps", set_ts, &restart_pco);

    TEST_SUBSTEP("Set \"tcp_sack\" option according to @p set_sack");
    set_sys_option_bool(pco_iut, "tcp_sack", set_sack, &restart_pco);

    TEST_SUBSTEP("Set \"tcp_dsack\" option according to @p set_dsack");
    set_sys_option_bool(pco_iut, "tcp_dsack", set_dsack, &restart_pco);

    /* Make sure Onload stack gets all configurations. */
    if (restart_pco)
        CHECK_RC(rcf_rpc_server_restart(pco_iut));

    /* Sniffer adds additional traffic to connection between Test Agent and
     * Engine. And it goes via home network. So need to be careful and check
     * that sniffer doesn't add too much load on the network (see ST-2153).
     */
    TEST_STEP("Add sniffer on Tester to capture packets.");
    sniff = sockts_ct_add_sniffer(pco_tst, tst_if);
    if (sniff == NULL)
        TEST_FAIL("Failed to start a sniffer");
    CFG_WAIT_CHANGES;

    sockts_ct_get_ns_rpcs(&pco_ns);
    sockts_ct_get_ns_veth_net_addr(pco_ns, net, &ns_addr);

    if (stimulus == TAPI_BPF_STIM_STIMULUS_SLOW_START)
    {
        slow_start_stim = TRUE;
        stimulus = TAPI_BPF_STIM_STIMULUS_NONE;
    }

    TEST_STEP("Load and link to the interface a BPF program for @p stimulus if "
              "it isn't @c TAPI_BPF_STIM_STIMULUS_NONE");
    tapi_bpf_stim_init(pco_tst, tst_if->if_name, stimulus, FALSE, &handle);

    if (tapi_onload_lib_exists(pco_iut->ta))
        client_opts.prefix = PATH_TO_TE_ONLOAD;
    else
        client_opts.prefix = NULL;
    client_opts.srv_addr = ns_addr;
    client_opts.chunk_size = server_opts.chunk_size = chunk_size;
    server_opts.prefix = NULL;
    /* Test duration is @c CT_APPRTT_DURATION_SEC seconds but if @p stimulus
     * slow start is tested, the duration is @CT_SLOW_START_TIMEOUT seconds.
     */
    if (!slow_start_stim)
        client_opts.time_to_run = CT_APPRTT_DURATION_SEC;
    else
        client_opts.time_to_run = CT_SLOW_START_TIMEOUT;

    TEST_STEP("Set parameters of traffic shaping on bottleneck and set delay "
              "of packets.");
    sockts_ct_set_btlnck_tbf_params(pco_tst->ta,
                                    CT_MBIT_PER_SEC2BYTES_PER_SEC(rate),
                                    CT_BTLNCK_TBF_DEFAULT_BURST,
                                    limit);
    sockts_ct_set_btlnck_netem_delay(pco_tst->ta, delay);

    TEST_STEP("Create client and server of ol-apprtt.");
    CHECK_RC(sockts_apprtt_create(pco_iut, &client_opts,
                                  pco_ns, &server_opts,
                                  &ol_app_rtt));

    TEST_STEP("Start client and server of ol-apprtt.");
    CHECK_RC(sockts_apprtt_start(ol_app_rtt));

    if (stimulus != TAPI_BPF_STIM_STIMULUS_NONE)
    {
        TEST_STEP("If @p stimulus parameter isn't @c TAPI_BPF_STIM_STIMULUS_NONE, i.e. we "
                  "are going to trigger stimulus, then");
        TEST_SUBSTEP("Wait @c CT_SLOW_START_TIMEOUT seconds for slow start.");
        VSLEEP(CT_SLOW_START_TIMEOUT, "Wait for slow start...");

        TEST_SUBSTEP("Trigger the @p stimulus @c CT_STIM_NUM times with "
                     "@c CT_REACTION_TIMEOUT seconds timeout for reaction.");
        for (i = 0; i < CT_STIM_NUM; i++)
        {
            switch (stimulus)
            {
                case TAPI_BPF_STIM_STIMULUS_DROP:
                    CHECK_RC(tapi_bpf_stim_drop(handle, stimulus_param));
                    break;

                case TAPI_BPF_STIM_STIMULUS_DUPLICATE:
                    CHECK_RC(tapi_bpf_stim_dup(handle, stimulus_param));
                    break;

                case TAPI_BPF_STIM_STIMULUS_DELAY:
                    CHECK_RC(tapi_bpf_stim_delay(handle, stimulus_param));
                    break;

                default:
                    if (!test_failed)
                    {
                        ERROR_VERDICT("Unknown stimulus");
                        test_failed = TRUE;
                    }
                    break;
            }
            VSLEEP(CT_REACTION_TIMEOUT, "Wait for reaction on stimulus...");
        }
    }

    TEST_STEP("Wait for ol-apprtt completion.");
    timeout_s = CT_APPRTT_DURATION_SEC;
    if (CT_APPRTT_EXTRA_TIMEOUT_COND)
        timeout_s += CT_APPRTT_EXTRA_TIMEOUT;
    CHECK_RC(sockts_apprtt_wait(ol_app_rtt, TE_SEC2MS(timeout_s) +
                                            pco_iut->def_timeout));
    TAPI_WAIT_NETWORK;
    CHECK_RC(tapi_sniffer_del(sniff));

    TEST_STEP("Get application level RTT values returned by ol-apprtt.");
    CHECK_RC(sockts_apprtt_getrtt_silent(ol_app_rtt, &rtt_values, TRUE, pco_iut,
                                         pco_ns));

    if (slow_start_stim && set_sack == TE_BOOL3_TRUE)
        acc_vals_id = CT_SLOW_START_ID;
    else if (slow_start_stim)
        acc_vals_id = CT_SLOW_START_NOSACK_ID;
    else if (limit <= CT_SMALL_BUFF_MAX)
        acc_vals_id = CT_SMALL_BUF_ID;
    else if (rate > CT_DEFAULT_RATE)
        acc_vals_id = CT_HIGH_RATE_ID;
    else
        acc_vals_id = CT_NORMAL_BUF_ID;

    acceptable_vals.median = acc_vals_map[acc_vals_id].median;
    acceptable_vals.mean = acc_vals_map[acc_vals_id].mean;
    acceptable_vals.out_of_range = acc_vals_map[acc_vals_id].out_of_range;
    acceptable_vals.retrans_num = acc_vals_map[acc_vals_id].retrans_num;

    /*
     * Dropped and duplicated packets significantly increase the
     * number of TCP retransmissions.
     */
    if (stimulus == TAPI_BPF_STIM_STIMULUS_DROP ||
        stimulus == TAPI_BPF_STIM_STIMULUS_DUPLICATE)
    {
        acceptable_vals.retrans_num += stimulus_param * CT_STIM_NUM;
    }

    /*
     * ST-2559: big stimulus parameter value leads to rare RTT splashes which
     * increases the difference between mean and median RTT values. We should
     * accept it.
     */
    if (CT_AGGRESSIVE_STIMULUS)
        acceptable_vals.mean = CT_AGGR_STIM_MEAN;

    if (!slow_start_stim)
    {
        rc = sockts_stats_int_get(&rtt_values, &rtt_stats);
        if (rc != 0)
            TEST_FAIL("Failed to get app level RTT statistics");
        /* Formula to calculate the number of chunks in slow start:
         * N = (5 * throughput_bytes_per_sec * app_rtt_in_us) / 1000000 / chunk_size,
         * where 5 is the coefficient from experiments with Linux CUBIC algorithm and
         * app_rtt_in_us - the median of all app level RTT values of TCP connection.
         */
        slow_start_in_chunks = (5ull * CT_BTLNCK_TBF_DEFAULT_RATE * rtt_stats.median) /
                               chunk_size / 1000000;
    }
    i = 0;
    TE_VEC_FOREACH(&rtt_values, rtt_val)
    {
        if (i >= slow_start_in_chunks)
            TE_VEC_APPEND(&rtt_values_for_stats, *rtt_val);
        i++;
    }
    if (te_vec_size(&rtt_values_for_stats) == 0)
    {
        /* This can happen if app level RTT values are too high */
        ERROR("Total number of sent chunks is %u, number of chunks in slow "
              "start is %u", te_vec_size(&rtt_values), slow_start_in_chunks);
        TEST_VERDICT("The number of app level RTT values is not enough for "
                     "analysis");
    }

    TEST_STEP("Get stats from RTT values and number of retransmissons from "
              "captured pcap file (don't get into account slow start state "
              "if @p stimulus isn't slow start).");
    TEST_SUBSTEP("Calculate the median app level RTT value.");
    TEST_SUBSTEP("Calculate the mean app level RTT value and the percentage "
                 "by how much the mean is greater or lower than the median.");
    TEST_SUBSTEP("Calculate the percent of values that are out of the [A, B] "
                 "range where A = median - @c CT_VALID_RANGE_WIDTH percent "
                 "and B = median + @c CT_VALID_RANGE_WIDTH percent.");
    TEST_SUBSTEP("Calculate the number of TCP retransmissions.");
    TEST_STEP("Check that statistics are acceptable.");
    CHECK_RC(sockts_ct_get_retrans_from_pcap(sniff, ns_addr, chunk_size,
                                             &retrans, &retrans_size));
    /* Skip the first @p slow_start_in_chunks chunks in total sum of TCP
     * retransmissions.
     */
    for (i = slow_start_in_chunks; i < retrans_size; i++)
        retrans_num += retrans[i];
    rc = sockts_ct_get_and_process_stats(&rtt_values_for_stats, retrans_num,
                                         &acceptable_vals, &stats, &test_failed);
    if (rc != 0)
        TEST_FAIL("Failed to process test statistics.");

    TEST_STEP("Print MI logs.");
    RING("App level RTT values and TCP retransmissions for the first %u chunks "
         "aren't counted in statistics.", slow_start_in_chunks);
    CHECK_RC(sockts_apprtt_mi_report_rtt(&rtt_values));
    CHECK_RC(sockts_pcap_mi_report_retrans(retrans, retrans_size));
    CHECK_RC(te_mi_log_meas("ol-apprtt",
        TE_MI_MEAS_V(TE_MI_MEAS(RTT, "App level RTT", MEDIAN, stats.median, MICRO),
                     TE_MI_MEAS(RTT, "App level RTT", MEAN, stats.mean, MICRO),
                     TE_MI_MEAS(RTT, "App level RTT", OUT_OF_RANGE,
                                stats.out_of_range, PLAIN),
                     TE_MI_MEAS(RETRANS, "Number of TCP retransmissions",
                                SINGLE, stats.retrans_num, PLAIN)),
        NULL, NULL));

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(sockts_apprtt_destroy(ol_app_rtt));
    tapi_bpf_stim_del(handle);
    te_vec_free(&rtt_values);
    te_vec_free(&rtt_values_for_stats);
    free(retrans);
    free(ns_addr);
    TEST_END;
}
