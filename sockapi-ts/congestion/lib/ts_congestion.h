/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Congestion Test Suite
 *
 * Helper definitions for congestion tests.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#ifndef __TS_SOCKTS_CONGESTION_H__
#define __TS_SOCKTS_CONGESTION_H__

/** Convert Mbit per sec to bytes per sec */
#define CT_MBIT_PER_SEC2BYTES_PER_SEC(_val) ((_val) * 125000)

/** Default value for tc qdisc tbf in bytes per second (10 Mbit/s) */
#define CT_BTLNCK_TBF_DEFAULT_RATE CT_MBIT_PER_SEC2BYTES_PER_SEC(10)

/** Default value for tc qdisc tbf burst in bytes */
#define CT_BTLNCK_TBF_DEFAULT_BURST 1600

/** Default value for tc qdisc tbf limit in bytes */
#define CT_BTLNCK_TBF_DEFAULT_LIMIT 50000

/** Default value for tc qdisc netem delay in milliseconds */
#define CT_RECEIVER_NETEM_DEFAULT_DELAY_MS 50

/**
 * Get congestion testing parameter from /local: subtree.
 *
 * @note Returned string should be freed after usage.
 *
 * @param name      Name of congestion testing parameter.
 *
 * @return String value of @p name congestion parameter.
 */
extern char * sockts_ct_param_get(const char *name);

/**
 * Configure network on TST for congestion testing. Create 2 pairs of VETHs,
 * 2 Linux bridges and network namespace on @p ta. First VETHs pair is
 * bottleneck where traffic will be shaped. Second VETHs pair is used for
 * connection with namespace. Bridges are needed to make link between @p ifname
 * and interface in namespace.
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param ta        Test Agent on TST.
 * @param ifname    Interface name on TST to connect with first bridge.
 * @param net       Network in which to allocate address for interface inside
 *                  namespace.
 */
extern void sockts_ct_tst_net_setup(const char *ta, const char *ifname,
                                    tapi_env_net *net);

/**
 * Remove network setup for congestion testing on TST.
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param ta      Name of Test Agent running in default network namespace.
 */
extern void sockts_ct_tst_net_cleanup(const char *ta);

/**
 * Get RPC server created inside namespace.
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param rpcs          Where to save pointer to created RPC server.
 */
extern void sockts_ct_get_ns_rpcs(rcf_rpc_server **rpcs);

/**
 * Set tc qdisc tbf parameters on bottleneck interface.
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param ta        Test Agent on TST.
 * @param rate      Rate of tbf.
 * @param burst     Burst of tbf.
 * @param limit     Limit of tbf.
 */
extern void sockts_ct_set_btlnck_tbf_params(const char *ta, int rate, int burst,
                                            int limit);

/**
 * Set tc qdisc netem delay on @p receiver_first_veth_name interface on TST.
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param ta        Test Agent on TST.
 * @param delay     Delay of packets in milliseconds.
 */
extern void sockts_ct_set_btlnck_netem_delay(const char *ta, int delay);

/**
 * Get IPv4 address of VETH interface in namespace.
 *
 * @note Returned address should be freed after usage.
 *       This function jumps to cleanup in case of failure.
 *
 * @param[in]  pco_ns   RPC server on agent in namespace.
 * @param[in]  net      Network handler.
 * @param[out] ns_addr  Pointer to the address.
 */
extern void sockts_ct_get_ns_veth_net_addr(rcf_rpc_server *pco_ns,
                                           tapi_env_net *net,
                                           struct sockaddr **ns_addr);

#endif /* __TS_SOCKTS_CONGESTION_H__ */
