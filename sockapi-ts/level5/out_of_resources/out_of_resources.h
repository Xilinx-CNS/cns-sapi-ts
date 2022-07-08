/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Data types and macros for level5-specific tests on
 * out-of-resources behaviour.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __LEVEL5_OUT_OF_RESOURCES_H__
#define __LEVEL5_OUT_OF_RESOURCES_H__

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_ip4.h"

/* Environment variable name to keep HW filters number. */
#define TE_HW_FILTERS "TE_HW_FILTERS_NUM"

/* Comparison precision */
#define PRECISION 0.05

/* Multiplier to make sure that hw filter limit will be reached */
#define HW_FILTERS_MULT 1.01
/**
 * Change rlimits on the RPC Agent
 *
 * @param pco       RPC server
 * @param resource  Resource to change limits
 * @param max_value New resource limit
 */
static inline void
change_rlimits(rcf_rpc_server *pco, int resource, rlim_t max_value)
{
    tarpc_rlimit rlim = {0, 0};

    rpc_getrlimit(pco, resource, &rlim);

    rlim.rlim_cur = max_value;
    rlim.rlim_max = max_value;

    rpc_setrlimit(pco, resource, &rlim);
}

/**
 * Get HW filters number.
 * 
 * @param pco RPC server
 * 
 * @return HW filters number
 */
static inline int
get_hw_filters_limit(rcf_rpc_server *pco)
{
    int val;
    if (rpc_getenv_int(pco, TE_HW_FILTERS, &val) != 0)
        TEST_FAIL("Could not get HW filters number");

    return val;
}

/**
 * Approximate comparison of two int numbers
 * 
 * @param v1  First number
 * @param v2  Second number
 * 
 * @return @c -1 if v1 < v2
 *         @c  1 if v1 > v2
 *         @c  0 if v1 == v2
 */
static inline int
approx_cmp(int v1, int v2)
{
    if (v1 > v2 * (1 + PRECISION))
        return 1;
    else if (v1 < v2 * (1 - PRECISION))
        return -1;
    return 0;
}

/**
 * Create CSAP listener for UDP packets.
 * 
 * @param rpcs   RPC server
 * @param iface  Interface to be listened
 * @param start  Start packets capture
 * 
 * @return CSAP handler
 */
static inline csap_handle_t
create_listener_csap_ext(rcf_rpc_server *rpcs,
                         const struct if_nameindex *iface, te_bool start)
{
    csap_handle_t csap;

    CHECK_RC(tapi_ip4_eth_csap_create(rpcs->ta, 0, iface->if_name,
        TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC, NULL, NULL,
        htonl(INADDR_ANY), htonl(INADDR_ANY), IPPROTO_UDP, &csap));

    if (start)
        CHECK_RC(tapi_tad_trrecv_start(rpcs->ta, 0, csap, NULL,
                                       TAD_TIMEOUT_INF, 0,
                                       RCF_TRRECV_COUNT));

    return csap;
}

/**
 * Create and start CSAP listener for UDP packets.
 * 
 * @param rpcs   RPC server
 * @param iface  Interface to be listened
 * 
 * @return CSAP handler
 */
static inline csap_handle_t
create_listener_csap(rcf_rpc_server *rpcs, const struct if_nameindex *iface)
{
    return create_listener_csap_ext(rpcs, iface, TRUE);
}

/**
 * Set LDPRELOAD environment variable to value from configuration.
 *
 * @param pco           RPC server
 *
 * @return Status code.
 */
extern te_errno set_ldpreload_library(rcf_rpc_server *pco);

/**
 * Set LD_PRELOAD and RLIMIT_NOFILE
 *
 * @param pco           RPC server
 * @param rlimit_nofile Required value of RLIMIT_NOFILE
 */
static inline void
prepare_parent_pco(rcf_rpc_server *pco, unsigned int rlimit_nofile)
{
    sockts_inc_rlimit(pco, RPC_RLIMIT_NOFILE, rlimit_nofile);
    set_ldpreload_library(pco);
}

/**
 * Check requested, opened and accelerated sockets numbers.
 * 
 * @param ef_no_fail      Corresponds to EF_NO_FAIL env value
 * @param requested       Requested sockets number to be created
 * @param opened          Atually opened sockets number
 * @param accelerated     Accelerated sockets number
 * @param errors          Errors number
 * @param hw_filters_max  HW filters limit
 * @param hw_filters      Current number of HW filters.
 *                        May be @c -1 if it's unknown.
 */
extern void hw_filters_check_results(te_bool ef_no_fail, int requested,
                                     int opened, int accelerated,
                                     int errors, int hw_filters_max,
                                     int hw_filters);


/**
 * Get current HW filters number of all wild sockets.
 *
 * @param rpcs   RPC server
 *
 * @return Number of HW filters
 */
extern int get_wild_sock_hw_filters_num(rcf_rpc_server *rpcs);

/**
 * Count IPv4 addresses number which are involved in HW flters using.
 *
 * @param ta    Test agent name
 * @param num   Addresses number
 *
 * @return Status code
 */
extern te_errno count_involved_addresses(const char *ta, int *num);

#endif /* !__LEVEL5_OUT_OF_RESOURCES_H__ */
