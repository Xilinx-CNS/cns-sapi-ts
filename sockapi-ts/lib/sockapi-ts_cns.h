/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI for checking Calico-style network namespace
 *
 * Definitions for TAPI for checking Calico-style network namespace
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_CNS_H__
#define __SOCKAPI_TS_CNS_H__

/**
 * Configure Calico-style network namespace on IUT, creating
 * TA and RPC server inside it (if --ool=netns_calico was not
 * specified, this function does nothing).
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param ta    Test Agent on IUT.
 */
extern void sockts_cns_setup(const char *ta);

/**
 * Remove Calico-style namespace, TA in it and auxiliary interfaces.
 *
 * @note This function jumps to cleanup in case of failure.
 *
 * @param ta      Name of Test Agent running in default network namespace.
 */
extern void sockts_cns_cleanup(const char *ta);

/**
 * Get network addresses assigned to an interface inside Calico-style
 * namespace.
 *
 * @param ip4_addr        Where to save IPv4 address.
 * @param ip6_addr        Where to save IPv6 address.
 *
 * @return Status code.
 */
extern te_errno sockts_cns_get_addrs(struct sockaddr_storage *ip4_addr,
                                     struct sockaddr_storage *ip6_addr);


/**
 * Get RPC server created inside Calico-style namespace.
 *
 * @param pco_iut       RPC server on IUT in default namespace.
 * @param no_reuse_pco  If @c TRUE, existing RPC server inside namespace
 *                      should not be reused.
 * @param rpcs          Where to save pointer to created RPC server.
 *
 * @return Status code.
 */
extern te_errno sockts_cns_get_rpcs(rcf_rpc_server *pco_iut,
                                    te_bool no_reuse_pco,
                                    rcf_rpc_server **rpcs);

/**
 * Declare common parameters for tests checking Calico-style
 * network namespace.
 */
#define SOCKTS_CNS_DECLARE_PARAMS \
    const char        *env_calico = NULL;                   \
    te_bool            test_calico = FALSE;                 \
    rcf_rpc_server    *pco_iut_cns = NULL;                  \
    te_bool            no_reuse_pco = FALSE;                \
                                                            \
    struct sockaddr_storage  iut_addr4_cns;                 \
    struct sockaddr_storage  iut_addr6_cns;                 \
    struct sockaddr         *iut_addr_cns = NULL;           \
                                                            \
    /*                                                      \
     * This should be got before processing                 \
     * environment - it can be reset after obtaining        \
     * RPC servers.                                         \
     */                                                     \
    CHECK_RC(tapi_no_reuse_pco_get(&no_reuse_pco))

/**
 * Obtain values of common parameters for tests checking Calico-style
 * network namespace (if --ool=netns_calico was not specified,
 * values are not obtained).
 *
 * @param _af       Address family
 */
#define SOCKTS_CNS_GET_PARAMS(_af) \
    do {                                                                \
        env_calico = getenv("SOCKAPI_TS_NETNS_CALICO");                 \
        if (env_calico != NULL && strcmp(env_calico, "true") == 0)      \
        {                                                               \
            test_calico = TRUE;                                         \
            CHECK_RC(sockts_cns_get_rpcs(                               \
                                      pco_iut,                          \
                                      no_reuse_pco, &pco_iut_cns));     \
            CHECK_RC(sockts_cns_get_addrs(&iut_addr4_cns,               \
                                          &iut_addr6_cns));             \
            if (_af == AF_INET)                                         \
                iut_addr_cns = SA(&iut_addr4_cns);                      \
            else                                                        \
                iut_addr_cns = SA(&iut_addr6_cns);                      \
                                                                        \
            CHECK_RC(tapi_allocate_port_htons(                          \
                        pco_iut_cns,                                    \
                        te_sockaddr_get_port_ptr(iut_addr_cns)));       \
        }                                                               \
    } while (0)

/**
 * Perform cleanup after testing Calico-style namespace.
 */
#define SOCKTS_CNS_CLEANUP \
    do {                                              \
        if (!test_calico)                             \
            break;                                    \
                                                      \
        if (pco_iut_cns->timed_out)                   \
            rcf_rpc_server_restart(pco_iut_cns);      \
        free(pco_iut_cns);                            \
    } while (0)

#endif /* !__SOCKAPI_TS_CNS_H__ */
