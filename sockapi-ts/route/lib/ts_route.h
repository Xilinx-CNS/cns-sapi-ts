/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Route Test Suite
 *
 * Helper definitions for route tests.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef __TS_SOCKTS_ROUTE_H__
#define __TS_SOCKTS_ROUTE_H__

#include "sockapi-ts_monitor.h"

#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_test.h"
#include "te_rpc_sys_socket.h"
#include "rcf_common.h"
#include "te_dbuf.h"
#include "sockapi-ts_cns.h"

/** ID of the first routing table to be used in tests. */
#define SOCKTS_RT_TABLE_FOO       111
/** ID of the second routing table to be used in tests. */
#define SOCKTS_RT_TABLE_BAR       120

/** Default value of IP TOS (used when IP TOS is tested). */
#define SOCKTS_RT_DEF_TOS 0x04

/**
 * A value of IP TOS used when we need TOS different
 * from default one.
 */
#define SOCKTS_RT_ANOTHER_TOS 0x1C

/** Offset of a TOS value inside a TOS byte in IP header. */
#define SOCKTS_IPTOS_OFFSET 2

/**
 * Obtain value of IP_TOS socket option by shifting
 * a given value to skip currently unused TOS bits.
 *
 * @param val_    Value to set for IP_TOS.
 */
#define SOCKTS_IPTOS_VAL(val_) \
    (val_ << SOCKTS_IPTOS_OFFSET)

/** Type of routes supported */
typedef enum route_type_e {
    DIRECT, /**< Direct route - via interface */
    INDIRECT, /**< Indirect route - via gateway */
} route_type_t;

/**
 * The list of values allowed for parameter of type 'route_type_t'
 */
#define ROUTE_TYPE_MAPPING_LIST \
            { "direct", (int)DIRECT }, \
            { "indirect", (int)INDIRECT }

/**
 * Get the value of parameter of type 'route_type_t'
 *
 * @param var_name_  Name of the variable used to get the value of
 *                   "var_name_" parameter of type 'route_type_t' (OUT)
 */
#define TEST_GET_ROUTE_TYPE_PARAM(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, ROUTE_TYPE_MAPPING_LIST)

/**
 * List of socket types to be passed to TEST_GET_ENUM_PARAM().
 */
#define SOCKTS_RT_SOCK_TYPES \
    { "tcp_active",             SOCKTS_SOCK_TCP_ACTIVE },       \
    { "tcp_passive",            SOCKTS_SOCK_TCP_PASSIVE_CL },   \
    { "udp",                    SOCKTS_SOCK_UDP_NOTCONN },      \
    { "udp_connect",            SOCKTS_SOCK_UDP }

/** Get socket type. */
#define SOCKTS_GET_RT_SOCK_TYPE(_sock_type) \
    TEST_GET_ENUM_PARAM(_sock_type, SOCKTS_RT_SOCK_TYPES)

/** Error code reported by some TAPI calls. */
enum sockts_rt_error_code {
    SOCKTS_RT_ERR_SEND_RECV = 1,  /**< Error occurred when checking
                                       send/recv */
    SOCKTS_RT_ERR_RPC_CONNECT,    /**< Connect function failed. */
    SOCKTS_RT_ERR_NOT_ACCEPTED,   /**< Listener socket did not become
                                       readable as expected. */
    SOCKTS_RT_ERR_RPC_SETSOCKOPT, /**< Error when setting socket option. */
    SOCKTS_RT_ERR_RPC_GETSOCKOPT, /**< Error when getting socket option. */
    SOCKTS_RT_ERR_WRONG_IUT_ADDR, /**< Wrong address was used on IUT. */
};

/** Structure describing error reported by TAPI call. */
typedef struct sockts_rt_error  {
    int                    err_code;      /**< Error code. */

    rcf_rpc_server        *rpcs;          /**< RPC server pointer. */
    te_errno               rpc_errno;     /**< Saved errno. */
    sockts_test_send_rc    test_send_err; /**< Error returned by
                                               sockts_test_send_ext() */
} sockts_rt_error;

/** Description of error encountered in the last TAPI method call. */
extern sockts_rt_error rt_error;

/**
 * Check that rt_error matches expectation.
 *
 * @param exp_error       Description of expected error.
 */
extern te_bool sockts_rt_error_check(sockts_rt_error *exp_error);

/**
 * Convert error description to string.
 *
 * @param err       Error description.
 *
 * @return String representation.
 */
extern const char *sockts_rt_error2str(sockts_rt_error *err);

/** Value of IP_TOS to be set for sockets (if non-negative). */
extern int sockts_rt_opt_tos;

/**
 * Interface name for SO_BINDTODEVICE socket option on
 * IUT socket (will be set if not empty).
 */
extern char sockts_rt_opt_iut_bind_dev[IFNAMSIZ];

/**
 * Check value returned by a TAPI call which can return
 * non-zero and set rt_error on failure, print error message
 * and stop testing if it is non-zero.
 *
 * @param expr_   Expression to check.
 */
#define SOCKTS_RT_CHECK_RC(expr_) \
    do {                                                        \
        int rc_;                                                \
                                                                \
        rc_ = (expr_);                                          \
        if (rc_ != 0)                                           \
        {                                                       \
            TEST_FAIL("%s line %d: %s fails with error %s",     \
                      __FILE__, __LINE__, # expr_,              \
                      sockts_rt_error2str(&rt_error));          \
        }                                                       \
    } while (0)

/*
 * Macros used for Calico-style namespace testing. SOCKTS_RT_CNS_SUPPORT
 * should be defined in a test supporting such testing before including
 * this header file.
 */
#ifdef SOCKTS_RT_CNS_SUPPORT

/**
 * Declare common parameters for tests checking Calico-style
 * network namespace.
 */
#define SOCKTS_RT_CNS_DECLARE_PARAMS SOCKTS_CNS_DECLARE_PARAMS

/**
 * Declare common parameters for tests with two interfaces checking
 * Calico-style network namespace.
 */
#define SOCKTS_RT_CNS_DECLARE_TWO_IFS_PARAMS \
    cfg_handle               rt_cns1 = CFG_HANDLE_INVALID;  \
    cfg_handle               rt_cns2 = CFG_HANDLE_INVALID

/**
 * Obtain values of common parameters for tests checking Calico-style
 * network namespace (if --ool=netns_calico was not specified,
 * values are not obtained).
 *
 * @param _af   Address family
 */
#define SOCKTS_RT_CNS_GET_PARAMS(_af) SOCKTS_CNS_GET_PARAMS(_af)

/**
 * Perform cleanup after testing Calico-style namespace.
 */
#define SOCKTS_RT_CNS_CLEANUP SOCKTS_CNS_CLEANUP

/**
 * In a test checking traffic routing over one of the two interfaces,
 * add a route to an address inside Calico-style namespace
 * via appropriate Tester interface (removing existing route to that
 * address if necessary), so that Tester can send data back via
 * expected path (does nothing if --ool=netns_calico was not used).
 *
 * @note Removing the previous route is necessary because sometimes
 *       there is the single Tester host with two interfaces connected
 *       to IUT, not two different Tester hosts.
 *
 * @param _first_path   Whether traffic should go over the first
 *                      IUT interface.
 */
#define TWO_IFS_CNS_ROUTE(_first_path) \
    do {                                                              \
        cfg_handle            *_rt_to_del;                            \
        cfg_handle            *_rt_to_add;                            \
        const struct sockaddr *_gw_addr;                              \
        const char            *_tst_ta;                               \
        const char            *_if_name;                              \
                                                                      \
        if (!test_calico)                                             \
            break;                                                    \
                                                                      \
        if (_first_path)                                              \
        {                                                             \
            _rt_to_add = &rt_cns1;                                    \
            _rt_to_del = &rt_cns2;                                    \
            _tst_ta = pco_tst1->ta;                                   \
            _gw_addr = iut_addr1;                                     \
            _if_name = tst1_if->if_name;                              \
        }                                                             \
        else                                                          \
        {                                                             \
            _rt_to_add = &rt_cns2;                                    \
            _rt_to_del = &rt_cns1;                                    \
            _tst_ta = pco_tst2->ta;                                   \
            _gw_addr = iut_addr2;                                     \
            _if_name = tst2_if->if_name;                              \
        }                                                             \
                                                                      \
        if (*_rt_to_del != CFG_HANDLE_INVALID)                        \
        {                                                             \
            CHECK_RC(cfg_del_instance(*_rt_to_del, FALSE));           \
            *_rt_to_del = CFG_HANDLE_INVALID;                         \
        }                                                             \
                                                                      \
        CHECK_RC(tapi_cfg_add_route(                                  \
                   _tst_ta,                                           \
                   iut_addr_cns->sa_family,                           \
                   te_sockaddr_get_netaddr(iut_addr_cns),             \
                   te_netaddr_get_bitsize(iut_addr_cns->sa_family),   \
                   te_sockaddr_get_netaddr(_gw_addr),                 \
                   _if_name, NULL,                                    \
                   0, 0, 0, 0, 0, 0, _rt_to_add));                    \
    } while (0)

/**
 * Add a route to an address inside Calico-style namespace on Tester,
 * so that Tester can send data back (this macro is for tests with routes
 * over the single interface). Does nothing if --ool=netns_calico was not
 * used.
 */
#define SINGLE_IF_CNS_ROUTE \
    do {                                                              \
        if (!test_calico)                                             \
            break;                                                    \
        CHECK_RC(tapi_cfg_add_route(                                  \
                   pco_tst->ta,                                       \
                   iut_addr_cns->sa_family,                           \
                   te_sockaddr_get_netaddr(iut_addr_cns),             \
                   te_netaddr_get_bitsize(iut_addr_cns->sa_family),   \
                   te_sockaddr_get_netaddr(iut_addr),                 \
                   tst_if->if_name, NULL,                             \
                   0, 0, 0, 0, 0, 0, NULL));                          \
    } while (0)

/** RPC server on which IUT socket should be created */
#define SOCKTS_RT_PCO_IUT_SOCK   (test_calico ? pco_iut_cns : pco_iut)

/** The single IP address on IUT */
#define SOCKTS_RT_IUT_ADDR       (test_calico ? iut_addr_cns : iut_addr)

/** The first IP address on IUT */
#define SOCKTS_RT_IUT_ADDR1      (test_calico ? iut_addr_cns : iut_addr1)

/**
 * The second IP address on IUT (the same as the first when checking
 * Calico-style namespace)
 */
#define SOCKTS_RT_IUT_ADDR2      (test_calico ? iut_addr_cns : iut_addr2)

/**
 * Evaluates to @c TRUE if Calico-style namespace is checked
 * and to @c FALSE otherwise.
 */
#define SOCKTS_RT_CNS_TEST       test_calico

#else /* ndef SOCKTS_RT_CNS_SUPPORT */

/*
 * Definitions of some macros for the case when Calico-style
 * namespace testing is not supported.
 */

#define SOCKTS_RT_PCO_IUT_SOCK   pco_iut
#define SOCKTS_RT_IUT_ADDR       iut_addr
#define SOCKTS_RT_IUT_ADDR1      iut_addr1
#define SOCKTS_RT_IUT_ADDR2      iut_addr2

#define SOCKTS_RT_CNS_DECLARE_PARAMS
#define SOCKTS_RT_CNS_DECLARE_TWO_IFS_PARAMS
#define SOCKTS_RT_CNS_GET_PARAMS(_af)
#define SOCKTS_RT_CNS_CLEANUP

#define TWO_IFS_CNS_ROUTE(_first_path)
#define SINGLE_IF_CNS_ROUTE

#define SOCKTS_RT_CNS_TEST       FALSE

#endif /* SOCKTS_RT_CNS_SUPPORT */

/**
 * Declare common parameters for a test with two interfaces.
 */
#define DECLARE_TWO_IFS_COMMON_PARAMS \
    rcf_rpc_server            *pco_iut = NULL;        \
    rcf_rpc_server            *pco_tst1 = NULL;       \
    rcf_rpc_server            *pco_tst2 = NULL;       \
    const struct if_nameindex *iut_if1 = NULL;        \
    const struct if_nameindex *iut_if2 = NULL;        \
    const struct if_nameindex *tst1_if = NULL;        \
    const struct if_nameindex *tst2_if = NULL;        \
    const struct sockaddr     *tst1_addr = NULL;      \
    const struct sockaddr     *tst2_addr = NULL;      \
    const struct sockaddr     *iut_addr1 = NULL;      \
    const struct sockaddr     *iut_addr2 = NULL;      \
    const struct sockaddr     *alien_addr = NULL;     \
    const struct sockaddr     *alien_gw = NULL;       \
    tapi_env_net              *net1 = NULL;           \
    te_bool                    single_peer = FALSE;   \
    SOCKTS_RT_CNS_DECLARE_PARAMS;                     \
    SOCKTS_RT_CNS_DECLARE_TWO_IFS_PARAMS

/**
 * Get values of common parameters for a test with two interfaces.
 */
#define GET_TWO_IFS_COMMON_PARAMS \
    TEST_GET_PCO(pco_iut);                            \
    TEST_GET_PCO(pco_tst1);                           \
    TEST_GET_PCO(pco_tst2);                           \
    TEST_GET_NET(net1);                               \
    TEST_GET_IF(iut_if1);                             \
    TEST_GET_IF(iut_if2);                             \
    TEST_GET_IF(tst1_if);                             \
    TEST_GET_IF(tst2_if);                             \
    TEST_GET_ADDR(pco_iut, iut_addr1);                \
    TEST_GET_ADDR(pco_iut, iut_addr2);                \
    TEST_GET_ADDR(pco_tst1, tst1_addr);               \
    TEST_GET_ADDR(pco_tst2, tst2_addr);               \
    TEST_GET_ADDR(pco_tst1, alien_addr);              \
    TEST_GET_ADDR(pco_tst1, alien_gw);                \
    SOCKTS_RT_CNS_GET_PARAMS(iut_addr1->sa_family);   \
                                                      \
    if (strcmp(pco_tst1->ta, pco_tst2->ta) == 0)      \
        single_peer = TRUE

/**
 * Add the same address on Tester hosts.
 *
 * @param single_peer_  Whether there is only one Tester host.
 * @param addr_         Network address.
 * @param hndl1_        Pointer to configuration handle for
 *                      the address on the first host.
 * @param hndl2_        Pointer to configuration handle for
 *                      the address on the second host.
 */
#define TWO_IFS_ADD_TST_ADDRS(single_peer_, addr_, hndl1_, hndl2_) \
    do {                                                              \
        int prefix_ = (SA(addr_)->sa_family == AF_INET ?              \
                       net1->ip4pfx : net1->ip6pfx);                  \
                                                                      \
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst1->ta,          \
                                               tst1_if->if_name,      \
                                               addr_,                 \
                                               prefix_,               \
                                               FALSE,                 \
                                               hndl1_));              \
        if (!single_peer_)                                            \
            CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst2->ta,      \
                                                   tst2_if->if_name,  \
                                                   addr_,             \
                                                   prefix_,           \
                                                   FALSE,             \
                                                   hndl2_));          \
                                                                      \
        /*                                                            \
         * NDP proxy is required to make Tester to respond to NDP     \
         * requests for an address assigned on another interface,     \
         * which it will have to do if we have the single host and    \
         * add requested address on only one of the interfaces.       \
         */                                                           \
        if (single_peer_ && addr_->sa_family == AF_INET6)             \
        {                                                             \
            CHECK_RC(sockts_rt_enable_ndp_proxy(pco_tst2->ta,         \
                                                tst2_if->if_name));   \
            CHECK_RC(tapi_cfg_add_neigh_proxy(pco_tst2->ta,           \
                                              tst2_if->if_name,       \
                                              addr_, NULL));          \
        }                                                             \
    } while (0)

/**
 * Remove FAILED neighbor entries by turning off/on network interfaces
 * on IUT and Tester (to be used with tests checking routes over
 * two interfaces from IUT).
 */
#define TWO_IFS_IP6_CLEANUP \
    do {                                                                  \
        if (alien_addr != NULL && alien_addr->sa_family == AF_INET6)      \
        {                                                                 \
            /* Clean FAILED neighbor entries, see OL bug 9774 */          \
            CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_tst1->ta,       \
                                                      tst1_if->if_name)); \
            CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_tst2->ta,       \
                                                      tst2_if->if_name)); \
            CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_iut->ta,        \
                                                      iut_if1->if_name)); \
            CLEANUP_CHECK_RC(tapi_cfg_base_if_down_up(pco_iut->ta,        \
                                                      iut_if2->if_name)); \
            CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_iut,               \
                                                   iut_if2->if_name));    \
            CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_iut,               \
                                                   iut_if1->if_name));    \
            CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_tst2,              \
                                                   tst2_if->if_name));    \
            CLEANUP_CHECK_RC(sockts_wait_for_if_up(pco_tst1,              \
                                                   tst1_if->if_name));    \
        }                                                                 \
    } while (0)

/**
 * Print to log /net nodes of configuration tree.
 */
extern void print_networks(void);

/**
 * Default number of packets to be sent when checking
 * a route.
 */
#define SOCKTS_RT_DEF_PKT_NUM 2

/**
 * Create a pair of sockets on IUT and Tester, bind and connect
 * them if required.
 *
 * @param rt_sock_type            Socket type.
 * @param pco_iut                 RPC server on IUT.
 * @param bind_iut                If @c TRUE, bind IUT socket.
 * @param iut_bind_addr           Address to which to bind IUT socket.
 * @param iut_conn_addr           Address to which to connect from Tester.
 * @param pco_tst                 RPC server on Tester.
 * @param tst_bind_addr           Address to which to bind Tester socket.
 * @param iut_s_out               Where to save IUT socket FD.
 * @param tst_s_out               Where to save Tester socket FD.
 * @param msg                     Message to begin verdicts with in case
 *                                of failure.
 *
 * @return @c 0 on success, value from sockts_rt_error_code
 *         on failure (description of error will be saved
 *         in rt_error).
 */
extern int sockts_rt_connection(
                     sockts_socket_type rt_sock_type,
                     rcf_rpc_server *pco_iut,
                     te_bool bind_iut,
                     const struct sockaddr *iut_bind_addr,
                     const struct sockaddr *iut_conn_addr,
                     rcf_rpc_server *pco_tst,
                     const struct sockaddr *tst_bind_addr,
                     int *iut_s_out, int *tst_s_out,
                     const char *msg);

/**
 * Send some data from a socket and receive it on peer to check
 * a route.
 *
 * @param rt_sock_type            Socket type.
 * @param rpcs_send               RPC server from which data is sent.
 * @param s_send                  Socket from which data is sent.
 * @param rpcs_recv               RPC server on which data is received.
 * @param s_recv                  Socket on which data is received.
 * @param dst_addr                Destination address (used only for
 *                                not connected UDP socket).
 * @param src_addr                If not @c NULL and UDP is checked,
 *                                address returned by @b recvfrom()
 *                                will be compared with this one
 *                                and any mismatch will be reported.
 * @param print_verdicts          If @c TRUE, print verdicts about
 *                                errors.
 * @param msg                     Message to print in verdicts
 *                                (may be @c NULL).
 *
 * @return Status code (see @ref sockts_test_send_rc).
 */
extern sockts_test_send_rc sockts_rt_test_send(
                              sockts_socket_type rt_sock_type,
                              rcf_rpc_server *rpcs_send, int s_send,
                              rcf_rpc_server *rpcs_recv, int s_recv,
                              const struct sockaddr *dst_addr,
                              const struct sockaddr *src_addr,
                              te_bool print_verdicts, const char *msg);

/**
 * Check a route between IUT and Tester by creating a pair of sockets
 * and sending data through them.
 *
 * @param rt_sock_type        Socket type.
 * @param pco_iut             IUT RPC server handle.
 * @param iut_addr            IUT network address.
 * @param pco_tst             Tester RPC server handle.
 * @param tst_addr            Tester network address.
 * @param iut_bind_to         Address type to which IUT socket
 *                            should be bound
 *                            (note that TCP passive socket is always
 *                            bound, even if SOCKTS_ADDR_NONE
 *                            is specified)).
 * @param check_iut_addr      If @c TRUE, check that packets (connection
 *                            request) received from IUT indeed comes
 *                            from @p iut_addr.
 * @param msg                 Message to print in verdicts
 *                            (if NULL, verdicts will not be
 *                            printed).
 *
 * @return 0 on success, value from sockts_rt_error_code
 *         on failure (description of error will be saved
 *         in rt_error).
 */
extern int sockts_rt_check_route(sockts_socket_type rt_sock_type,
                                 rcf_rpc_server *pco_iut,
                                 const struct sockaddr *iut_addr,
                                 rcf_rpc_server *pco_tst,
                                 const struct sockaddr *tst_addr,
                                 sockts_addr_type iut_bind_to,
                                 te_bool check_iut_addr,
                                 const char *msg);

/**
 * Macro for logging test scenario steps.
 *
 * @param format_...      Format string and arguments.
 */
#define SOCKTS_RT_RING(format_...) \
    RING("SCENARIO: " format_)

/**
 * Generic function for checking that traffic goes according to
 * configured route in tests with two interfaces.
 *
 * @param first_if          Whether traffic should go over
 *                          the first interface.
 * @param iut_addr          Network address from which data is sent.
 * @param tst_addr          Network address to which data is sent.
 * @param tos               IP TOS value (will be used if not negative).
 * @param iut_bind_to       Address type to which IUT socket should
 *                          be bound.
 * @param check_iut_addr    If @c TRUE, check that packets (connection
 *                          request) received from IUT indeed comes from
 *                          @p iut_addr.
 * @param msg               Message to print in verdicts.
 * @param env               Pointer to test environment structure.
 * @param pco_iut           IUT RPC server handle.
 * @param pco_tst1          TESTER1 RPC server handle.
 * @param pco_tst2          TESTER2 RPC server handle.
 * @param rt_sock_type      Socket type.
 * @param iut_if1_monitor   Pointer to monitor for the first IUT interface.
 * @param iut_if2_monitor   Pointer to monitor for the second IUT interface.
 * @param tst1_if_monitor   Pointer to monitor for the TESTER1 interface.
 * @param tst2_if_monitor   Pointer to monitor for the TESTER2 interface.
 */
extern void sockts_rt_two_ifs_check_route(
                                    te_bool first_if,
                                    const struct sockaddr *iut_addr,
                                    const struct sockaddr *tst_addr,
                                    int tos,
                                    sockts_addr_type iut_bind_to,
                                    te_bool check_iut_addr,
                                    const char *msg,
                                    const struct tapi_env *env,
                                    rcf_rpc_server *pco_iut,
                                    rcf_rpc_server *pco_tst1,
                                    rcf_rpc_server *pco_tst2,
                                    sockts_socket_type rt_sock_type,
                                    sockts_if_monitor *iut_if1_monitor,
                                    sockts_if_monitor *iut_if2_monitor,
                                    sockts_if_monitor *tst1_if_monitor,
                                    sockts_if_monitor *tst2_if_monitor);

/**
 * Generic function for checking that traffic goes according to
 * configured route using single IUT socket in tests with two interfaces.
 *
 * @param first_if          Whether traffic should go over
 *                          the first interface.
 * @param iut_addr          Network address from which data is sent.
 * @param tst_addr          Network address to which data is sent.
 * @param msg               Message to print in verdicts.
 * @param env               Pointer to test environment structure.
 * @param pco_iut           IUT RPC server handle.
 * @param pco_tst           Tester RPC server handle.
 * @param rt_sock_type      Socket type.
 * @param iut_if1_monitor   Pointer to monitor for the first IUT interface.
 * @param iut_if2_monitor   Pointer to monitor for the second IUT interface.
 * @param tst1_if_monitor   Pointer to monitor for the first tester
 *                          interface.
 * @param tst2_if_monitor   Pointer to monitor for the second tester
 *                          interface.
 * @param handover          Socket is unaccelerated if @c TRUE.
 */
extern void sockts_rt_one_sock_check_route(te_bool first_if,
                                   const struct sockaddr *iut_addr,
                                   const struct sockaddr *tst_addr,
                                   const char *msg,
                                   const struct tapi_env *env,
                                   rcf_rpc_server *pco_iut,
                                   rcf_rpc_server *pco_tst,
                                   int *iut_s, int *tst_s,
                                   sockts_socket_type rt_sock_type,
                                   sockts_if_monitor *iut_if1_monitor,
                                   sockts_if_monitor *iut_if2_monitor,
                                   sockts_if_monitor *tst1_if_monitor,
                                   sockts_if_monitor *tst2_if_monitor,
                                   te_bool handover);

/**
 * Generic macro for checking that traffic goes according to
 * configured route in tests with two interfaces.
 *
 * @param first_if_       Whether traffic should go over
 *                        the first interface.
 * @param iut_addr_       Network address from which data is sent.
 * @param tst_addr_       Network address to which data is sent.
 * @param tos_            IP TOS value (will be used if not negative).
 * @param iut_bind_to_    Address type to which IUT socket should
 *                        be bound.
 * @param msg_            Message to print in verdicts.
 */
#define TWO_IFS_CHECK_ROUTE_GEN(first_if_, iut_addr_, tst_addr_, \
                                tos_, iut_bind_to_, msg_) \
    sockts_rt_two_ifs_check_route(first_if_, iut_addr_, tst_addr_,    \
                                  tos_, iut_bind_to_, FALSE, msg_,    \
                                  &env,                               \
                                  SOCKTS_RT_PCO_IUT_SOCK,             \
                                  pco_tst1, pco_tst2,                 \
                                  rt_sock_type,                       \
                                  &iut_if1_monitor,                   \
                                  &iut_if2_monitor,                   \
                                  &tst1_if_monitor,                   \
                                  &tst2_if_monitor)

/**
 * Check that traffic goes according to configured route in tests
 * with two interfaces.
 *
 * @param first_if_       Whether traffic should go over
 *                        the first interface.
 * @param tst_addr_       Network address to which data is sent.
 * @param msg_            Message to print in verdicts.
 */
#define TWO_IFS_CHECK_ROUTE(first_if_, tst_addr_, msg_) \
    TWO_IFS_CHECK_ROUTE_GEN(first_if_,                              \
                            (first_if_ ? SOCKTS_RT_IUT_ADDR1 :      \
                                         SOCKTS_RT_IUT_ADDR2),      \
                            tst_addr_, -1, SOCKTS_ADDR_NONE, msg_)

/**
 * Generic macro for checking that traffic goes according to configured
 * route using single IUT socket in tests with two interfaces.
 *
 * @param first_if_       Whether traffic should go over
 *                        the first interface.
 * @param handover_       Socket is unaccelerated if @c TRUE.
 * @param msg_            Message to print in verdicts.
 */
#define SOCKTS_RT_CHECK_ROUTE_ONE_SOCK(first_if_, handover_, msg_) \
    sockts_rt_one_sock_check_route(first_if_, SOCKTS_RT_IUT_ADDR,       \
                                   tst_addr, msg_, &env,                \
                                   SOCKTS_RT_PCO_IUT_SOCK, pco_tst,     \
                                   &iut_s, &tst_s, rt_sock_type,        \
                                   &iut_if1_monitor, &iut_if2_monitor,  \
                                   &tst1_if_monitor, &tst2_if_monitor,  \
                                   handover_)

/**
 * A version of TWO_IFS_CHECK_ROUTE for policy based routing
 * tests.
 *
 * @param first_if_       Whether traffic should go over
 *                        the first interface.
 * @param iut_addr_       Source network address.
 * @param tst_addr_       Destination network address.
 * @param tos_            IP TOS value.
 * @param iut_bind_to     Address type to which to bind
 *                        IUT socket (see sockts_addr_type).
 * @param msg_            Message to print in verdicts.
 */
#define TWO_IFS_CHECK_ROUTE_PBR_GEN(first_if_, iut_addr_, tst_addr_, \
                                    tos_, iut_bind_to_, msg_) \
    do {                                                          \
        /*                                                        \
         * If we use address from IUT interface not directly      \
         * connected to checked Tester interface, a route         \
         * to it should be added on Tester.                       \
         */                                                       \
        if (SOCKTS_RT_CNS_TEST)                                   \
        {                                                         \
            TWO_IFS_CNS_ROUTE(first_if_);                         \
        }                                                         \
        else if (iut_addr_ == iut_addr1 && !first_if_)            \
        {                                                         \
            CHECK_RC(tapi_cfg_add_route(                          \
                        pco_tst2->ta, af,                         \
                        te_sockaddr_get_netaddr(iut_addr1),       \
                        route_prefix, NULL, tst2_if->if_name,     \
                        NULL, 0, 0, 0, 0, 0, 0,                   \
                        &rh_tester_fix));                         \
        }                                                         \
        else if (iut_addr_ == iut_addr2 && first_if_)             \
        {                                                         \
             CHECK_RC(tapi_cfg_add_route(                         \
                        pco_tst1->ta, af,                         \
                        te_sockaddr_get_netaddr(iut_addr2),       \
                        route_prefix, NULL, tst1_if->if_name,     \
                        NULL, 0, 0, 0, 0, 0, 0,                   \
                        &rh_tester_fix));                         \
        }                                                         \
        CFG_WAIT_CHANGES;                                         \
                                                                  \
        TWO_IFS_CHECK_ROUTE_GEN(                                  \
                          first_if_, iut_addr_, tst_addr_,        \
                          tos_, iut_bind_to_,                     \
                          msg_);                                  \
                                                                  \
        if (rh_tester_fix != CFG_HANDLE_INVALID)                  \
        {                                                         \
            CHECK_RC(tapi_cfg_del_route(&rh_tester_fix));         \
            CFG_WAIT_CHANGES;                                     \
        }                                                         \
    } while (0)

/**
 * A version of TWO_IFS_CHECK_ROUTE for checking IP rules with
 * different criteria.
 *
 * @param first_if_       Whether traffic should go over
 *                        the first interface.
 * @param iut_addr_       Source network address.
 * @param tst_addr_       Destination network address.
 * @param tos_            IP TOS value.
 * @param criterion_      Rule criterion.
 * @param msg_            Message to print in verdicts.
 */
#define TWO_IFS_CHECK_ROUTE_PBR(first_if_, iut_addr_, tst_addr_, \
                                tos_, criterion_, msg_) \
    TWO_IFS_CHECK_ROUTE_PBR_GEN(first_if_, iut_addr_, tst_addr_,        \
                                (criterion_ == SOCKTS_RT_RULE_TOS ?     \
                                      tos_ : -1),                       \
                                (criterion_ == SOCKTS_RT_RULE_FROM ?    \
                                      SOCKTS_ADDR_SPEC :                \
                                      SOCKTS_ADDR_NONE),                \
                                msg_)

/**
 * A version of DECLARE_TWO_IFS_COMMON_PARAMS for policy based
 * routing tests.
 */
#define DECLARE_TWO_IFS_COMMON_PARAMS_PBR \
    DECLARE_TWO_IFS_COMMON_PARAMS;                              \
    const struct sockaddr *iut_addr = NULL;                     \
    cfg_handle             rh_tester_fix = CFG_HANDLE_INVALID

/**
 * Choose IUT address to which socket is bound, prefering an
 * address assigned to Solarflare interface.
 * Set iut_addr variable to the chosen address.
 */
#define PBR_GET_IUT_ADDR \
    do {                                                            \
        te_bool iut_if1_iut_;                                       \
                                                                    \
        if (SOCKTS_RT_CNS_TEST)                                     \
        {                                                           \
            iut_addr = SOCKTS_RT_IUT_ADDR1;                         \
            break;                                                  \
        }                                                           \
                                                                    \
        iut_if1_iut_ = sockts_if_iut(&env, pco_iut->ta,             \
                                     iut_if1->if_name);             \
        if (iut_if1_iut_)                                           \
            iut_addr = iut_addr1;                                   \
        else                                                        \
            iut_addr = iut_addr2;                                   \
                                                                    \
        SOCKTS_RT_RING("iut_addr%d was chosen as "                  \
                       "IUT bind address",                          \
                       (iut_addr == iut_addr1 ? 1 : 2));            \
                                                                    \
        if (iut_addr->sa_family == AF_INET6)                        \
        {                                                           \
            const char *if_name = (iut_addr == iut_addr1 ?          \
                                    iut_if2->if_name :              \
                                    iut_if1->if_name);              \
                                                                    \
            /*                                                      \
             * NDP proxy is required to make IUT to respond to NDP  \
             * requests for an address assigned on another          \
             * interface.                                           \
             */                                                     \
            CHECK_RC(sockts_rt_enable_ndp_proxy(                    \
                                            pco_iut->ta,            \
                                            if_name));              \
            CHECK_RC(tapi_cfg_add_neigh_proxy(pco_iut->ta,          \
                                              if_name, iut_addr,    \
                                              NULL));               \
        }                                                           \
    } while (0)

/**
 * Add IP rule with specified
 * tos and table.
 *
 * @param rpcs      RPC server handle.
 * @param rule      Rule pointer.
 * @param af        Address family.
 * @param table     Table ID.
 * @param tos       TOS value.
 *
 * @return Status code.
 */
extern te_errno sockts_rt_add_tos_rule(rcf_rpc_server *rpcs,
                                       te_conf_ip_rule *rule,
                                       int af,
                                       int table, int tos);

/** IP rule criteria. */
typedef enum {
    SOCKTS_RT_RULE_UNDEF,   /**< Undefined criterion. */
    SOCKTS_RT_RULE_FROM,    /**< Source address. */
    SOCKTS_RT_RULE_TO,      /**< Destination address. */
    SOCKTS_RT_RULE_TOS,     /**< IP TOS. */
} sockts_rt_rule_criterion;

/**
 * List of values allowed for a test parameter of type
 * sockts_rt_rule_criterion.
 */
#define SOCKTS_RT_RULE_CRITERION_MAPPING_LIST \
            { "from",   SOCKTS_RT_RULE_FROM },  \
            { "to",     SOCKTS_RT_RULE_TO },    \
            { "tos",    SOCKTS_RT_RULE_TOS }

/**
 * Get the value of test parameter of type sockts_rt_rule_criterion.
 *
 * @param var_name_  Variable used to get the value of
 *                   "var_name_" parameter (OUT)
 */
#define TEST_GET_RT_RULE_CRITERION_PARAM(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, \
                        SOCKTS_RT_RULE_CRITERION_MAPPING_LIST)

/**
 * Fill IP rule structure according to rule criterion.
 *
 * @param rule        Rule structure pointer.
 * @param af          Address family.
 * @param criterion   IP rule criterion.
 * @param table       Routing table ID.
 * @param src         Source address.
 * @param src_prefix  Source address prefix.
 * @param dst         Destination address.
 * @param dst_prefix  Destination address prefix.
 * @param tos         IP TOS.
 * @param priority    Rule priority.
 */
extern void sockts_rt_fill_rule(te_conf_ip_rule *rule,
                                int af,
                                sockts_rt_rule_criterion criterion,
                                int table,
                                const struct sockaddr *src,
                                int src_prefix,
                                const struct sockaddr *dst,
                                int dst_prefix,
                                int tos,
                                int priority);

/**
 * Fill IP rule structure according to rule criterion
 * (simplified version using default values).
 *
 * @param rule        Rule structure pointer.
 * @param af          Address family.
 * @param criterion   IP rule criterion.
 * @param src         Source address.
 * @param dst         Destination address.
 */
static inline void
sockts_rt_fill_rule_simple(te_conf_ip_rule *rule,
                           int af,
                           sockts_rt_rule_criterion criterion,
                           const struct sockaddr *src,
                           const struct sockaddr *dst)
{
    sockts_rt_fill_rule(rule, af, criterion,
                        SOCKTS_RT_TABLE_FOO,
                        src, te_netaddr_get_bitsize(af),
                        dst, te_netaddr_get_bitsize(af),
                        SOCKTS_RT_DEF_TOS, -1);
}

/**
 * Fill IP rule structure and add IP rule.
 *
 * @param rpcs        RPC server handle.
 * @param af          Address family.
 * @param criterion   IP rule criterion.
 * @param table       Routing table ID.
 * @param src_addr    Source address.
 * @param src_prefix  Source address prefix.
 * @param dst_addr    Destination address.
 * @param dst_prefix  Destination address prefix.
 * @param tos         IP TOS.
 * @param priority    Rule priority.
 * @param rule        Pointer to IP rule structure.
 * @param rule_added  If not NULL, will be set to TRUE
 *                    if the rule was added successfully.
 */
extern void
sockts_rt_fill_add_rule(rcf_rpc_server *rpcs,
                        int af,
                        sockts_rt_rule_criterion criterion,
                        int table,
                        const struct sockaddr *src_addr,
                        int src_prefix,
                        const struct sockaddr *dst_addr,
                        int dst_prefix,
                        int tos,
                        int priority,
                        te_conf_ip_rule *rule,
                        te_bool *rule_added);

/**
 * Enable NDP proxy on a given interface, so that IPv6 addresses assigned
 * to another interface on the same host will be resolvable for hosts
 * sending requests via a given interface.
 *
 * @note Not only @b proxy_ndp but also @b forwarding must be turned on
 *       for NDP proxy to work, so this function can change both.
 *       It is supposed that Configurator will rollback changes
 *       automatically at the end of test if necessary.
 *       You also need to add specific IPv6 addresses with
 *       @b tapi_cfg_add_neigh_proxy() after enabling NDP proxy to use it
 *       for them.
 *
 * @param ta        Test Agent name.
 * @param if_name   Interface name.
 *
 * @return Status code.
 */
extern te_errno sockts_rt_enable_ndp_proxy(const char *ta,
                                           const char *if_name);

/**
 * Set some interface parameters so that MACVLAN will work as expected.
 *
 * @param ta      Test Agent name.
 * @param ifname  Interface name.
 *
 * @return Status code.
 */
extern te_errno sockts_rt_fix_macvlan_conf(const char *ta,
                                           const char *if_name);

#endif /* _TE_SOCKTS_ROUTE_H_ */
