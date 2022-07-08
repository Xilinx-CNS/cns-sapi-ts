/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Route Test Suite
 *
 * Helper definitions for multipath route tests.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef __TS_SOCKTS_ROUTE_MPATH_H__
#define __TS_SOCKTS_ROUTE_MPATH_H__

#include "sockapi-test.h"
#include "tapi_tcp.h"

/** Structure storing connected pair of sockets. */
typedef struct multipath_conn {
    int                       iut_s;      /**< IUT socket. */
    int                       tst_s;      /**< Tester socket. */
    struct sockaddr_storage   iut_addr;   /**< IUT network address. */
    struct sockaddr_storage   tst_addr;   /**< Tester network address. */
} multipath_conn;

/**
 * Structure storing arguments for @b check_multipath_route().
 */
typedef struct multipath_check_state {
    rcf_rpc_server            *pco_iut;       /**< RPC server on IUT. */
    rcf_rpc_server            *pco_tst;       /**< RPC server on Tester. */
    /*
     * Two RPC servers are specified for gateway because
     * when there is actually no gateway and both links
     * between hosts are direct, then @b gwa_addr is on
     * Tester and @b gwb_addr is on IUT.
     */
    rcf_rpc_server            *pco_gwa;       /**< The first gateway RPC
                                                   server (connection to
                                                   IUT). */
    rcf_rpc_server            *pco_gwb;       /**< The second gateway RPC
                                                   server (connection to
                                                   Tester). */
    const struct if_nameindex *iut1_if;       /**< Interface of the first
                                                   path on IUT. */
    const struct if_nameindex *iut2_if;       /**< Interface of the second
                                                   path on IUT. */
    te_bool                    iut1_acc;      /**< Set to @c TRUE if traffic
                                                   over the first IUT
                                                   interface should be
                                                   accelerated. */
    te_bool                    iut2_acc;      /**< Set to @c TRUE if traffic
                                                   over the second IUT
                                                   interface should be
                                                   accelerated. */
    const struct if_nameindex *tst1_if;       /**< Interface of the first
                                                   path on Tester. */
    const struct if_nameindex *tst2_if;       /**< Interface of the second
                                                   path on Tester. */
    const struct if_nameindex *tst_bind_if;   /**< Interface to which Tester
                                                   socket is bound. */
    tapi_env_net              *tst_net;       /**< Network to which
                                                   a multipath route is
                                                   added on IUT. */
    const struct sockaddr     *iut_addr;      /**< Address on IUT (to bind
                                                   IUT sockets to). */
    const struct sockaddr     *tst_addr;      /**< Address on Tester (to
                                                   bind Tester sockets to).
                                                   */
    const struct sockaddr     *iut2_addr;     /**< Address on the second
                                                   IUT interface. */
    const struct sockaddr     *tst2_addr;     /**< Address on the second
                                                   Tester interface. */
    const struct sockaddr     *gwa_addr;      /**< Gateway address on
                                                   an interface connected
                                                   to the first IUT
                                                   interface. */
    const struct sockaddr     *gwb_addr;      /**< Gateway address on
                                                   an interface connected
                                                   to the first Tester
                                                   interface. */

    const struct sockaddr     *iut_src_addr;  /**< If not @c NULL, use this
                                                   address as preferred
                                                   source address of
                                                   the route on IUT and
                                                   for binding IUT
                                                   socket. */

    unsigned int               conns_num;     /**< Number of connections to
                                                   test. */
    unsigned int               pkts_per_conn; /**< Packets to send over
                                                   every connection. */
    sockts_socket_type         sock_type;     /**< Socket type. */
    te_bool                    diff_addrs;    /**< If @c TRUE, use new
                                                   address to bind every
                                                   new Tester socket;
                                                   otherwise change only
                                                   port. */
    te_bool                    bind_iut;      /**< Whether to bind IUT
                                                   socket. */

    unsigned int               weight1;       /**< Weight of the first
                                                   route. */
    unsigned int               weight2;       /**< Weight of the second
                                                   route. */

    te_bool           reuse_conns;      /**< If @c TRUE, connected sockets
                                             should be saved when calling
                                             check_multipath_route() the
                                             first time and reused by its
                                             subsequent calls. */

    te_bool                    verbose;       /**< If @c TRUE, print verbose
                                                   logs. */

    /* All the properties below are internal, tests should not touch them */

    csap_handle_t              iut_csap1;     /**< CSAP on the first IUT
                                                   interface. */
    csap_handle_t              iut_csap2;     /**< CSAP on the second IUT
                                                   interface. */
    csap_handle_t              tst_csap1;     /**< CSAP on the first Tester
                                                   interface. */
    csap_handle_t              tst_csap2;     /**< CSAP on the second Tester
                                                   interface. */

    int                        iut_s;         /**< IUT socket. */
    int                        tst_s;         /**< Tester socket. */
    te_bool                    reused_socks;  /**< If @c TRUE, @b iut_s
                                                   and @b tst_s are also
                                                   stored in @b saved_conns.
                                                   */

    multipath_conn   *saved_conns;      /**< Array of saved connections. */
    unsigned int      saved_conns_num;  /**< Number of elements in
                                             @b saved_conns. */
    /*
     * Internal variables related to configuring routes.
     * See configure_multipath_routes() for more details.
     */

    struct sockaddr_storage   iut_common_net; /**< Network to which both
                                                   IUT addresses belong. */
    unsigned int              iut_common_pfx; /**< Network prefix for
                                                   @b iut_common_net. */

    te_bool           conf_fixed;       /**< Whether necessary configuration
                                             changes (like enabling
                                             forwarding) were already made.
                                             */
    te_conf_ip_rule   tst_rule;         /**< IP rule created on Tester. */
    te_bool           tst_rule_added;   /**< Whether IP rule was created
                                             on Tester. */
    cfg_handle        iut_rt_hndl;      /**< Configuration handle of IUT
                                             route. */
    cfg_handle        tst_rt_hndl;      /**< Configuration handle of Tester
                                             route. */
    unsigned int      rt_weight1;       /**< Actual weight of the first path
                                             of the IUT route. */
    unsigned int      rt_weight2;       /**< Actual weight of the second
                                             path of the IUT route. */
} multipath_check_state;

/** Initializer for multipath_check_state. */
#define MULTIPATH_CHECK_STATE_INIT \
    { .pco_iut = NULL,                                  \
      .pco_tst = NULL,                                  \
      .pco_gwa = NULL,                                  \
      .pco_gwb = NULL,                                  \
      .iut1_if = NULL,                                  \
      .iut2_if = NULL,                                  \
      .iut1_acc = FALSE,                                \
      .iut2_acc = FALSE,                                \
      .tst1_if = NULL,                                  \
      .tst2_if = NULL,                                  \
      .tst_net = NULL,                                  \
      .tst_bind_if = NULL,                              \
      .iut_addr = NULL,                                 \
      .tst_addr = NULL,                                 \
      .iut2_addr = NULL,                                \
      .tst2_addr = NULL,                                \
      .gwa_addr = NULL,                                 \
      .gwb_addr = NULL,                                 \
      .iut_src_addr = NULL,                             \
      .conns_num = 0,                                   \
      .pkts_per_conn = 0,                               \
      .sock_type = SOCKTS_SOCK_UDP,                     \
      .diff_addrs = FALSE,                              \
      .bind_iut = TRUE,                                 \
      .weight1 = 0,                                     \
      .weight2 = 0,                                     \
      .reuse_conns = FALSE,                             \
      .verbose = FALSE,                                 \
      .iut_csap1 = CSAP_INVALID_HANDLE,                 \
      .iut_csap2 = CSAP_INVALID_HANDLE,                 \
      .tst_csap1 = CSAP_INVALID_HANDLE,                 \
      .tst_csap2 = CSAP_INVALID_HANDLE,                 \
      .iut_s = -1,                                      \
      .tst_s = -1,                                      \
      .reused_socks = FALSE,                            \
      .saved_conns = NULL,                              \
      .saved_conns_num = 0,                             \
      .iut_common_net = { .ss_family = AF_UNSPEC, },    \
      .iut_common_pfx = 0,                              \
      .conf_fixed = FALSE,                              \
      .tst_rule_added = FALSE,                          \
      .iut_rt_hndl = CFG_HANDLE_INVALID,                \
      .tst_rt_hndl = CFG_HANDLE_INVALID,                \
      .rt_weight1 = 0,                                  \
      .rt_weight2 = 0,                                  \
    }

/** Declare common parameters for multipath tests. */
#define MULTIPATH_COMMON_PARAMS_DECL \
    rcf_rpc_server        *pco_iut = NULL;              \
    rcf_rpc_server        *pco_gwa = NULL;              \
    rcf_rpc_server        *pco_gwb = NULL;              \
    rcf_rpc_server        *pco_tst = NULL;              \
                                                        \
    const struct sockaddr *iut1_addr = NULL;            \
    const struct sockaddr *iut2_addr = NULL;            \
    const struct sockaddr *gwa_addr = NULL;             \
    const struct sockaddr *gwb_addr = NULL;             \
    const struct sockaddr *tst1_addr = NULL;            \
    const struct sockaddr *tst2_addr = NULL;            \
    tapi_env_net          *tst_remote_net = NULL;       \
    const struct sockaddr *tst_remote_addr = NULL;      \
    tapi_env_net          *iut_remote_net = NULL;       \
    const struct sockaddr *iut_remote_addr = NULL;      \
                                                        \
    const struct if_nameindex *iut1_if = NULL;          \
    const struct if_nameindex *iut2_if = NULL;          \
    const struct if_nameindex *tst1_if = NULL;          \
    const struct if_nameindex *tst2_if = NULL;          \
    const struct if_nameindex *tst_remote_if = NULL;    \
                                                        \
    unsigned int            conns_num;                  \
    unsigned int            pkts_per_conn;              \
    sockts_socket_type      sock_type;                  \
    te_bool                 diff_addrs;                 \
    te_bool                 bind_iut;                   \
    te_bool                 iut_other_src

/** Get common parameters for multipath tests. */
#define MULTIPATH_COMMON_PARAMS_GET \
    TEST_GET_PCO(pco_iut);                        \
    TEST_GET_PCO(pco_gwa);                        \
    TEST_GET_PCO(pco_gwb);                        \
    TEST_GET_PCO(pco_tst);                        \
    TEST_GET_IF(iut1_if);                         \
    TEST_GET_IF(iut2_if);                         \
    TEST_GET_IF(tst1_if);                         \
    TEST_GET_IF(tst2_if);                         \
    TEST_GET_IF(tst_remote_if);                   \
    TEST_GET_ADDR(pco_iut, iut1_addr);            \
    TEST_GET_ADDR(pco_iut, iut2_addr);            \
    TEST_GET_ADDR(pco_iut, iut_remote_addr);      \
    TEST_GET_ADDR(pco_tst, tst1_addr);            \
    TEST_GET_ADDR(pco_tst, tst2_addr);            \
    TEST_GET_ADDR(pco_tst, tst_remote_addr);      \
    TEST_GET_ADDR(pco_gwa, gwa_addr);             \
    TEST_GET_ADDR(pco_gwb, gwb_addr);             \
    TEST_GET_NET(tst_remote_net);                 \
    TEST_GET_NET(iut_remote_net);                 \
    TEST_GET_UINT_PARAM(conns_num);               \
    TEST_GET_UINT_PARAM(pkts_per_conn);           \
    SOCKTS_GET_SOCK_TYPE(sock_type);              \
    TEST_GET_BOOL_PARAM(diff_addrs);              \
    TEST_GET_BOOL_PARAM(bind_iut);                \
    TEST_GET_BOOL_PARAM(iut_other_src)

/**
 * Initialize properties of multipath_check_state structure
 * from common parameters of multipath tests.
 *
 * @param _state      Pointer to multipath_check_state structure.
 */
#define MULTIPATH_COMMON_PARAMS_SET(_state) \
    do {                                                                \
        (_state)->pco_iut = pco_iut;                                    \
        (_state)->pco_tst = pco_tst;                                    \
        (_state)->pco_gwa = pco_gwa;                                    \
        (_state)->pco_gwb = pco_gwb;                                    \
        (_state)->iut1_if = iut1_if;                                    \
        (_state)->iut2_if = iut2_if;                                    \
        (_state)->iut1_acc = sockts_if_accelerated(&env, pco_iut->ta,   \
                                                   iut1_if->if_name);   \
        (_state)->iut2_acc = sockts_if_accelerated(&env, pco_iut->ta,   \
                                                   iut2_if->if_name);   \
        (_state)->tst1_if = tst1_if;                                    \
        (_state)->tst2_if = tst2_if;                                    \
        (_state)->tst_bind_if = tst_remote_if;                          \
        (_state)->tst_net = tst_remote_net;                             \
        (_state)->iut_addr = iut1_addr;                                 \
        (_state)->tst_addr = tst_remote_addr;                           \
        (_state)->iut2_addr = iut2_addr;                                \
        (_state)->tst2_addr = tst2_addr;                                \
        (_state)->gwa_addr = gwa_addr;                                  \
        (_state)->gwb_addr = gwb_addr;                                  \
        (_state)->conns_num = conns_num;                                \
        (_state)->pkts_per_conn = pkts_per_conn;                        \
        (_state)->sock_type = sock_type;                                \
        (_state)->diff_addrs = diff_addrs;                              \
        (_state)->bind_iut = bind_iut;                                  \
                                                                        \
        if (iut_other_src)                                              \
        {                                                               \
            (_state)->iut_src_addr = iut_remote_addr;                   \
            if (iut1_addr->sa_family == AF_INET)                        \
            {                                                           \
                tapi_sockaddr_clone_exact(iut_remote_net->ip4addr,      \
                                          &(_state)->iut_common_net);   \
                (_state)->iut_common_pfx = iut_remote_net->ip4pfx;      \
            }                                                           \
            else                                                        \
            {                                                           \
                tapi_sockaddr_clone_exact(iut_remote_net->ip6addr,      \
                                          &(_state)->iut_common_net);   \
                (_state)->iut_common_pfx = iut_remote_net->ip6pfx;      \
            }                                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            multipath_get_common_net(iut1_addr, iut2_addr,              \
                                     &(_state)->iut_common_net,         \
                                     &(_state)->iut_common_pfx);        \
        }                                                               \
    } while (0)

/**
 * Perform cleanup after @b check_multipath_route() (if required).
 *
 * @param state     Pointer to multipath_check_state structure previously
 *                  passed to @b check_multipath_route().
 *
 * @return Status code.
 */
extern te_errno multipath_check_state_clean(multipath_check_state *state);

/**
 * Check whether multipath route works as expected.
 *
 * @note If actually a route has only a single path, weight
 *       for the other path should be set to @c 0.
 *
 * @param state     Route interfaces, addresses, RPC servers and
 *                  other arguments.
 * @param stage     Message to be printed in verdicts.
 *
 * @return Status code.
 */
extern te_errno check_multipath_route(multipath_check_state *state,
                                      const char *stage);

/**
 * Set @c fib_multipath_hash_policy if it is present (no error is reported
 * if it is not found).
 *
 * @param af        Address family.
 * @param rpcs      RPC server.
 * @param value     Value to set.
 *
 * @return Status code.
 */
extern te_errno multipath_set_hash_policy(int af, rcf_rpc_server *rpcs,
                                          int value);

/**
 * Get common network for a pair of network addresses.
 *
 * @param addr1           The first address.
 * @param addr2           The second address.
 * @param net_addr        Where to save common network address.
 * @param net_prefix      Where to save common network prefix.
 */
extern void multipath_get_common_net(const struct sockaddr *addr1,
                                     const struct sockaddr *addr2,
                                     struct sockaddr_storage *net_addr,
                                     unsigned int *net_prefix);

/**
 * (Re)configure multipath routes according to paths weights. If
 * weight is zero, path is not included (or excluded if route
 * already exists).
 *
 * @param state       Pointer to multipath_check_state structure where
 *                    all parameters for routes are stored.
 */
extern void configure_multipath_routes(multipath_check_state *state);

#endif /* _TE_SOCKTS_MPATH_ROUTE_H_ */
