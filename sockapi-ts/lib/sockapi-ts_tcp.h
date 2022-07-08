/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common includes and definitions for TCP tests.
 *
 * $Id$
 */

#ifndef __TS_SOCKAPI_TS_TCP_H__
#define __TS_SOCKAPI_TS_TCP_H__

#include "te_config.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef STDC_HEADERS
#include <stdlib.h>
#include <stdarg.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "te_defs.h"
#include "rcf_rpc.h"
#include "asn_usr.h"

/**
 * How to close IUT socket.
 */
typedef enum {
    CL_CLOSE = 0,  /**< Use close() */
    CL_SHUTDOWN,   /**< Use shutdown() */
    CL_EXIT,       /**< Use exit() */
    CL_KILL,       /**< Kill IUT process */
    CL_DUP2,       /**< Use dup2 */
} closing_way;

#define CLOSING_WAY  \
    { "close", CL_CLOSE },          \
    { "shutdown", CL_SHUTDOWN },    \
    { "exit", CL_EXIT },            \
    { "kill", CL_KILL },            \
    { "dup2", CL_DUP2 }

/**
 * List of socket flags, can be passed to macro @b TEST_GET_ENUM_PARAM.
 */
#define SOCKTS_SOCKET_FLAGS \
    { "none", 0 },                       \
    { "cloexec", RPC_SOCK_CLOEXEC },     \
    { "nonblock", RPC_SOCK_NONBLOCK }

/**
 * Get socket flag.
 */
#define SOCKTS_GET_SOCK_FLAGS(flag_name) \
    TEST_GET_ENUM_PARAM(flag_name, SOCKTS_SOCKET_FLAGS)

/**
 * Wait until TCP listenq is cleaned.
 *
 * @param rpcs  RPC server handler
 * @param addr  Interface address
 */
extern void sockts_wait_cleaned_listenq(rcf_rpc_server *rpcs,
                                        const struct sockaddr *addr);


/**
 * Wait until TCP socket is destroyed. Note! Onload accelerated socket is
 * tracked in a special way using @b onload_stackdump utility, so it should
 * be determined if the socket is accelerated or not.
 *
 * @param rpcs      RPC server handler
 * @param src_addr  Source address
 * @param dst_addr  Destination address
 * @param timeout   Timeout in seconds
 * @param onload    Is it Onload accelerated socket?
 * @param orphaned  The socket is orphaned
 */
extern void sockts_wait_socket_closing_spec(rcf_rpc_server *rpcs,
                                            const struct sockaddr *src_addr,
                                            const struct sockaddr *dst_addr,
                                            int timeout, te_bool onload,
                                            te_bool orphaned);

/**
 * Wait until TCP socket is destroyed, it is determined inside the function
 * if the socket is accelerated or not.
 *
 * @param rpcs      RPC server handler
 * @param src_addr  Source address
 * @param dst_addr  Destination address
 * @param timeout   Timeout in seconds
 */
extern void sockts_wait_socket_closing(rcf_rpc_server *rpcs,
                                       const struct sockaddr *src_addr,
                                       const struct sockaddr *dst_addr,
                                       int timeout);

/**
 * Read a part of send buffer after its overfilling.
 *
 * @param rpcs  RPC server handle.
 * @param sock  Socket to read data.
 * @param sent  Total data amount which was sent.
 *
 * @return Read data amount.
 */
extern int sockts_tcp_read_part_of_send_buf(rcf_rpc_server *rpcs, int sock,
                                            uint64_t sent);

/**
 * Measure backlog passed to listen() as number of connections which
 * accept() can return after a lot of connections were established
 * and after that closed by a peer.
 *
 * @note The function always disables silent_pass mode for the first
 * and last iterations associated with @p exp_backlog.
 *
 * @param rpcs1             RPC server where listener socket is created.
 * @param addr1             Address to which listener socket is bond.
 * @param listener          Listener socket.
 * @param rpcs2             RPC server from where to call connect().
 * @param addr2             Network address to use on @p rpcs2.
 * @param exp_backlog       Expected backlog value (this function will try
 *                          to establish two times more connections or
 *                          @c SOCKTS_TCP_MIN_BACKLOG connections if it is
 *                          bigger).
 * @param log_msg           String to print in verdicts.
 *
 * @return Measured backlog value (in case of failure this function will
 *         terminate current test with TEST_VERDICT).
 */
extern int sockts_tcp_measure_listen_backlog(rcf_rpc_server *rpcs1,
                                             const struct sockaddr *addr1,
                                             int listener,
                                             rcf_rpc_server *rpcs2,
                                             const struct sockaddr *addr2,
                                             unsigned int exp_backlog,
                                             const char *log_msg);

/**
 * Check if socket with appropriate RSS couplet exists. System utility
 * @b netstat is used or @b onload_stackdump if Onload is used in the
 * testing.
 *
 * @param rpcs      RPC server handle
 * @param src_addr  Source address
 * @param dst_addr  Destination address
 * @param orphaned  The socket is orphaned
 *
 * @return @c TRUE if socket does not exist
 */
extern te_bool sockts_socket_is_closed(rcf_rpc_server *rpcs,
                                       const struct sockaddr *src_addr,
                                       const struct sockaddr *dst_addr,
                                       te_bool onload, te_bool orphaned);

/**
 * Close pair of connected tcp sockets.
 * Implementation allows to avoid TIME_WAIT state for IUT socket.
 *
 * @param pco_iut        IUT RPC server handler
 * @param pco_tst        Tester RPC server handler
 * @param iut_s          TCP socket on IUT
 * @param tst_s          TCP socket on tester
 */
extern void sockts_pair_close_check(rcf_rpc_server *pco_iut,
                                    rcf_rpc_server *pco_tst,
                                    int iut_s, int tst_s);


/**
 * Create and close new socket to be cached.
 *
 * @param pco_iut   IUT RPC server handler
 * @param pco_tst   Tester RPC server handler
 * @param iut_addr  IUT IP address
 * @param tst_addr  Tester IP address
 * @param iut_l     IUT listener socket or @c -1 in active case
 * @param active    Determines passive or active socket should be cached
 * @param caching   Whether caching is enabled
 */
extern void sockts_create_cached_socket(rcf_rpc_server *pco_iut,
                                        rcf_rpc_server *pco_tst,
                                        const struct sockaddr *iut_addr,
                                        const struct sockaddr *tst_addr,
                                        int iut_l, te_bool active,
                                        te_bool caching);

/**
 * Exercise if the IUT socket is cached and it can be reused.
 *
 * @param pco_iut   IUT RPC server handler
 * @param pco_iut2  Aux IUT RPC server handler to get Onload cache
 *                  stats and make checking based on this.
 *                  Must not be @c NULL.
 * @param pco_tst   Tester RPC server handler
 * @param iut_addr  IUT IP address
 * @param tst_addr  Tester IP address
 * @param iut_l     IUT listener socket or @c -1,
 *                  caching reusing won't be checked in this case
 * @param iut_s     Tested IUT socket
 * @param active    Determines passive or active socket should be cached
 */
extern void sockts_tcp_check_cache_reuse(rcf_rpc_server *pco_iut,
                                         rcf_rpc_server *pco_iut2,
                                         rcf_rpc_server *pco_tst,
                                         const struct sockaddr *iut_addr,
                                         const struct sockaddr *tst_addr,
                                         int iut_l, int iut_s, te_bool active);

/**
 * Close IUT socket according to @p way and send some data from tester.
 * Check the correct linger behavior. Function prints verdict
 * if any errors occur.
 *
 * @note This function jumps to cleanup in case of critical errors
 *       which are test side or configuration problems.
 *
 * @param pco_iut         IUT RPC server handler
 * @param pco_tst         Tester RPC server handler
 * @param pco_iut_par     Parent IUT RPC server handler (in case if @p way
 *                        is @c exit or @c kill)
 * @param iut_s           Pointer to connected IUT socket descriptor
 * @param tst_s           Tester connected socket descriptor
 * @param tst_if_name     Tester interface name string
 * @param iut_addr        Pointer to IUT socket address
 * @param linger_val      Structure containing actual socket linger data
 * @param should_linger   Parameter to choose whether the linger option should
 *                        work or not
 * @param way             How to close a socket
 * @param ovfill_buf      If @c TRUE - overfill send/receive buffers
 *
 * @return Status code
 */
te_errno
sockts_close_check_linger(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                          rcf_rpc_server *pco_iut_par,
                          int *iut_s, int tst_s,
                          char *tst_if_name, const struct sockaddr *iut_addr,
                          tarpc_linger *linger_val, te_bool should_linger,
                          closing_way way, te_bool ovfill_buf);

/**
 * Compute TCP payload length from values of relevant fields
 * in TCP/IP headers. This function is used because CSAP sometimes
 * reports some payload (consisting of zero bytes) when actually there
 * is no payload at all.
 *
 * @note This function does not take into account IPv6 extension
 *       headers.
 *
 * @param pkt       Packet captured by CSAP.
 *
 * @return Payload length (or @c -1 in case of failure).
 */
extern int sockts_tcp_payload_len(asn_value *pkt);

/**
 * Check that flags reported by fcntl() match socket flags.
 *
 * @param pco            RPC server handle
 * @param s              Socket to check
 * @param sock_flags     Flags to check
 *
 * @return Status code
 */
extern te_errno sockts_check_sock_flags(rcf_rpc_server *pco, int s, int sock_flags);

/**
 * Disable TCP segmentation offload
 *
 * @param ta            Test agent name
 * @param ifname        Interface name
 *
 * @return Status code
 */
extern te_errno sockts_disable_tcp_segmentation(const char *ta,
                                                const char *ifname);

/**
 * Enable TCP segmentation offload
 *
 * @param ta            Test agent name
 * @param ifname        Interface name
 *
 * @return Status code
 */
extern te_errno sockts_enable_tcp_segmentation(const char *ta,
                                               const char *ifname);
/**
 * Call @b shutdown(@c SHUT_WR) on IUT TCP socket and its Tester peer
 * if requested. Check that IUT socket is in expected TCP state
 * after that.
 *
 * @param pco_iut       RPC server on IUT.
 * @param iut_s         TCP socket on IUT.
 * @param iut_addr      Address:port of IUT socket.
 * @param pco_tst       RPC server on Tester.
 * @param tst_s         TCP socket on Tester.
 * @param tst_addr      Address:port of Tester socket.
 * @param shutdown_iut  If @c TRUE, call @b shutdown(@c SHUT_WR) on
 *                      IUT socket.
 * @param shutdown_tst  If @c TRUE, call @b shutdown(@c SHUT_WR) on
 *                      Tester socket.
 * @param tst_first     Perform @b shutdown(@c SHUT_WR) on Tester socket
 *                      first. It only makes sense if both @p shutdown_iut
 *                      and @p shutdown_tst are @c TRUE.
 * @param tcp_state     If not @c NULL, TCP state of IUT socket will
 *                      be saved here.
 * @param overfilled    Whether send queue of @p iut_s is overfilled or
 *                      not.
 */
extern void sockts_shutdown_check_tcp_state(rcf_rpc_server *pco_iut,
                                            int iut_s,
                                            const struct sockaddr *iut_addr,
                                            rcf_rpc_server *pco_tst,
                                            int tst_s,
                                            const struct sockaddr *tst_addr,
                                            te_bool shutdown_iut,
                                            te_bool shutdown_tst,
                                            te_bool tst_first,
                                            rpc_tcp_state *tcp_state,
                                            te_bool overfilled);


/**
 * Check that data can be sent in both directions
 * via connection between TCP socket and CSAP TCP
 * socket emulation.
 *
 * @note This function prints verdict in case of failure.
 *
 * @param rpcs          RPC server.
 * @param s             TCP socket.
 * @param csap_s        Handler of CSAP TCP socket emulation.
 *
 * @return Status code.
 */
extern te_errno sockts_check_tcp_conn_csap(rcf_rpc_server *rpcs, int s,
                                           tapi_tcp_handler_t csap_s);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
