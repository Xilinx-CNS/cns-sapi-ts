/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TCP Test Suite
 *
 * TAPI for checking TCP Initial Sequence Numbers.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef __TS_TCP_ISN_CHECK_H__
#define __TS_TCP_ISN_CHECK_H__

#include "sockapi-test.h"
#include "tapi_tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type of argument passed to CSAP callback to store information
 * about processed packets.
 */
typedef struct sockts_isn_pkt_data {
    uint32_t        seqn;           /**< Last captured SEQN */
    uint32_t        ackn;           /**< Last captured ACKN */

    uint32_t        isn;            /**< TCP ISN */
    struct timeval  isn_tv;         /**< Timestamp from the packet
                                         with ISN */
    te_bool         isn_captured;   /**< Whether packet with ISN
                                         was captured */

    te_bool         failed;         /**< Will be set to @c TRUE
                                         if processing of captured
                                         packets failed */
} sockts_isn_pkt_data;

/** Structure describing checked connection. */
typedef struct sockts_isn_conn {
    rcf_rpc_server          *pco_iut;       /**< RPC server on IUT */
    rcf_rpc_server          *pco_tst;       /**< RPC server on Tester */
    const struct sockaddr   *iut_addr;      /**< IP address on IUT */
    const struct sockaddr   *tst_addr;      /**< IP address on Tester */
    const struct sockaddr   *iut_lladdr;    /**< Ethernet address on
                                                 IUT */
    const struct sockaddr   *tst_lladdr;    /**< Ethernet address on
                                                 Tester */

    const struct if_nameindex  *iut_if;     /**< Network interface on
                                                 IUT */
    const struct if_nameindex  *tst_if;     /**< Network interface on
                                                 Tester */

    te_bool                  iut_passive;   /**< If @c TRUE, listener socket
                                                 is on IUT, otherwise it is
                                                 on Tester */
    int                      listener_s;    /**< Listener socket */
    int                      iut_s;         /**< Connected socket on IUT */
    int                      tst_s;         /**< Connected socket on
                                                 Tester */

    sockts_isn_pkt_data      pkt_data;      /**< Argument passed to our
                                                 CSAP callback */
    tapi_tad_trrecv_cb_data  cb_data;       /**< Argument for CSAP
                                                 get/stop functions */
    csap_handle_t            tst_recv_csap; /**< CSAP to capture
                                                 packets sent from IUT */
    csap_handle_t            iut_send_csap; /**< CSAP to send RST to
                                                 kill @c TIME_WAIT socket
                                                 on Tester */
    asn_value               *rst_tmpl;      /**< RST packet template */
} sockts_isn_conn;

/** Initializer for sockts_isn_conn */
#define SOCKTS_ISN_CONN_INIT \
    {                                             \
        .listener_s = -1,                         \
        .iut_s = -1,                              \
        .tst_s = -1,                              \
        .tst_recv_csap = CSAP_INVALID_HANDLE,     \
        .iut_send_csap = CSAP_INVALID_HANDLE,     \
    }

/**
 * Initialize sockts_isn_conn structure.
 *
 * @param pco_iut         RPC server on IUT.
 * @param pco_tst         RPC server on Tester.
 * @param iut_addr        IP address on IUT.
 * @param tst_addr        IP address on Tester.
 * @param iut_lladdr      Ethernet address on IUT.
 * @param tst_lladdr      Ethernet address on Tester.
 * @param iut_if          Network interface on IUT.
 * @param tst_if          Network interface on Tester.
 * @param conn            Structure to be initialized.
 */
extern void sockts_isn_conn_init(rcf_rpc_server *pco_iut,
                                 rcf_rpc_server *pco_tst,
                                 const struct sockaddr *iut_addr,
                                 const struct sockaddr *tst_addr,
                                 const struct sockaddr *iut_lladdr,
                                 const struct sockaddr *tst_lladdr,
                                 const struct if_nameindex *iut_if,
                                 const struct if_nameindex *tst_if,
                                 sockts_isn_conn *conn);

/**
 * Establish connection, capture TCP ISN sent from IUT.
 *
 * @param conn          TCP connection description.
 * @param iut_passive   Whether connection should be established passively
 *                      from IUT.
 */
extern void sockts_isn_conn_establish(sockts_isn_conn *conn,
                                      te_bool iut_passive);

/**
 * Terminate TCP connection, capture last SEQN/ACKN sent from IUT.
 *
 * @note This function always sends @c FIN from Tester firstly,
 *       to ensure that no @c TIME_WAIT socket is left on IUT.
 *       If there is no listener socket on Tester side, RST is
 *       also sent to Tester to kill @c TIME_WAIT socket there,
 *       so that the same address/port can be reused there.
 *       This means that @b sockts_isn_conn_establish() can be
 *       used with the same sockts_isn_conn structure immediately
 *       after calling this function.
 *
 * @param conn          TCP connection description.
 */
extern void sockts_isn_conn_terminate(sockts_isn_conn *conn);

/**
 * Release resources allocated for sockts_isn_conn structure.
 *
 * @param conn        Pointer to the structure.
 */
extern void sockts_isn_conn_cleanup(sockts_isn_conn *conn);

/**
 * Send some data from IUT to Tester over TCP connection
 * described by a sockts_isn_conn structure.
 *
 * @param conn        Pointer to the structure.
 * @param send_size   Number of bytes to send.
 * @param timeout     How long to wait before terminating
 *                    data sending.
 */
extern void sockts_isn_conn_send(sockts_isn_conn *conn,
                                 size_t send_size,
                                 int timeout);

/**
 * Get TCP ISN captured during connection establishment.
 *
 * @param conn        Pointer to sockts_isn_conn structure.
 * @param isn         Where to save ISN.
 *
 * @return Status code.
 */
extern te_errno sockts_isn_conn_get_isn(sockts_isn_conn *conn,
                                        uint32_t *isn);

/**
 * Get timestamp of packet with ISN sent from IUT.
 *
 * @param conn        Pointer to sockts_isn_conn structure.
 * @param isn_tv      Where to save timestamp.
 *
 * @return Status code.
 */
extern te_errno sockts_isn_conn_get_isn_ts(sockts_isn_conn *conn,
                                           struct timeval *isn_tv);

/**
 * Get last SEQN sent from IUT when terminating connection.
 *
 * @param conn        Pointer to sockts_isn_conn structure.
 * @param seqn        Where to save SEQN.
 *
 * @return Status code.
 */
extern te_errno sockts_isn_conn_get_last_seqn(sockts_isn_conn *conn,
                                              uint32_t *seqn);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_TCP_ISN_CHECK_H__ */
