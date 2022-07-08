/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI to handle ol-apprtt tool.
 *
 * Definitions for TAPI to handle ol-apprtt tool.
 *
 * Typical API usage:
 * @code{.c}
 * #include "sockapi-ts_apprtt.h"
 *
 * sockts_apprtt_handle            *ol_app_rtt = NULL;
 * sockts_apprtt_client_options     client_opts;
 * sockts_apprtt_server_options     server_opts;
 * te_vec                           rtt_values;
 *
 * client_opts.srv_addr = tst_addr;
 * client_opts.time_to_run = TIME2RUN;
 * server_opts.chunk_size = 1000000;
 *
 * CHECK_RC(sockts_apprtt_create(pco_iut, &client_opts,
 *                               pco_tst, &server_opts,
 *                               &ol_app_rtt));
 *
 * CHECK_RC(sockts_apprtt_start(ol_app_rtt));
 * CHECK_RC(sockts_apprtt_wait(ol_app_rtt, TE_SEC2MS(TIME2RUN) + 100));
 * CHECK_RC(sockts_apprtt_getrtt(ol_app_rtt, &rtt_values));
 *
 * int *rtt;
 * TE_VEC_FOREACH(&rtt_values, rtt)
 *     RING("%d", *rtt);
 *
 * @endcode
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_APPRTT_H__
#define __SOCKAPI_TS_APPRTT_H__

#include "sockapi-test.h"
#include "te_errno.h"
#include "tapi_job.h"
#include "te_vector.h"

/** Number of output channels for ol-apprtt: for stdout and stderr. */
#define APPRTT_OUT_CHANNELS_NUM 2

/** Client command line options. */
typedef struct sockts_apprtt_client_options
{
    const char             *prefix;         /**< Prefix before ol-apprtt. */
    const struct sockaddr  *srv_addr;       /**< Server address. */
    unsigned int            time_to_run;    /**< Time to run in seconds. */
    unsigned int            chunk_size;     /**< Size of a data chunk for
                                                 RTT measuring. */
} sockts_apprtt_client_options;

/** Server command line options. */
typedef struct sockts_apprtt_server_options
{
    const char     *prefix;         /**< Prefix before ol-apprtt. */
    unsigned int    chunk_size;     /**< Size of a data chunk that a
                                         server "acks". */
} sockts_apprtt_server_options;

/**
 * Structure describing an instance (client or server) of
 * "ol-apprtt" application.
 */
typedef struct apprtt_instance_handle
{
    tapi_job_t          *job;               /**< Agent job instance. */
    tapi_job_factory_t  *factory;           /**< Factory to create a job. */

    tapi_job_channel_t *
        out_channels[APPRTT_OUT_CHANNELS_NUM]; /**< Standart output channels.*/

    te_vec               args;              /**< Vector used for generating
                                                 command line arguments list.*/
} apprtt_instance_handle;

/** "ol-apprtt" application handle. */
typedef struct sockts_apprtt_handle
{
    apprtt_instance_handle  client;     /**< Client instance handle. */
    apprtt_instance_handle  server;     /**< Server instance handle. */
    tapi_job_channel_t     *rtt_filter; /**< Filter to obtain RTT values. */
} sockts_apprtt_handle;

/**
 * Create "ol-apprtt" application and initialize with specified options.
 *
 * @param[in]  client_pco    RPC server for running a client instance.
 * @param[in]  client_opts   Options to pass to the client.
 * @param[in]  server_pco    RPC server for running a server instance.
 * @param[in]  server_opts   Options to pass to the server.
 * @param[out] app           The application hadnle.
 *
 * @return Status code.
 */
extern te_errno
sockts_apprtt_create(rcf_rpc_server *client_pco,
                     sockts_apprtt_client_options *client_opts,
                     rcf_rpc_server *server_pco,
                     sockts_apprtt_server_options *server_opts,
                     sockts_apprtt_handle **app);

/**
 * Start "ol-apprtt" application.
 *
 * @param app               The application handle.
 *
 * @return Status code.
 */
extern te_errno
sockts_apprtt_start(sockts_apprtt_handle *app);

/**
 * Wait for "ol-apprtt" application to stop.
 *
 * @param app               The application handle.
 * @param timeout_ms        Timeout in ms to wait.
 *
 * @return Status code.
 */
extern te_errno
sockts_apprtt_wait(sockts_apprtt_handle *app, int timeout_ms);

/**
 * Get result of running the client "ol-apprtt" application.
 *
 * @param[in]  app          The application handle.
 * @param[out] rtt_values   Vector to store the RTT values array. The vector
 *                          must be freed with @ref te_vec_free() function
 *                          at test cleanup section.
 *
 * @return Status code.
 */
extern te_errno
sockts_apprtt_getrtt(sockts_apprtt_handle *app, te_vec *rtt_values);

/**
 * The same as sockts_apprtt_getrtt() but without RPC logging on client and
 * server sides.
 *
 * @param[in]  app          The application handle.
 * @param[out] rtt_values   Vector to store the RTT values array. The vector
 *                          must be freed with @ref te_vec_free() function
 *                          at test cleanup section.
 * @param[in]  silent       If @c TRUE then RPC logging will be disabed.
 * @param[in]  client_pco   RPC server with the client instance.
 * @param[in]  server_pco   RPC server with the server instance.
 *
 * @return Status code.
 */
extern te_errno
sockts_apprtt_getrtt_silent(sockts_apprtt_handle *app,
                            te_vec *rtt_values,
                            te_bool silent,
                            rcf_rpc_server *client_pco,
                            rcf_rpc_server *server_pco);

/**
 * Destroy "ol-apprtt" application and free all internal data.
 *
 * @param app               The application handle.
 *
 * @return Status code.
 */
extern te_errno
sockts_apprtt_destroy(sockts_apprtt_handle *app);

/**
 * Output application level RTT values via MI logger in JSON format.
 * This report should be used to draw graph.
 *
 * @param[in] rtt_values    Vector to store the RTT values array.
 *
 * @return Status code.
 */
extern te_errno sockts_apprtt_mi_report_rtt(te_vec *rtt_values);

#endif /* __SOCKAPI_TS_APPRTT_H__ */
