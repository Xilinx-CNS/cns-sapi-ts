/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI to handle ol-apprtt tool.
 *
 * Implementation for TAPI to handle ol-apprtt tool.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include "sockapi-ts_apprtt.h"
#include "tapi_job_opt.h"
#include "tapi_job_factory_rpc.h"
#include "te_mi_log.h"

#define SOCKTS_APPRTT_PATH "ol-apprtt"

/** Timeout for receiving data from channel. in milliseconds. */
#define APPRTT_WAIT_TIMEOUT     1000

/**
 * Generic function to initialize agent job for server or client.
 *
 * @param rpcs  RPC server to create a factory.
 * @param h     Instance handle.
 *
 * @return Status code.
 */
static te_errno
apprtt_init_job(rcf_rpc_server *rpcs, apprtt_instance_handle *h)
{
    te_errno rc = 0;
    tapi_job_channel_t *result = NULL;

    if ((rc = tapi_job_factory_rpc_create(rpcs, &h->factory)) != 0)
    {
        ERROR("%s(): failed to create a factory", __FUNCTION__);
        return rc;
    }

    if ((rc = tapi_job_create(h->factory, NULL, ((char **)h->args.data.ptr)[0],
                              (const char **)h->args.data.ptr, NULL,
                              &h->job)) != 0)
    {
        ERROR("%s(): failed to create a job", __FUNCTION__);
        return rc;
    }

    if ((rc = tapi_job_alloc_output_channels(h->job, APPRTT_OUT_CHANNELS_NUM,
                                             h->out_channels)) != 0)
    {
        ERROR("%s(): failed to allocate output channels", __FUNCTION__);
        return rc;
    }

    if ((rc = tapi_job_attach_filter(TAPI_JOB_CHANNEL_SET(h->out_channels[0],
                                                          h->out_channels[1]),
                                     NULL, FALSE, TE_LL_WARN, &result)) != 0)
    {
        ERROR("%s(): failed to attach a filter to output channels",
              __FUNCTION__);
        return rc;
    }

    /*
     * Print all messages which are not APP-RTT values (i.e. starting with a
     * digit). RTT values are noisy and are processed by a specific TAPI Job
     * filter.
     */
    if ((rc = tapi_job_filter_add_regexp(result, "^(?![0-9]).+", 0)) != 0)
        ERROR("%s(): failed to add regexp for the filter", __FUNCTION__);

    return rc;
}

/**
 * Initialize an agent job for client instance.
 *
 * @param rpcs  RPC client for running the client.
 * @param h     Client handle.
 * @param opts  Client command line options
 *
 * @return Status code.
 */
static te_errno
apprtt_init_client_job(rcf_rpc_server *rpcs, apprtt_instance_handle *h,
                       sockts_apprtt_client_options *opts)
{
    te_errno rc = 0;
    const char *path = NULL;

    const tapi_job_opt_bind opt_binds[] = TAPI_JOB_OPT_SET(
        TAPI_JOB_OPT_DUMMY((opts->prefix != NULL) ? SOCKTS_APPRTT_PATH : ""),
        TAPI_JOB_OPT_SOCKADDR_PTR("--srv-addr", FALSE,
                                  sockts_apprtt_client_options, srv_addr),
        TAPI_JOB_OPT_UINT("--time-to-run", FALSE, NULL,
                          sockts_apprtt_client_options, time_to_run),
        TAPI_JOB_OPT_UINT("--chunk-size", FALSE, NULL,
                          sockts_apprtt_client_options, chunk_size),
        TAPI_JOB_OPT_DUMMY("--data-check")
    );

    if (opts->prefix != NULL)
        path = opts->prefix;
    else
        path = SOCKTS_APPRTT_PATH;

    rc = tapi_job_opt_build_args(path, opt_binds, opts, &h->args);
    if (rc != 0)
    {
        ERROR("%s(): Failed to create command line arguments", __FUNCTION__);
        return rc;
    }

    return apprtt_init_job(rpcs, h);
}

/**
 * Initialize an agent job for server instance.
 *
 * @param rpcs  RPC server for running the server.
 * @param h     Server handle.
 * @param opts  Server command line options
 *
 * @return Status code.
 */
static te_errno
apprtt_init_server_job(rcf_rpc_server *rpcs, apprtt_instance_handle *h,
                       sockts_apprtt_server_options *opts)
{
    te_errno rc = 0;
    const char *path = NULL;

    const tapi_job_opt_bind opt_binds[] = TAPI_JOB_OPT_SET(
        TAPI_JOB_OPT_DUMMY((opts->prefix != NULL) ? SOCKTS_APPRTT_PATH : ""),
        TAPI_JOB_OPT_UINT("--chunk-size", FALSE, NULL,
                          sockts_apprtt_server_options, chunk_size),
        TAPI_JOB_OPT_DUMMY("--data-check")
    );

    if (opts->prefix != NULL)
        path = opts->prefix;
    else
        path = SOCKTS_APPRTT_PATH;

    rc = tapi_job_opt_build_args(path, opt_binds, opts, &h->args);
    if (rc != 0)
    {
        ERROR("%s(): Failed to create command line arguments", __FUNCTION__);
        return rc;
    }

    return apprtt_init_job(rpcs, h);
}

/**
 * Generic function for waiting client or server.
 *
 * @param job           Agent job handle.
 * @param name          Name of instance (for logging purpose).
 * @param timeout_ms    Timeout in ms to wait.
 *
 * @return Status code.
 */
static te_errno
apprtt_instance_wait(tapi_job_t *job, const char *name, int timeout_ms)
{
    tapi_job_status_t status = {0};
    te_errno          rc = 0;

    if ((rc = tapi_job_wait(job, timeout_ms, &status)) != 0)
    {
        ERROR("%s(): waiting for %s failed", __FUNCTION__, name);
        return rc;
    }

    if (status.type == TAPI_JOB_STATUS_SIGNALED)
    {
        WARN("%s(): %s was terminated by a signal", __FUNCTION__, name);
        return 0;
    }
    else if (status.type == TAPI_JOB_STATUS_UNKNOWN)
    {
        ERROR("%s(): %s terminated by unknown reason", __FUNCTION__, name);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }
    else if (status.value != 0)
    {
        ERROR("%s(): %s failed with return code %d",
              __FUNCTION__, name, status.value);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    return rc;
}

/** See definition in sockapi-ts_apprtt.h */
te_errno
sockts_apprtt_create(rcf_rpc_server *client_pco,
                     sockts_apprtt_client_options *client_opts,
                     rcf_rpc_server *server_pco,
                     sockts_apprtt_server_options *server_opts,
                     sockts_apprtt_handle **app)
{
    sockts_apprtt_handle   *apprtt_handle = NULL;
    int                     rc = 0;

    if (app == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    apprtt_handle = tapi_calloc(1, sizeof(*apprtt_handle));
    *app = apprtt_handle;

    rc = apprtt_init_server_job(server_pco, &apprtt_handle->server,
                                server_opts);
    if (rc != 0)
        return rc;

    rc = apprtt_init_client_job(client_pco, &apprtt_handle->client,
                                client_opts);
    if (rc != 0)
        return rc;

    rc = tapi_job_attach_filter(
                TAPI_JOB_CHANNEL_SET(apprtt_handle->client.out_channels[0]),
                "rtt", TRUE, 0, &apprtt_handle->rtt_filter);
    if (rc != 0)
        return rc;

    /*
     * "ol-apprtt" client output is:
     *  <output>
     *   some string
     *   XXXXX
     *   XXXXX
     *   XXXXX
     *   .....
     *   some string
     *   some string
     *  </output>
     *
     *  The XXXXX's are decimal values which we need to catch.
     */
    return tapi_job_filter_add_regexp(apprtt_handle->rtt_filter,
                                      "[0-9]+\\s", 0);
}

/** See definition in sockapi-ts_apprtt.h */
te_errno
sockts_apprtt_start(sockts_apprtt_handle *app)
{
    te_errno rc = 0;

    if ((rc = tapi_job_start(app->server.job)) != 0)
    {
        ERROR("%s(): failed to start server job", __FUNCTION__);
        return rc;
    }

    if ((rc = tapi_job_start(app->client.job)) != 0)
    {
        ERROR("%s(): failed to start client job", __FUNCTION__);
        return rc;
    }

    return rc;
}

/** See definition in sockapi-ts_apprtt.h */
te_errno
sockts_apprtt_wait(sockts_apprtt_handle *app, int timeout_ms)
{
    te_errno rc = 0;

    if ((rc = apprtt_instance_wait(app->client.job, "client",
                                   timeout_ms)) != 0)
    {
        return rc;
    }

    return apprtt_instance_wait(app->server.job, "server", timeout_ms);
}

/** See definition in sockapi-ts_apprtt.h */
te_errno
sockts_apprtt_getrtt(sockts_apprtt_handle *app, te_vec *rtt_values)
{
    tapi_job_buffer_t buf = TAPI_JOB_BUFFER_INIT;
    te_errno          rc = 0;
    te_vec            rtts = TE_VEC_INIT(int);
    const char       *ptr = NULL;

    while (!buf.eos && rc == 0)
    {
        rc = tapi_job_receive(TAPI_JOB_CHANNEL_SET(app->rtt_filter),
                              APPRTT_WAIT_TIMEOUT, &buf);
        if (TE_RC_GET_ERROR(rc) == TE_ETIMEDOUT)
        {
            rc = 0;
            break;
        }
    }

    ptr = buf.data.ptr;

    while ((size_t)(ptr - buf.data.ptr) < buf.data.len)
    {
        int rtt = 0;

        if (sscanf(ptr, "%d\n", &rtt) != 1)
        {
            ERROR("%s(): failed to obtain RTT value", __FUNCTION__);
            te_vec_free(&rtts);
            return TE_RC(TE_TAPI, TE_EFAIL);
        }

        TE_VEC_APPEND(&rtts, rtt);

        while (*ptr++ != '\n');
    }

    *rtt_values = rtts;

    return rc;
}

/** See definition in sockapi-ts_apprtt.h */
te_errno
sockts_apprtt_getrtt_silent(sockts_apprtt_handle *app,
                            te_vec *rtt_values,
                            te_bool silent,
                            rcf_rpc_server *client_pco,
                            rcf_rpc_server *server_pco)
{
    te_errno rc;
    te_bool client_silent_def = client_pco->silent_default;
    te_bool server_silent_def = server_pco->silent_default;

    if (silent)
    {
        client_pco->silent = client_pco->silent_default = TRUE;
        server_pco->silent = server_pco->silent_default = TRUE;
    }

    rc = sockts_apprtt_getrtt(app, rtt_values);

    if (silent)
    {
        client_pco->silent = client_pco->silent_default = client_silent_def;
        server_pco->silent = server_pco->silent_default = server_silent_def;
    }
    return rc;
}

/** See definition in sockapi-ts_apprtt.h */
te_errno
sockts_apprtt_destroy(sockts_apprtt_handle *app)
{
    te_errno    rc = 0;

    if (app == NULL)
        return 0;

    if (app->client.job != NULL)
    {
        if ((rc = tapi_job_destroy(app->client.job, -1)) != 0)
        {
            ERROR("%s(): failed to destroy %s client instance with error %r",
                  __FUNCTION__, SOCKTS_APPRTT_PATH, rc);
        }
    }

    if (app->server.job != NULL)
    {
        if ((rc = tapi_job_destroy(app->server.job, -1)) != 0)
        {
            ERROR("%s(): failed to destroy %s server instance with error %r",
                  __FUNCTION__, SOCKTS_APPRTT_PATH, rc);
        }
    }

    tapi_job_factory_destroy(app->client.factory);
    tapi_job_factory_destroy(app->server.factory);

    free(app);
    return 0;
}

te_errno
sockts_apprtt_mi_report_rtt(te_vec *rtt_values)
{
    te_mi_logger *logger;
    te_errno      rc;
    int          *elem;

    rc = te_mi_logger_meas_create("ol-apprtt", &logger);
    if (rc != 0)
        return rc;

    TE_VEC_FOREACH(rtt_values, elem)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_RTT, "App-level RTT",
                              TE_MI_MEAS_AGGR_SINGLE, *elem,
                              TE_MI_MEAS_MULTIPLIER_MICRO);
    }

    /* Add "graph" view. See bug 10986 for details. */
    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH, "",
                               "App-level RTT");
    te_mi_logger_meas_graph_axis_add_name(
                                      logger, NULL,
                                      TE_MI_MEAS_VIEW_LINE_GRAPH, "",
                                      TE_MI_GRAPH_AXIS_X,
                                      TE_MI_GRAPH_AUTO_SEQNO);

    te_mi_logger_destroy(logger);
    return 0;
}
