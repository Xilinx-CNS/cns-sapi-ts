/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Onload API extension. 
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 *
 * $Id:
 */

/** Log user */
#define TE_LGR_USER "Onload"

#include "sockapi-ts.h"
#include "onload.h"
#include "tapi_host_ns.h"

/* Onload cplane server name. */
#define ONLOAD_CPLANE_SERVER_NAME "onload_cp_server"

int
tapi_onload_object_create(rcf_rpc_server *rpcs, const char *object_type)
{
    int s = -1;
    int fds[2] = {-1, -1};

    if (strcmp(object_type, "TCP") == 0)
        s = rpc_socket(rpcs, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    else if (strcmp(object_type, "UDP") == 0)
        s = rpc_socket(rpcs, RPC_AF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    else if (strcmp(object_type, "pipe") == 0)
    {
        rpc_pipe(rpcs, fds);
        /* leave only one fd */
        rpc_close(rpcs, fds[1]);
        s = fds[0];
    }
    else if (strcmp(object_type, "epoll") == 0)
        s = rpc_epoll_create(rpcs, 1);
    else
        TEST_FAIL("Invalid parameter %s", object_type);

    return s;
}

int
tapi_onload_compare_stack_names(rcf_rpc_server *rpcs1,
                                rcf_rpc_server *rpcs2,
                                const char *object_type,
                                const char *prefix,
                                te_bool exact_match)
{
    int s1, s2;
    char *s1_name, *s2_name;

    s1 = tapi_onload_object_create(rpcs1, object_type);
    s2 = tapi_onload_object_create(rpcs2, object_type);

    s1_name = tapi_onload_get_stackname(rpcs1, s1);
    s2_name = tapi_onload_get_stackname(rpcs2, s2);

    /* close the objects prior to other checks */
    rpc_close(rpcs1, s1);
    rpc_close(rpcs2, s2);

    if (strncmp(s1_name, prefix, strlen(prefix)) != 0 ||
        strncmp(s2_name, prefix, strlen(prefix)) != 0)
    {
        ERROR("Wrong prefixes set for stacknames");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if ((strcmp(s1_name, s2_name) == 0) && !exact_match)
    {
        ERROR("Stacknames match although suffixes must differ");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if ((strcmp(s1_name, s2_name) != 0) && exact_match)
    {
        ERROR("Stacknames don't match although they MUST");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    return 0;
}

/* See description in the fd_cache.h */
te_bool
tapi_onload_socket_is_cached(rcf_rpc_server *rpcs, int sock)
{
    rpc_stat st;
    tarpc_onload_stat ostat;
    int rc_sys;
    int rc_ol;

    memset(&st, 0, sizeof(st));
    memset(&ostat, 0, sizeof(ostat));

    rc_ol = rpc_onload_fd_stat(rpcs, sock, &ostat);

    RPC_AWAIT_IUT_ERROR(rpcs);
    if ((rc_sys = rpc_fstat(rpcs, sock, &st)) < 0 &&
        RPC_ERRNO(rpcs) != RPC_EBADF)
        TEST_FAIL("fstat() failed with unexpected errno: %r",
                  RPC_ERRNO(rpcs));

    if (rc_ol == 0 && rc_sys == 0)
        return TRUE;

    return FALSE;
}

/* See description in the onload.h */
te_bool
tapi_onload_check_socket_caching(rcf_rpc_server *rpcs1, int sock,
                                 rcf_rpc_server *rpcs2,
                                 int sockcache_contention)
{
    if (!tapi_onload_check_sockcache_contention(rpcs2, sockcache_contention))
        return FALSE;

    return tapi_onload_socket_is_cached(rpcs1, sock);
}


/* See description in onload.h */
int
tapi_onload_get_stats_val(rcf_rpc_server *rpcs, const char *name)
{
    int rc;
    int num = 0;

    if (!tapi_onload_lib_exists(rpcs->ta))
        TEST_VERDICT("This iteration cannot be tested with unaccelerated "
                     "socket");

    rc = rpc_get_stat_from_orm_json(rpcs, name, &num);
    if (rc != 0)
        TEST_VERDICT("Failed to get %s value from Onload stats", name);

    return num;
}

/* See description in onload.h */
int
tapi_onload_get_free_cache(rcf_rpc_server *rpcs, te_bool active, te_bool *reuse)
{
    char       *buf = NULL;
    char       *ptr = NULL;
    int         num = 0;
    const char *command = "te_onload_stdump lots | grep ";

    if (!tapi_onload_lib_exists(rpcs->ta))
        TEST_VERDICT("This iteration cannot be tested with unaccelerated "
                     "socket");

    RPC_AWAIT_IUT_ERROR(rpcs);
    rpc_shell_get_all(rpcs, &buf, "%s %s", -1, command,
                      active ? "'active cache:'" : "sockcache:");
    if (buf != NULL)
    {
        if (active)
            ptr = strstr(buf, "avail");
        else
            ptr = buf;

        if ((ptr = strchr(ptr, '=')) == NULL)
            num = 0;
        else
            num = atoi(ptr + 1);
    }
    else
    {
        TEST_VERDICT("Failed to get Onload %s cache length",
                     active ? "active" : "passive");
    }

    if (reuse != NULL)
    {
        /* Check for passive scalable cache */
        if (!active && (strstr(buf, "cache=EMPTY") != NULL))
        {
            free(buf);
            RPC_AWAIT_IUT_ERROR(rpcs);
            rpc_shell_get_all(rpcs, &buf, "%s 'passive scalable cache:'", -1,
                              command);
        }

        if (buf[0] == '\0' || strstr(buf, "cache=EMPTY") != NULL)
            *reuse = FALSE;
        else
            *reuse = TRUE;
    }

    free(buf);

    return num;
}

typedef struct reset_nic_ctx {
    sockts_reset_mode mode;
    sockts_rpcs_h     srpc_h;
    char             *agt_dir;
} reset_nic_ctx;

/**
 * Reset an interface using Onload utility @b cmdclient.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param ctx       The context
 *
 * @return Status code.
 */
static te_errno
reset_nic_tool(const char *ta, const char *ifname, reset_nic_ctx *ctx)
{
    rpc_wait_status  st;
    sockts_rpcs     *srpc;
    te_errno         rc;

    if (ctx->mode != SOCKTS_RESET_NIC_WORLD)
    {
        ERROR("Wrong mode value for 'cmdclient' utility: %d", ctx->mode);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    rc = sockts_rpcs_get(ta, &ctx->srpc_h, &srpc);
    if (rc != 0)
        return rc;

    RPC_AWAIT_IUT_ERROR(srpc->rpcs);
    st = rpc_system_ex(srpc->rpcs, "%s/%s -c 'reboot; q' ioctl=%s",
                       ctx->agt_dir, SOCKTS_CMDCLIENT, ifname);
    if (st.flag != RPC_WAIT_STATUS_EXITED || st.value != 0)
    {
        ERROR("Failed to reset interface");
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    return 0;
}

/**
 * Reset an interface using a method defined by @p ctx->mode.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param ctx       The context
 *
 * @return Status code.
 */
static te_errno
reset_nic(const char *ta, const char *ifname, reset_nic_ctx *ctx)
{
    te_errno rc;

    switch (ctx->mode)
    {
        case SOCKTS_RESET_ETHTOOL:
            rc = tapi_cfg_if_reset(ta, ifname);
            break;

        case SOCKTS_RESET_DOWN_UP:
            rc = tapi_cfg_base_if_down(ta, ifname);
            if (rc != 0)
                return rc;
            TAPI_WAIT_NETWORK;
            rc = tapi_cfg_base_if_up(ta, ifname);
            break;

        default:
            rc = reset_nic_tool(ta, ifname, ctx);
    }

    return rc;
}

/**
 * Callback function to reset real network interfaces.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param opaque    The context (@c reset_nic_ctx)
 *
 * @return Status code.
 */
static te_errno
reset_nic_cb(const char *ta, const char *ifname, void *opaque)
{
    te_interface_kind       kind;
    te_errno                rc;

    rc = tapi_cfg_get_if_kind(ta, ifname, &kind);
    if (rc != 0)
        return rc;

    if (kind == TE_INTERFACE_KIND_NONE)
    {
        rc = reset_nic(ta, ifname, (reset_nic_ctx *)opaque);
        if (rc != 0)
            return rc;
    }

    return tapi_host_ns_if_parent_iter(ta, ifname, &reset_nic_cb, opaque);
}

/* See description in onload.h */
void
sockts_reset_interface(const char *ta, const char *ifname,
                       sockts_reset_mode mode)
{
    reset_nic_ctx   ctx = {.mode = mode};
    te_errno        rc;
    te_errno        rc2;

    rc = cfg_get_instance_fmt(NULL, &ctx.agt_dir, "/agent:%s/dir:", ta);
    if (rc != 0)
        TEST_FAIL("Failed to get agent directory");

    sockts_rpcs_init(&ctx.srpc_h);

    rc = reset_nic_cb(ta, ifname, (void *)&ctx);

    free(ctx.agt_dir);

    rc2 = sockts_rpcs_release(&ctx.srpc_h);
    if (rc == 0)
        rc = rc2;

    if (rc != 0)
        TEST_FAIL("NIC reset failed: %r", rc);
}

/* See description in onload.h */
int
tapi_onload_stacks_number(rcf_rpc_server *rpcs)
{
    char     *out_cmd_buf = NULL;
    int       num;

    RPC_AWAIT_IUT_ERROR(rpcs);
    rpc_shell_get_all(rpcs, &out_cmd_buf,
                      "wc -l /proc/driver/onload/stacks", -1);

    num = atoi(out_cmd_buf);
    free(out_cmd_buf);

    return num;
}

/* See description in onload.h */
te_errno
tapi_onload_check_single_stack(rcf_rpc_server *rpcs)
{
    int num;

    num = tapi_onload_stacks_number(rpcs);

    if (num == 0)
    {
        RING_VERDICT("Onload stack does not exist");
        return TE_RC(TE_TAPI, TE_ENOENT);
    }
    if (num > 1)
    {
        ERROR("Onload stacks number: %d", num);
        RING_VERDICT("There are more than one Onload stacks");
        return TE_RC(TE_TAPI, TE_ETOOMANY);
    }

    return 0;
}

te_errno
tapi_onload_copy_sapi_ts_script(rcf_rpc_server *rpcs, const char *script_name)
{
    te_errno rc;
    const char *sapi_dir = NULL;
    char script_path[PATH_MAX];
    char dst_path[PATH_MAX];
    char *agt_dir = NULL;

    if ((sapi_dir = getenv("SOCKAPI_TS_LIBDIR")) == NULL)
    {
        ERROR("Environment variable SOCKAPI_TS_LIBDIR is not set");
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    rc = cfg_get_instance_fmt(NULL, &agt_dir, "/agent:%s/dir:", rpcs->ta);
    if (rc != 0)
    {
        ERROR("Failed to get instance /agent:%s/dir:", rpcs->ta);
        return rc;
    }

    TE_SPRINTF(script_path, "%s/scripts/%s", sapi_dir,
               script_name);
    TE_SPRINTF(dst_path, "%s/%s", agt_dir, script_name);

    rc = rcf_ta_put_file(rpcs->ta, 0, script_path, dst_path);
    if (rc != 0)
    {
        ERROR("Failed to put file '%s' to '%s'", script_path, dst_path);
        return rc;
    }
    RING("File '%s' put to %s:%s", script_path, rpcs->ta, dst_path);
    return rc;
}

/* See description in onload.h */
void
tapi_onload_check_single_rss_cpus(rcf_rpc_server *rpcs)
{
    cfg_val_type type = CVT_STRING;
    char *rss_cpus_val = NULL;

    CHECK_RC(cfg_get_instance_fmt(&type, &rss_cpus_val,
                                  "/agent:%s/module:sfc/parameter:rss_cpus",
                                  rpcs->ta));
    if (strcmp(rss_cpus_val, "1") != 0)
    {
        TEST_FAIL("rss_cpus sfc module parameter has incorrect value - %s "
                  "instead of 1. Please reload drivers using \"rss_cpus=1\"",
                  rss_cpus_val);
    }

    free(rss_cpus_val);
}

/* See description in onload.h */
void
tapi_onload_module_param_set(rcf_rpc_server *rpcs, const char *name,
                             const char *val, char **old_val,
                             te_bool log_restore)
{
    rpc_wait_status rc;

    if (old_val != NULL)
    {
        CHECK_RC(cfg_get_instance_fmt(NULL, old_val,
                                  "/agent:%s/module:onload/parameter:%s",
                                  rpcs->ta, name));
    }

    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, val),
             "/agent:%s/module:onload/parameter:%s",
             rpcs->ta, name));

    RPC_AWAIT_IUT_ERROR(rpcs);
    rc = rpc_system_ex(rpcs, "echo 'sockapi-ts: %s Onload module "
                             "parameter %s to %s' > /dev/kmsg",
                             log_restore ? "restore" : "set",
                             name, val);
    if (rc.value != 0)
        ERROR("%s(): failed to write a message to /dev/kmsg on IUT",  __func__);
}

/* See description in onload.h */
void
tapi_onload_module_ci_tp_log_set(rcf_rpc_server *rpcs, const char *val,
                                 char **old_val)
{
    tapi_onload_module_param_set(rpcs, "ci_tp_log", val, old_val, FALSE);
}

/* See description in onload.h */
void
tapi_onload_module_ci_tp_log_restore(rcf_rpc_server *rpcs, const char *val)
{
    tapi_onload_module_param_set(rpcs, "ci_tp_log", val, NULL, TRUE);
}
