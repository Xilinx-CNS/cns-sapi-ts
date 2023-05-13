/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Test Suite prologue.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef DOXYGEN_TEST_SPEC

/** Logging subsystem entity name */
#define TE_TEST_NAME    "prologue"

#include "sockapi-test.h"

#include "sockapi-ts.h"
#include "logger_ten.h"
#include "tapi_test.h"
#include "tapi_proc.h"
#include "tapi_cfg_iptables.h"
#include "tapi_network.h"
#include "tapi_host_ns.h"
#include "tapi_tags.h"
#include "onload.h"
#include "lib-ts.h"
#include "lib-ts_netns.h"
#include "lib-ts_timestamps.h"

#define CONSOLE_NAME      "serial_console"
#define AGENT_FOR_CONSOLE SERIAL_LOG_PARSER_AGENT

/**
 * Callback function to disable LRO on all teaming interfaces.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param opaque    The context (unused)
 *
 * @return Status code.
 */
static te_errno
team_ifs_disable_lro_cb(const char *ta, const char *ifname, void *opaque)
{
    te_interface_kind kind;
    te_errno          rc;

    UNUSED(opaque);

    rc = tapi_cfg_get_if_kind(ta, ifname, &kind);
    if (rc == 0 && kind == TE_INTERFACE_KIND_TEAM)
        rc = tapi_cfg_if_feature_set(ta, ifname, "rx-lro", 0);

    return rc;
}

/**
 * Disable LRO on all teaming interfaces of a host.
 * The reason is SF bug 73281.
 *
 * @param ta    Name of a test agent on the host
 *
 * @return Status code.
 */
static te_errno
sockts_team_ifs_disable_lro(const char *ta)
{
    te_errno rc;
    char    *host;

    rc = tapi_host_ns_get_host(ta, &host);
    if (rc != 0)
        return rc;

    rc = tapi_host_ns_if_host_iter(host, &team_ifs_disable_lro_cb, NULL);
    free(host);

    return rc;
}

/**
 * Configure IP_TRANSPARENT testing.
 *
 * @param pco_iut   IUT RPC server.
 *
 */
/* According to the bug 55326:
 *
 * To enable ip transparent we should get value of @b ST_IP_TRANSPARENT
 * and if it is @c "yes" using configurator on IUT:
 *
 * sudo iptables -t mangle -N DIVERT
 * sudo iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
 * sudo iptables -t mangle -A DIVERT -j MARK --set-mark 1
 * sudo iptables -t mangle -A DIVERT -j ACCEPT
 * sudo ip rule add fwmark 1 lookup 100
 * sudo ip route add local 0.0.0.0/0 dev lo table 100
 *
 */
static void
configure_ip_transparent(rcf_rpc_server *pco_iut)
{
    const char     *st_ip_transparent = getenv("ST_IP_TRANSPARENT");
    uint32_t        required;
    te_conf_ip_rule ip_rule;
    char            dst_addr[INET_ADDRSTRLEN] = {0};
    char           *if_name = NULL;
    cfg_handle     *interfaces = NULL;
    unsigned int    num;

    if (st_ip_transparent == NULL || strcmp(st_ip_transparent, "yes") != 0)
        return;

    CHECK_RC(cfg_find_pattern_fmt(&num, &interfaces, "/agent:%s/interface:*",
                                  pco_iut->ta));
    if (num != 0)
        CHECK_RC(cfg_get_inst_name(interfaces[0], &if_name));
    else
        TEST_VERDICT("IUT doesn't have interfaces");
    free(interfaces);

    CHECK_RC(tapi_cfg_iptables_chain_add(pco_iut->ta, if_name, "mangle",
                                         "DIVERT", FALSE));
    CHECK_RC(tapi_cfg_iptables_cmd(pco_iut->ta, if_name, "mangle", "DIVERT",
                                   "-A PREROUTING -p tcp -m socket -j"));
    CHECK_RC(tapi_cfg_iptables_cmd(pco_iut->ta, if_name, "mangle", "DIVERT",
                                   "-A -j MARK --set-mark 1"));
    CHECK_RC(tapi_cfg_iptables_cmd(pco_iut->ta, if_name, "mangle", "DIVERT",
                                   "-A -j ACCEPT"));

    CHECK_RC(te_conf_ip_rule_from_str("fwmark=1,table=100", &required,
                                      &ip_rule));
    CHECK_RC(tapi_cfg_add_rule(pco_iut->ta, AF_INET, &ip_rule));

    CHECK_RC(tapi_cfg_add_full_route(pco_iut->ta, AF_INET, dst_addr, 0, NULL,
                                     "lo", NULL, "local", 0, 0, 0, 0, 0, 0,
                                     100, NULL));

    free(if_name);

    CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 1, NULL,
                                  "net/ipv4/conf:lo/forwarding"));
    CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 0, NULL,
                                  "net/ipv4/conf:lo/rp_filter"));
    CHECK_RC(tapi_cfg_sys_set_int(pco_iut->ta, 0, NULL,
                                  "net/ipv4/conf:all/rp_filter"));
}

/**
 * Redirect all outcoming packets from @p pco to NFQUEUE queue 0.
 *
 * @param pco            TST RPC server
 * @param iut_ip_addr    IP address of IUT
 *
 */
static void
configure_nfqueue_tst(rcf_rpc_server *pco)
{
    char           *ifname_1 = NULL;
    char           *ifname_2 = NULL;

    if (getenv("SOCKAPI_TS_IP_OPTIONS") == NULL)
        return;

    ifname_1 = getenv("TE_TST1_IUT");
    if (ifname_1 != NULL)
    {
        CHECK_RC(tapi_cfg_iptables_chain_add(pco->ta, ifname_1, "mangle",
                                             "NFQ_A", FALSE));
        CHECK_RC(tapi_cfg_iptables_cmd_fmt(pco->ta, ifname_1, "mangle", "NFQ_A",
                                           "-A OUTPUT -o %s -j", ifname_1));
        CHECK_RC(tapi_cfg_iptables_cmd(pco->ta, ifname_1, "mangle", "NFQ_A",
                                       "-A -j NFQUEUE --queue-num 0"));
    }
    else
    {
        ERROR("There is no TE_TST1_IUT interface to set NFQUEUE");
    }

    if (ifname_1 != NULL)
        ifname_2 = getenv("TE_TST1_IUT_IUT");

    if (!te_str_is_null_or_empty(ifname_2))
    {
        CHECK_RC(tapi_cfg_iptables_chain_add(pco->ta, ifname_2, "mangle",
                                             "NFQ_B", FALSE));
        CHECK_RC(tapi_cfg_iptables_cmd_fmt(pco->ta, ifname_2, "mangle", "NFQ_B",
                                           "-A OUTPUT -o %s -j", ifname_2));
        CHECK_RC(tapi_cfg_iptables_cmd(pco->ta, ifname_2, "mangle", "NFQ_B",
                                       "-A -j NFQUEUE --queue-num 0"));
    }
    else
    {
        WARN("There is no TE_TST1_IUT_IUT interface to set NFQUEUE");
    }
}


/**
 * Copy SF `cmdclient` tool to test agent @p ta.
 *
 * @param ta        Target test agent name
 * @param agt_dir   Destination directory
 */
static void
copy_cmdclient(const char *ta, const char *agt_dir)
{
    char *cmdclient = getenv("SF_TS_CMDCLIENT");
    char  dst_path[PATH_MAX];

    if (cmdclient == NULL || *cmdclient == '\0')
        return;

    TE_SPRINTF(dst_path, "%s/%s", agt_dir, SOCKTS_CMDCLIENT);

    CHECK_RC(rcf_ta_put_file(ta, 0, cmdclient, dst_path));
    RING("File '%s' put to %s:%s", cmdclient, ta, dst_path);
}

/**
 * Copy SF tool to test agent @p ta.
 *
 * @param ta            Target test agent name
 * @param onload_gnu    Onload GNU location
 * @param agt_dir       Destination directory
 * @param onload_path   Path in the Onload GNU directory to copy from
 * @param te_name       File name to copy to
 */
static void
copy_onload_tool(const char *ta, const char *onload_gnu,
                 const char *agt_dir, const char *onload_path,
                 const char *te_name)
{
    char  onload_tool_path[PATH_MAX];
    char  dst_path[PATH_MAX];

    TE_SPRINTF(onload_tool_path, "%s/%s", onload_gnu, onload_path);
    TE_SPRINTF(dst_path, "%s/%s", agt_dir, te_name);

    CHECK_RC(libts_file_copy_ta(ta, onload_tool_path, dst_path, FALSE));
}
/**
 * Copy Onload tools to IUT test agent.
 *
 * @param pco_iut   IUT RPC server handle
 */
static void
copy_onload_tools(rcf_rpc_server *pco_iut)
{
    cfg_val_type val_type;
    char        *onload_gnu = getenv("SFC_ONLOAD_GNU");
    char        *onload_local = getenv("SFC_ONLOAD_LOCAL");
    char        *path = getenv("SFC_ONLOAD_LOCAL");
    char         dst_path[PATH_MAX];
    char        *zf_gnu = getenv("SFC_ZETAFERNO_GNU");
    char        *agt_dir = NULL;
    char *nonsf = getenv("TE_DUT_NONSF");
    te_bool is_sfc = te_str_is_null_or_empty(nonsf) || strcmp(nonsf, "0") == 0;

    val_type = CVT_STRING;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &agt_dir, "/agent:%s/dir:",
                                  pco_iut->ta));


    if (onload_gnu != NULL && *onload_gnu != '\0' && !sockts_zf_shim_run())
    {
        if (onload_local != NULL && strcmp(onload_local, "yes") == 0)
        {
            TE_SPRINTF(dst_path, "iut:%s", onload_gnu);
            path = dst_path;
        }
        else
            path = onload_gnu;
        copy_onload_tool(pco_iut->ta, path, agt_dir,
                         "tools/onload_mibdump/onload_mibdump",
                         "te_onload_mibdump");
        if (tapi_onload_run())
        {
            copy_onload_tool(pco_iut->ta, path, agt_dir,
                             "tools/ip/onload_stackdump",
                             "te_onload_stdump");

            /*
             * ulhepler build profile requires onload_helper tool
             * in the path
             */
            copy_onload_tool(pco_iut->ta, path, agt_dir,
                             "tools/onload_helper/onload_helper",
                             "onload_helper");
        }
    }

    if (sockts_zf_shim_run())
    {
        te_string zf_stackdump_path = TE_STRING_INIT_STATIC(RCF_MAX_PATH);

        if (zf_gnu != NULL && *zf_gnu != '\0')
        {
            CHECK_RC(te_string_append(&zf_stackdump_path, "bin/stripped/%s",
                     ZF_STACKDUMP_NAME));
            copy_onload_tool(pco_iut->ta, zf_gnu, agt_dir,
                             zf_stackdump_path.ptr, ZF_STACKDUMP_NAME);
        }
        else if (onload_gnu != NULL && *onload_gnu != '\0')
        {
            CHECK_RC(te_string_append(&zf_stackdump_path, "tools/zf/%s",
                     ZF_STACKDUMP_NAME));
            copy_onload_tool(pco_iut->ta, onload_gnu, agt_dir,
                             zf_stackdump_path.ptr, ZF_STACKDUMP_NAME);
        }
    }

    if (is_sfc)
        copy_cmdclient(pco_iut->ta, agt_dir);

    free(agt_dir);
}

/**
 * Get existing RPC server on a given TA, if it is present.
 *
 * @param ta      Test Agent name.
 * @param rpcs    Where to save pointer to RPC server structure
 *                (should be freed by calling function). Will be
 *                set to @c NULL if no RPC servers was found.
 */
static void
ta_get_rpcs(const char *ta, rcf_rpc_server **rpcs)
{
    cfg_handle     *rpcs_handles = NULL;
    unsigned int    rpcs_num = 0;
    char           *rpc_name = NULL;

    CHECK_RC(cfg_find_pattern_fmt(&rpcs_num, &rpcs_handles,
                                  "/agent:%s/rpcserver:*", ta));
    if (rpcs_num > 0)
    {
        CHECK_RC(cfg_get_inst_name(rpcs_handles[0], &rpc_name));
        CHECK_RC(rcf_rpc_server_get(ta, rpc_name, NULL,
                                    RCF_RPC_SERVER_GET_EXISTING |
                                    RCF_RPC_SERVER_GET_REUSE,
                                    rpcs));
        free(rpc_name);
    }
    else
    {
        *rpcs = NULL;
    }

    free(rpcs_handles);
}

/**
 * Restart all the network interfaces which are currently UP, or
 * wait for restarted interfaces to become ready.
 * Restart will result in disappearance of IPv6 FAILED neighbor
 * entries (see OL bug 9774) and in recovering of IPv6 link-local
 * addresses if they are not present.
 *
 * @param wait_ready      If @c FALSE, restart the interfaces. If @c TRUE,
 *                        wait until all the interfaces are
 *                        ready after restart.
 */
static void
restart_all_interfaces(te_bool wait_ready)
{
    cfg_handle     *ta_handles = NULL;
    unsigned int    ta_num = 0;
    char           *ta_name = NULL;

    cfg_handle     *ifs_handles = NULL;
    unsigned int    ifs_num = 0;
    char           *if_name = NULL;
    cfg_val_type    type;
    int             status;
    int             if_index;

    rcf_rpc_server *rpcs_aux = NULL;
    te_bool         rpcs_created;

    unsigned int    i;
    unsigned int    j;

    CHECK_RC(cfg_find_pattern_fmt(&ta_num, &ta_handles, "/agent:*"));

    for (i = 0; i < ta_num; i++)
    {
        CHECK_RC(cfg_get_inst_name(ta_handles[i], &ta_name));

        rpcs_aux = NULL;
        rpcs_created = FALSE;

        CHECK_RC(cfg_find_pattern_fmt(&ifs_num, &ifs_handles,
                                      "/agent:%s/interface:*", ta_name));

        for (j = 0; j < ifs_num; j++)
        {
            CHECK_RC(cfg_get_inst_name(ifs_handles[j], &if_name));


            type = CVT_INTEGER;
            CHECK_RC(cfg_get_instance_fmt(&type, &if_index,
                                          "/agent:%s/interface:%s/index:",
                                          ta_name, if_name));
            if (if_index == 1 || strcmp(if_name, "lo") == 0)
            {
                /* Do not touch loopback interface */
                free(if_name);
                continue;
            }

            type = CVT_INTEGER;
            CHECK_RC(cfg_get_instance_fmt(&type, &status,
                                          "/agent:%s/interface:%s/status:",
                                          ta_name, if_name));

            if (status)
            {
                if (wait_ready)
                {
                    if (rpcs_aux == NULL)
                    {
                        ta_get_rpcs(ta_name, &rpcs_aux);
                        if (rpcs_aux == NULL)
                        {
                            CHECK_RC(rcf_rpc_server_create(
                                            ta_name, "rpc_ifs_restart",
                                            &rpcs_aux));
                            rpcs_created = TRUE;
                        }
                    }

                    CHECK_RC(sockts_wait_for_if_up(rpcs_aux, if_name));
                }
                else
                {
                    CHECK_RC(tapi_cfg_base_if_down_up(ta_name, if_name));
                }
            }

            free(if_name);
        }

        free(ifs_handles);
        free(ta_name);

        if (rpcs_created)
            CHECK_RC(rcf_rpc_server_destroy(rpcs_aux));
        else
            free(rpcs_aux);
    }

    free(ta_handles);
}

/*
 * Copy zf library to IUT agent directory.
 * It is necessary when using ZF socket shim. Socket shim itself is
 * used via LD_PRELOAD, but it depends on the zf library. To avoid using
 * NFS this library should be copied to IUT agent.
 */
static void
copy_lib_for_zfshim()
{
    cfg_val_type  val_type;
    const char   *onload_gnu;
    const char   *zf_gnu;
    te_string     src = TE_STRING_INIT_STATIC(RCF_MAX_PATH);
    te_string     dst = TE_STRING_INIT_STATIC(RCF_MAX_PATH);
    char         *agt_dir = NULL;
    te_errno      rc;
    const char   *ta;

    if (!sockts_zf_shim_run())
        return;

    if ((ta = getenv("TE_IUT_TA_NAME_NS")) == NULL)
        return;

    onload_gnu = getenv("SFC_ONLOAD_GNU");
    zf_gnu = getenv("SFC_ZETAFERNO_GNU");

    if (onload_gnu == NULL && zf_gnu == NULL)
        return;

    val_type = CVT_STRING;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &agt_dir, "/agent:%s/dir:",
                                  ta));
    CHECK_RC(te_string_append(&dst, "%s/libonload_zf.so.1", agt_dir));

    /*
     * Zetaferno has a separate repo after onload-8.0 release.
     * It must be taken into account when setting LD_LIBRARY_PATH.
     */
    if (zf_gnu != NULL && zf_gnu[0] != '\0')
        CHECK_RC(te_string_append(&src, "%s/lib/", zf_gnu));
    else
        CHECK_RC(te_string_append(&src, "%s/lib/zf/", onload_gnu));
    CHECK_RC(te_string_append(&src, "libonload_zf.so"));

    if ((rc = access(src.ptr, F_OK)) < 0)
    {
        ERROR("There is no such library: %s", src.ptr);
        return;
    }
    rc = rcf_ta_put_file(ta, 0, src.ptr, dst.ptr);
    if (rc != 0)
    {
        ERROR("Failed to put file '%s' to %s:%s", src.ptr, ta, dst.ptr);
    }
    else
    {
        RING("File '%s' put to %s:%s", src.ptr, ta, dst.ptr);
    }
}

/**
 * Start a daemon which capture all packets from NFQUEUE queue 0 on @p pco agent.
 *
 * @param pco    TST RPC server
 *
 */
static void
start_nfqueue_handler(rcf_rpc_server *pco)
{
    tarpc_pid_t     pid = -1;
    const char     *sapi_dir = NULL;
    char           *ta_dir = NULL;
    int             fd_out;
    char            buf_out[TAPI_READ_BUF_SIZE] = {0};
    int             bytes;
    cfg_val_type    val_t_str = CVT_STRING;

    if (getenv("SOCKAPI_TS_IP_OPTIONS") == NULL)
        return;

    if ((sapi_dir = getenv("SOCKAPI_TS_LIBDIR")) == NULL)
        TEST_FAIL("Environment variable SOCKAPI_TS_LIBDIR is not set");

    CHECK_RC(cfg_get_instance_fmt(&val_t_str, &ta_dir,
                                  "/agent:%s/dir:", pco->ta));

    pid = rpc_te_shell_cmd(pco, "nice -n -20 %s/nfq_daemon", -1,
                           NULL, &fd_out, NULL, ta_dir);
    if (pid < 0)
    {
        ERROR("Failed to run %snfq_daemon", ta_dir);
        goto cleanup;
    }

    if (rpc_waitpid(pco, pid, NULL, 0) < 0)
    {
        ERROR("Failed to waitpid() of %d", pid);
        goto cleanup;
    }

    pid = 0;
    if ((bytes = rpc_read(pco, fd_out, buf_out, sizeof(buf_out))) > 0)
    {
        pid = atoi(buf_out);
    }
    else
    {
        ERROR("Failed to get nfq_daemon output");
    }

    if (cfg_add_instance_fmt(NULL, CFG_VAL(INTEGER, pid),
                             "/local:%s/nfqueue_pid:", pco->ta) != 0)
    {
        rpc_kill(pco, pid, RPC_SIGKILL);
        ERROR("Failed to add nfq_daemon pid to cfg tree");
    }

    if (pid == 0)
        ERROR("Failed to parse nfq_daemon output");

    if (pid == -1)
        ERROR("Failed to start NFQUEUE handler on %s", pco->ta);

cleanup:
    free(ta_dir);
}

/**
 * Set variable ONLOAD_PRELOAD on rpc server
 *
 * @param rpcs RPC server handle.
 */
static void
set_onload_preload(rcf_rpc_server *rpcs)
{
    te_errno rc;
    char *lib_path;

    rc = cfg_get_instance_fmt(NULL, &lib_path, "/local:%s/socklib:",
                              rpcs->ta);

    if (rc == 0)
    {
        if (*lib_path == '\0')
            return;

        CHECK_RC(rcf_ta_set_var(rpcs->ta, 0, "ONLOAD_PRELOAD", RCF_STRING,
                                lib_path));
        rpc_setenv(rpcs, "ONLOAD_PRELOAD", lib_path, 1);
        /* For more details see ON-11983 */
        CHECK_RC(tapi_sh_env_set_int(rpcs, "SFNT_AVOID_FORK", 1, TRUE, FALSE));
    }
    else if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
    {
        TEST_FAIL("cfg_get_instance() failed; rc %d", rc);
    }

}

/**
 * Ping until success
 *
 * @param rpcs      RPC server handle
 * @param ifname    Interface name
 * @param addr      Destination address
 * @param attempts  Number of attempts (time between attemts is 1 second)
 */
static void
wait_connection(rcf_rpc_server *rpcs, const char *ifname,
                const struct sockaddr *addr, int attempts)
{
    int i;
    rpc_wait_status rc;
    te_errno tapi_rc = 0;
    char addr_str[INET6_ADDRSTRLEN] = {0};
    const char *ping_cmd = "ping -w1 -c1";

    if (inet_ntop(addr->sa_family, te_sockaddr_get_netaddr(addr), addr_str,
                  sizeof(addr_str)) == NULL)
    {
        TEST_FAIL("Failed to convert address to string (%s)", strerror(errno));
    }

    RING("%s(): Call the \"%s\" command up to %d times until it succeeds",
         __FUNCTION__, ping_cmd, attempts);
    for (i = 0; i < attempts; i++)
    {
        /* Do not log anything but errors, unless it is the last iteration. */
        if (i < attempts - 1)
            rpcs->silent_pass = TRUE;

        /* Flush IUT neighbours to prevent the ping tool from early quitting
         * and guarantee that the link is really tested each time. */
        tapi_rc = tapi_neight_flush(rpcs, ifname);
        if (tapi_rc != 0)
            break;

        /*
         * Do not log the ping tool (neither success nor error messages)
         * unless it is the last iteration.
         */
        if (i < attempts - 1)
            rpcs->silent = TRUE;

        RPC_AWAIT_IUT_ERROR(rpcs);
        rc = rpc_system_ex(rpcs, "%s %s >/dev/null", ping_cmd, addr_str);
        if (rc.value == 0)
            break;
    }

    if (i == attempts || tapi_rc != 0)
        TEST_FAIL("Failed to wait for the connection to be established");
}

/**
 * Set some Onload module parameters. Setting operation for these
 * parameters can fail and it should be ignored, so they are not
 * set in configuration files.
 */
static void
set_onload_module_params(void)
{
    const char *iut_ta = getenv("TE_IUT_TA_NAME");
    const char *cplane_track_xdp = getenv("SFC_CPLANE_TRACK_XDP");
    te_errno rc;

    if (cplane_track_xdp == NULL || *cplane_track_xdp == '\0')
        return;

    if (iut_ta == NULL)
        TEST_FAIL("TE_IUT_TA_NAME is not set");

    rc = cfg_set_instance_fmt(
                    CFG_VAL(STRING, cplane_track_xdp),
                    "/agent:%s/module:onload/parameter:cplane_track_xdp",
                    iut_ta);
    if (rc != 0)
    {
        if (rc == TE_RC(TE_CS, TE_ENOENT))
        {
            WARN("Failed to set Onload module parameter cplane_track_xdp, "
                 "rc=%r", rc);
        }
        else
        {
            TEST_FAIL("Setting cplane_track_xdp parameter failed with "
                      "unexpected error %r", rc);
        }
    }
}

/**
 * Add TRC tags reflecting device information.
 *
 * @note The macro has to be called inside @ref trc_tags_add
 *
 * @param ta_     Test agent name.
 * @param ifname_ Interface name.
 * @param info_   Device information to retrieve and tag.
 */
#define TRC_TAGS_ADD_DEVICE_INFO(ta_, ifname_, info_) \
    do {                                                                      \
        char *dev_info_ = NULL;                                               \
        te_string dev_info_str_ = TE_STRING_INIT;                             \
                                                                              \
        te_string_append(&dev_info_str_, "%s", #info_ "-");                   \
                                                                              \
        rc = tapi_cfg_if_deviceinfo_##info_##_get(ta_, ifname_, &dev_info_);  \
        if (rc != 0)                                                          \
        {                                                                     \
            ERROR("tapi_cfg_if_deviceinfo_" #info_ "_get() failed to get "    \
                  #info_ " for interface %s on %s: %r", ifname_, ta_, rc);    \
            free(dev_info_);                                                  \
            goto out;                                                         \
        }                                                                     \
        te_string_append(&dev_info_str_, "%s", dev_info_);                    \
        /* SWNETLINUX-5028: firmware-version in not available for EF100 */    \
        if (strcmp(dev_info_str_.ptr, #info_ "-N/A") == 0)                    \
        {                                                                     \
            WARN(#info_ " is not available.");                                \
            te_string_free(&dev_info_str_);                                   \
            free(dev_info_);                                                  \
            break;                                                            \
        }                                                                     \
                                                                              \
        rc = te_string_replace_all_substrings(&dev_info_str_, "-", " ");      \
        if (rc != 0)                                                          \
        {                                                                     \
            ERROR("te_string_replace_all_substrings() failed to replace "     \
                  "spaces on hyphens in %s: %r", dev_info_str_.ptr, rc);      \
            te_string_free(&dev_info_str_);                                   \
            free(dev_info_);                                                  \
            goto out;                                                         \
        }                                                                     \
                                                                              \
        rc = tapi_tags_add_tag(dev_info_str_.ptr, NULL);                      \
        if (rc != 0)                                                          \
        {                                                                     \
            ERROR("tapi_tags_add_tag() failed to add " #info_ " tag "         \
                  "for interface %s on %s: %r", ifname_, ta_, rc);            \
            te_string_free(&dev_info_str_);                                   \
            free(dev_info_);                                                  \
            goto out;                                                         \
        }                                                                     \
                                                                              \
        te_string_free(&dev_info_str_);                                       \
        free(dev_info_);                                                      \
    } while(0)

/**
 * Add TRC tags for the test configuration.
 *
 * @return Status code.
 */
static te_errno
trc_tags_add(rcf_rpc_server *rpcs, const char *ifname)
{
    tqe_string *phys_iface;
    te_errno rc = 0;
    tqh_strings phys_ifaces = TAILQ_HEAD_INITIALIZER(phys_ifaces);
    const char *ta = sockts_get_used_agt_name(rpcs, ifname);

    sockts_find_parent_if(rpcs, ifname, &phys_ifaces);
    phys_iface = TAILQ_FIRST(&phys_ifaces);

    if (phys_iface != NULL)
    {
        TRC_TAGS_ADD_DEVICE_INFO(ta, phys_iface->v, drivername);
        TRC_TAGS_ADD_DEVICE_INFO(ta, phys_iface->v, driverversion);
        TRC_TAGS_ADD_DEVICE_INFO(ta, phys_iface->v, firmwareversion);
    }
    else
    {
        ERROR("sockts_find_parent_if() failed to get "
              "parent (physical) interface");

        rc = TE_RC(TE_TAPI, TE_ENOENT);
    }

out:
    sockts_free_used_params_name();
    tq_strings_free(&phys_ifaces, &free);

    return rc;
}

/**
 * Set Socket API library names for Test Agents in accordance
 * with configuration in configurator.conf.
 *
 * @retval EXIT_SUCCESS     success
 * @retval EXIT_FAILURE     failure
 */
int
main(int argc, char **argv)
{
    char           *st_rpcs_no_share = getenv("ST_RPCS_NO_SHARE");
    char           *disable_timestamps = getenv("DISABLE_TIMESTAMPS");
    char           *st_no_ip6 = getenv("ST_NO_IP6");

    char           *ifs_restart_env = getenv("SAPI_RESET_IFS");
    te_bool         restart_ifs = FALSE;

    rcf_rpc_server *pco_iut;
    rcf_rpc_server *pco_tst;
    rcf_rpc_server *pco_gw;  /* does not exist in env.peer2peer */
    rcf_rpc_server *pco_reuse_stack;

    const struct sockaddr *gw_iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    const struct if_nameindex *iut_if = NULL;

    char       *ef_name;
    char       *te_sniff_csconf = getenv("TE_SNIFF_CSCONF");
    char       *st_debug_kmemleak = getenv("ST_DEBUG_KMEMLEAK");

    char       name[SOCKTS_LEAK_FNAME_MAX_LEN];

/* Redefine as empty to avoid environment processing here */
#undef TEST_START_SPECIFIC
#define TEST_START_SPECIFIC
    TEST_START;
    tapi_env_init(&env);

    libts_init_console_loglevel();

    if (ifs_restart_env != NULL &&
        (strcasecmp(ifs_restart_env, "yes") == 0 ||
         strcasecmp(ifs_restart_env, "1") == 0))
    {
        restart_ifs = TRUE;
    }

    if (tapi_onload_run())
        set_onload_module_params();

    libts_fix_tas_path_env();
    /* Restart existing RPC servers after updating PATH on Test Agents */
    CHECK_RC(rcf_rpc_servers_restart_all());

    if (restart_ifs)
    {
        RING("Restarting grabbed network interfaces...");
        restart_all_interfaces(FALSE);
        CHECK_RC(cfg_synchronize("/:", TRUE));
        RING("All interfaces were restarted");
    }
    /*
     * Now we use TA-TEN connectivity mode based on VETH intefaces
     * to avoid problems with the ST-1714 issue.
     * But it's necessary to remember that this mode may cause
     * Configurator failures in epilogue on old kernels (see ST-1000).
     * It's necessary to call @ref libts_set_zf_host_addr()
     * after network namespace setup to set a proper address for
     * Zetaferno implicit binds.
     */
    CHECK_RC(libts_setup_namespace(LIBTS_NETNS_CONN_VETH));
    copy_lib_for_zfshim();

    tapi_network_setup(st_no_ip6 == NULL || *st_no_ip6 == '\0');
    libts_set_zf_host_addr();

    rc = tapi_cfg_env_local_to_agent();
    if (rc != 0)
    {
        TEST_FAIL("tapi_cfg_env_local_to_agent() failed: %r", rc);
    }

    rc = libts_copy_socklibs();
    if (rc != 0)
    {
        TEST_FAIL("Processing of /local:*/socklib: failed: %r", rc);
    }

    if (st_rpcs_no_share == NULL || *st_rpcs_no_share == '\0')
    {
        rc = tapi_cfg_rpcs_local_to_agent();
        if (rc != 0)
        {
            TEST_FAIL("Failed to start all RPC servers: %r", rc);
        }
    }

    if (te_sniff_csconf != NULL)
    {
        CHECK_RC(cfg_process_history(te_sniff_csconf, NULL));
    }

    if (TEST_BEHAVIOUR(prologue_sleep) > 0)
        SLEEP(test_behaviour_storage.prologue_sleep);

    CFG_WAIT_CHANGES;
    CHECK_RC(rc = cfg_synchronize("/:", TRUE));

    TEST_START_ENV;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    pco_gw = tapi_env_get_pco(&env, "pco_gw");
    if (pco_gw == NULL)
        TEST_GET_ADDR(pco_tst, tst_addr);
    else
        TEST_GET_ADDR(pco_gw, gw_iut_addr);

    start_nfqueue_handler(pco_gw == NULL ? pco_tst : pco_gw);

    if (restart_ifs)
    {
        /*
         * This should be done after RPC servers are created, to avoid
         * creating/destroying RPC servers by this procedure which is
         * time-consuming.
         */
        RING("Checking that all the restarted interfaces are ready...");
        restart_all_interfaces(TRUE);
        RING("All interfaces are ready");
    }

    /*
     * Disable LRO on all teaming interfaces. The reason is SF bug 73281:
     * with enabled LRO setting large MTU may hang and break testing.
     */
    CHECK_RC(sockts_team_ifs_disable_lro(pco_iut->ta));
    CHECK_RC(sockts_team_ifs_disable_lro(
                            pco_gw == NULL ? pco_tst->ta : pco_gw->ta));

    if (disable_timestamps != NULL &&
        strcmp(disable_timestamps, "yes") == 0)
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 0, NULL,
                                         "net/ipv4/tcp_timestamps"));
    }
    else
    {
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 1, NULL,
                                         "net/ipv4/tcp_timestamps"));
    }

    libts_timestamps_configure_sfptpd();
    copy_onload_tools(pco_iut);

    /*
     * Flush neighbours tables in all hosts to
     * avoid invalid neighbours entry
     */
    CHECK_RC(tapi_neight_flush_ta(pco_tst));
    if (pco_gw != NULL)
        CHECK_RC(tapi_neight_flush_ta(pco_gw));
    CHECK_RC(tapi_neight_flush_ta(pco_iut));

    sockts_leak_file_name(pco_iut, "_p", name, sizeof(name));
    if (sockts_save_netstat_out(pco_iut, name) == -1)
        WARN("Could not save netstat output");

    configure_ip_transparent(pco_iut);

    if (tapi_onload_lib_exists(pco_iut->ta))
        set_onload_preload(pco_iut);

    /* Make sure Onload stack gets all configurations applied in prologue. */
    CHECK_RC(rcf_rpc_server_restart(pco_iut));

    ef_name = rpc_getenv(pco_iut, "EF_NAME");
    if (ef_name != NULL && strcmp(ef_name, "") != 0)
    {

        CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_reuse_stack",
                                       &pco_reuse_stack));
        rcf_rpc_setlibname(pco_reuse_stack, pco_iut->nv_lib);
        rpc_socket(pco_reuse_stack, RPC_AF_INET, RPC_SOCK_STREAM,
                          RPC_PROTO_DEF);
    }
    /*
     * Sometimes after rebooting the hos ipmi/conserver stops showing
     * anything. This problem is solved if you send "enter" to console.
     * For more information see OL bug 9831.
     */
    libts_send_enter2serial_console(AGENT_FOR_CONSOLE, "rpcs_serial",
                                    CONSOLE_NAME);

    configure_nfqueue_tst(pco_gw == NULL ? pco_tst : pco_gw);

    /*
     * ST-2219: the teaming aggregation needs sometimes up to 25 seconds
     * to be ready.
     * ST-2592: EF100 NICs sometimes take up to 120 second to be ready.
     */
    TEST_STEP("Wait for the connection between IUT and Tester to be "
              "established");
    wait_connection(pco_iut, iut_if->if_name,
                    pco_gw == NULL ? tst_addr : gw_iut_addr, 120);

    if (st_debug_kmemleak != NULL && strcmp(st_debug_kmemleak, "yes") == 0)
    {
        TEST_STEP("Get status of the Kernel Memory Leak Detector on IUT");

        char *ta = NULL;
        CHECK_NOT_NULL((ta = getenv("TE_IUT_TA_NAME")));

        sockts_kmemleak_get_report(ta);

        char *st_night_testing = getenv("ST_NIGHT_TESTING");
        if (st_night_testing == NULL || strcmp(st_night_testing, "yes") != 0)
        {
            TEST_STEP("Clear the list of all current possible memory leaks "
                      " on IUT");
            sockts_kmemleak_clear(ta);
        }
    }

    TEST_STEP("Add TRC tags");
    CHECK_RC(trc_tags_add(pco_iut, iut_if->if_name));

    CHECK_RC(rc = cfg_tree_print(NULL, TE_LL_RING, "/:"));

    TEST_SUCCESS;

cleanup:

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
