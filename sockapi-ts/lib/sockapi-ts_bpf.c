/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 *
 * Implementation of test API to work with BPF objects.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#include "sockapi-ts.h"
#include "sockapi-ts_bpf.h"
#include "vlan_common.h"
#include "tapi_test.h"
#include "sockapi-ts_target_build.h"

static const char *
sockts_bpf_linktype2str(tapi_bpf_link_point link_point)
{
    switch (link_point)
    {
        case TAPI_BPF_LINK_XDP:
            return "XDP";

        case TAPI_BPF_LINK_TC_INGRESS:
            return "TC ingress";

        default:
            return "<unknown>";
    }
}

/* See description in sockts_bpf.h */
te_errno
sockts_find_parent_netns(rcf_rpc_server *rpcs,
                         const char *ifname,
                         char *agent_parent,
                         char *ifname_parent)
{
    char          *parent = NULL;
    char          *point = NULL;
    char           hostname[RCF_MAX_NAME];
    cfg_val_type   type = CVT_STRING;
    int            token_pos = 0;;
    char          *token;
    int            rc = 0;

    rpc_gethostname(rpcs, hostname, sizeof(hostname));
    /* If host with domain is retrieved, leave only host name */
    point = strchr(hostname, '.');
    if (point != NULL)
       *point = '\0';

    rc = cfg_get_instance_fmt(&type, &parent,
                              "/local:/host:%s/agent:%s/interface:%s/parent:0",
                              hostname, rpcs->ta, ifname);

    if (rc != 0)
    {
        ERROR("Failed to find instance of parent of netns interface");
        return rc;
    }

    token = strtok(parent, "/");
    while (token != NULL)
    {
        switch (token_pos)
        {
            case 2:
                if (agent_parent != NULL)
                    sscanf(token, "agent:%s", agent_parent);
                break;
            case 3:
                if (ifname_parent != NULL)
                    sscanf(token, "interface:%s", ifname_parent);
                break;
            default:
                break;
        }

        token_pos++;
        token = strtok(NULL, "/");
    }

    free(parent);

    return 0;
}

/** Name of agent that would be used in BPF tests */
static char *used_agt_name = NULL;

/** Name of interface that would be used in BPF tests */
static char *used_interface_name = NULL;

/**
 * Initializer for used_agt_name and used_interface_name
 *
 * @param rpcs                RPC server handle
 * @param ifname              Interface name
 */
static void
sockts_init_used_params_name(rcf_rpc_server *rpcs,
                             const char *ifname)
{
    used_agt_name = malloc(RCF_MAX_NAME);
    used_interface_name = malloc(IF_NAMESIZE);

    if (sockts_not_pure_netns_used())
    {
        sockts_find_parent_netns(rpcs, ifname,
                                 used_agt_name,
                                 used_interface_name);
        return;
    }

    TE_STRLCPY(used_agt_name, rpcs->ta, RCF_MAX_NAME);
    TE_STRLCPY(used_interface_name, ifname, IF_NAMESIZE);
}

void
sockts_free_used_params_name()
{
    free(used_agt_name);
    free(used_interface_name);
}

/**
 * Determine if agent name is the same as the name of agent from env variable
 *
 * @param agt_name      Name of agent
 * @param env_agt_name  Name of env variable
 *
 * @return  @c TRUE in case of match, @c FALSE otherwise
 */
static te_bool
sockts_is_agt_name_pattern(const char *agt_name, const char *env_agt_name)
{
    char *env_name = getenv(env_agt_name);

    if (env_name != NULL)
        return (strcmp(agt_name, env_name) == 0);
    else
        ERROR("ENV variable %s is set to NULL", env_agt_name);

    return FALSE;
}

/**
 * Determine if agent name is @c TE_IUT_TA_NAME_NS
 *
 * @param agt_name    Name of agent
 *
 * @return  @c TRUE in case of match, @c FALSE otherwise
 */
static te_bool
sockts_is_agt_netns(const char *agt_name)
{
    return sockts_is_agt_name_pattern(agt_name, "TE_IUT_TA_NAME_NS");
}

/**
 * Determine if agent name is @c TE_IUT_TA_NAME
 *
 * @param agt_name    Name of agent
 *
 * @return  @c TRUE in case of match, @c FALSE otherwise
 */
static te_bool
sockts_is_agt_A(const char *agt_name)
{
    return sockts_is_agt_name_pattern(agt_name, "TE_IUT_TA_NAME");
}

/* See description in sockts_bpf.h */
char*
sockts_get_used_agt_name(rcf_rpc_server *rpcs,
                         const char *ifname)
{
    if (!sockts_is_agt_netns(rpcs->ta))
        return rpcs->ta;

    if (used_agt_name == NULL)
        sockts_init_used_params_name(rpcs, ifname);

    return used_agt_name;
}

/* See description in sockts_bpf.h */
char*
sockts_get_used_if_name(rcf_rpc_server *rpcs,
                        const char *ifname)
{
    if (!sockts_is_agt_A(rpcs->ta))
        return ifname;

    if (used_interface_name == NULL)
        sockts_init_used_params_name(rpcs, ifname);

    return used_interface_name;
}

/**
 * Extended version of sockts_bpf_find_parent_if.
 *
 * @param find_netns_parent  If @c TRUE, find parent
 *                           agent/interface for namespaced @p ifname.
 */
static void
sockts_bpf_find_parent_if_ext(rcf_rpc_server *rpcs,
                              const char *ifname,
                              tqh_strings *xdp_ifaces,
                              te_bool find_netns_parent)
{
    te_interface_kind   kind;
    tqh_strings         slaves;
    tqe_string         *slave;
    te_errno            rc = 0;
    rcf_rpc_server     *rpcs_used = rpcs;
    char               *real_ta_name = rpcs->ta;
    char                real_ifname[IF_NAMESIZE];
    char                buf[IF_NAMESIZE];
    char                netns_ifname[IF_NAMESIZE];
    char                netns_agt[RCF_MAX_NAME];

    if (sockts_not_pure_netns_used() && find_netns_parent)
    {
        if (sockts_find_parent_netns(rpcs, ifname,
                                     netns_agt,
                                     netns_ifname) == 0)
        {
            real_ta_name = netns_agt;
            TE_STRLCPY(real_ifname, netns_ifname, IF_NAMESIZE);
            CHECK_RC(rcf_rpc_server_create(real_ta_name, "rpc_used",
                                           &rpcs_used));
        }
        else
        {
            TEST_FAIL("Failed to find a parent of NETNS interface: %s.", ifname);
        }
    }
    else
    {
        TE_STRLCPY(real_ifname, ifname, IF_NAMESIZE);
    }

    CHECK_RC(tapi_cfg_get_if_kind(real_ta_name, real_ifname, &kind));

    switch (kind)
    {
        case TE_INTERFACE_KIND_NONE:
            rc = tq_strings_add_uniq_dup(xdp_ifaces, real_ifname);
            if (rc == 0)
                return;
            else if (rc != 1)
                CHECK_RC(rc);
            break;

        case TE_INTERFACE_KIND_VLAN:
        case TE_INTERFACE_KIND_MACVLAN:
        case TE_INTERFACE_KIND_IPVLAN:
            CHECK_RC(tapi_cfg_get_if_parent(real_ta_name, real_ifname, buf, sizeof(buf)));
            /*
             * In case of a net namespace the function is not able to find
             * parent interface and returns an empty string. In such case
             * consider the vlan interface as a parent one.
             */
            if (*buf != '\0')
                sockts_bpf_find_parent_if_ext(rpcs_used, buf, xdp_ifaces, FALSE);
            else
                CHECK_RC(tq_strings_add_uniq_dup(xdp_ifaces, real_ifname));
            break;

        case TE_INTERFACE_KIND_BOND:
        case TE_INTERFACE_KIND_TEAM:
            rpc_bond_get_slaves(rpcs_used, real_ifname, &slaves, NULL);
            for (slave = TAILQ_FIRST(&slaves);
                 slave != NULL;
                 slave = TAILQ_NEXT(slave, links))
            {
                sockts_bpf_find_parent_if_ext(rpcs_used, slave->v, xdp_ifaces, FALSE);
            }
            tq_strings_free(&slaves, &free);
            break;

        default:
            TEST_FAIL("Unknown kind of interface: %s.", real_ifname);
            break;
    }

    if (sockts_not_pure_netns_used() && find_netns_parent)
        rcf_rpc_server_destroy(rpcs_used);
}

/* See description in sockts_bpf.h */
void
sockts_bpf_find_parent_if(rcf_rpc_server *rpcs,
                          const char *ifname,
                          tqh_strings *xdp_ifaces)
{
    sockts_bpf_find_parent_if_ext(rpcs, ifname, xdp_ifaces, TRUE);
}

/* See description in sockts_bpf.h */
void
sockts_bpf_prog_link(rcf_rpc_server *rpcs,
                     const char *ifname,
                     unsigned int bpf_id,
                     const char *prog_name,
                     te_bool find_phys_ifaces,
                     tapi_bpf_link_point link_type,
                     tqh_strings *bpf_ifaces)
{
    te_errno rc;

    if (bpf_ifaces == NULL)
        TEST_FAIL("Pointer to list of interfaces is NULL.");

    if (find_phys_ifaces)
    {
        tqe_string *iface;

        sockts_bpf_find_parent_if(rpcs, ifname, bpf_ifaces);

        for (iface = TAILQ_FIRST(bpf_ifaces);
             iface != NULL;
             iface = TAILQ_NEXT(iface, links))
        {
            rc = tapi_bpf_prog_link(sockts_get_used_agt_name(rpcs, ifname),
                                    iface->v,
                                    bpf_id, link_type, prog_name);
            if (rc != 0)
            {
                TEST_VERDICT("Failed to link %s program on parent "
                             "interface %s: %r",
                             sockts_bpf_linktype2str(link_type),
                             iface->v, TE_RC_GET_ERROR(rc));
            }
        }
    }
    else
    {
        rc = tapi_bpf_prog_link(sockts_get_used_agt_name(rpcs, ifname),
                                sockts_get_used_if_name(rpcs, ifname),
                                bpf_id, link_type, prog_name);
        if (rc != 0)
        {
            TEST_VERDICT("Failed to link %s program: %r",
                         sockts_bpf_linktype2str(link_type),
                         TE_RC_GET_ERROR(rc));
        }
        CHECK_RC(tq_strings_add_uniq_dup(bpf_ifaces, ifname));
    }

    CFG_WAIT_CHANGES;
}

/* See description in sockts_bpf.h */
void
sockts_bpf_prog_unlink(rcf_rpc_server *rpcs,
                       char *ifname,
                       tapi_bpf_link_point link_type,
                       tqh_strings *bpf_ifaces)
{
    tqe_string *iface;

    if (bpf_ifaces == NULL)
        return;

    for (iface = TAILQ_FIRST(bpf_ifaces);
         iface != NULL;
         iface = TAILQ_NEXT(iface, links))
    {
        tapi_bpf_prog_unlink(sockts_get_used_agt_name(rpcs, ifname), iface->v, link_type);
    }

    tq_strings_free(bpf_ifaces, &free);
}

/* See description in sockts_bpf.h */
void
sockts_bpf_set_rlim_memlock(rcf_rpc_server *rpcs, uint64_t value)
{
    uint64_t    memlock_cur, memlock_max;

    CHECK_RC(cfg_get_uint64(&memlock_cur,
                        "/agent:%s/rlimits:/memlock:/cur:", rpcs->ta));
    CHECK_RC(cfg_get_uint64(&memlock_max,
                        "/agent:%s/rlimits:/memlock:/max:", rpcs->ta));

    if (memlock_cur != value || memlock_max != value)
    {
        RING("Current rlimits/memlock values: cur=%u, max=%u", memlock_cur,
             memlock_max);
        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(UINT64, value),
                        "/agent:%s/rlimits:/memlock:/max:", rpcs->ta));
        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(UINT64, value),
                        "/agent:%s/rlimits:/memlock:/cur:", rpcs->ta));
    }
}

/* See description in sockts_bpf.h */
void
sockts_bpf_map_arr32_to_str(rcf_rpc_server *rpcs, char *ifname, unsigned int bpf_id,
                            const char *map_name, te_string *str)
{
    te_errno        rc;
    unsigned int    entries;
    uint32_t        key, val;

    CHECK_RC(sockts_bpf_map_get_max_entries(rpcs, ifname, bpf_id, map_name, &entries));

    for (key = 0; key < entries; key++)
    {
        if ((rc = sockts_bpf_map_lookup_kvpair(rpcs, ifname, bpf_id, map_name,
                                        (uint8_t *)&key, sizeof(key),
                                        (uint8_t *)&val, sizeof(val))) != 0)
        {
            TEST_FAIL("%s() sockts_bpf_map_lookup_kvpair() -> %r",
                       __FUNCTION__, rc);
        }

        if ((rc = te_string_append(str, "%s%u(%d)", key == 0 ? "" :  ", ",
                                   key, val)) != 0)
        {
            TEST_FAIL("%s() te_string_append() -> %r", __FUNCTION__, rc);
        }
    }
}

/* See description in sockts_bpf.h */
te_errno
sockts_bpf_object_init(bpf_object_handle *bpf_obj, rcf_rpc_server *rpcs,
                       const char *xdp_prog_name)
{
    if (bpf_obj == NULL || rpcs == NULL || xdp_prog_name == NULL)
        return TE_EINVAL;

    bpf_obj->rpcs = rpcs;
    bpf_obj->path = NULL;
    bpf_obj->id = 0;
    bpf_obj->xdp_prog = XDP_PROGRAM_HANDLE_INIT(xdp_prog_name,
                                                bpf_obj->xdp_prog);
    return 0;
}

/* See description in sockts_bpf.h */
te_errno
sockts_bpf_object_load(bpf_object_handle *bpf_obj, const char *bpf_name)
{
    tqe_string *iface;

    if (bpf_obj == NULL || bpf_obj->rpcs == NULL)
        return TE_EINVAL;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    bpf_obj->path = sockts_bpf_get_path(bpf_obj->rpcs, iface->v, bpf_name);
    return sockts_bpf_obj_init(bpf_obj->rpcs, iface->v, bpf_obj->path,
                               TAPI_BPF_PROG_TYPE_XDP, &bpf_obj->id);
}

/* See description in sockts_bpf.h */
te_errno
sockts_bpf_object_unload(bpf_object_handle *bpf_obj)
{
    tqe_string *iface;

    if (bpf_obj == NULL || bpf_obj->rpcs == NULL)
        return TE_EINVAL;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    free(bpf_obj->path);
    if (bpf_obj->id != 0)
        return sockts_bpf_obj_fini(bpf_obj->rpcs, iface->v, bpf_obj->id);

    return 0;
}

/* See description in sockts_bpf.h */
te_errno
sockts_bpf_object_prog_name_check(bpf_object_handle *bpf_obj)
{
    tqe_string *iface;

    if (bpf_obj == NULL || bpf_obj->rpcs == NULL)
        return TE_EINVAL;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    return sockts_bpf_prog_name_check(bpf_obj->rpcs,
                                      iface->v,
                                      bpf_obj->id,
                                      bpf_obj->xdp_prog.name);
}

/* See description in sockts_bpf.h */
te_errno
sockts_bpf_object_map_name_check(bpf_object_handle *bpf_obj,
                                 const char *map_name)
{
    tqe_string *iface;

    if (bpf_obj == NULL || bpf_obj->rpcs == NULL)
        return TE_EINVAL;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    return sockts_bpf_map_name_check(bpf_obj->rpcs, iface->v,
                                     bpf_obj->id, map_name);
}

/* See description in sockts_bpf.h */
te_errno
sockts_bpf_object_read_u32_map(bpf_object_handle *bpf_obj,
                               const char *map_name,
                               unsigned int key, unsigned int *val)
{
    tqe_string *iface;

    if (bpf_obj == NULL || bpf_obj->rpcs == NULL || val == NULL)
        return TE_EINVAL;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    return sockts_bpf_map_lookup_kvpair(bpf_obj->rpcs, iface->v, bpf_obj->id, map_name,
                                        (uint8_t *)&key, sizeof(key),
                                        (uint8_t *)val, sizeof(*val));
}

/* See description in sockapi-ts_bpf.h */
te_errno
sockts_bpf_xdp_load_tuple(rcf_rpc_server *pco, const char *ifname,
                          unsigned int bpf_id,
                          const char *map_name,
                          const struct sockaddr* src_addr,
                          const struct sockaddr* dst_addr,
                          rpc_socket_type sock_type)
{
    te_errno rc;
    bpf_tuple rule;
    unsigned int key = 0;

    if ((rc = sockts_bpf_map_name_check(pco, ifname, bpf_id, map_name)) != 0)
        return rc;

    tapi_sockaddr_clone_exact(dst_addr, &rule.dst_addr);
    tapi_sockaddr_clone_exact(src_addr, &rule.src_addr);

    switch (sock_type)
    {
        case RPC_SOCK_STREAM:
            rule.proto = IPPROTO_TCP;
            break;

        case RPC_SOCK_DGRAM:
            rule.proto = IPPROTO_UDP;
            break;

        default:
            ERROR("%s(): unsupported socket type %s", __FUNCTION__,
                  socktype_rpc2str(sock_type));
            return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if ((rc = sockts_bpf_map_set_writable(pco, ifname, bpf_id, map_name)) != 0)
        return rc;

    return sockts_bpf_map_update_kvpair(pco, ifname, bpf_id, map_name,
                                        (uint8_t *)&key, sizeof(key),
                                        (uint8_t *)&rule, sizeof(rule));
}

/* See description in sockapi-ts_bpf.h */
te_errno
sockts_bpf_build_all(rcf_rpc_server *pco)
{
    char           *ta_dir = NULL;
    te_errno        rc = 0;
    const char     *sapi_dir = NULL;
    te_string       src_dir = TE_STRING_INIT;

    if ((sapi_dir = getenv("SOCKAPI_TS_LIBDIR")) == NULL)
    {
        ERROR("Environment variable SOCKAPI_TS_LIBDIR is not set");
        return TE_RC(TE_MODULE_NONE, TE_EFAIL);
    }

    rc = cfg_get_instance_fmt(NULL, &ta_dir, "/agent:%s/dir:", pco->ta);
    if (rc != 0)
        return rc;

    rc = te_string_append(&src_dir, "%s/%s", sapi_dir, SOCKTS_BPF_SRC_DIR);
    if (rc != 0)
        goto exit;

    rc = sockts_build_dir(pco, src_dir.ptr, ta_dir, FALSE);
    if (rc != 0)
        ERROR("Failed to build BPF: %r", rc);

exit:
    rc = sockts_cleanup_build(src_dir.ptr, FALSE);
    free(ta_dir);
    te_string_free(&src_dir);
    return rc;
}

te_errno
sockts_bpf_build_stimuli(rcf_rpc_server *pco)
{
    char           *ta_dir = NULL;
    te_errno        rc = 0;
    const char     *te_dir = NULL;
    te_string       src_dir = TE_STRING_INIT;

    if ((te_dir = getenv("TE_BASE")) == NULL)
    {
        ERROR("Environment variable TE_BASE is not set");
        return TE_RC(TE_MODULE_NONE, TE_EFAIL);
    }

    rc = cfg_get_instance_fmt(NULL, &ta_dir, "/agent:%s/dir:", pco->ta);
    if (rc != 0)
        return rc;

    rc = te_string_append(&src_dir, "%s/%s", te_dir, "bpf");
    if (rc != 0)
        goto exit;

    rc = sockts_build_dir(pco, src_dir.ptr, ta_dir, FALSE);
    if (rc != 0)
        ERROR("Failed to build BPF: %r", rc);

exit:
    rc = sockts_cleanup_build(src_dir.ptr, FALSE);
    free(ta_dir);
    te_string_free(&src_dir);
    return rc;
}
