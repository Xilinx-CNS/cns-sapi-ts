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

        sockts_find_parent_if(rpcs, ifname, bpf_ifaces);

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

        te_string_append(str, "%s%u(%d)", key == 0 ? "" :  ", ", key, val);
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

    te_string_append(&src_dir, "%s/%s", sapi_dir, SOCKTS_BPF_SRC_DIR);

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

    te_string_append(&src_dir, "%s/%s", te_dir, "bpf");

    rc = sockts_build_dir(pco, src_dir.ptr, ta_dir, FALSE);
    if (rc != 0)
        ERROR("Failed to build BPF: %r", rc);

exit:
    rc = sockts_cleanup_build(src_dir.ptr, FALSE);
    free(ta_dir);
    te_string_free(&src_dir);
    return rc;
}
