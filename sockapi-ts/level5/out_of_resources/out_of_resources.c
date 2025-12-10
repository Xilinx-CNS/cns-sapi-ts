/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Auxiliary functions for out of resources tests.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#include "out_of_resources.h"
#include "tapi_host_ns.h"

/* See description in out_of_resources.h */
te_errno
set_ldpreload_library(rcf_rpc_server *pco)
{
    te_errno    rc;
    char       *library = NULL;
    char       *library_name;

    rc = cfg_get_instance_fmt(NULL, &library, "/local:%s/socklib:", 
                              pco->ta);

    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_ENOENT)
    {
        ERROR("cfg_get_instance() failed; rc %r", rc);
        return rc;
    }

    if (rc == 0 && !te_str_is_null_or_empty(library))
    {
        library_name = strrchr(library, '/');
        if (library_name != NULL)
            library_name++;
        else 
            library_name = library;

        rpc_setenv(pco, "LD_PRELOAD", library_name, 1);
    }

    return 0;
}

/* See description in out_of_resources.h */
void
hw_filters_check_results(te_bool ef_no_fail, int requested, int opened,
                         int accelerated, int errors, int hw_filters_max,
                         int hw_filters)
{
    RING("Results: requested/opened/accelerated/errors hw_filters_max: "
         "%d/%d/%d/%d  %d", requested, opened, accelerated,
         errors, hw_filters_max);

    if (opened == accelerated)
        TEST_VERDICT("Out-of-resources condition was not achieved");

    /** Number of observed HW filters or accelerated sockets
     * should not differ much from HW filters limit
     */
    if (approx_cmp(hw_filters == -1 ? accelerated : hw_filters,
                   hw_filters_max) != 0)
    {
        TEST_VERDICT("%s number differs from HW filters limit",
                     hw_filters == -1 ?
                         "Opened accelerated sockets" : "Observed filters");
    }
    /** If EF_NO_FAIL=1 part of the created sockets will be unaccelerated.
     * In case @c EF_NO_FAIL=0 @b bind() and others can fail when few HW
     * filters left. */
    if (ef_no_fail)
    {
        if (errors != 0)
            TEST_VERDICT("Fails were observed when EF_NO_FAIL=1");
    }
    else if (accelerated + errors != opened)
    {
        TEST_VERDICT("Non-accelerated sockets were opened but they should "
                     "not when EF_NO_FAIL=0");
    }
}

/* See description in out_of_resources.h */
int
get_wild_sock_hw_filters_num(rcf_rpc_server *rpcs)
{
    char cmd[128] = {0};
    char *buf = NULL;
    int num = 0;

    snprintf(cmd, sizeof(cmd), "te_onload_stdump filters | grep -c FILTER ");
    rpc_shell_get_all(rpcs, &buf, cmd, -1);
    if (buf != NULL)
    {
        num = atoi(buf);
        free(buf);
    }
    else
    {
        TEST_VERDICT("Failed to get current HW filters number"
                     " from Onload stats");
    }

    return num;
}

/**
 * Count IPv4 addresses number in configurator set.
 *
 * @param addrs     Handler to the addresses set
 * @param addr_num  Total addresses number
 * @param ipv4_num  IPv4 addresses number
 *
 * @return Status code
 */
static inline int
get_ipv4_addresses_num(cfg_handle *addrs, size_t addr_num, size_t *ipv4_num)
{
    struct sockaddr_storage addr;
    char *addr_str = NULL;
    unsigned int i;
    int num = 0;
    int rc;

    for (i = 0; i < addr_num; i++)
    {
        if ((rc = cfg_get_inst_name(addrs[i], &addr_str)) != 0)
        {
            ERROR("Failed to get instance name: %r", rc);
            return rc;
        }

        if ((rc = te_sockaddr_netaddr_from_string(addr_str,
                                                  SA(&addr))) != 0)
        {
            ERROR("Failed to convert address from string '%s': %r",
                  addr_str, rc);
            free(addr_str);
            return rc;
        }

        if (addr.ss_family == AF_INET)
            num++;
        free(addr_str);
        addr_str = NULL;
    }

    *ipv4_num = num;

    return 0;
}

typedef struct count_addrs_ctx {
    tqh_strings ifs;
    size_t      num;
} count_addrs_ctx;

/**
 * Count IPv4 addresses number on a network interface.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param ctx       The counting context
 *
 * @return Status code
 */
static te_errno
count_nic_addresses(const char *ta, const char *ifname, count_addrs_ctx *ctx)
{
    cfg_handle  *addrs    = NULL;
    unsigned int addr_num = 0;
    te_string    ta_ifname = TE_STRING_INIT;
    size_t       num;
    te_errno     rc;

    te_string_append(&ta_ifname, "%s/%s", ta, ifname);

    if (tq_strings_add_uniq(&ctx->ifs, ta_ifname.ptr) != FALSE)
    {
        te_string_free(&ta_ifname);
        return 0;
    }

    if ((rc = cfg_find_pattern_fmt(&addr_num, &addrs,
                                   "/agent:%s/interface:%s/net_addr:*",
                                   ta, ifname)) != 0)
    {
        ERROR("Failed to get net_addr list for /agent:%s/interface:%s/: %r",
              ta, ifname, rc);
        return rc;
    }

    rc = get_ipv4_addresses_num(addrs, addr_num, &num);
    free(addrs);
    if (rc == 0)
        ctx->num += num;

    return rc;
}

/**
 * Callback function to count IPv4 addresses on a network interface and all
 * its descendants.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param opaque    The context
 *
 * @return Status code.
 */
static te_errno
count_addr_children_cb(const char *ta, const char *ifname, void *opaque)
{
    te_errno rc;

    rc = count_nic_addresses(ta, ifname, (count_addrs_ctx *)opaque);
    if (rc != 0)
        return rc;

    return tapi_host_ns_if_child_iter(ta, ifname, &count_addr_children_cb,
                                      opaque);
}

/**
 * Callback function to count IPv4 addresses on SFC network interfaces and all
 * their descendants.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param opaque    The context
 *
 * @return Status code.
 */
static te_errno
count_addr_sfc_cb(const char *ta, const char *ifname, void *opaque)
{
    te_errno    rc;
    te_bool     sfc;

    rc = sockts_interface_is_sfc(ta, ifname, &sfc);
    if (rc != 0 || sfc == FALSE)
        return rc;

    return count_addr_children_cb(ta, ifname, opaque);
}

/* See description in out_of_resources.h */
te_errno
count_involved_addresses(const char *ta, int *num)
{
    count_addrs_ctx ctx = {.num = 0};
    char           *host = NULL;
    te_errno        rc;

    rc = tapi_host_ns_get_host(ta, &host);
    if (rc != 0)
        return rc;

    TAILQ_INIT(&ctx.ifs);
    rc = tapi_host_ns_if_host_iter(host, &count_addr_sfc_cb, &ctx);

    tq_strings_free(&ctx.ifs, &free);
    free(host);

    if (rc == 0)
        *num = ctx.num;

    return rc;
}
