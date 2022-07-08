/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 *
 * @defgroup level5-bpf_onload_lib Onload specific common BPF functions
 * @ingroup level5-bpf
 * @{
 *
 * @brief Onload specific BPF testing helper functions
 *
 * Helper functions to use in level5/bpf package.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 *
 */

#ifndef __LEVEL5_BPF_ONLOAD_LIB_H__
#define __LEVEL5_BPF_ONLOAD_LIB_H__

#include "sockapi-ts_bpf.h"

/** Value to link XDP program to wildcard interface. */
#define XDP_LINK_WILD_IFACE     0

/** Value to link XDP program to wildcard stack. */
#define XDP_LINK_WILD_STACK     ""

/** Initializer for @ref xdp_attach_onload_pair. */
#define XDP_STACK_IF_PAIR_INIT { NULL, -1 }

/**
 * Onload XDP program attachment point containing a stack name
 * and interfave index.
 */
typedef struct xdp_attach_onload_pair
{
    const char *stack_name;     /**< Name of a stack to attach. */
    int         if_index;       /**< Index of an interface to attach. */
} xdp_attach_onload_pair;

/**
 * Set Onload XDP attachment environment variables ("TEST_LIBBPF_IFINDEX"
 * and "TEST_LIBBPF_STACK") to attach a program to the specified
 * stack/interface pair specified in @p iface_stack_pair.
 *
 * @c TEST_LIBBPF_IFINDEX - environment variable for setting interface index
 * to attach an XDP program to. Setting this variable to
 * @ref XDP_LINK_WILD_IFACE value attaches program to wildcard interface.
 *
 * @c TEST_LIBBPF_STACK - environment variable for setting stack name to
 * attach an XDP program to. Setting this variable to
 * @ref XDP_LINK_WILD_STACK value attaches program to wildcard stack.
 *
 * @note       This variables are set on the agent, RPC server is not restared.
 *
 * @param      rpcs              The RPC server to which variables are set
 * @param      iface_stack_pair  The pair of stack/interface to attach
 *
 * @return     Status code
 */
static inline te_errno
xdp_program_onload_link_setenv(rcf_rpc_server *rpcs,
                               xdp_attach_onload_pair *iface_stack_pair)
{
    te_errno rc = 0;

    if (rpcs == NULL || iface_stack_pair == NULL)
        return TE_EINVAL;

    if (iface_stack_pair->stack_name == NULL ||
        iface_stack_pair->if_index == -1)
    {
        return TE_EINVAL;
    }

    rc = tapi_sh_env_set_int(rpcs, "TEST_LIBBPF_IFINDEX",
                             iface_stack_pair->if_index,
                             TRUE, FALSE);
    if (rc != 0)
        return rc;

    return tapi_sh_env_set(rpcs, "TEST_LIBBPF_STACK",
                           iface_stack_pair->stack_name,
                           TRUE, FALSE);
}

/**
 * Link the XDP program to the Onload stack/interface pair.
 *
 * @note       Unique @p conf_ifname has to be passed every time we want
 *             to link new program to some stack/interface pair. We cannot
 *             link a program twice to the same interface, because
 *             Configurator will overwite previous program with the new one
 *             and fail to roll it back.
 *
 * @param      bpf_obj           The BPF object handler pointer
 * @param      iface_stack_pair  The interface/stack pair to attach
 * @param      conf_ifname       Interface name for Configurator (it is used
 *                               only in Configurator database - XDP program
 *                               is not attached to it really).
 *
 * @return     Status code
 */
static inline te_errno
xdp_program_onload_link(bpf_object_handle *bpf_obj,
                        xdp_attach_onload_pair *iface_stack_pair,
                        const char *conf_ifname)
{
    te_errno rc = 0;
    tqe_string *iface;

    if (bpf_obj == NULL || conf_ifname == NULL)
        return TE_EINVAL;

    rc = xdp_program_onload_link_setenv(bpf_obj->rpcs, iface_stack_pair);
    if (rc != 0)
        return rc;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    return tapi_bpf_prog_link(sockts_get_used_agt_name(bpf_obj->rpcs, iface->v),
                              conf_ifname, bpf_obj->id,
                              TAPI_BPF_LINK_XDP, bpf_obj->xdp_prog.name);

    return rc;
}

/**
 * Unlink the XDP program from the Onload stack/interface pair.
 *
 * @param      bpf_obj           The BPF object handler pointer
 * @param      iface_stack_pair  The interface/stack pair to detach
 *
 * @return     Status code
 */
static inline te_errno
xdp_program_onload_unlink(bpf_object_handle *bpf_obj,
                          xdp_attach_onload_pair *iface_stack_pair,
                          const char *conf_ifname)
{
    te_errno rc = 0;
    tqe_string *iface;

    if (bpf_obj == NULL)
        return TE_EINVAL;

    rc = xdp_program_onload_link_setenv(bpf_obj->rpcs, iface_stack_pair);
    if (rc != 0)
        return rc;

    iface = TAILQ_FIRST(&(bpf_obj->xdp_prog.ifaces));

    tapi_bpf_prog_unlink(sockts_get_used_agt_name(bpf_obj->rpcs, iface->v),
                         conf_ifname, TAPI_BPF_LINK_XDP);

    return rc;
}

/**@} <!-- END level5-bpf_onload_lib --> */

#endif /* __LEVEL5_BPF_ONLOAD_LIB_H__ */
