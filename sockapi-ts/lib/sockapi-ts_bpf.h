/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief BPF/XDP Test Suite
 *
 * Auxilliary functions for BPF package.
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_BPF_H__
#define __SOCKAPI_TS_BPF_H__

#include "tapi_bpf.h"
#include <sys/resource.h>

/** Buffer size for reading from stdout and stderr */
#define SOCKTS_BPF_CMD_BUF_SIZE 4096

#define SOCKTS_BPF_SRC_DIR "sockapi-ts/bpf_prog/"

#define SOCKTS_BPF_TGZ_NAME "bpf_programs.tgz"

/** Minimum memlock value to load BPF/XDP program into kernel */
#define SOCKTS_BPF_RLIMITS_MEMLOCK RLIM_INFINITY

/**
 * Initializer for @ref xdp_program_handle.
 *
 * @param _prog_name    Name of an XDP program
 * @param _var_name     Variable name
 *
 * Example:
 * @code{.c}
 * xdp_program_handle prog = XDP_PROGRAM_HANDLE_INIT("prog", prog);
 * @endcode
 */
#define XDP_PROGRAM_HANDLE_INIT(_prog_name, _var_name) (xdp_program_handle) \
    { .name = _prog_name, .ifaces = TAILQ_HEAD_INITIALIZER(_var_name.ifaces) }

/** XDP program handle type. */
typedef struct xdp_program_handle
{
    const char     *name;       /**< XDP program name. */
    tqh_strings     ifaces;     /**< List of interfaces. */
} xdp_program_handle;

/** BPF object handle type. */
typedef struct bpf_object_handle
{
    rcf_rpc_server     *rpcs;       /**< RPC server to which the object
                                         is loaded. */
    char               *path;       /**< Path to object file on agent side. */
    unsigned int        id;         /**< BPF object ID. */
    xdp_program_handle  xdp_prog;   /**< XDP program within the object. */
} bpf_object_handle;

/**
 * Structure contains a rule for XDP program.
 * The same is defined in sockapi-ts/bpf/bpf_programs/bpf.h
 */
typedef struct bpf_tuple {
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    uint8_t                 proto;
} bpf_tuple;

/**
 * Determine if it is needed to find parent agent and interface
 *
 * @return    @c TRUE if netns used with vlan/macvlan/ipvlan or bond/team
 *            @c FALSE if only netns used or netns not used
 */
static inline te_bool
sockts_not_pure_netns_used()
{
    return (getenv("SOCKAPI_TS_NETNS") != NULL &&
            (getenv("TE_IUT_TST1_MV") != NULL ||
            getenv("TE_IUT_TST1_VLAN") != NULL ||
            getenv("SOCKAPI_TS_BOND_NAME") != NULL) ||
            getenv("SOCKAPI_TS_IPVLAN_ENV"));
}

/**
 * Find parent interface and agent for NETNS interface
 *
 * @param[in] rpcs            RPC server handle
 * @param[in] ifname          Interface name
 * @param[out] agent_parent   Parent agent name
 * @param[out] ifname_parent  Parent interface name
 *
 * @return Status code
 */
extern te_errno
sockts_find_parent_netns(rcf_rpc_server *rpcs,
                         const char *ifname,
                         char *agent_parent,
                         char *ifname_parent);

/**
 * Free used_agt_name and used_interface_name variables
 */
extern void
sockts_free_used_params_name();

/**
 * Getter for used_agt_name
 *
 * @param rpcs                RPC server handle
 * @param ifname              Interface name
 */
extern char*
sockts_get_used_agt_name(rcf_rpc_server *rpcs,
                         const char *ifname);

/**
 * Getter for used_interface_name
 *
 * @param rpcs                RPC server handle
 * @param ifname              Interface name
 */
extern char*
sockts_get_used_if_name(rcf_rpc_server *rpcs,
                        const char *ifname);

/**
 * Get full path to BPF object on Test Agent.
 *
 * @note Return value should be freed when it is no longer needed.
 *
 * @param rpcs              RPC server handle
 * @param ifname        Interface name
 * @param bpf_name      BPF object name
 *
 * @return Path to BPF object.
 */
static inline char *
sockts_bpf_get_path(rcf_rpc_server *rpcs, const char *ifname,
                    const char *bpf_name)
{
    char *ta_dir = NULL;
    cfg_val_type val_type = CVT_STRING;
    char buf[RCF_MAX_PATH];
    char *real_ta = sockts_get_used_agt_name(rpcs, ifname);

    CHECK_RC(cfg_get_instance_fmt(&val_type, &ta_dir,
                                  "/agent:%s/dir:", real_ta));
    TE_SPRINTF(buf, "%s/%s.o", ta_dir, bpf_name);
    free(ta_dir);
    return strdup(buf);
}

/**
 * Find parent physical interfaces.
 *
 * @param rpcs              RPC server handle
 * @param ifname            Interface name
 * @param[out] xdp_ifaces   List of interfaces
 */
extern void sockts_bpf_find_parent_if(rcf_rpc_server *rpcs,
                                      const char *ifname,
                                      tqh_strings *xdp_ifaces);

/**
 * Link BPF program to a @p link_type attach point on interface. If interface
 * is a kind of VLAN or team/bond interface then if @p find_phys_ifaces
 * is @c TRUE, find parent physical interfaces and link to them.
 *
 * @param rpcs              RPC server handle
 * @param ifname            Interface name
 * @param bpf_id            BPF id
 * @param prog_name         Program name
 * @param find_phys_ifaces  If @c FALSE, link to @p ifname;
 *                          if @c TRUE, link to parent physical interfaces
 * @param link_type         Type of link point
 * @param[out] bpf_ifaces   List of interfaces
 */
extern void
sockts_bpf_prog_link(rcf_rpc_server *rpcs, const char *ifname,
                     unsigned int bpf_id, const char *prog_name,
                     te_bool find_phys_ifaces, tapi_bpf_link_point link_type,
                     tqh_strings *bpf_ifaces);

/**
 * XDP wrapper for @ref sockts_bpf_prog_link().
 */
static inline void
sockts_bpf_link_xdp_prog(rcf_rpc_server *rpcs,
                         const char *ifname,
                         unsigned int bpf_id,
                         const char *prog_name,
                         te_bool find_phys_ifaces,
                         tqh_strings *xdp_ifaces)
{
    sockts_bpf_prog_link(rpcs, ifname, bpf_id, prog_name, find_phys_ifaces,
                         TAPI_BPF_LINK_XDP, xdp_ifaces);
}

/**
 * Unlink BPF program of @p link_type attach point from interfaces and free
 * list of interfaces.
 *
 * @param rpcs          RPC server handle
 * @param ifname        Interface name
 * @param link_type     Type of link point
 * @param bpf_ifaces    List of interfaces
 *
 * @return Status code
 */
extern void
sockts_bpf_prog_unlink(rcf_rpc_server *rpcs,
                       char *ifname,
                       tapi_bpf_link_point link_type,
                       tqh_strings *bpf_ifaces);

/**
 * XDP wrapper for @ref sockts_bpf_prog_unlink().
 */
static inline void
sockts_bpf_unlink_xdp(rcf_rpc_server *rpcs,
                      char *ifname,
                      tqh_strings *xdp_ifaces)
{
    sockts_bpf_prog_unlink(rpcs, ifname, TAPI_BPF_LINK_XDP, xdp_ifaces);
}

/**
 * Set rlimits/memlock value(s) to @p value
 *
 * @param rpcs          RPC server handle
 * @param value         New value to set
 */
extern void sockts_bpf_set_rlim_memlock(rcf_rpc_server *rpcs,
                                        uint64_t value);

/**
 * Convert key/values of the map to string representation, where are both
 * keys and values have 32 bit size.
 *
 * @param rpcs          RPC server handle
 * @param ifname        Interface name
 * @param bpf_id        Id of bpf object
 * @param map_name      The name of map
 * @param[out] str      Pointer to string
 */
void
sockts_bpf_map_arr32_to_str(rcf_rpc_server *rpcs, char *ifname, unsigned int bpf_id,
                            const char *map_name, te_string *str);

/**
 * Set BPF object handler with initial values. This function has to be
 * called before any actions on BPF object.
 *
 * @param      bpf_obj        The BPF object handler pointer
 * @param      rpcs           RPC server to which the BPF object will
 *                            be loaded (in @ref bpf_object_load)
 * @param      xdp_prog_name  The XDP program name
 *
 * @return     Status code
 */
te_errno
sockts_bpf_object_init(bpf_object_handle *bpf_obj, rcf_rpc_server *rpcs,
                       const char *xdp_prog_name);

/**
 * Load the BPF object to agent.
 *
 * @param      bpf_obj   The BPF object handler pointer
 * @param      bpf_name  The BPF object name
 *
 * @return     Status code
 */
te_errno
sockts_bpf_object_load(bpf_object_handle *bpf_obj, const char *bpf_name);

/**
 * Unload and delete the BPF object from agent.
 *
 * @param      bpf_obj  The BPF object handler pointer
 *
 * @return     Status code
 */
te_errno
sockts_bpf_object_unload(bpf_object_handle *bpf_obj);

/**
 * Check that program name from the BPF object is in list of loaded programs.
 *
 * @param      bpf_obj  The BPF object handler pointer
 *
 * @return     Status code
 */
te_errno
sockts_bpf_object_prog_name_check(bpf_object_handle *bpf_obj);

/**
 * Check that map name from the BPF object is in list of loaded maps.
 *
 * @param      bpf_obj  The BPF object handler pointer
 * @param      map_name Map name to check
 *
 * @return     Status code
 */
te_errno
sockts_bpf_object_map_name_check(bpf_object_handle *bpf_obj,
                                 const char *map_name);

/**
 * Read unsigned integer value stored in @p key from the map with
 * name @p map_name.
 *
 * @param[in]  bpf_obj   The BPF object handler pointer
 * @param[in]  map_name  The map name
 * @param[in]  key       The key
 * @param[out] val       Output value
 *
 * @return     Status code
 */
te_errno
sockts_bpf_object_read_u32_map(bpf_object_handle *bpf_obj,
                               const char *map_name,
                               unsigned int key, unsigned int *val);

/**
 * Load a 5-tuple rule into the zero key of BPF map with name @p map_name.
 * The map must be @c BPF_MAP_TYPE_ARRAY type.
 *
 * @note The @p map_name map becomes writable after the function execution.
 *
 * @param ta        Agent name.
 * @param ifname    Interface name.
 * @param bpf_id    BPF ID.
 * @param map_name  Name of the map to store the rule.
 * @param src_addr  Source address.
 * @param dst_addr  Destination address.
 * @param sock_type Socket type.
 *
 * @return Status code
 */
te_errno sockts_bpf_xdp_load_tuple(rcf_rpc_server *pco, const char *ifname,
                                   unsigned int bpf_id,
                                   const char *map_name,
                                   const struct sockaddr* src_addr,
                                   const struct sockaddr* dst_addr,
                                   rpc_socket_type sock_type);

/**
 * Build all BPF programs which are located in @c SOCKTS_BPF_SRC_DIR
 * directory.
 *
 * @param pco   RPC server, on which build executes.
 *
 * @return Status code.
 */
te_errno sockts_bpf_build_all(rcf_rpc_server *pco);

/**
 * Build stimuli BPF programs which are located in @c ${TE_BASE}/bpf
 * directory.
 *
 * @param pco   RPC server, on which build executes.
 *
 * @return Status code.
 */
extern te_errno sockts_bpf_build_stimuli(rcf_rpc_server *pco);

/** Wrapper for tapi_bpf_obj_init */
static inline te_errno
sockts_bpf_obj_init(rcf_rpc_server *rpcs,
                    const char *ifname,
                    const char *path,
                    tapi_bpf_prog_type type,
                    unsigned int *bpf_id)
{
    return tapi_bpf_obj_init(
               sockts_get_used_agt_name(rpcs, ifname),
               path, type, bpf_id);
}

/** Wrapper for tapi_bpf_prog_name_check */
static inline te_errno
sockts_bpf_prog_name_check(rcf_rpc_server *rpcs,
                           const char *ifname, unsigned int bpf_id,
                           const char *prog_name)
{
    return tapi_bpf_prog_name_check(sockts_get_used_agt_name(rpcs, ifname),
                                    bpf_id, prog_name);
}

/** Wrapper for tapi_bpf_map_update_kvpair */
static inline te_errno
sockts_bpf_map_update_kvpair(rcf_rpc_server *rpcs,
                             const char *ifname,
                             unsigned int bpf_id,
                             const char *map,
                             const uint8_t *key,
                             unsigned int key_size,
                             const uint8_t *val,
                             unsigned int val_size)
{
    return tapi_bpf_map_update_kvpair(sockts_get_used_agt_name(rpcs, ifname),
                                      bpf_id, map, key, key_size,
                                      val, val_size);
}

/** Wrapper for tapi_bpf_map_lookup_kvpair */
static inline te_errno
sockts_bpf_map_lookup_kvpair(rcf_rpc_server *rpcs,
                             const char *ifname,
                             unsigned int bpf_id,
                             const char *map,
                             const uint8_t *key,
                             unsigned int key_size,
                             uint8_t *val,
                             unsigned int val_size)
{
    return tapi_bpf_map_lookup_kvpair(sockts_get_used_agt_name(rpcs, ifname),
                                      bpf_id, map, key, key_size,
                                      val, val_size);
}

/** Wrapper for tapi_map_delete_kvpair */
static inline te_errno
sockts_bpf_map_delete_kvpair(rcf_rpc_server *rpcs,
                             const char *ifname,
                             unsigned int bpf_id,
                             const char *map,
                             const uint8_t *key,
                             unsigned int key_size)
{
    return tapi_bpf_map_delete_kvpair(sockts_get_used_agt_name(rpcs, ifname),
                                      bpf_id, map, key, key_size);
}

/** Wrapper for tapi_bpf_obj_fini */
static inline te_errno
sockts_bpf_obj_fini(rcf_rpc_server *rpcs,
                    const char *ifname, unsigned int bpf_id)
{
    te_errno rc = tapi_bpf_obj_fini(sockts_get_used_agt_name(rpcs, ifname),
                                    bpf_id);
    sockts_free_used_params_name();
    return rc;
}

/** Wrapper for tapi_bpf_map_get_list */
static inline te_errno
sockts_bpf_map_get_list(rcf_rpc_server *rpcs,
                        const char *ifname, unsigned int bpf_id,
                        char ***map, unsigned int *map_count)
{
    return tapi_bpf_map_get_list(sockts_get_used_agt_name(rpcs, ifname),
                                 bpf_id, map, map_count);
}

/** Wrapper for tapi_bpf_map_get_typ */
static inline te_errno
sockts_bpf_map_get_type(rcf_rpc_server *rpcs,
                        const char *ifname, unsigned int bpf_id,
                        const char *map, tapi_bpf_map_type *type)
{
    return tapi_bpf_map_get_type(sockts_get_used_agt_name(rpcs, ifname),
                                 bpf_id, map, type);
}

/** Wrapper for tapi_bpf_map_get_key_size */
static inline te_errno
sockts_bpf_map_get_key_size(rcf_rpc_server *rpcs,
                            const char *ifname,
                            unsigned int bpf_id,
                            const char *map,
                            unsigned int *key_size)
{
    return tapi_bpf_map_get_key_size(sockts_get_used_agt_name(rpcs, ifname),
                                     bpf_id, map, key_size);
}

/** Wrapper for tapi_bpf_map_get_max_entries */
static inline te_errno
sockts_bpf_map_get_max_entries(rcf_rpc_server *rpcs,
                               const char *ifname,
                               unsigned int bpf_id,
                               const char *map,
                               unsigned int *max_entries)
{
    return tapi_bpf_map_get_max_entries(sockts_get_used_agt_name(rpcs, ifname),
                                        bpf_id, map, max_entries);
}

/** Wrapper for tapi_bpf_map_set_writable */
static inline te_errno
sockts_bpf_map_set_writable(rcf_rpc_server *rpcs,
                            const char *ifname,
                            unsigned int bpf_id,
                            const char *map)
{
    return tapi_bpf_map_set_writable(sockts_get_used_agt_name(rpcs, ifname),
                                     bpf_id, map);
}

/** Wrapper for tapi_bpf_map_unset_writable */
static inline te_errno
sockts_bpf_map_unset_writable(rcf_rpc_server *rpcs,
                              const char *ifname,
                              unsigned int bpf_id,
                              const char *map)
{
    return tapi_bpf_map_unset_writable(sockts_get_used_agt_name(rpcs, ifname),
                                       bpf_id, map);
}

/** Wrapper for tapi_bpf_map_get_key_list */
static inline te_errno
sockts_bpf_map_get_key_list(rcf_rpc_server *rpcs,
                            const char *ifname,
                            unsigned int bpf_id,
                            const char *map,
                            unsigned int *key_size,
                            uint8_t ***key,
                            unsigned int *count)
{
    return tapi_bpf_map_get_key_list(sockts_get_used_agt_name(rpcs, ifname),
                                     bpf_id, map, key_size, key, count);
}

/** Wrapper for tapi_bpf_perf_event_init */
static inline te_errno
sockts_bpf_perf_event_init(rcf_rpc_server *rpcs,
                           const char *ifname, unsigned int bpf_id,
                           const char *map, unsigned int event_size)
{
    return tapi_bpf_perf_event_init(sockts_get_used_agt_name(rpcs, ifname),
                                    bpf_id, map, event_size);
}

/** Wrapper for tapi_bpf_perf_event_deinit */
static inline te_errno
sockts_bpf_perf_event_deinit(rcf_rpc_server *rpcs,
                             const char *ifname, unsigned int bpf_id,
                             const char *map)
{
    return tapi_bpf_perf_event_deinit(sockts_get_used_agt_name(rpcs, ifname),
                                      bpf_id, map);
}

/** Wrapper for tapi_bpf_perf_get_events */
static inline te_errno
sockts_bpf_perf_get_events(rcf_rpc_server *rpcs,
                           const char *ifname, unsigned int bpf_id, const char *map,
                           unsigned int *num, uint8_t **data)
{
    return tapi_bpf_perf_get_events(sockts_get_used_agt_name(rpcs, ifname),
                                    bpf_id, map, num, data);
}

/** Wrapper for tapi_bpf_perf_map_get_list */
static inline te_errno
sockts_bpf_perf_map_get_list(rcf_rpc_server *rpcs,
                             const char *ifname,
                             unsigned int bpf_id,
                             char ***map,
                             unsigned int *map_count)
{
    return  tapi_bpf_perf_map_get_list(sockts_get_used_agt_name(rpcs, ifname),
                                       bpf_id, map, map_count);
}

/** Wrapper for tapi_bpf_map_type_name_check */
static inline te_errno
sockts_bpf_map_type_name_check(rcf_rpc_server *rpcs,
                               const char *ifname, unsigned int bpf_id,
                               const char *map_name,
                               tapi_bpf_map_type map_type)
{
    return tapi_bpf_map_type_name_check(sockts_get_used_agt_name(rpcs, ifname),
                                        bpf_id, map_name, map_type);
}

/** Wrapper for tapi_bpf_map_name_check */
static inline te_errno
sockts_bpf_map_name_check(rcf_rpc_server *rpcs,
                          const char *ifname, unsigned int bpf_id,
                          const char *map_name)
{
    return tapi_bpf_map_name_check(sockts_get_used_agt_name(rpcs, ifname),
                                   bpf_id, map_name);
}

/** Wrapper for tapi_bpf_map_check_type */
static inline te_errno
sockts_bpf_map_check_type(rcf_rpc_server *rpcs,
                          const char *ifname,
                          unsigned int bpf_id,
                          const char *map_name,
                          tapi_bpf_map_type exp_map_type)
{
    return tapi_bpf_map_check_type(sockts_get_used_agt_name(rpcs, ifname),
                                   bpf_id, map_name, exp_map_type);
}

#endif /* !__SOCKAPI_TS_BPF_H__ */
