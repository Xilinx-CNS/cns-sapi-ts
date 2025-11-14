/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2025 Advanced Micro Devices, Inc. */
#ifndef __PARSE_ORM_JSON_H__
#define __PARSE_ORM_JSON_H__
/** @file
 * @brief sapi-ts Test Agent Library
 *
 * sockapi-ts-specific RPC routines implementation-
 *
 * @author Nikolai Kosovskii <nikolai.kosovskii@arknetworks.am>
 *
 * $Id$
 */
#include <jansson.h>
#include <arpa/inet.h>
#include "agentlib.h"
#include "te_sockaddr.h"
#include "te_rpc_sys_socket.h"

/**
 * Convert state to number in range 0->0xe, as it said and used in Onload.
 *
 * Taken from Onload src/include/ci/internal/ip.h
 */
#define CI_TCP_STATE_NUM(s)    (((s) & 0xf000) >> 12u)

/**
 * Convert TCP state associated numbers in range 0->0xe used in Onload to
 * rpc_tcp_state enum.
 *
 * Inspired by Onload function ci_tcp_state_num_str()
 * from src/include/ci/internal/ip.h
 *
 * @param state_i    Interior Onload number in range 0->0xe to represent
 *                   TCP state
 *
 * @return RPC constant corresponding to a given interior Onload number
 */
rpc_tcp_state ci_tcp_state_2_rpc_tcp_state(int state_i);

/**
 * Convert tcp state values used in Onload and orm_json output to
 * rpc_tcp_state enum.
 *
 * Inspired by Onload macro ci_tcp_state_str()
 * from src/include/ci/internal/ip.h
 */
#define orm_json_tcp_state_2_rpc_tcp_state(_i) \
    ci_tcp_state_2_rpc_tcp_state(CI_TCP_STATE_NUM(_i))

/**
 * Get output of command on TA in te_string representation
 *
 * @param[in]  cmd   String with the command.
 * @param[out] str   Output.
 *
 * @return Status code.
 */
te_errno ta_read_cmd(const char *cmd, te_string *str);

/**
 * Get TCP state from an orm_json tool's output.
 *
 * @param joutput     Serialized JSON orm_json output.
 * @param loc_addr    Local address.
 * @param rem_addr    Remote address.
 * @param state       Where to save obtained TCP state.
 * @param found       Will be set to @c TRUE if a socket was
 *                    found and state is not TCP_CLOSED.
 *
 * @return Status code.
 * @retval TE_ENOENT  No information about TCP state was found.
 * @retval TE_EFMT    Unexpected JSON format.
 * @retval 0          Success.
 */
te_errno orm_json_get_tcp_state(const char *joutput,
                                const struct sockaddr *loc_addr,
                                const struct sockaddr *rem_addr,
                                rpc_tcp_state *state, bool *found);

/**
 * Get statistic from an orm_json tool's output.
 *
 * @param      joutput    Serialized JSON orm_json output.
 * @param      stat_name  Name of the statistic.
 * @param[out] stat_value Value of the statistic.
 *
 * @return Status code.
 * @retval TE_ENOENT  No information about this statistic was found.
 * @retval TE_EFMT    Unexpected JSON format.
 * @retval 0          Success.
 */
te_errno orm_json_get_stat(const char *joutput, const char *stat_name,
                           int *stat_value);

/**
 * Get number of members in listenq from an orm_json tool's output.
 *
 * @param      joutput   Serialized JSON orm_json output.
 * @param      loc_addr  Local address.
 * @param[out] n_listenq Number of members in listenq.
 *
 * @return Status code.
 * @retval TE_ENOENT     No information about this listen queue was found.
 * @retval TE_EFMT       Unexpected JSON format.
 * @retval 0             Success.
 */
te_errno orm_json_get_n_listenq(const char *joutput,
                                const struct sockaddr *loc_addr,
                                int *n_listenq);

#endif /* __PARSE_ORM_JSON_H__ */
