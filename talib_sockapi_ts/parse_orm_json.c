/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2025 Advanced Micro Devices, Inc. */
/** @file
 * @brief sapi-ts Test Agent Library
 *
 * sockapi-ts-specific RPC routines implementation-
 *
 * @author Nikolai Kosovskii <nikolai.kosovskii@arknetworks.am>
 *
 * $Id$
 */
#include "parse_orm_json.h"

#define FREAD_BUF_LEN 1024

/**
 * Check JSON type obtained value with given key of given JSON object.
 *
 * @param      _object_name Parent JSON object.
 * @param      _key         Key of the JSON object.
 * @param[out] _var         Variable where value was saved.
 * @param      _type        Type to be checked.
 * @param      _terminate   Should we set rc and go to cleanup.
 */
#define JSON_CHECK_GOTTEN(_object_name, _key, _var, _type, _terminate) \
    do {                                                                   \
        if (!json_is_##_type(_var))                                        \
        {                                                                  \
            ERROR("There is no " #_type " in " #_object_name " "           \
                  "JSON object with \" %s \" key", _key);                  \
                                                                           \
            if (_terminate)                                                \
            {                                                              \
                rc = TE_RC(TE_TAPI, TE_EFMT);                              \
                goto cleanup;                                              \
            }                                                              \
        }                                                                  \
    } while(0)

/**
 * Get and check JSON type value with given key of given JSON object.
 *
 * @param      _object_name Parent JSON object.
 * @param      _key         Key of the JSON object.
 * @param[out] _var[out]    Variable where value should be saved.
 * @param      _type        Type to be checked.
 * @param      _terminate   Should we set rc and go to cleanup.
 */
#define JSON_OBJECT_GET_CHECK_EXT(_object_name, _key, _var, _type, \
                                  _terminate) \
    do {                                                                   \
        _var = json_object_get(_object_name, _key);                        \
        JSON_CHECK_GOTTEN(_object_name, _key, _var, _type, _terminate);    \
    } while(0)

/**
 * Get and check JSON type value with given key of given JSON object.
 * The name of the variable to be saved the value is the key with "j" as
 * a prefix.
 *
 * @param _object_name    Parent JSON object.
 * @param _key            Key of the JSON object.
 * @param _type           Type to be checked.
 * @param _terminate      Should we set rc and go to cleanup.
 */
#define JSON_OBJECT_GET_CHECK(_object_name, _key, _type, _terminate) \
    JSON_OBJECT_GET_CHECK_EXT(j##_object_name, #_key, j##_key, _type,     \
                              _terminate)

rpc_tcp_state ci_tcp_state_2_rpc_tcp_state(int state_i)
{
  static const rpc_tcp_state state_strs[] = {
    /*
     * Below there are rpc_tcp_state value, corresponding onload_stack_dump
     * string and corresponding constant from Onload. The last constant
     * divided by 0x1000 coincides with the index of this array.
     * NB. There are no sockets in the TCP_SYN_RECV state in Onload. The
     * information of such sockets is held in a special way with information
     * about corresponding sockets in the TCP_LISTEN state.
     */
    RPC_TCP_CLOSE,       /* CLOSED      CI_TCP_CLOSED            */
    RPC_TCP_LISTEN,      /* LISTEN      CI_TCP_LISTEN            */
    RPC_TCP_SYN_SENT,    /* SYN-SENT    CI_TCP_SYN_SENT          */
    RPC_TCP_ESTABLISHED, /* ESTABLISHED CI_TCP_ESTABLISHED       */
    RPC_TCP_CLOSE_WAIT,  /* CLOSE_WAIT  CI_TCP_CLOSE_WAIT        */
    RPC_TCP_LAST_ACK,    /* LAST-ACK    CI_TCP_LAST_ACK          */
    RPC_TCP_FIN_WAIT1,   /* FIN-WAIT1   CI_TCP_FIN_WAIT1         */
    RPC_TCP_FIN_WAIT2,   /* FIN-WAIT2   CI_TCP_FIN_WAIT2         */
    RPC_TCP_CLOSING,     /* CLOSING     CI_TCP_CLOSING           */
    RPC_TCP_TIME_WAIT,   /* TIME-WAIT   CI_TCP_TIME_WAIT         */
    /*
     * Next values correspond to RPC_TCP_UNKNOWN
     *                      FREE        CI_TCP_STATE_FREE
     *                      UDP         CI_TCP_STATE_UDP
     *                      PIPE        CI_TCP_STATE_PIPE
     *                      AUXBUF      CI_TCP_STATE_AUXBUF
     *                      ACTIVE_WILD CI_TCP_STATE_ACTIVE_WILD
     */
  };

  if (state_i < 0 || state_i >= (sizeof(state_strs) / sizeof(state_strs[0])))
    return RPC_TCP_UNKNOWN;

  return state_strs[state_i];
}

/* See the description in parse_orm_json.h */
te_errno
ta_read_cmd(const char *cmd, te_string *str)
{
    FILE *f = NULL;
    char buf[FREAD_BUF_LEN];
    size_t sys_rc;
    te_errno rc;
    pid_t cmd_pid;

    rc = ta_popen_r(cmd, &cmd_pid, &f);
    if (rc != 0)
    {
        ERROR("%s(): ta_popen_r() failed with '%s', rc=%r", __FUNCTION__, cmd,
              rc);
        goto cleanup;
    }
    while (!feof(f))
    {
        sys_rc = fread(buf, 1, FREAD_BUF_LEN - 1, f);
        if (ferror(f) != 0)
        {
            ERROR("%s(): failed to read pipe with output of '%s'",
                  __FUNCTION__, cmd);
            rc = TE_RC(TE_TAPI, TE_EFAIL);
            goto cleanup;
        }
        buf[sys_rc] = '\0';

        rc = te_string_append(str, "%s", buf);
        if (rc != 0)
            goto cleanup;
    }

cleanup:

    if (f != NULL)
    {
        te_errno rc2;

        rc2 = ta_pclose_r(cmd_pid, f);
        if (rc2 != 0)
        {
            ERROR("ta_pclose_r() failed, %r", rc);
            if (rc == 0)
                rc = rc2;
        }
    }

    return rc;
}

/**
 * Check if struct sockaddr address @p addr has provided IP address and port.
 * Port is checked only if @p check_port is @c TRUE.
 *
 * @param addr        Socket address
 * @param ip_str      IP address as a string
 * @param port        Port (host byte order)
 * @param check_port  Shoud we check port number
 *
 * @return @c TRUE in case of match, @c FALSE otherwise
 */
static bool
sockaddr_cmp(const struct sockaddr *addr, const char *ip_str, int port,
             bool check_port)
{
    char *addr_ip_str = te_ip2str(addr);
    bool rc;
    rc = strcmp(ip_str, addr_ip_str) == 0;
    if (check_port && rc)
        rc = htons(*te_sockaddr_get_port_ptr(addr)) == port;
    free(addr_ip_str);

    return rc;
}

/**
 * Check if entry about socket with given TCP state @p state, source IP address
 * @p s_addr_str, source port number @p s_port, destination IP address
 * @p d_addr_str, and destination port number @p d_port corresponds to socket
 * with provided @s_sockaddr and @d_sockaddr. The actual check depends on
 * @p state.
 *
 * @param state        Socket state
 * @param s_sockaddr   Source socket address
 * @param s_addr_str   Source IP address as a string
 * @param s_port       Source port (host byte order)
 * @param d_sockaddr   Destination socket address
 * @param d_addr_str   Destination IP address as a string
 * @param d_port       Destination port (host byte order)
 *
 * @return @c TRUE in case of match, @c FALSE otherwise
 */
static bool
check_state_addr_port(rpc_tcp_state state, const struct sockaddr *s_sockaddr,
                      const char *s_addr_str, int s_port,
                      const struct sockaddr *d_sockaddr,
                      const char *d_addr_str, int d_port)
{
    bool rc = FALSE;

    switch (state)
    {
        case RPC_TCP_CLOSE:
            /*
             * Information about already closed sockets is stored in Onload.
             * We should't consider these sockets.
             */
            break;

        case RPC_TCP_LISTEN:
            /* For sockets in TCP_LISTEN we should't check destination port */
            rc = sockaddr_cmp(s_sockaddr, s_addr_str, s_port, TRUE) &&
                 sockaddr_cmp(d_sockaddr, d_addr_str, d_port, FALSE);
            break;

        default:
            rc = sockaddr_cmp(s_sockaddr, s_addr_str, s_port, TRUE) &&
                 sockaddr_cmp(d_sockaddr, d_addr_str, d_port, TRUE);
    }

    return rc;
}

/* See the description in parse_orm_json.h */
te_errno
orm_json_get_tcp_state(const char *joutput, const struct sockaddr *loc_addr,
                       const struct sockaddr *rem_addr, rpc_tcp_state *state,
                       bool *found)
{
    te_errno rc = TE_RC(TE_TAPI, TE_ENOENT);
    json_error_t error;
    json_t *jmain;
    json_t *jjson;
    json_t *jjson_elt;
    int jjson_i;
    const char *jjson_elt_id;
    json_t *jjson_elt_issue;
    json_t *jstack;
    json_t *jtcp;
    json_t *jtcp_issue;
    const char *tcp_id;
    json_t *jtcp_state;
    json_t *js;
    json_t *jb;
    json_t *jstate;
    json_t *jladdr;
    json_t *jcp;
    json_t *jlport;
    json_t *jpkt;
    json_t *jdport;
    json_t *jipx;
    json_t *jip4;
    json_t *jip_daddr;

    jmain = json_loads(joutput, 0, &error);

    if (jmain == NULL)
    {
        ERROR("json_loads fails with message: \"%s\", position: %u",
              error.text, error.position);
        rc = TE_RC(TE_TAPI, TE_EFMT);
        goto cleanup;
    }
    /*
     * The corresponding serialized JSON looks like this.
     * {
     * ...
     *     "json": [
     *         {
     *             "0": {
     * ...
     *                 "stack": {
     * ...
     *                     "tcp": {
     *                         "2045": {
     *                             "tcp_state": {
     *                                 "s": {
     *                                     "b": {
     *                                         "bufid": 2045,
     *                                         "state": 582,
     * ...
     *                                     },
     * ...
     *                                     "laddr": "192.168.20.1",
     *                                     "cp": {
     *                                         "laddr": "192.168.20.1",
     *                                         "lport": 20988,
     * ...
     *                                     },
     *                                     "pkt": {
     *                                         "dport": 20989,
     *                                         "ipx": {
     *                                             "ip4": {
     * ...
     *                                                 "ip_saddr": "192.168.20.1",
     *                                                 "ip_daddr": "192.168.210.2"
     *                                             }
     *                                         }
     *                                     },
     * ...
     *                                 },
     * ...
     *                             }
     *                         },
     * ...
     *                     },
     * ...
     *                 },
     * ...
     *             }
     *         }
     *     ]
     * }
     */
    JSON_CHECK_GOTTEN(the whole json, "main", jmain, object, TRUE);
    JSON_OBJECT_GET_CHECK(main, json, array, TRUE);
    json_array_foreach(jjson, jjson_i, jjson_elt)
    {
        if (!json_is_object(jjson_elt))
        {
            ERROR("Element in jjson with index %d is not an object", jjson_i);
            rc = TE_RC(TE_TAPI, TE_EFMT);
            goto cleanup;
        }
        json_object_foreach(jjson_elt, jjson_elt_id, jjson_elt_issue)
        {
            JSON_OBJECT_GET_CHECK(json_elt_issue, stack, object, FALSE);
            JSON_OBJECT_GET_CHECK(stack, tcp, object, FALSE);
            json_object_foreach(jtcp, tcp_id, jtcp_issue)
            {
                rpc_tcp_state cur_state;

                JSON_OBJECT_GET_CHECK(tcp_issue, tcp_state, object, FALSE);
                JSON_OBJECT_GET_CHECK(tcp_state, s, object, FALSE);
                JSON_OBJECT_GET_CHECK(s, b, object, FALSE);
                JSON_OBJECT_GET_CHECK(b, state, integer, FALSE);
                cur_state = orm_json_tcp_state_2_rpc_tcp_state(
                                json_integer_value(jstate));
                JSON_OBJECT_GET_CHECK(s, laddr, string, FALSE);
                JSON_OBJECT_GET_CHECK(s, cp, object, FALSE);
                JSON_OBJECT_GET_CHECK(cp, lport, integer, FALSE);
                JSON_OBJECT_GET_CHECK(s, pkt, object, FALSE);
                JSON_OBJECT_GET_CHECK(pkt, dport, integer, FALSE);
                JSON_OBJECT_GET_CHECK(pkt, ipx, object, FALSE);
                JSON_OBJECT_GET_CHECK(ipx, ip4, object, FALSE);
                JSON_OBJECT_GET_CHECK(ip4, ip_daddr, string, FALSE);
                if (check_state_addr_port(cur_state, loc_addr,
                                          json_string_value(jladdr),
                                          json_integer_value(jlport), rem_addr,
                                          json_string_value(jip_daddr),
                                          json_integer_value(jdport)))
                {
                    *found = TRUE;
                    *state = cur_state;
                    rc = 0;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    json_decref(jmain);

    return rc;
}
