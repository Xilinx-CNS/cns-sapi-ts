/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-inherit_derived Checking inhereting socket options after fork and exec
 *
 * @objective Check that socket inherits options after @b fork() and
 *            @b execve().
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param domain        Domain to be used for socket creation
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param opt_name      Option to be tested
 * @param method        Method of socket descriptor/process obtaining:
 *                      exec, inherit (fork), DuplicateSocket, DuplicateHandle,
 *                      etc.
 * @param before        If @c TRUE, obtain the child socket before
 *                      @b setsockopts(), @c FALSE in the opposite case
 *
 * @par Test sequence:
 * -# Create a socket @p iut_s from @p domain, @p sock_type type
 *    on @p pco_iut.
 * -# If @p before is @c TRUE, get child socket according to @p method.
 * -# Call @b setsockopt() with specified socket option and check
 *    expected result/errno.
 * -# If @p before is @c FALSE, get child socket according to @p method.
 * -# Call @b getsockopt() on parent and child sockets.
 * -# Compare results.
 * -# Close @p iut_s.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/inherit_derived"

#include "sockapi-test.h"
#include "sockopts_common.h"

#define PREPARE_OPTLEN(_opt_name, _optval) \
    do {                                                                \
        rpc_sockopt_value *__optval = (void *)_optval;                  \
        switch (_opt_name)                                              \
        {                                                               \
            /* boolean options */                                       \
            case RPC_SO_DEBUG:                      /*set/get*/         \
            case RPC_SO_REUSEADDR:                  /*set/get*/         \
            case RPC_SO_DONTROUTE:                  /*set/get*/         \
            case RPC_SO_BROADCAST:                  /*set/get*/         \
            case RPC_SO_KEEPALIVE:                  /*set/get*/         \
            case RPC_SO_OOBINLINE:                  /*set/get*/         \
            case RPC_SO_TIMESTAMP:                  /*set/get*/         \
            case RPC_SO_TIMESTAMPNS:                /*set/get*/         \
            case RPC_SO_TIMESTAMPING:               /*set/get*/         \
                (__optval)->v_int = 1;                                  \
                break;                                                  \
            /* int options */                                           \
            case RPC_SO_SNDBUF:                     /*set/get*/         \
            case RPC_SO_SNDBUFFORCE:                /*set/get*/         \
            case RPC_SO_RCVBUF:                     /*set/get*/         \
            case RPC_SO_RCVBUFFORCE:                /*set/get*/         \
                (__optval)->v_int = rand_range(10240, 20480);           \
                break;                                                  \
            case RPC_SO_RCVLOWAT:                   /*set/get*/         \
                (__optval)->v_int = 2;                                  \
                break;                                                  \
            case RPC_SO_PRIORITY:                   /*set/get*/         \
                (__optval)->v_int = 1;                                  \
                break;                                                  \
           /* complex options */                                        \
            case RPC_SO_LINGER:                     /*set/get*/         \
                (__optval)->v_linger.l_onoff  = 1;                      \
                (__optval)->v_linger.l_linger = 0;                      \
                break;                                                  \
            case RPC_SO_RCVTIMEO:                   /*set/get*/         \
            case RPC_SO_SNDTIMEO:                   /*set/get*/         \
                (__optval)->v_tv.tv_sec = 2;                            \
                (__optval)->v_tv.tv_usec = 0;                           \
                break;                                                  \
            case RPC_SO_TYPE:                       /*get*/             \
            case RPC_SO_ERROR:                      /*get*/             \
            case RPC_SO_ACCEPTCONN:                 /*get*/             \
                (__optval)->v_int = 0;                                  \
                break;                                                  \
            case RPC_SO_BINDTODEVICE:                                   \
                strcpy((char *)_optval, iut_if->if_name);               \
                break;                                                  \
            default:                                                    \
                 TEST_FAIL("Unexpected(unsupported) option");           \
                 break;                                                 \
        }                                                               \
    } while (0)

#define SET_OPT_CHECK_ERR(_rpcs, _sock, _optname, _optval, _experr) \
    do {                                                                   \
        RPC_AWAIT_IUT_ERROR(_rpcs);                                        \
        int _er = 0;                                                       \
        if (_optname == RPC_SO_BINDTODEVICE)                               \
        {                                                                  \
            _er = rpc_setsockopt_raw(_rpcs, _sock, _optname, _optval,      \
                                     strlen((const char *)_optval) + 1);   \
        }                                                                  \
        else                                                               \
        {                                                                  \
            _er = rpc_setsockopt(_rpcs, _sock, _optname, _optval);         \
        }                                                                  \
                                                                           \
        if (_experr != 0)                                                  \
        {                                                                  \
            if (_er != -1)                                                 \
                TEST_VERDICT("setsockopt(%s, %s) returns %d instead of -1",\
                             socklevel_rpc2str(rpc_sockopt2level(_optname)), \
                             sockopt_rpc2str(_optname), _er);              \
            CHECK_RPC_ERRNO(_rpcs, _experr,                                \
                            "setsockopt() called with incorrect parameter,"\
                            " returns -1, but");                           \
        }                                                                  \
        else if (_er != 0)                                                 \
        {                                                                  \
            int _err = RPC_ERRNO(_rpcs);                                   \
                                                                           \
            TEST_VERDICT("setsockopt(%s, %s) unexpectedly failed with "    \
                         "errno %s", socklevel_rpc2str(rpc_sockopt2level(_optname)),           \
                         sockopt_rpc2str(_optname), errno_rpc2str(_err));  \
        }                                                                  \
    } while (0)

static int
rpc_getsockopt_comm(rcf_rpc_server *rpcs, int s,
                    rpc_sockopt optname, void *optval)
{
    if (optname == RPC_SO_BINDTODEVICE)
    {
        socklen_t optlen = IFNAMSIZ;
        return rpc_getsockopt_raw(rpcs, s, optname, optval, &optlen);
    }
    else
    {
        return rpc_getsockopt(rpcs, s, optname, optval);
    }
}

int
main(int argc, char *argv[])
{
    rpc_socket_type        sock_type;
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *child_rpcs = NULL;

    int                    iut_s = -1;
    int                    child_s = -1;

    const char            *method;

    rpc_sockopt            opt_name;
    te_bool                before = FALSE;

    uint8_t                opt_val[128];
    uint8_t                opt_val1[128];

    int               rc1, rc2;
    rpc_errno         exp_errno;
    rpc_socket_domain domain;

    const struct if_nameindex *iut_if;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_if);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);
    TEST_GET_STRING_PARAM(method);
    TEST_GET_BOOL_PARAM(before);

    switch (opt_name)
    {
        case RPC_SO_ACCEPTCONN: exp_errno = RPC_ENOPROTOOPT; break;
        case RPC_SO_ERROR:
            exp_errno = RPC_ENOPROTOOPT;
            break;

        case RPC_SO_TYPE: exp_errno = RPC_ENOPROTOOPT; break;
        case RPC_SO_BROADCAST:
            exp_errno = 0;
            break;
        case RPC_SO_DEBUG: exp_errno = 0; break;
        case RPC_SO_DONTROUTE: exp_errno = 0; break;
        case RPC_SO_PRIORITY: exp_errno = 0; break;
        case RPC_SO_RCVBUF: exp_errno = 0; break;
        case RPC_SO_RCVBUFFORCE: exp_errno = 0; break;
        case RPC_SO_RCVLOWAT: exp_errno = 0; break;
        case RPC_SO_RCVTIMEO: exp_errno = 0; break;
        case RPC_SO_REUSEADDR: exp_errno = 0; break;
        case RPC_SO_SNDBUF: exp_errno = 0; break;
        case RPC_SO_SNDBUFFORCE: exp_errno = 0; break;
        case RPC_SO_SNDTIMEO: exp_errno = 0; break;
        case RPC_SO_BINDTODEVICE: exp_errno = 0; break;

        case RPC_SO_KEEPALIVE:
        case RPC_SO_LINGER:
        case RPC_SO_OOBINLINE:
        case RPC_SO_TIMESTAMP:
        case RPC_SO_TIMESTAMPNS:
        case RPC_SO_TIMESTAMPING:
            exp_errno = 0;
            break;
        default:
            TEST_FAIL("Unexpected option is specified");
    }

    memset(opt_val, 0, sizeof(opt_val));
    PREPARE_OPTLEN(opt_name, opt_val);

    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    /* Call execve/fork and set socket option in requered siquence. */
    if (before)
        SET_OPT_CHECK_ERR(pco_iut, iut_s, opt_name, opt_val, exp_errno);

    if (strcmp(method, "exec") == 0)
    {
        memset(opt_val1, 0, sizeof(opt_val1));
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc2 = rpc_getsockopt_comm(pco_iut, iut_s, sockts_fix_get_opt(opt_name),
                                  opt_val1);

        if ((rc = rcf_rpc_server_exec(pco_iut)) != 0)
        {
            CHECK_RC(rcf_rpc_server_exec(pco_iut));
        }
        child_rpcs = pco_iut;
        child_s = iut_s;
    }
    else 
        rpc_create_child_process_socket(method, pco_iut, iut_s, domain,
                                        sock_type, &child_rpcs, &child_s);
    if (!before)
        SET_OPT_CHECK_ERR(pco_iut, iut_s, opt_name, opt_val, exp_errno);

    /* Get socket option for the father socket. */
    memset(opt_val, 0, sizeof(opt_val));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc1 = rpc_getsockopt_comm(pco_iut, iut_s, sockts_fix_get_opt(opt_name),
                              opt_val);

    if (strcmp(method, "exec") != 0)
    {
        memset(opt_val1, 0, sizeof(opt_val1));
        RPC_AWAIT_IUT_ERROR(child_rpcs);
        rc2 = rpc_getsockopt_comm(child_rpcs, child_s, sockts_fix_get_opt(opt_name),
                                  opt_val1);
    }

    if (rc1 != rc2)
        TEST_VERDICT("getsockopt() on child and parent sockets returned "
                  "different results");

    if (rc1 == -1)
    {
        if (RPC_ERRNO(pco_iut) != RPC_ERRNO(child_rpcs))
            TEST_VERDICT("getsockopt() on child and parent sockets "
                         "returned different error");
        TEST_SUCCESS;
    }

    if (memcmp(opt_val, opt_val1, sizeof(opt_val)) != 0)
    {
        if (opt_name == RPC_SO_BINDTODEVICE)
        {
            RING("Option values: %s (parent) %s (child)",
                 (char *)opt_val, (char *)opt_val1);
        }
        else
        {
            RING("Option values: %d (parent) %d (child)",
                 ((rpc_sockopt_value *)opt_val)->v_int,
                 ((rpc_sockopt_value *)opt_val1)->v_int);
        }
        TEST_VERDICT("Different option value for parent and child sockets");
    }

    TEST_SUCCESS;

cleanup:
    if (child_rpcs == pco_iut && child_s != iut_s)
        CLEANUP_RPC_CLOSE(pco_iut, child_s);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
