/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-inherited_option Inheritance of options from socket
 *
 * @objective Checking that socket options set on socket are inherited by
 *            socket after some operations on it.
 *
 * @type conformance
 *
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param checkopt          Option for checking
 * @param how               What operation should be called on the socket
 * @param listen_before     Whether we should try to get/change default
 *                          option value after @b listen() call
 * @param accept_before     Whether we should try to get/change default
 *                          option value after @b accept() call
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of the @c SOCK_STREAM type on the
 *    @p IUT side;
 * -# Create @p tst_s socket of the @c SOCK_STREAM type on the
 *    @p TESTER side;
 * -# @b bind() @p pco_iut socket to the INADDR_ANY address/port;
 * -# @b bind() @p pco_tst socket to the @p tst_addr;
 * -# If @p how is @c connect_failed_connect call @b connect() on
 *    @p pco_iut. It will return @c -1, and set errno to @c ECONNREFUSED.
 *    Then call @b listen() on @p pco_tst and call @b connect() again on
 *    @p pco_iut socket.
 * -# If @p how is @c connect_failed_listen call @b connect() on
 *    @p pco_iut. It will return @c -1, and set errno to @c ECONNREFUSED.
 *    Then call @b listen() on @p pco_tst and call @b listen() on
 *    @p pco_iut socket.
 * -# If @p how is @c listen_shutdown_connect call @b listen() on @p pco_iut
 *    socket then call @b shutdown(@c SHUT_RD) on it. Then call @b listen()
 *    on @p pco_tst and call @b connect() on @p pco_iut.
 * -# If @p how is @c listen_shutdown_listen call @b listen() on @p pco_iut
 *    socket then call @b shutdown(@c SHUT_RD) on it. Then call @b listen()
 *    on @p pco_iut.
 * -# If @p how is @c listen_accept call @b listen() on @p pco_iut then
 *    @b connect() on @p pco_tst and after that @b accept() on @p pco_iut.
 * -# If @p how is @c listen_accept_shutdown call @b listen() on @p pco_iut
 *    then @b connect() on @p pco_tst and after that @b accept() and
 *    @b shutdown(WR) on @p pco_iut.
 * -# If @p how is @c listen_accept_close call @b listen() on @p pco_iut
 *    then @b connect() on @p pco_tst and after that @b accept() on
 *    @p pco_iut. Set @c SO_LINGER option on connected TESTER socket
 *    with value 0, and call @b close() on it. As a result accepted
 *    socket on IUT should receive RST and move to @c TCP_CLOSE state.
 * -# If @p how is @c listen_shutdown_rd call @b listen() on @p pco_iut
 *    then call @b shutdown(@c SHUT_RD) on @p pco_iut.
 * -# If @p how is @c listen_shutdown_wr call @b listen() on @p pco_iut
 *    then call @b shutdown(@c SHUT_WR) on @p pco_iut.
 * -# If @p how is @c listen_shutdown_rdwr call @b listen() on @p pco_iut
 *    then call @b shutdown(@c SHUT_RDWR) on @p pco_iut.
 * -# In all cases, check that we can retrieve default socket option value
 *    and set a new one, and after that it will be inherited.
 * -# If @p how is @c listen_accept[_shutdown|_close] check that the value
 *    of @p checkopt set on @p iut_s is inherited by accepted socket; in
 *    other cases check that @p pco_iut socket hasn't changed option
 *    value after this operations.
 * -# Close crated sockets, return to the original configuration.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/inherited_option"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_sockets.h"
#include "sockopts_common.h"

#include <netinet/ip.h>

#define IP_TS_OPTS_LEN  12

#define SET_GET_OPT(_sock, _opt, _optval, _optret) \
    do {                                                                \
        RPC_AWAIT_IUT_ERROR(pco_iut);                                   \
        ret = rpc_setsockopt(pco_iut, _sock, _opt, &(_optval));         \
        if (ret != 0)                                                   \
        {                                                               \
            TEST_VERDICT("setsockopt(%s, %s) failed with errno %s",     \
                         socklevel_rpc2str(rpc_sockopt2level(_opt)),    \
                         sockopt_rpc2str(checkopt),                     \
                         errno_rpc2str(RPC_ERRNO(pco_iut)));            \
        }                                                               \
        rpc_getsockopt(pco_iut, _sock, sockts_fix_get_opt(_opt),        \
                       &(_optret));                                     \
    } while (0)

#define SET_OPT_NEW(_sock, _opt, _optdef, _optret, _optret_len, _str) \
    do {                                                                \
        rpc_sockopt_value   optval;                                     \
        int                 optval_len = sizeof(optval);                \
                                                                        \
        memset(&optval, 0, optval_len);                                 \
        memset(&(_optret), 0, sizeof(_optret));                         \
        if (sockopt_is_boolean(_opt))                                   \
        {                                                               \
            optval.v_int = ((_optdef).v_int == 0 ? 1 : 0);              \
            SET_GET_OPT(_sock, _opt, optval, _optret);                  \
            if (!!(_optret).v_int != optval.v_int)                      \
            {                                                           \
                RING_VERDICT("%sSet of %s to %d returned success, but " \
                             "applied value %d does not match set",     \
                             (_str), sockopt_rpc2str(_opt),             \
                             optval.v_int, !!(_optret).v_int);          \
                is_failed = TRUE;                                       \
            }                                                           \
        }                                                               \
        else switch (_opt)                                              \
        {                                                               \
            /* int options */                                           \
            case RPC_IP_TOS:                        /*set/get*/         \
            case RPC_IP_TTL:                        /*set/get*/         \
            case RPC_SO_UPDATE_ACCEPT_CONTEXT:                          \
            case RPC_SO_UPDATE_CONNECT_CONTEXT:                         \
                optval.v_int = (_optdef).v_int + 5;                     \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                /* we don't check a result in this case */              \
                break;                                                  \
                                                                        \
            case RPC_SO_SNDBUF:                     /*set/get*/         \
            case RPC_SO_SNDBUFFORCE:                /*set/get*/         \
            case RPC_SO_RCVBUF:                     /*set/get*/         \
            case RPC_SO_RCVBUFFORCE:                /*set/get*/         \
                optval.v_int = (_optdef).v_int / 3;                     \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                /* we don't check a result in this case */              \
                break;                                                  \
                                                                        \
            case RPC_SO_RCVLOWAT:                   /*set/get*/         \
            case RPC_TCP_MAXSEG:                                        \
                optval.v_int = (_optdef).v_int + 100;                   \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                if ((_optret).v_int != optval.v_int)                    \
                    TEST_FAIL("Set of %s to %d returned success, but "  \
                              "applied value %d does not match set",    \
                              sockopt_rpc2str(_opt), optval.v_int,      \
                              (_optret).v_int);                         \
                break;                                                  \
                                                                        \
            case RPC_SO_SNDLOWAT:                   /*set/get*/         \
            /* Linux does not change this value and always returns 1 */ \
                optval.v_int = (_optdef).v_int + 100;                   \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                if ((_optret).v_int != optval.v_int)                    \
                    TEST_FAIL("Set of %s to %d returned success, but "  \
                              "applied value %d does not match set",    \
                              sockopt_rpc2str(_opt), optval.v_int,      \
                              (_optret).v_int);                         \
                break;                                                  \
                                                                        \
            case RPC_TCP_KEEPIDLE:                  /*set/get*/         \
            case RPC_TCP_KEEPINTVL:                 /*set/get*/         \
            case RPC_SO_RCVTIMEO:                   /*set/get*/         \
            case RPC_SO_SNDTIMEO:                   /*set/get*/         \
                memcpy(&optval, &(_optdef), sizeof(tarpc_timeval));     \
                optval.v_tv.tv_sec = (_optdef).v_tv.tv_sec + 5;         \
                if (((_opt) == RPC_SO_RCVTIMEO) ||                      \
                    ((_opt) == RPC_SO_SNDTIMEO))                        \
                {                                                       \
                    optval.v_tv.tv_usec =                               \
                        (_optdef).v_tv.tv_usec + 100000;                \
                }                                                       \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                if ((_optret).v_tv.tv_sec != optval.v_tv.tv_sec ||      \
                    (_optret).v_tv.tv_usec != optval.v_tv.tv_usec)      \
                    TEST_FAIL("Set of %s to %s returned success, but "  \
                              "applied value %s does not match set",    \
                              sockopt_rpc2str(_opt),                    \
                              tarpc_timeval2str(&optval.v_tv),          \
                              tarpc_timeval2str(&(_optret).v_tv));      \
                break;                                                  \
                                                                        \
            case RPC_TCP_KEEPCNT:                   /*set/get*/         \
                optval.v_int = (_optdef).v_int + 2;                     \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                if ((_optret).v_int != optval.v_int)                    \
                    TEST_FAIL("Set of %s to %d returned success, but "  \
                              "applied value %d does not match set",    \
                              sockopt_rpc2str(_opt), optval.v_int,      \
                              (_optret).v_int);                         \
                break;                                                  \
                                                                        \
            case RPC_SO_PRIORITY:                   /*set/get*/         \
                optval.v_int = ((_optdef).v_int == 0 ? 1 : 0);          \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                if ((_optret).v_int != optval.v_int)                    \
                    TEST_FAIL("Set of %s to %d returned success, but "  \
                              "applied value %d does not match set",    \
                              sockopt_rpc2str(_opt), optval.v_int,      \
                              (_optret).v_int);                         \
                break;                                                  \
                                                                        \
           /* complex options */                                        \
            case RPC_SO_LINGER:                     /*set/get*/         \
                memcpy(&optval, &(_optdef), sizeof(tarpc_linger));      \
                optval.v_linger.l_onoff =                               \
                    ((_optdef).v_linger.l_onoff == 0 ? 1 : 0);          \
                SET_GET_OPT(_sock, _opt, optval, _optret);              \
                if (!!(_optret).v_linger.l_onoff !=                     \
                        optval.v_linger.l_onoff ||                      \
                    (_optret).v_linger.l_linger !=                      \
                        optval.v_linger.l_linger)                       \
                    TEST_FAIL("Set of %s to {%d,%d} returned success, " \
                              "but applied value {%d,%d} does not "     \
                              "match set", sockopt_rpc2str(_opt),       \
                              optval.v_linger.l_onoff,                  \
                              optval.v_linger.l_linger,                 \
                              !!(_optret).v_linger.l_onoff,             \
                              (_optret).v_linger.l_linger);             \
                break;                                                  \
                                                                        \
            case RPC_IP_OPTIONS:                                        \
                RPC_AWAIT_IUT_ERROR(pco_iut);                           \
                ret = rpc_setsockopt_raw(pco_iut, _sock, _opt,          \
                                         ip_opts, sizeof(ip_opts));     \
                if (ret != 0)                                           \
                {                                                       \
                    TEST_VERDICT("setsockopt(%s) failed with errno %s", \
                                 sockopt_rpc2str(checkopt),             \
                                 errno_rpc2str(RPC_ERRNO(pco_iut)));    \
                }                                                       \
                (_optret_len) = sizeof(_optret);                        \
                rpc_getsockopt_raw(pco_iut, _sock, _opt, &(_optret),    \
                                   &(_optret_len));                     \
                if ((_optret_len) == sizeof(ip_opts))                   \
                {                                                       \
                    if (memcmp(&(_optret), ip_opts,                     \
                               sizeof(ip_opts)) != 0)                   \
                    {                                                   \
                        TEST_VERDICT("getsockopt(IP_OPTIONS) when IP "  \
                                     "timestamp option is set returned "\
                                     "success but strange value");      \
                    }                                                   \
                }                                                       \
                else if ((_optret_len) ==                               \
                         sizeof(ip_opts) + sizeof(struct in_addr))      \
                {                                                       \
                    if (memcmp(((uint8_t *)&(_optret)) +                \
                                   sizeof(struct in_addr), ip_opts,     \
                               sizeof(ip_opts)) != 0)                   \
                    {                                                   \
                        TEST_VERDICT("getsockopt(IP_OPTIONS) when IP "  \
                                     "timestamp option is set returned "\
                                     "success but strange value");      \
                    }                                                   \
                    if (*(in_addr_t *)&(_optret) != htonl(INADDR_ANY))  \
                    {                                                   \
                        TEST_VERDICT("getsockopt(IP_OPTIONS) when IP "  \
                                     "timestamp option is set returned "\
                                     "success but unexpected final "    \
                                     "destination address");            \
                    }                                                   \
                    WARN("getsockopt(IP_OPTIONS) returns final "        \
                         "destination address plus set IP options");    \
                }                                                       \
                else                                                    \
                {                                                       \
                    TEST_VERDICT("getsockopt(IP_OPTIONS) returns "      \
                                 "unexpected option value");            \
                }                                                       \
                break;                                                  \
                                                                        \
            case RPC_SO_BINDTODEVICE:                                   \
                RPC_AWAIT_IUT_ERROR(pco_iut);                           \
                ret = rpc_setsockopt_raw(pco_iut, _sock, _opt,          \
                                         iut_iface,                     \
                                         strlen(iut_iface) + 1);        \
                if (ret != 0)                                           \
                {                                                       \
                    TEST_VERDICT("setsockopt(%s) failed with errno %r", \
                                 sockopt_rpc2str(_opt),                 \
                                 RPC_ERRNO(pco_iut));                   \
                }                                                       \
                (_optret_len) = sizeof(_optret);                        \
                RPC_AWAIT_IUT_ERROR(pco_iut);                           \
                ret = rpc_getsockopt_raw(pco_iut, _sock, _opt,          \
                                         &(_optret), &(_optret_len));   \
                if (ret != 0)                                           \
                {                                                       \
                    TEST_VERDICT("getsockopt(%s) failed with errno %r", \
                                 sockopt_rpc2str(_opt),                 \
                                 RPC_ERRNO(pco_iut));                   \
                }                                                       \
                if (_optret_len != strlen(iut_iface) + 1)               \
                {                                                       \
                    TEST_VERDICT("getsockopt(%s) returned "             \
                                 "invalid option length %d",            \
                                 sockopt_rpc2str(_opt), _optret_len);   \
                }                                                       \
                else if (strcmp((char *)&(_optret), iut_iface) != 0)    \
                {                                                       \
                    TEST_FAIL("Set of %s to %s returned success, but "  \
                              "applied value %s does not match set",    \
                              sockopt_rpc2str(_opt), iut_iface,         \
                              &(_optret));                              \
                }                                                       \
                break;                                                  \
                                                                        \
            default:                                                    \
                 TEST_FAIL("Unexpected(unsupported) option");           \
                 break;                                                 \
        }                                                               \
    } while (0)

#define CHECK_INHERITED_OPT(_sock, _opt, _optval, _optval_len,            \
                            _optdef, _str)                                \
    do {                                                                  \
        if ((_opt) == RPC_IP_OPTIONS ||                                   \
            (_opt) == RPC_SO_BINDTODEVICE)                                \
        {                                                                 \
            uint8_t     buf[40];                                          \
            socklen_t   optlen;                                           \
                                                                          \
            optlen = sizeof(buf);                                         \
            rpc_getsockopt_raw(pco_iut, _sock, _opt, buf, &optlen);       \
            if (optlen != (_optval_len) ||                                \
                memcmp(buf, &(_optval), optlen) != 0)                     \
            {                                                             \
                TEST_VERDICT("%s%s option value is not "                  \
                             "inherited on '%s' transition",              \
                             (_str), sockopt_rpc2str(_opt), how);         \
            }                                                             \
        }                                                                 \
        else                                                              \
        {                                                                 \
            rpc_sockopt_value   optret;                                   \
                                                                          \
            memset(&optret, 0, sizeof(optret));                           \
            rpc_getsockopt(pco_iut, _sock,                                \
                           sockts_fix_get_opt(_opt), &optret);            \
            if (memcmp(&optret, &(_optval), sizeof(optret)) == 0)         \
            {                                                             \
                /* Inherited exactly */                                   \
            }                                                             \
            else if (memcmp(&optret, &(_optdef),                          \
                            sizeof(optret)) == 0)                         \
            {                                                             \
                /* Reset to default */                                    \
                TEST_VERDICT("%s%s option value is reset to "             \
                             "default on '%s' transition", (_str),        \
                             sockopt_rpc2str(_opt), how);                 \
            }                                                             \
            else if ((_opt) == RPC_SO_RCVBUF ||                           \
                     (_opt) == RPC_SO_RCVBUFFORCE)                        \
            {                                                             \
                cfg_val_type val_type = CVT_INTEGER;                      \
                unsigned int iut_mtu;                                     \
                unsigned int mss;                                         \
                                                                          \
                CHECK_RC(cfg_get_instance_fmt(&val_type, &iut_mtu,        \
                             "/agent:%s/interface:%s/mtu:",               \
                             pco_iut->ta, iut_if->if_name));              \
                mss = iut_mtu - 52;                                       \
                RING("Interface MTU is %u. Calculated MSS is %u.",        \
                     iut_mtu, mss);                                       \
                                                                          \
                if (optret.v_int >= ((_optval).v_int + (int)(2 * mss)) || \
                    optret.v_int <= ((_optval).v_int - (int)(2 * mss)))   \
                {                                                         \
                    TEST_VERDICT("%sSO_RCVBUF changes "                   \
                                 "unexpectedly", (_str));                 \
                }                                                         \
                else if (optret.v_int % mss == 0)                         \
                {                                                         \
                    TEST_VERDICT("%sSO_RCVBUF is rounded %s to "          \
                                 "MSS=%u on '%s' transition",             \
                                 (_str),                                  \
                                 optret.v_int > (_optval).v_int ?         \
                                    "up" : "down", mss, how);             \
                }                                                         \
                else if (optret.v_int != (_optval).v_int)                 \
                    TEST_VERDICT("%sSO_RCVBUF changes in "                \
                                 "accordance with SF specific "           \
                                 "feature", (_str));                      \
            }                                                             \
            else if (sockopt_is_boolean(_opt) &&                          \
                     (!optret.v_int == !(_optval).v_int))                 \
            {                                                             \
                /*                                                        \
                 * Option is boolean and it inherits its value as         \
                 * as boolean value.                                      \
                 */                                                       \
            }                                                             \
            else if ((_opt) == RPC_SO_LINGER &&                           \
                     (!optret.v_linger.l_onoff ==                         \
                      !(_optval).v_linger.l_onoff) &&                     \
                     (optret.v_linger.l_linger ==                         \
                      (_optval).v_linger.l_linger))                       \
            {                                                             \
                /* SO_LINGER l_onoff is boolean */                        \
            }                                                             \
            else                                                          \
            {                                                             \
                RING_VERDICT("%s%s option value is changed to "           \
                             "unexpected value on '%s' transition",       \
                             (_str), sockopt_rpc2str(_opt), how);         \
                memcpy(&(_optval), &optret, sizeof(optret));              \
                is_failed = TRUE;                                         \
            }                                                             \
        }                                                                 \
    } while (0)

#define BUF_SIZE 1024

#define STRCMP_END(_s1, _s2) \
    strcmp((_s1), (_s2) + strlen(_s2) - strlen(_s1))

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_tst = NULL;
    const struct if_nameindex  *iut_if;
    const struct sockaddr      *tst_addr;
    const struct sockaddr      *iut_addr;
    te_bool                     listen_before = FALSE;
    te_bool                     accept_before = FALSE;
    const char                 *how;
    rpc_sockopt                 checkopt;

    int                         ret;
    struct sockaddr_storage     local_addr;
    socklen_t                   local_addrlen;

    int                         aux_s1 = -1;
    int                         aux_s2 = -1;
    int                         iut_s = -1;
    int                         tst_s = -1;
    int                         acc_s = -1;

    rpc_sockopt_value           optdef;
    rpc_sockopt_value           optnew;
    socklen_t                   optnew_len;
    rpc_sockopt_value           optsaved;

    te_bool                     is_failed = FALSE;
    tarpc_linger                linger_val;
    char                        send_buf[BUF_SIZE];
    rpc_tcp_state               tcp_state;

    uint8_t ip_opts[IP_TS_OPTS_LEN] =
        { IPOPT_TIMESTAMP, IP_TS_OPTS_LEN, 5, 0, };

    char iut_iface[IFNAMSIZ];

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCKOPT(checkopt);
    TEST_GET_BOOL_PARAM(listen_before);
    TEST_GET_BOOL_PARAM(accept_before);
    TEST_GET_STRING_PARAM(how);

    /*
     * Obtain iut interface name to pass to SO_BINDTODEVICE option,
     * according to tester address, which iut will connect to.
     */
    if ((tst_addr->sa_family == AF_INET &&
         SIN(tst_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) ||
        (tst_addr->sa_family == AF_INET6 &&
         IN6_IS_ADDR_LOOPBACK(&(SIN6(tst_addr)->sin6_addr))))
        strcpy(iut_iface, "lo");
    else
        strcpy(iut_iface, iut_if->if_name);

    if (strcmp_start("connect_another_listen", how) == 0)
    {
        GEN_CONNECTION(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                       tst_addr, iut_addr, &aux_s2, &aux_s1);
    }
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.ss_family = iut_addr->sa_family;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, CONST_SA(&local_addr));

    local_addrlen = sizeof(local_addr);
    rpc_getsockname(pco_iut, iut_s, SA(&local_addr), &local_addrlen);

    if (strcmp_start("connect_another_listen", how) != 0)
    {
        tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                           RPC_SOCK_STREAM, RPC_PROTO_DEF);

        rpc_bind(pco_tst, tst_s, tst_addr);
        if ((listen_before == TRUE) &&
            (strcmp_start("connect", how) != 0))
        {
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        }
    }

    memset(&optdef, 0, sizeof(optdef));
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_getsockopt(pco_iut, iut_s, sockts_fix_get_opt(checkopt),
                         &optdef);
    if (ret != 0)
    {
        TEST_VERDICT("getsockopt(%s, %s) failed with errno %s",
                     socklevel_rpc2str(rpc_sockopt2level(checkopt)),
                     sockopt_rpc2str(sockts_fix_get_opt(checkopt)),
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    SET_OPT_NEW(iut_s, checkopt, optdef, optnew, optnew_len,
                strcmp_start("listen_accept", how) == 0 ?
                "[listening socket] " : "");

    if (strcmp_start("listen_accept", how) == 0 && accept_before)
    {
        memcpy(&optsaved, &optnew, sizeof(optnew));
        te_sockaddr_set_netaddr(SA(&local_addr),
                                te_sockaddr_get_netaddr(iut_addr));
        rpc_connect(pco_tst, tst_s, CONST_SA(&local_addr));
        acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
        SET_OPT_NEW(acc_s, checkopt, optdef, optnew, optnew_len, "");
    }

    if (strcmp_start("connect_another_listen", how) != 0)
    {
        if (strcmp_start("connect", how) == 0)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, tst_addr);
            if (rc == -1)
                CHECK_RPC_ERRNO(pco_iut, RPC_ECONNREFUSED,
                                "RPC connect on iut_s failed with "
                                "unexpected errno.");
            else
                TEST_FAIL("connect() returns %d instead of -1", rc);
        }
        else if (listen_before == FALSE)
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            if (rc < 0)
                TEST_VERDICT("listen() unexpectedly failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    if (strcmp_start("connect_another_listen", how) == 0)
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        CHECK_INHERITED_OPT(iut_s, checkopt, optnew, optnew_len,
                            optdef, "");
        if (is_failed)
            TEST_STOP;
        TEST_SUCCESS;
    }

    if (strcmp_start("listen_accept", how) == 0)
    {
        if (!accept_before)
        {
            memcpy(&optsaved, &optnew, sizeof(optnew));

            te_sockaddr_set_netaddr(SA(&local_addr),
                                    te_sockaddr_get_netaddr(iut_addr));
            rpc_connect(pco_tst, tst_s, CONST_SA(&local_addr));

            acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);

            CHECK_INHERITED_OPT(acc_s, checkopt, optnew, optnew_len,
                                optdef, "");
        }

        if (strcmp(how, "listen_accept_shutdown") == 0)
        {
            rpc_shutdown(pco_iut, acc_s, RPC_SHUT_WR);
            CHECK_INHERITED_OPT(acc_s, checkopt, optnew, optnew_len,
                                optdef, "");
        }
        else if (strcmp(how, "listen_accept_close") == 0)
        {
            linger_val.l_onoff = 1;
            linger_val.l_linger = 0;
            rpc_setsockopt(pco_tst, tst_s, RPC_SO_LINGER, &linger_val);
            rpc_close(pco_tst, tst_s);
            tst_s = -1;
            TAPI_WAIT_NETWORK;

            tcp_state = tapi_get_tcp_sock_state(pco_iut, acc_s);
            if (tcp_state != RPC_TCP_CLOSE)
            {
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rpc_send(pco_iut, acc_s, send_buf, BUF_SIZE, 0);

                tcp_state = tapi_get_tcp_sock_state(pco_iut, acc_s);
                if (tcp_state != RPC_TCP_CLOSE)
                    TEST_FAIL("Failed to achieve TCP_CLOSE state");
            }
            CHECK_INHERITED_OPT(acc_s, checkopt, optnew, optnew_len,
                                optdef, "");
        }

        /* Restore value applicable to listening socket */
        memcpy(&optnew, &optsaved, sizeof(optnew));
    }
    else if (strcmp_start("listen_shutdown", how) == 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (strcmp(how, "listen_shutdown_wr") == 0)
        {
            ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
            if (ret != 0)
            {
                TEST_VERDICT("shutdown(SHUT_WR) of listening socket "
                             "failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
        else if (strcmp(how, "listen_shutdown_rdwr") == 0)
        {
            ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RDWR);
            if (ret != 0)
            {
                TEST_VERDICT("shutdown(SHUT_RDWR) of listening socket "
                             "failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
        else
        {
            ret = rpc_shutdown(pco_iut, iut_s, RPC_SHUT_RD);
            if (ret != 0)
            {
                TEST_VERDICT("shutdown(SHUT_RD) of listening socket "
                             "failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }

            if (strcmp(how, "listen_shutdown_listen") == 0)
            {
                rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            }
            else if (strcmp(how, "listen_shutdown_connect") == 0)
            {
                rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

                RPC_AWAIT_IUT_ERROR(pco_iut);
                ret = rpc_connect(pco_iut, iut_s, tst_addr);
                if (ret != 0)
                {
                    TEST_VERDICT("connect() after listen-shutdown(RD) "
                                 "unexpectedly failed with errno %s",
                                 errno_rpc2str(RPC_ERRNO(pco_iut)));
                }
            }
        }
    }
    else
    {
        if (strcmp(how, "connect_failed_listen") == 0)
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        else
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, tst_addr);
            if (rc < 0)
                TEST_VERDICT("connect() after failed connect() "
                             "unexpectedly failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    CHECK_INHERITED_OPT(iut_s, checkopt, optnew, optnew_len,
                        optdef,
                        strcmp_start("listen_accept", how) == 0 ?
                        "[listening socket] " : "");

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, aux_s1);
    CLEANUP_RPC_CLOSE(pco_tst, aux_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
