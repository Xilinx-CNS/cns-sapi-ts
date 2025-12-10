/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Implementation of helper functions for route tests.
 */

#include "ts_route.h"
#include "tapi_sockets.h"

/*
 * This timeout includes ARP resolution and 3-way TCP handshake. It must
 * be larger than TAPI_WAIT_NETWORK_DELAY.
 */
#define RT_NET_TIMEOUT (TAPI_WAIT_NETWORK_DELAY * 4)

/* See description in ts_route.h */
sockts_rt_error rt_error;

/* See description in ts_route.h */
int sockts_rt_opt_tos = -1;

/* See description in ts_route.h */
char sockts_rt_opt_iut_bind_dev[IFNAMSIZ] = "";

/**
 * Save error reported by TAPI call.
 *
 * @param err_code  Error code.
 * @param rpcs      RPC server handle.
 *
 * @return Error code from @ref sockts_rt_error_code.
 */
static int
set_rt_error(int err_code,
             rcf_rpc_server *rpcs)
{
    memset(&rt_error, 0, sizeof(rt_error));

    rt_error.err_code = err_code;

    rt_error.rpcs = rpcs;
    if (rpcs != NULL)
        rt_error.rpc_errno = RPC_ERRNO(rpcs);

    return err_code;
}

/**
 * Save error reported by sockts_test_send_ext() call.
 *
 * @param rc          Value returned by the call.
 * @param rpcs_send   RPC server used for sending.
 * @param rpcs_recv   RPC server used for receiving.
 *
 * @return Error code from @ref sockts_rt_error_code.
 */
static int
set_rt_send_recv_error(sockts_test_send_rc rc,
                       rcf_rpc_server *rpcs_send,
                       rcf_rpc_server *rpcs_recv)
{
    memset(&rt_error, 0, sizeof(rt_error));

    rt_error.err_code = SOCKTS_RT_ERR_SEND_RECV;
    rt_error.test_send_err = rc;

    if (rc == SOCKTS_TEST_SEND_FIRST_SEND_FAIL ||
        rc == SOCKTS_TEST_SEND_NON_FIRST_SEND_FAIL)
    {
        rt_error.rpcs = rpcs_send;
        rt_error.rpc_errno = RPC_ERRNO(rpcs_send);
    }
    else if (rc == SOCKTS_TEST_SEND_RECV_FAIL)
    {
        rt_error.rpcs = rpcs_recv;
        rt_error.rpc_errno = RPC_ERRNO(rpcs_recv);
    }

    return rt_error.err_code;
}

/* See description in ts_route.h */
te_bool
sockts_rt_error_check(sockts_rt_error *exp_error)
{
    if (rt_error.err_code != exp_error->err_code)
        return FALSE;

    if (rt_error.err_code == SOCKTS_RT_ERR_SEND_RECV)
    {
        if (rt_error.test_send_err != exp_error->test_send_err)
            return FALSE;

        /*
         * It makes sense to check errno only if sending/receiving
         * function itself failed. There are other types of failures in
         * which errno is not set, for example when packets were received
         * in a wrong order.
         */
        if (rt_error.test_send_err == SOCKTS_TEST_SEND_FIRST_SEND_FAIL ||
            rt_error.test_send_err ==
                              SOCKTS_TEST_SEND_NON_FIRST_SEND_FAIL ||
            rt_error.test_send_err ==
                              SOCKTS_TEST_SEND_RECV_FAIL)
        {
            if (rt_error.rpcs != exp_error->rpcs ||
                rt_error.rpc_errno != exp_error->rpc_errno)
                return FALSE;
        }
    }
    else if (rt_error.err_code != SOCKTS_RT_ERR_NOT_ACCEPTED)
    {
        /*
         * errno is not checked for SOCKTS_RT_ERR_NOT_ACCEPTED
         * because it is detected not as failure of accept(),
         * but as no events on listener reported by IOMUX function.
         */
        if (rt_error.rpcs != exp_error->rpcs ||
            rt_error.rpc_errno != exp_error->rpc_errno)
            return FALSE;
    }

    return TRUE;
}

/* See description in ts_route.h */
const char *
sockts_rt_error2str(sockts_rt_error *err)
{
    /*
     * TE_STRING_INIT_STATIC() cannot be used here, compiler will
     * complain that "initializer element is not constant".
     */
    static char       buf[2048] = "";
    static te_string  str = TE_STRING_BUF_INIT(buf);

    te_string_reset(&str);

    te_string_append(&str, "{ code=");
    switch (err->err_code)
    {
        case SOCKTS_RT_ERR_SEND_RECV:
            te_string_append(&str, "ERR_SEND_RECV");
            break;

        case SOCKTS_RT_ERR_RPC_CONNECT:
            te_string_append(&str, "ERR_RPC_CONNECT");
            break;

        case SOCKTS_RT_ERR_NOT_ACCEPTED:
            te_string_append(&str, "ERR_NOT_ACCEPTED");
            break;

        case SOCKTS_RT_ERR_RPC_SETSOCKOPT:
            te_string_append(&str, "ERR_RPC_SETSOCKOPT");
            break;

        case SOCKTS_RT_ERR_RPC_GETSOCKOPT:
            te_string_append(&str, "ERR_RPC_GETSOCKOPT");
            break;

        case SOCKTS_RT_ERR_WRONG_IUT_ADDR:
            te_string_append(&str, "ERR_WRONG_IUT_ADDR");
            break;
    }

    if (err->err_code == SOCKTS_RT_ERR_SEND_RECV)
    {
        te_string_append(&str, ", '%s'",
                         sockts_test_send_rc2str(err->test_send_err));
    }

    if (err->rpcs != NULL)
    {
        te_string_append(&str, ", rpcs=%s, errno=%s",
                         err->rpcs->name,
                         errno_rpc2str(err->rpc_errno));
    }

    te_string_append(&str, " }");

    return str.ptr;
}

/**
 * Prepare a socket (set socket options, etc) after
 * creating it.
 *
 * @param iut_socket    Whether socket is on IUT or on Tester.
 * @param rpcs          RPC server.
 * @param s             Socket.
 * @param rt_sock_type  Socket type.
 * @param is_listener   Whether it is listener socket.
 * @param msg           String to print in verdicts.
 */
static te_errno
prepare_socket(te_bool iut_socket,
               rcf_rpc_server *rpcs, int s,
               rpc_socket_domain domain,
               sockts_socket_type rt_sock_type,
               te_bool is_listener,
               const char *msg)
{
    int     option_value;
    int     rc;

    const char *msg_str = (msg == NULL ? "" : msg);
    const char *msg_delim = (msg == NULL ? "" : ": ");
    const char *sname = (iut_socket ? "IUT socket" : "Tester socket");
    const char *opt_name = NULL;

    UNUSED(rt_sock_type);
    UNUSED(is_listener);

    if (sockts_rt_opt_tos >= 0)
    {
        rpc_sockopt tos_opt;

        if (domain == RPC_PF_INET)
            tos_opt = RPC_IP_TOS;
        else
            tos_opt = RPC_IPV6_TCLASS;

        opt_name = sockopt_rpc2str(tos_opt);

        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_setsockopt_int(rpcs, s, tos_opt, sockts_rt_opt_tos);
        if (rc < 0)
        {
            ERROR_VERDICT("%s%sSetting %s failed with errno "
                          "%r on %s", msg_str, msg_delim, opt_name,
                          RPC_ERRNO(rpcs), sname);
            return set_rt_error(SOCKTS_RT_ERR_RPC_SETSOCKOPT,
                                rpcs);
        }

        option_value = 0;
        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_getsockopt(rpcs, s, tos_opt, &option_value);
        if (rc < 0)
        {
            ERROR_VERDICT("%s%sGetting %s value after setting it failed "
                          "with errno %r on %s", msg_str, msg_delim,
                          opt_name, RPC_ERRNO(rpcs), sname);
            return set_rt_error(SOCKTS_RT_ERR_RPC_GETSOCKOPT,
                                rpcs);
        }
        else if (option_value != sockts_rt_opt_tos)
        {
            ERROR_VERDICT("%s%sObtained value of %s option differs "
                          "from set value for %s",
                          msg_str, msg_delim, opt_name, sname);
            return set_rt_error(SOCKTS_RT_ERR_RPC_GETSOCKOPT,
                                rpcs);
        }
    }

    if (strlen(sockts_rt_opt_iut_bind_dev) > 0 && iut_socket)
    {
        RPC_AWAIT_ERROR(rpcs);
        rc = rpc_setsockopt_raw(rpcs, s, RPC_SO_BINDTODEVICE,
                                sockts_rt_opt_iut_bind_dev,
                                strlen(sockts_rt_opt_iut_bind_dev) + 1);
        if (rc < 0)
        {
            ERROR_VERDICT("%s%sSetting SO_BINDTODEVICE failed with errno "
                          "%r on %s", msg_str, msg_delim, RPC_ERRNO(rpcs),
                          sname);
            return set_rt_error(SOCKTS_RT_ERR_RPC_SETSOCKOPT,
                                rpcs);
        }
    }

    return 0;
}

/* See description in ts_route.h */
void
print_networks(void)
{
    cfg_handle     *net_handles = NULL;
    unsigned int    n_nets = 0;
    unsigned int    i;
    char           *net_oid = NULL;

    CHECK_RC(cfg_find_pattern("/net:*", &n_nets, &net_handles));

    for (i = 0; i < n_nets; i++)
    {
        cfg_get_oid_str(net_handles[i], &net_oid);
        cfg_tree_print(NULL, TE_LL_RING, net_oid);
        free(net_oid);
    }

    free(net_handles);
}

/* See description in lib/ts_route.h */
sockts_test_send_rc
sockts_rt_test_send(sockts_socket_type rt_sock_type,
                    rcf_rpc_server *rpcs_send, int s_send,
                    rcf_rpc_server *rpcs_recv, int s_recv,
                    const struct sockaddr *dst_addr,
                    const struct sockaddr *src_addr,
                    te_bool print_verdicts,
                    const char *msg)
{
    sockts_test_send_ext_args args = SOCKTS_TEST_SEND_EXT_ARGS_INIT;

    args.rpcs_send = rpcs_send;
    args.s_send = s_send;
    args.rpcs_recv = rpcs_recv;
    args.s_recv = s_recv;
    if (rt_sock_type == SOCKTS_SOCK_UDP_NOTCONN)
        args.dst_addr = dst_addr;
    if (sock_type_sockts2rpc(rt_sock_type) == RPC_SOCK_DGRAM)
    {
        args.check_dgram = TRUE;
        args.src_addr = src_addr;
    }
    args.send_wait = TAPI_WAIT_NETWORK_DELAY;
    args.recv_timeout = RT_NET_TIMEOUT;
    args.pkts_num = SOCKTS_RT_DEF_PKT_NUM;
    args.print_verdicts = print_verdicts;
    args.vpref = msg;

    return sockts_test_send_ext(&args);
}

/* See description in ts_route.h */
int
sockts_rt_connection(sockts_socket_type rt_sock_type,
                     rcf_rpc_server *pco_iut,
                     te_bool bind_iut,
                     const struct sockaddr *iut_bind_addr,
                     const struct sockaddr *iut_conn_addr,
                     rcf_rpc_server *pco_tst,
                     const struct sockaddr *tst_bind_addr,
                     int *iut_s_out, int *tst_s_out,
                     const char *msg)
{
    rpc_socket_type     sock_type;
    rpc_socket_domain   domain;
    te_bool             readable = FALSE;

    rcf_rpc_server   *rpcs_srv = NULL;
    rcf_rpc_server   *rpcs_clnt = NULL;

    int iut_s = -1;
    int tst_s = -1;
    int s_listener = -1;
    int s_srv = -1;
    int s_clnt = -1;

    int rc = 0;
    int result = 0;

    sock_type = sock_type_sockts2rpc(rt_sock_type);
    domain = rpc_socket_domain_by_addr(tst_bind_addr);

    if (sock_type == RPC_SOCK_DGRAM)
    {
        iut_s = rpc_socket(pco_iut, domain,
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        result = prepare_socket(TRUE, pco_iut, iut_s,
                                domain, rt_sock_type, FALSE, msg);
        if (result != 0)
            goto cleanup;

        if (bind_iut)
            rpc_bind(pco_iut, iut_s, iut_bind_addr);

        if (rt_sock_type == SOCKTS_SOCK_UDP)
        {
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, tst_bind_addr);

            if (rc < 0)
            {
                if (msg != NULL)
                {
                    ERROR_VERDICT("%s: connect() failed with errno %r",
                                  msg, RPC_ERRNO(pco_iut));
                }

                result = set_rt_error(SOCKTS_RT_ERR_RPC_CONNECT,
                                      pco_iut);
                goto cleanup;
            }
        }

        tst_s = rpc_socket(pco_tst, domain,
                           RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        result = prepare_socket(FALSE, pco_tst, tst_s,
                                domain, rt_sock_type, FALSE, msg);
        if (result != 0)
            goto cleanup;

        rpc_bind(pco_tst, tst_s, tst_bind_addr);
    }
    else
    {
        const struct sockaddr  *srv_conn_addr = NULL;
        const struct sockaddr  *srv_bind_addr = NULL;
        const struct sockaddr  *clnt_bind_addr = NULL;
        int                     fdflags;

        if (rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            rpcs_srv = pco_tst;
            rpcs_clnt = pco_iut;
            srv_bind_addr = tst_bind_addr;
            srv_conn_addr = tst_bind_addr;
            clnt_bind_addr = iut_bind_addr;
        }
        else
        {
            rpcs_srv = pco_iut;
            rpcs_clnt = pco_tst;
            srv_bind_addr = iut_bind_addr;
            srv_conn_addr = iut_conn_addr;
            clnt_bind_addr = tst_bind_addr;
        }

        s_listener = rpc_socket(rpcs_srv, domain,
                                RPC_SOCK_STREAM,
                                RPC_PROTO_DEF);
        result = prepare_socket((rpcs_srv == pco_iut),
                                 rpcs_srv, s_listener,
                                 domain, rt_sock_type, TRUE, msg);
        if (result != 0)
            goto cleanup;

        rpc_bind(rpcs_srv, s_listener, srv_bind_addr);
        rpc_listen(rpcs_srv, s_listener, SOCKTS_BACKLOG_DEF);

        s_clnt = rpc_socket(rpcs_clnt, domain,
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        result = prepare_socket((rpcs_clnt == pco_iut),
                                rpcs_clnt, s_clnt,
                                domain, rt_sock_type, FALSE, msg);
        if (result != 0)
            goto cleanup;

        if (rt_sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL || bind_iut)
            rpc_bind(rpcs_clnt, s_clnt, clnt_bind_addr);

        fdflags = rpc_fcntl(rpcs_clnt, s_clnt,
                            RPC_F_GETFL, 0);
        rpc_fcntl(rpcs_clnt, s_clnt, RPC_F_SETFL,
                  fdflags | RPC_O_NONBLOCK);

        RPC_AWAIT_ERROR(rpcs_clnt);
        rc = rpc_connect(rpcs_clnt, s_clnt, srv_conn_addr);
        if (rc < 0 && RPC_ERRNO(rpcs_clnt) != RPC_EINPROGRESS)
        {
            if (msg != NULL)
            {
                ERROR_VERDICT("%s: connect() failed with errno %r",
                              msg, RPC_ERRNO(rpcs_clnt));
            }

            if (rpcs_clnt == pco_tst)
            {
                TEST_STOP;
            }
            else
            {
                result = set_rt_error(SOCKTS_RT_ERR_RPC_CONNECT,
                                      rpcs_clnt);
                goto cleanup;
            }
        }

        RPC_GET_READABILITY(readable, rpcs_srv, s_listener,
                            RT_NET_TIMEOUT);
        if (!readable)
        {
            if (msg != NULL)
            {
                ERROR_VERDICT("%s: listener did not "
                              "accept connection", msg);
            }

            result = set_rt_error(SOCKTS_RT_ERR_NOT_ACCEPTED,
                                  rpcs_srv);
            goto cleanup;
        }

        rpc_fcntl(rpcs_clnt, s_clnt, RPC_F_SETFL, fdflags);
        s_srv = rpc_accept(rpcs_srv, s_listener, NULL, NULL);
        rpc_close(rpcs_srv, s_listener);
        s_listener = -1;

        result = prepare_socket((rpcs_srv == pco_iut),
                                rpcs_srv, s_srv,
                                domain, rt_sock_type,
                                FALSE, msg);
        if (result != 0)
            goto cleanup;

        if (rt_sock_type == SOCKTS_SOCK_TCP_ACTIVE)
        {
            iut_s = s_clnt;
            tst_s = s_srv;
        }
        else
        {
            iut_s = s_srv;
            tst_s = s_clnt;
        }
        s_clnt = -1;
        s_srv = -1;
    }

    *iut_s_out = iut_s;
    iut_s = -1;
    *tst_s_out = tst_s;
    tst_s = -1;

cleanup:

    if (tst_s >= 0)
        rpc_close(pco_tst, tst_s);
    if (iut_s >= 0)
        rpc_close(pco_iut, iut_s);
    if (s_listener >= 0)
        rpc_close(rpcs_srv, s_listener);
    if (s_srv >= 0)
        rpc_close(rpcs_srv, s_srv);
    if (s_clnt >= 0)
        rpc_close(rpcs_clnt, s_clnt);

    if (sock_type == RPC_SOCK_STREAM &&
        s_clnt >= 0)
    {
        /* Let all connections to terminate normally */
        TAPI_WAIT_NETWORK;
    }

    return result;
}

/* See description in ts_route.h */
int
sockts_rt_check_route(sockts_socket_type rt_sock_type,
                      rcf_rpc_server *pco_iut,
                      const struct sockaddr *iut_addr,
                      rcf_rpc_server *pco_tst,
                      const struct sockaddr *tst_addr,
                      sockts_addr_type iut_bind_to,
                      te_bool check_iut_addr,
                      const char *msg)
{
    rpc_socket_type     sock_type;
    rpc_socket_domain   domain;

    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage iut_conn_addr;
    struct sockaddr_storage tst_bind_addr;
    te_bool                 bind_iut = TRUE;

    sockts_test_send_rc     test_send_rc;

    int iut_s = -1;
    int tst_s = -1;
    int result = 0;

    sock_type = sock_type_sockts2rpc(rt_sock_type);
    domain = rpc_socket_domain_by_addr(iut_addr);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr,
                                 &iut_bind_addr));
    tapi_sockaddr_clone_exact(SA(&iut_bind_addr),
                              &iut_conn_addr);
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                 &tst_bind_addr));

    if (iut_bind_to == SOCKTS_ADDR_WILD)
        te_sockaddr_set_wildcard(SA(&iut_bind_addr));

    if (iut_bind_to == SOCKTS_ADDR_MCAST)
    {
        if (domain == RPC_PF_INET)
        {
            SIN(&iut_bind_addr)->sin_addr.s_addr =
                    htonl(rand_range(0xe0000100, 0xefffffff));
        }
        else
        {
            unsigned int i;

            SIN6(&iut_bind_addr)->sin6_addr.s6_addr[0] = 0xff;
            SIN6(&iut_bind_addr)->sin6_addr.s6_addr[1] = 0x1e;
            for (i = 2; i < sizeof(SIN6(&iut_bind_addr)->sin6_addr.s6_addr);
                 i++)
            {
                SIN6(&iut_bind_addr)->sin6_addr.s6_addr[i] =
                                                rand_range(1, 255);
            }
        }
    }

    if (iut_bind_to == SOCKTS_ADDR_NONE)
        bind_iut = FALSE;

    result = sockts_rt_connection(rt_sock_type, pco_iut, bind_iut,
                                  SA(&iut_bind_addr), SA(&iut_conn_addr),
                                  pco_tst, SA(&tst_bind_addr),
                                  &iut_s, &tst_s, msg);
    if (result != 0)
        goto cleanup;

    if (check_iut_addr && sock_type == RPC_SOCK_STREAM)
    {
        struct sockaddr_storage real_iut_addr;
        socklen_t               addr_len;

        addr_len = sizeof(real_iut_addr);
        rpc_getpeername(pco_tst, tst_s, SA(&real_iut_addr), &addr_len);

        if (te_sockaddrcmp(SA(&real_iut_addr), addr_len,
                           SA(&iut_conn_addr),
                           te_sockaddr_get_size(
                                      SA(&iut_conn_addr))) != 0)
        {
            if (msg != NULL)
            {
                ERROR_VERDICT("%s: getpeername() on Tester returned "
                              "unexpected address", msg);
            }

            result = set_rt_error(SOCKTS_RT_ERR_WRONG_IUT_ADDR,
                                  NULL);
            goto cleanup;
        }
    }

    test_send_rc = sockts_rt_test_send(rt_sock_type, pco_iut, iut_s,
                                       pco_tst, tst_s,
                                       SA(&tst_bind_addr),
                                       (check_iut_addr ?
                                          SA(&iut_conn_addr) : NULL),
                                       msg != NULL, msg);

    if (test_send_rc != 0)
        result = set_rt_send_recv_error(test_send_rc, pco_iut, pco_tst);

cleanup:
    if (tst_s >= 0)
        rpc_close(pco_tst, tst_s);
    if (iut_s >= 0)
        rpc_close(pco_iut, iut_s);

    if (sock_type == RPC_SOCK_STREAM)
    {
        /* Let all connections to terminate normally */
        TAPI_WAIT_NETWORK;
    }

    return result;
}

/* See description in ts_route.h */
void
sockts_rt_two_ifs_check_route(te_bool first_if,
                              const struct sockaddr *iut_addr,
                              const struct sockaddr *tst_addr,
                              int tos,
                              sockts_addr_type iut_bind_to,
                              te_bool check_iut_addr,
                              const char *msg,
                              const struct tapi_env *env,
                              rcf_rpc_server *pco_iut,
                              rcf_rpc_server *pco_tst1,
                              rcf_rpc_server *pco_tst2,
                              sockts_socket_type rt_sock_type,
                              sockts_if_monitor *iut_if1_monitor,
                              sockts_if_monitor *iut_if2_monitor,
                              sockts_if_monitor *tst1_if_monitor,
                              sockts_if_monitor *tst2_if_monitor)
{
    rcf_rpc_server          *rpcs_tst = NULL;
    const char              *if_pos;
    const char              *err_msg = msg;

    if (err_msg == NULL)
    {
        if (first_if)
            err_msg = "Checking the first channel";
        else
            err_msg = "Checking the second channel";
    }

    if_pos = (first_if ? "first" : "second");

    SOCKTS_RT_RING("Checking that traffic goes via "
                   "the %s IUT interface",
                   if_pos);

    if (first_if)
        rpcs_tst = pco_tst1;
    else
        rpcs_tst = pco_tst2;

    SOCKTS_RT_RING("Creating a pair of sockets and "
                   "sending data from IUT to Tester");

    if (tos >= 0)
        sockts_rt_opt_tos = tos;
    SOCKTS_RT_CHECK_RC(sockts_rt_check_route(
                                   rt_sock_type,
                                   pco_iut, iut_addr,
                                   rpcs_tst, tst_addr,
                                   iut_bind_to,
                                   check_iut_addr,
                                   err_msg));
    if (tos >= 0)
        sockts_rt_opt_tos = -1;
    TAPI_WAIT_NETWORK;

    SOCKTS_RT_RING("Checking that CSAP captured packets "
                   "only on the %s Tester interface", if_pos);
    CHECK_TWO_IFS_IN(tst1_if_monitor, tst2_if_monitor,
                     first_if, !first_if, err_msg);

    SOCKTS_RT_RING("Checking that outgoing packets are "
                   "captured by CSAP on %s IUT interface "
                   "only if traffic is not accelerated",
                   if_pos);
    if (first_if)
    {
        CHECK_IF_ACCELERATED(env, iut_if1_monitor,
                             err_msg);
    }
    else
    {
        CHECK_IF_ACCELERATED(env, iut_if2_monitor,
                             err_msg);
    }
}

/* See description in ts_route.h */
void
sockts_rt_one_sock_check_route(te_bool first_if,
                               const struct sockaddr *iut_addr,
                               const struct sockaddr *tst_addr,
                               const char *msg,
                               const struct tapi_env *env,
                               rcf_rpc_server *pco_iut,
                               rcf_rpc_server *pco_tst,
                               int *iut_s, int *tst_s,
                               sockts_socket_type rt_sock_type,
                               sockts_if_monitor *iut_if1_monitor,
                               sockts_if_monitor *iut_if2_monitor,
                               sockts_if_monitor *tst1_if_monitor,
                               sockts_if_monitor *tst2_if_monitor,
                               te_bool handover)
{
    const char     *if_pos;
    const char     *err_msg = msg;
    te_string       err_str = TE_STRING_INIT_STATIC(1000);

    sockts_test_send_rc     test_send_rc;

    if (err_msg == NULL)
    {
        if (first_if)
            err_msg = "Checking the first channel";
        else
            err_msg = "Checking the second channel";
    }

    if_pos = (first_if ? "first" : "second");

    SOCKTS_RT_RING("Checking that traffic goes via "
                   "the %s IUT interface",
                   if_pos);

    if (*iut_s == -1)
    {
        SOCKTS_RT_RING("Create IUT and tester sockets pair, bind them and "
                       "connect if required");
        if (sockts_rt_connection(rt_sock_type, pco_iut, TRUE, iut_addr,
                                 iut_addr, pco_tst, tst_addr,
                                 iut_s, tst_s, err_msg) != 0)
        {
            TEST_FAIL("Failed to create a pair of sockets or establish "
                      "connection");
        }
    }

    SOCKTS_RT_RING("Send data in both directions between IUT and Tester");

    te_string_append(&err_str, "%s, sending from IUT", err_msg);

    test_send_rc = sockts_rt_test_send(rt_sock_type, pco_iut, *iut_s,
                                       pco_tst, *tst_s,
                                       tst_addr, NULL,
                                       TRUE, err_str.ptr);
    if (test_send_rc != SOCKTS_TEST_SEND_SUCCESS)
        TEST_STOP;

    te_string_reset(&err_str);
    te_string_append(&err_str, "%s, sending from Tester", err_msg);

    test_send_rc = sockts_rt_test_send(
                            (rt_sock_type == SOCKTS_SOCK_UDP ?
                                  SOCKTS_SOCK_UDP_NOTCONN : rt_sock_type),
                            pco_tst, *tst_s,
                            pco_iut, *iut_s,
                            iut_addr, NULL,
                            TRUE, err_str.ptr);
    if (test_send_rc != SOCKTS_TEST_SEND_SUCCESS)
        TEST_STOP;

    SOCKTS_RT_RING("Checking that CSAP captured packets "
                   "only on the %s Tester interface", if_pos);
    CHECK_TWO_IFS_IN(tst1_if_monitor, tst2_if_monitor,
                     first_if, !first_if, err_msg);

    SOCKTS_RT_RING("Checking that outgoing packets are "
                   "captured by CSAP on %s IUT interface "
                   "only if traffic is not accelerated",
                   if_pos);

    if (!handover)
    {
        if (first_if)
            CHECK_IF_ACCELERATED(env, iut_if1_monitor, err_msg);
        else
            CHECK_IF_ACCELERATED(env, iut_if2_monitor, err_msg);
    }
}

/* See description in ts_route.h */
te_errno
sockts_rt_add_tos_rule(rcf_rpc_server *rpcs,
                       te_conf_ip_rule *rule,
                       int af,
                       int table, int tos)
{
    te_conf_ip_rule_init(rule);
    rule->family = af;
    rule->table = table;
    rule->tos = tos;
    rule->mask |= TE_IP_RULE_FLAG_TOS | TE_IP_RULE_FLAG_TABLE;
    return tapi_cfg_add_rule(rpcs->ta, af, rule);
}

/* See description in ts_route.h */
void
sockts_rt_fill_rule(te_conf_ip_rule *rule,
                    int af,
                    sockts_rt_rule_criterion criterion,
                    int table,
                    const struct sockaddr *src,
                    int src_prefix,
                    const struct sockaddr *dst,
                    int dst_prefix,
                    int tos,
                    int priority)
{
    rule->mask |= TE_IP_RULE_FLAG_FAMILY;
    rule->family = af;

    if (table >= 0)
    {
        rule->mask |= TE_IP_RULE_FLAG_TABLE;
        rule->table = table;
    }

    if (priority >= 0)
    {
        rule->mask |= TE_IP_RULE_FLAG_PRIORITY;
        rule->priority = priority;
    }

    switch (criterion)
    {
        case SOCKTS_RT_RULE_FROM:
            rule->mask |= TE_IP_RULE_FLAG_SRC;
            tapi_sockaddr_clone_exact(src, &rule->src);
            if (src_prefix >= 0)
            {
                rule->mask |= TE_IP_RULE_FLAG_SRCLEN;
                rule->srclen = src_prefix;
            }
            break;

        case SOCKTS_RT_RULE_TO:
            rule->mask |= TE_IP_RULE_FLAG_DST;
            tapi_sockaddr_clone_exact(dst, &rule->dst);
            if (dst_prefix >= 0)
            {
                rule->mask |= TE_IP_RULE_FLAG_DSTLEN;
                rule->dstlen = dst_prefix;
            }
            break;

        case SOCKTS_RT_RULE_TOS:
            rule->mask |= TE_IP_RULE_FLAG_TOS;
            rule->tos = tos;
            break;

        default:
            TEST_FAIL("Unknown IP rule criterion");
    }
}

/* See description in ts_route.h */
void
sockts_rt_fill_add_rule(rcf_rpc_server *rpcs,
                        int af,
                        sockts_rt_rule_criterion criterion,
                        int table,
                        const struct sockaddr *src_addr,
                        int src_prefix,
                        const struct sockaddr *dst_addr,
                        int dst_prefix,
                        int tos,
                        int priority,
                        te_conf_ip_rule *rule,
                        te_bool *rule_added)
{
    te_conf_ip_rule_init(rule);
    sockts_rt_fill_rule(rule, af, criterion,
                        table,
                        src_addr, src_prefix,
                        dst_addr, dst_prefix,
                        tos, priority);
    CHECK_RC(tapi_cfg_add_rule(rpcs->ta, af, rule));

    if (rule_added != NULL)
        *rule_added = TRUE;
}

/* See description in ts_route.h */
te_errno
sockts_rt_enable_ndp_proxy(const char *ta, const char *if_name)
{
    te_errno rc;
    int      current_value;

    rc = tapi_cfg_sys_get_int(ta, &current_value,
                              "net/ipv6/conf:%s/forwarding", if_name);
    if (rc == 0 && current_value == 0)
    {
        rc = tapi_cfg_sys_set_int(ta, 1, NULL,
                                  "net/ipv6/conf:%s/forwarding", if_name);
    }

    if (rc == 0)
    {
        rc = tapi_cfg_sys_get_int(ta, &current_value,
                                  "net/ipv6/conf:%s/proxy_ndp", if_name);
    }
    if (rc == 0 && current_value == 0)
    {
        rc = tapi_cfg_sys_set_int(ta, 1, NULL,
                                  "net/ipv6/conf:%s/proxy_ndp", if_name);
    }

    return rc;
}

/* See description in ts_route.h */
te_errno
sockts_rt_fix_macvlan_conf(const char *ta,
                           const char *if_name)
{
    te_errno rc = 0;

    /*
     * We set two properties: arg_ignore=1 and rp_filter=2.
     * The first one prevents parent interface from responding
     * with its MAC to ARP requests for IP address assigned to
     * MAC VLAN interface. Why the second property is required,
     * is not known, however without it packets sent to MAC
     * address assigned to MAC VLAN interface seem to be ignored.
     * Without changes made by this function, IP address assigned
     * to MAC VLAN interface works like it is assigned to parent
     * interface, so it is not clear whether MAC VLAN is working
     * at all.
     */

    rc = tapi_cfg_sys_set_int(ta, 2, NULL,
                              "net/ipv4/conf:%s/rp_filter", if_name);
    if (rc != 0)
        return rc;

    return tapi_cfg_sys_set_int(ta, 1, NULL,
                                "net/ipv4/conf:%s/arp_ignore", if_name);
}
