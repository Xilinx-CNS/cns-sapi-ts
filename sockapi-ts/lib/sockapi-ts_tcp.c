/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Implementation of API for TCP tests.
 *
 * $Id$
 */

#include "sockapi-ts.h"
#include "onload.h"
#include "tapi_mem.h"
#include "asn_usr.h"
#include "sockapi-ts_tcp.h"

/**
 * Delay in milliseconds between read calls which should be enough to
 * process TCP activity after a read call.
 */
#define READ_DELAY 100

/**
 * Check if listen queue does not have sockets in SYN_RECV states bound to
 * @p addr.
 *
 * @param rpcs  RPC server handler
 * @param addr  Interface address
 *
 * @return @c TRUE the listen queue is empty
 */
static te_bool
netstat_listenq_is_empty(rcf_rpc_server *rpcs, const struct sockaddr *addr)
{
    rpc_wait_status st;

    RPC_AWAIT_IUT_ERROR(rpcs);
    st = rpc_system_ex(rpcs, "netstat -tan | grep SYN_RECV | grep %s",
                       sockaddr_h2str(addr));
    if (st.value != 0)
        return TRUE;

    return FALSE;
}

/**
 * Check if listen queue does not have sockets in SYN_RECV states bound to
 * @p addr using @b onload_stackdump or @b zf_stackdump utility.
 *
 * @param rpcs      RPC server handler
 * @param addr      Interface address
 * @param use_zf    Whether to use @b onload_stackdump or
 *                  @b zf_stackdump utility
 *
 * @return @c TRUE the listen queue is empty
 */
static te_bool
onload_listenq_is_empty(rcf_rpc_server *rpcs,
                        const struct sockaddr *addr,
                        te_bool use_zf)
{
    static const char *zf_path = NULL;
    rpc_wait_status st;
    int rc, n_listenq;

    if (use_zf)
        zf_path = sockts_zf_stackdump_path(rpcs);

    RPC_AWAIT_IUT_ERROR(rpcs);
    if (use_zf)
    {
        st = rpc_system_ex(rpcs, "%s dump | grep 'lcl=%s.*SYN-RCVD' "
                           "2>&1 1>/dev/null", zf_path,
                           sockaddr_h2str(addr));
    }
    else
    {
        rc = rpc_get_n_listenq_from_orm_json(rpcs, addr, &n_listenq);
    }
    if ((zf_path && st.value != 0) || (!zf_path && rc == 0 && n_listenq == 0))
        return TRUE;

    return FALSE;
}

/* See description in sockapi-ts_tcp.h */
void
sockts_wait_cleaned_listenq(rcf_rpc_server *rpcs,
                            const struct sockaddr *addr)
{
#define TCP_MAX_ATTEMPTS 125
#define MSEC_BEFORE_NEXT_ATTEMPT 1000

    te_bool onload = tapi_onload_lib_exists(rpcs->ta);
    te_bool zf_shim = sockts_zf_shim_run();
    int i;

    for (i = 0; i < TCP_MAX_ATTEMPTS; i++)
    {
        if (zf_shim)
        {
            if (onload_listenq_is_empty(rpcs, addr, TRUE))
                return;
        }
        else if (onload)
        {
            if (onload_listenq_is_empty(rpcs, addr, FALSE))
                return;
        }
        else if (netstat_listenq_is_empty(rpcs, addr))
        {
            return;
        }

        MSLEEP(MSEC_BEFORE_NEXT_ATTEMPT);
    }

    TEST_VERDICT("listenq was not cleaned");
}

/**
 * Convert address specified in @p addr to a string to use with grep. It
 * prints IP address and port. In case of IPv6 the address is surrounded
 * with brackets unless @p no_brackets is set to @c TRUE.
 * Double backslashes stand before brackets to escape them.
 *
 * @param       addr        The address to be converted into string.
 * @param       no_brackets Do not surround IPv6 address with brackets.
 * @param       buf         Output buffer for the string.
 * @param       len         Length of the buffer.
 *
 * @return      Status code
 */
static te_errno
sockts_sockaddr2grepstr(const struct sockaddr *addr, te_bool no_brackets,
                        char *buf, size_t len)
{
    te_errno    rc = 0;
    char        addr_str[INET6_ADDRSTRLEN];

    rc = te_sockaddr_h2str_buf(addr, addr_str, sizeof(addr_str));
    if (rc == 0)
    {
        snprintf(buf, len,
                 addr->sa_family == AF_INET6 && !no_brackets ?
                 "\\\\[%s\\\\]:%u" : "%s:%u",
                 addr_str, ntohs(te_sockaddr_get_port(addr)));
    }

    return rc;
}

/* See description in sockapi-ts_tcp.h */
te_bool
sockts_socket_is_closed(rcf_rpc_server *rpcs, const struct sockaddr *src_addr,
                        const struct sockaddr *dst_addr, te_bool onload,
                        te_bool orphaned)
{
    const char *cmd = onload ? "te_onload_stdump netstat" : "netstat -tan";
    rpc_wait_status st;

    /*
     * Do not use brackets around IPv6 addresses when grepping in Linux
     * because "netstat" does not print them unlike "te_onload_stdump netstat".
     */
    te_bool         no_brackets = !onload;

    char src_buf[TE_SOCKADDR_STR_LEN];
    char dst_buf[TE_SOCKADDR_STR_LEN];

    if (onload && orphaned)
        cmd = "te_onload_stdump -z dump";

    CHECK_RC(sockts_sockaddr2grepstr(src_addr, no_brackets, src_buf,
                                     sizeof(src_buf)));
    CHECK_RC(sockts_sockaddr2grepstr(dst_addr, no_brackets, dst_buf,
                                     sizeof(dst_buf)));

    RPC_AWAIT_IUT_ERROR(rpcs);
    st = rpc_system_ex(rpcs, "%s | grep %s.*%s 2>&1 1>/dev/null", cmd,
                       src_buf, dst_buf);
    if (st.value != 0)
        return TRUE;

    return FALSE;
}

/* See description in sockapi-ts_tcp.h */
void
sockts_pair_close_check(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                        int iut_s, int tst_s)
{
    char buf[1];

    rpc_close(pco_tst, tst_s);
    TAPI_WAIT_NETWORK;
    if (rpc_read(pco_iut, iut_s, buf, 1) != 0)
        TEST_FAIL("read() call returned non-zero value after"
                  "peer socket closing");

    rpc_close(pco_iut, iut_s);
}
/* See description in sockapi-ts_tcp.h */
void
sockts_wait_socket_closing_spec(rcf_rpc_server *rpcs,
                                const struct sockaddr *src_addr,
                                const struct sockaddr *dst_addr,
                                int timeout,
                                te_bool onload, te_bool orphaned)
{
    int i;

    for (i = 0;; i++)
    {
        if (sockts_socket_is_closed(rpcs, src_addr, dst_addr, onload,
                                    orphaned))
            return;

        if (i >= timeout)
            break;
        SLEEP(1);
    }

    TEST_VERDICT("Socket was not closed");
}

/* See description in sockapi-ts_tcp.h */
void
sockts_wait_socket_closing(rcf_rpc_server *rpcs,
                           const struct sockaddr *src_addr,
                           const struct sockaddr *dst_addr,
                           int timeout)
{

    int             i;
    rpc_tcp_state   tcp_state;
    te_bool         found = FALSE;

    for (i = 0;; i++)
    {
        CHECK_RC(rpc_get_tcp_socket_state(rpcs, src_addr, dst_addr,
                                          &tcp_state, &found));

        if (!found)
            return;
        else if (i >= timeout)
            break;

        SLEEP(1);
    }

    TEST_VERDICT("Socket was not closed");
}

/* See description in sockapi-ts_tcp.h */
int
sockts_tcp_read_part_of_send_buf(rcf_rpc_server *rpcs, int sock,
                                 uint64_t sent)
{
    size_t sndbuf;
    size_t buf_len;
    size_t rlen;
    rpc_ptr rpcbuf;
    int rcvbuf;
    int rcvbuf_p;
    int rc;

    rpc_ioctl(rpcs, sock, RPC_FIONREAD, &rcvbuf);
    sndbuf = sent - rcvbuf;

    /* Read by 10% of send buffer size a time. */
    buf_len = sndbuf / 10;
    rpcbuf = rpc_malloc(rpcs, buf_len);

    rlen = sndbuf;
    do {
        rc = rpc_readbuf(rpcs, sock, rpcbuf, rlen > buf_len ?
                                             buf_len : rlen);
        if (rc == 0)
        {
            rpc_free(rpcs, rpcbuf);
            TEST_VERDICT("Tester unexpectedly got EOF");
        }
        rlen -= rc;

        MSLEEP(READ_DELAY);
        rcvbuf_p = rcvbuf;
        rpc_ioctl(rpcs, sock, RPC_FIONREAD, &rcvbuf);

        /* Leave the loop as soon as we see more data from the peer in
         * the rcvbuf. */
        if (rcvbuf != rcvbuf_p - rc)
            break;
    } while (rlen > 0);

    rpc_free(rpcs, rpcbuf);
    rlen = sndbuf - rlen;

    RING("sent %llu, rcvbuf %d, sndbuf current %llu initial %"
         TE_PRINTF_SIZE_T"d, rlen %"TE_PRINTF_SIZE_T"d",
         sent, rcvbuf, sent - rcvbuf - rlen, sndbuf, rlen);

    if ((size_t)rcvbuf >= sent - rlen)
        TEST_VERDICT("No data left in send buffer");

    return rlen;
}

/**
 * Minimum number of connections established by
 * sockts_tcp_measure_listen_backlog().
 */
#define SOCKTS_TCP_MIN_BACKLOG 10

/* See description in sockapi-ts_tcp.h */
int
sockts_tcp_measure_listen_backlog(rcf_rpc_server *rpcs1,
                                  const struct sockaddr *addr1,
                                  int listener,
                                  rcf_rpc_server *rpcs2,
                                  const struct sockaddr *addr2,
                                  unsigned int exp_backlog,
                                  const char *log_msg)
{
    int    *peer_socks = NULL;
    int     s;
    int     i;
    int     conns = 0;
    int     conn_attempts;
    int     backlog = 0;
    int     rc;
    te_bool readable = FALSE;
    te_bool recv_data = TRUE;
    te_bool silent_def1 = rpcs1->silent_pass_default;
    te_bool silent_def2 = rpcs2->silent_pass_default;

    tarpc_linger             optval;
    struct sockaddr_storage *peer_addrs = NULL;
    struct sockaddr_storage  peer_addr;
    socklen_t                peer_addr_len;
    char                     buf[sizeof(peer_addr) * 2];

    /*
     * On Linux there are two queues - one for fully established
     * connections which can be returned by accept() (its size is limited
     * by listen backlog) and another one for those which are being
     * established (which is not limited by listen backlog and may be
     * much larger). Connection is moved from the second queue to the first
     * one once ACK arrives from peer to our SYN-ACK. However if the first
     * queue is full, this ACK is simply ignored, and on IUT a socket
     * remains in SYN_RECEIVED state, so it tries to retransmit SYN-ACK
     * until timeout reached. But from the peer it looks like connection
     * is already established (it does not require any response to ACK
     * it sent after getting SYN-ACK). So it is possible to get more
     * successful connect() calls on the peer than number of sockets
     * accept() can immediately return on IUT.
     * */

    conn_attempts = MAX(exp_backlog * 3 / 2, SOCKTS_TCP_MIN_BACKLOG);
    peer_socks = tapi_calloc(conn_attempts, sizeof(int));
    peer_addrs = tapi_calloc(conn_attempts, sizeof(*peer_addrs));

    /*
     * Initiate one and a half times more connections than expected
     * listen backlog.
     */

    for (i = 0; i < conn_attempts; i++)
    {
        if (i == 0 || i + 1 == conn_attempts)
            rpcs2->silent_pass = rpcs2->silent_pass_default = FALSE;
        else
            rpcs2->silent_pass = rpcs2->silent_pass_default = silent_def2;

        peer_socks[i] = rpc_socket(rpcs2,
                                   rpc_socket_domain_by_addr(addr2),
                                   RPC_SOCK_STREAM, RPC_PROTO_DEF);
        conns++;

        rpc_fcntl(rpcs2, peer_socks[i], RPC_F_SETFL, RPC_O_NONBLOCK);

        /*
         * Set SO_LINGER with zero timeout for Tester sockets,
         * so that their closing will be immediate (with sending RST).
         */
        optval.l_onoff = 1;
        optval.l_linger = 0;
        rpc_setsockopt(rpcs2, peer_socks[i], RPC_SO_LINGER, &optval);

        CHECK_RC(tapi_sockaddr_clone(rpcs2, addr2, &peer_addrs[i]));
        rpc_bind(rpcs2, peer_socks[i], SA(&peer_addrs[i]));

        RPC_AWAIT_ERROR(rpcs2);
        rc = rpc_connect(rpcs2, peer_socks[i], addr1);
        if (rc < 0 && RPC_ERRNO(rpcs2) != RPC_EINPROGRESS)
            TEST_VERDICT("%s: nonblocking connect() failed "
                         "with unexpected errno %r",
                         log_msg, RPC_ERRNO(rpcs2));
    }

    TAPI_WAIT_NETWORK;

    for (i = 0; i < conns; i++)
    {
        if (i == 0 || i + 1 == conns)
            rpcs2->silent_pass = rpcs2->silent_pass_default = FALSE;
        else
            rpcs2->silent_pass = rpcs2->silent_pass_default = silent_def2;

        RPC_AWAIT_ERROR(rpcs2);
        rc = rpc_send(rpcs2, peer_socks[i], &peer_addrs[i],
                      sizeof(*peer_addrs), 0);
        if (rc < 0 && RPC_ERRNO(rpcs2) != RPC_EAGAIN)
            TEST_VERDICT("%s: send() failed with unexpected errno %r",
                         log_msg, RPC_ERRNO(rpcs2));
    }

    TAPI_WAIT_NETWORK;

    /*
     * Close Tester sockets, so that futher SYN-ACKs sent by
     * IUT connections hanging in SYN_RECEIVED state will not
     * be acknowledged.
     */

    for (i = 0; i < conns; i++)
    {
        if (i == 0 || i + 1 == conns)
            rpcs2->silent_pass = rpcs2->silent_pass_default = FALSE;
        else
            rpcs2->silent_pass = rpcs2->silent_pass_default = silent_def2;

        rpc_fcntl(rpcs2, peer_socks[i], RPC_F_SETFL, 0);
        RPC_CLOSE(rpcs2, peer_socks[i]);
    }
    free(peer_socks);
    free(peer_addrs);

    TAPI_WAIT_NETWORK;

    /*
     * Check how many sockets accept() can return.
     */
    i = 0;
    while (TRUE)
    {
        if (i == 0)
            rpcs1->silent_pass = rpcs1->silent_pass_default = FALSE;
        else
            rpcs1->silent_pass = rpcs1->silent_pass_default = silent_def1;

        RPC_GET_READABILITY(readable, rpcs1, listener, 0);
        if (readable)
        {
            peer_addr_len = sizeof(peer_addr);
            memset(&peer_addr, 0, sizeof(peer_addr));
            RPC_AWAIT_ERROR(rpcs1);
            s = rpc_accept(rpcs1, listener,
                           SA(&peer_addr), &peer_addr_len);
            if (s < 0)
                TEST_VERDICT("%s: accept() failed with errno %r",
                             log_msg, RPC_ERRNO(rpcs1));

            /*
             * To simplify checking in case of connections reordering
             * in accept queue, Tester sockets sent their addresses
             * as data, and here it is checked that received data
             * matches peer address.
             */

            if (recv_data)
            {
                RPC_GET_READABILITY(readable, rpcs1, s, 0);
                if (!readable)
                {
                    ERROR_VERDICT("%s: accepted socket is not readable",
                                  log_msg);
                    recv_data = FALSE;
                }
                else
                {
                    RPC_AWAIT_ERROR(rpcs1);
                    rc = rpc_recv(rpcs1, s, buf, sizeof(buf), 0);
                    if (rc < 0)
                    {
                        ERROR_VERDICT("%s: recv() failed with errno %r",
                                      log_msg, RPC_ERRNO(rpcs1));
                        recv_data = FALSE;
                    }
                    else
                    {
                        SOCKTS_CHECK_RECV(rpcs1, &peer_addr, buf,
                                          sizeof(peer_addr), rc);
                    }
                }
            }

            RPC_CLOSE(rpcs1, s);
            backlog++;

            if (backlog > conns)
                TEST_VERDICT("%s: accept() returned too many connections",
                             log_msg);
        }
        else
        {
            break;
        }
        i++;
    }

    rpcs1->silent_pass = rpcs1->silent_pass_default = silent_def1;
    return backlog;
}

/**
 * Send some data via @b send() call and check the returned value
 * and returned error. Function uses the @b RPC_AWAIT_IUT_ERROR macro
 * to avoid test fail when error occurs. Function prints error verdicts.
 *
 * @param rpc_srv             RPC server handle
 * @param s                   Sending socket
 * @param buf                 Buffer with data to send
 * @param len                 Size of data to send
 * @param ignore_err          If @c TRUE - do not print verdict if @b send()
 *                            returned a value different from -1
 * @param exp_err             Expected error to be returned by @b send()
 * @param failed              Pointer to variable to store result of checking.
 *                            If some error occurs it is set to @c TRUE, else
 *                            it is not modified.
 * @param exp_retval_verdict  Verdict which is printed if @b send() returned
 *                            a value different from -1
 * @param exp_err_verdict     Verdict which is printed if @b send() returned
 *                            an error different from expected
 */
static void
sockts_send_check_err(rcf_rpc_server *rpc_srv, int s, char *buf, size_t len,
                      te_bool ignore_err, rpc_errno exp_err, te_bool *failed,
                      char *exp_retval_verdict, char *exp_err_verdict)
{
    int     rc = 0;
    te_bool macro_failed;
    RPC_AWAIT_IUT_ERROR(rpc_srv);
    rc = rpc_send(rpc_srv, s, buf, len, 0);
    if (rc != -1)
    {
        if (!ignore_err)
        {
            ERROR_VERDICT("%s", exp_retval_verdict);
            *failed = TRUE;
        }
    }
    else
    {
        CHECK_RPC_ERRNO_NOEXIT(rpc_srv, exp_err, macro_failed, "%s",
                               exp_err_verdict);
        if (macro_failed)
          *failed = TRUE;
    }
}

/* See description in sockapi-ts_tcp.h */
te_errno
sockts_close_check_linger(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                          rcf_rpc_server *pco_iut_par,
                          int *iut_s, int tst_s,
                          char *tst_if_name, const struct sockaddr *iut_addr,
                          tarpc_linger *linger_val, te_bool should_linger,
                          closing_way way, te_bool ovfill_buf)
{
    char                buf[4096];
    size_t              buflen = sizeof(buf);
    struct rpc_tcp_info info;
    int                 rc = 0;
    tsa_packets_counter ctx = {0};
    te_bool             is_failed = FALSE;
    unsigned long int   exp_duration = 0;
    csap_handle_t       csap = CSAP_INVALID_HANDLE;
    te_bool             ignore_err = !should_linger;

    if (linger_val->l_linger < 0)
    {
        RING_VERDICT("l_linger value is less than a zero");
        return TE_EINVAL;
    }

    /* Overfill receive buffer of tst_s socket if required. */
    if (ovfill_buf)
      rpc_overfill_buffers(pco_iut, *iut_s, NULL);

    CHECK_RC(tapi_tcp_ip4_eth_csap_create(
                pco_tst->ta, 0, tst_if_name,
                TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                NULL, NULL, 0,
                *((in_addr_t *)te_sockaddr_get_netaddr(iut_addr)),
                -1, te_sockaddr_get_port(iut_addr), &csap));

    /**
     * Free receive buffer of IUT socket (if something was already
     * sent by TESTER during previous checks on another socket fd)
     */
    rpc_drain_fd_simple(pco_iut, *iut_s, NULL);

    /* Start CSAP sniffer to track transmitted packets.
     * Maybe some delay should be here after the call, but now it works fine.
     * See bug 9644 for more information. */
    CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                   TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

    pco_iut->timeout = TE_SEC2MS(linger_val->l_linger) + pco_iut->def_timeout;
    sockts_close(pco_iut, pco_iut_par, iut_s, way);

    if (way == CL_EXIT || way == CL_KILL)
        exp_duration = 0;
    else
        exp_duration = should_linger ? TE_SEC2US(linger_val->l_linger) : 0;

    CHECK_CALL_DURATION_INT_GEN(pco_iut->duration, TST_TIME_INACCURACY,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                exp_duration, exp_duration,
                                ERROR, RING_VERDICT,
                                "close() call on 'iut_s' had "
                                "unexpectedly %s duration",
                                pco_iut->duration < exp_duration ?
                                "short" : "long");

    TAPI_WAIT_NETWORK;

    /* Stop CSAP sniffer and check the transmitted packets. */
    rcf_ta_trrecv_stop(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);
    tsa_print_packet_stats(&ctx);

    if (linger_val->l_linger == 0)
    {
        if (should_linger && ctx.rst_ack == 0)
            RING_VERDICT("RST-ACK was not caught");

        if (!should_linger && ctx.rst_ack != 0)
            RING_VERDICT("Unexpected RST-ACK was caught");

        rpc_getsockopt(pco_tst, tst_s, RPC_TCP_INFO, &info);
        if (info.tcpi_state != RPC_TCP_CLOSE && should_linger)
        {
            RING_VERDICT("IUT socket does not send RST on closing");
            is_failed = TRUE;
        }
    }

    if (linger_val->l_linger > 0)
    {
        if (ctx.rst_ack != 0 || ctx.rst != 0 || ctx.fin_ack != 0 ||
            ctx.push_fin_ack != 0)
            RING_VERDICT("Unexpected finalizing packet was caught after "
                         "IUT socket closing");

        memset(&ctx, 0, sizeof(ctx));
        /* Start CSAP sniffer to track transmitted packets. */
        CHECK_RC(tapi_tad_trrecv_start(pco_tst->ta, 0, csap, NULL,
                                       TAD_TIMEOUT_INF, 0, RCF_TRRECV_PACKETS));

        /* Check that 'iut_s' socket sends nothing (not FIN nor RST segment) */
        rpc_getsockopt(pco_tst, tst_s, RPC_TCP_INFO, &info);
        if (info.tcpi_state != RPC_TCP_ESTABLISHED)
        {
            RING_VERDICT("Tester socket was unexpectedly moved "
                         "from TCP_ESTABLISHED to %s",
                         tcp_state_rpc2str(info.tcpi_state));
            is_failed = TRUE;
        }

        /*
         * send some data from 'tst_s' socket;
         * 'iut_s' socket should not have sent RST, so that the first send
         * should be successfully completed.
         */
        RPC_AWAIT_IUT_ERROR(pco_tst);
        rc = rpc_send(pco_tst, tst_s, buf, buflen, 0);
        if (rc < 0)
        {
            TEST_FAIL("send() called on tst socket first time "
                      "returns %d instead of number of bytes sent", rc);
        }
        TAPI_WAIT_NETWORK;

        /* Stop CSAP sniffer and check the transmitted packets. */
        rcf_ta_trrecv_stop(pco_tst->ta, 0, csap, tsa_packet_handler, &ctx, NULL);

        if (should_linger && ctx.rst == 0)
            RING_VERDICT("RST was not caught");

        tsa_print_packet_stats(&ctx);
        if (!should_linger &&
            (ctx.rst_ack != 0 || ctx.rst != 0 || ctx.fin_ack != 0 ||
             ctx.push_fin_ack != 0))
            RING_VERDICT("Unexpected finalizing packet was caught after packet "
                         "transmission by tester");
    }

    sockts_send_check_err(pco_tst, tst_s, buf, buflen, ignore_err,
                          RPC_ECONNRESET, &is_failed,
                          "After closing 'iut_s' socket, send() on 'tst_s' "
                          "did not return -1",
                          "After closing 'iut_s' socket, send() on 'tst_s'");

    sockts_send_check_err(pco_tst, tst_s, buf, buflen, ignore_err,
                          RPC_EPIPE, &is_failed,
                          "After closing 'iut_s' socket, send() "
                          "called second time on 'tst_s' did not return -1",
                          "After closing 'iut_s' socket, "
                          "send() called second time on 'tst_s'");

    CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, csap));

    return is_failed == TRUE ? TE_EFAIL : 0;
}
/* See description in sockapi-ts_tcp.h */
void
sockts_create_cached_socket(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                            const struct sockaddr *iut_addr,
                            const struct sockaddr *tst_addr,
                            int iut_l, te_bool active, te_bool caching)
{
    rcf_rpc_server            *pco_cl = pco_tst;
    rcf_rpc_server            *pco_srv = pco_iut;
    struct sockaddr_storage    iut_aux_addr;
    struct sockaddr_storage    tst_aux_addr;
    const struct sockaddr     *addr_cl;
    const struct sockaddr     *addr_srv;
    int sock_cl;
    int sock_srv;
    int listener;
    int cache;

    if (!caching)
        return;

    CHECK_RC(tapi_sockaddr_clone(pco_tst, iut_addr, &iut_aux_addr));
    CHECK_RC(tapi_sockaddr_clone(pco_iut, tst_addr, &tst_aux_addr));

    addr_cl = SA(&tst_aux_addr);
    addr_srv = SA(&iut_aux_addr);

    if (active)
    {
        pco_cl = pco_iut;
        pco_srv = pco_tst;
        addr_cl = SA(&iut_aux_addr);
        addr_srv = SA(&tst_aux_addr);

        listener = rpc_socket(pco_srv, rpc_socket_domain_by_addr(addr_cl),
                              RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_srv, listener, addr_srv);
        rpc_listen(pco_srv, listener, -1);
    }
    else
    {
        if (iut_l == -1)
        {
            TEST_FAIL("Creation of cached socket in passive mode assumes"
                      " keeping  listener socket open.  Argument 'iut_l'"
                      " must not be equal -1 in this case.");
            return;
        }
        listener = iut_l;
        addr_srv = iut_addr;
    }

    sock_cl = rpc_socket(pco_cl, rpc_socket_domain_by_addr(addr_cl),
                         RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_connect(pco_cl, sock_cl, addr_srv);
    TAPI_WAIT_NETWORK;
    sock_srv = rpc_accept(pco_srv, listener, NULL, NULL);

    if (active)
    {
        RPC_CLOSE(pco_srv, listener);
        sockts_pair_close_check(pco_cl, pco_srv, sock_cl, sock_srv);
    }
    else
    {
        sockts_pair_close_check(pco_srv, pco_cl, sock_srv, sock_cl);
    }

    if (tapi_sh_env_get_int(pco_iut, "EF_SOCKET_CACHE_MAX", &cache) != 0 ||
        cache == 0 || !tapi_onload_lib_exists(pco_iut->ta))
        return;

    if (!tapi_onload_socket_is_cached(pco_iut, active ? sock_cl : sock_srv))
        RING_VERDICT("Aux accepted socket was not cached");
}

/* See description in sockapi-ts_tcp.h */
void
sockts_tcp_check_cache_reuse(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_iut2,
                             rcf_rpc_server *pco_tst,
                             const struct sockaddr *iut_addr,
                             const struct sockaddr *tst_addr, int iut_l,
                             int iut_s, te_bool active)
{
    int cache_limit = 0;
    int cache = 0;
    int cached = 0;
    int hit = 0;
    te_bool reuse;

    if (tapi_sh_env_get_int(pco_iut, "EF_SOCKET_CACHE_MAX",
                            &cache_limit) != 0 || cache_limit <= 0)
        return;

    if (iut_s != -1 && !tapi_onload_socket_is_cached(pco_iut, iut_s))
        RING_VERDICT("Socket was not cached");

    if (iut_l == -1 && !active)
        return;

    cache = tapi_onload_get_free_cache(pco_iut2, active, &reuse);
    cached = tapi_onload_get_stats_val(pco_iut2,
                                       "sockcache_cached") + 1;
    hit = tapi_onload_get_stats_val(pco_iut2, "sockcache_hit");
    if (cache < cache_limit && cache > 0 && reuse)
        hit++;

    sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr, iut_l,
                                active, TRUE);
    if (tapi_onload_get_stats_val(pco_iut2, "sockcache_cached") != cached ||
        tapi_onload_get_stats_val(pco_iut2, "sockcache_hit") != hit)
    {
        RING_VERDICT("It was expected to get sockcache_cached=%d and "
                     "sockcache_hit=%d", cached, hit);
    }
}

/* See description in sockapi-ts_tcp.h */
te_errno
sockts_check_sock_flags(rcf_rpc_server *pco, int s, int sock_flags)
{
    int flags_1 = -1;
    int flags_2 = -1;

    RPC_AWAIT_ERROR(pco);
    flags_1 = rpc_fcntl(pco, s, RPC_F_GETFL);
    if (flags_1 < 0)
    {
	ERROR_VERDICT("fcntl() which tried to get status flags "
		      "failed with errno: %r",
		      RPC_ERRNO(pco));
        return RPC_ERRNO(pco);
    }

    RPC_AWAIT_ERROR(pco);
    flags_2 = rpc_fcntl(pco, s, RPC_F_GETFD);
    if (flags_2 < 0)
    {
        ERROR_VERDICT("fcntl() which tried to get descriptor flags "
		      "failed with errno: %r",
		      RPC_ERRNO(pco));
        return RPC_ERRNO(pco);
    }

    if (flags_1 & RPC_O_NONBLOCK)
    {
	if (!(sock_flags & RPC_SOCK_NONBLOCK))
	    TEST_VERDICT("O_NONBLOCK is set unexpectedly on a socket");
    }
    else
    {
	if (sock_flags & RPC_SOCK_NONBLOCK)
	    TEST_VERDICT("O_NONBLOCK is not set on a socket");
    }

    if (flags_2 == 0)
    {
	if (sock_flags & RPC_SOCK_CLOEXEC)
	    TEST_VERDICT("FD_CLOEXEC is not set on a socket");
    }
    else
    {
	if (!(sock_flags & RPC_SOCK_CLOEXEC))
	    TEST_VERDICT("FD_CLOEXEC is set unexpectedly on a socket");
    }

    return 0;
}

/* See description in sockapi-ts_tcp.h */
int
sockts_tcp_payload_len(asn_value *pkt)
{
    te_errno rc;
    unsigned int len;

    rc = tapi_tcp_get_hdrs_payload_len(pkt, NULL, &len);
    if (rc != 0)
        return -1;

    return (int)len;
}

static te_errno
sockts_change_tcp_segmentation_status(const char *ta, const char *ifname,
                                      int tx_tcp_segment_val)
{
    te_errno rc;

    rc = tapi_cfg_if_feature_set_all_parents(
                                          ta, ifname,
                                          "tx-tcp-segmentation",
                                          tx_tcp_segment_val);
    if (rc != 0)
    {
        ERROR("Failed to set tx-tcp-segmentation value to %d",
              tx_tcp_segment_val);
        return rc;
    }
    rc = tapi_cfg_if_feature_set_all_parents(
                                          ta, ifname,
                                          "tx-tcp6-segmentation",
                                          tx_tcp_segment_val);
    if (rc != 0)
    {
        ERROR("Failed to set tx-tcp6-segmentation value to %d",
              tx_tcp_segment_val);
        return rc;
    }

    return 0;
}

/* See description in sockapi-ts_tcp.h */
te_errno
sockts_disable_tcp_segmentation(const char *ta, const char *ifname)
{
    return sockts_change_tcp_segmentation_status(ta, ifname, 0);
}

/* See description in sockapi-ts_tcp.h */
te_errno
sockts_enable_tcp_segmentation(const char *ta, const char *ifname)
{
    return sockts_change_tcp_segmentation_status(ta, ifname, 1);
}

/* See description in sockopts_common.h */
void
sockts_shutdown_check_tcp_state(rcf_rpc_server *pco_iut, int iut_s,
                                const struct sockaddr *iut_addr,
                                rcf_rpc_server *pco_tst, int tst_s,
                                const struct sockaddr *tst_addr,
                                te_bool shutdown_iut, te_bool shutdown_tst,
                                te_bool tst_first, rpc_tcp_state *tcp_state,
                                te_bool overfilled)
{
    rpc_tcp_state          exp_tcp_state;
    rpc_tcp_state          real_tcp_state;
    te_bool                found = FALSE;
    rpc_tcp_info           info;

    if (shutdown_iut && !tst_first)
    {
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
        if (shutdown_tst)
            TAPI_WAIT_NETWORK;
    }

    if (shutdown_tst)
        rpc_shutdown(pco_tst, tst_s, RPC_SHUT_WR);

    if (shutdown_iut && tst_first)
    {
        if (shutdown_tst)
            TAPI_WAIT_NETWORK;
        rpc_shutdown(pco_iut, iut_s, RPC_SHUT_WR);
    }

    if (shutdown_iut || shutdown_tst)
        TAPI_WAIT_NETWORK;

    exp_tcp_state = RPC_TCP_ESTABLISHED;
    if (shutdown_iut)
    {
        if (shutdown_tst)
        {
            if (tst_first)
            {
                exp_tcp_state = overfilled ? RPC_TCP_LAST_ACK:
                                             RPC_TCP_CLOSE;
            }
            else
            {
                exp_tcp_state = overfilled ? RPC_TCP_CLOSING:
                                             RPC_TCP_TIME_WAIT;
            }
        }
        else
        {
            exp_tcp_state = overfilled ? RPC_TCP_FIN_WAIT1 :
                                         RPC_TCP_FIN_WAIT2;
        }
    }
    else if (shutdown_tst)
    {
        exp_tcp_state = RPC_TCP_CLOSE_WAIT;
    }

    /*
     * rpc_get_tcp_socket_state() is slow, so it is used only
     * for TIME_WAIT state which can be incorrectly reported as
     * CLOSE by getsockopt(TCP_INFO).
     */

    if (exp_tcp_state == RPC_TCP_TIME_WAIT)
    {
        rpc_get_tcp_socket_state(pco_iut, iut_addr, tst_addr,
                                 &real_tcp_state, &found);
        if (!found)
        {
            TEST_VERDICT("rpc_get_tcp_socket_state() did not find "
                         "IUT socket");
        }
    }
    else
    {
        rpc_getsockopt(pco_iut, iut_s, RPC_TCP_INFO, &info);
        real_tcp_state = info.tcpi_state;
    }

    if (real_tcp_state != exp_tcp_state)
    {
        TEST_VERDICT("IUT socket is in %s state instead of %s",
                     tcp_state_rpc2str(real_tcp_state),
                     tcp_state_rpc2str(exp_tcp_state));
    }

    if (tcp_state != NULL)
        *tcp_state = exp_tcp_state;
}

/* See description in sockapi-ts_tcp.h */
te_errno
sockts_check_tcp_conn_csap(rcf_rpc_server *rpcs, int s,
                           tapi_tcp_handler_t csap_s)
{
#define SEND_LEN 1000
#define BUF_LEN  (SEND_LEN * 2)
    char send_buf[BUF_LEN];
    char recv_buf[BUF_LEN];
    int  rc;

    te_bool  readable = FALSE;
    te_errno result = 0;

    te_dbuf recv_dbuf = TE_DBUF_INIT(0);

    te_fill_buf(send_buf, SEND_LEN);

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_send(rpcs, s, send_buf, SEND_LEN, 0);
    if (rc < 0)
    {
        ERROR_VERDICT("send() failed with errno %r", RPC_ERRNO(rpcs));
        result = TE_EFAIL;
        goto cleanup;
    }
    if (rc != SEND_LEN)
        TEST_FAIL("send() returned unexpected result");

    tapi_tcp_recv_data(csap_s, TAPI_WAIT_NETWORK_DELAY, TAPI_TCP_AUTO,
                       &recv_dbuf);
    RING("Checking TCP connection: %d bytes sent, %d bytes received",
         SEND_LEN, (int)recv_dbuf.len);

    if (recv_dbuf.len != SEND_LEN ||
        memcmp(send_buf, recv_dbuf.ptr, SEND_LEN) != 0)
    {
        if (recv_dbuf.len == 0)
        {
            ERROR_VERDICT("No data was received by CSAP");
        }
        else
        {
            ERROR_VERDICT("Data received by CSAP does not match data sent "
                          "from socket when checking connection");
        }

        result = TE_EFAIL;
        goto cleanup;
    }

    te_fill_buf(send_buf, SEND_LEN);
    CHECK_RC(tapi_tcp_send_msg(csap_s,
                               (uint8_t *)send_buf, SEND_LEN,
                               TAPI_TCP_AUTO, 0,
                               TAPI_TCP_AUTO, 0,
                               NULL, 0));
    /*
     * This is used instead of TAPI_WAIT_NETWORK only to make waiting
     * faster, as data usually arrives sooner than timeout expires.
     */
    RPC_GET_READABILITY(readable, rpcs, s, TAPI_WAIT_NETWORK_DELAY);

    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_recv(rpcs, s, recv_buf, BUF_LEN, RPC_MSG_DONTWAIT);

    if (rc != SEND_LEN ||
        memcmp(send_buf, recv_buf, SEND_LEN) != 0)
    {
        if (rc < 0)
        {
            if (RPC_ERRNO(rpcs) != RPC_EAGAIN)
            {
                ERROR_VERDICT("recv() failed with unexpected "
                              "errno %r", RPC_ERRNO(rpcs));
            }
            else
            {
                ERROR_VERDICT("No data was received by socket");
            }
        }
        else
        {
            if (rc == 0)
            {
                ERROR_VERDICT("recv() returned 0");
            }
            else
            {
                ERROR_VERDICT("Data received by socket does not match "
                              "data sent from CSAP when checking "
                              "connection");
            }
        }

        result = TE_EFAIL;
    }

cleanup:

    te_dbuf_free(&recv_dbuf);
    return result;
}

/* See description in sockapi-ts_tcp.h */
te_errno
sockts_connect_retry(rcf_rpc_server *rpcs, int sock,
                     const struct sockaddr *iut_addr, int wait_accept_min_s,
                     int wait_accept_max_s)
{
/* Number of attempts to establish a connection */
#define ACCEPT_ATTEMPTS_NUM  60
/* Timeout for connect() */
#define WAIT_CONNECT_TO_MS   100000
    tarpc_timeval   tv = {0, 0};
    int             i;
    time_t          sec;
    te_errno        errno;

    rpc_gettimeofday(rpcs, &tv, NULL);
    sec = tv.tv_sec;

    for (i = 0; i < ACCEPT_ATTEMPTS_NUM; i++)
    {
        RPC_AWAIT_IUT_ERROR(rpcs);
        /*
         * After some number of connections, rpc_connect() may hang for more
         * than 10 seconds, which is the default rpcs->timeout
         */
        rpcs->timeout = WAIT_CONNECT_TO_MS;
        if (rpc_connect(rpcs, sock, iut_addr) == 0)
            break;

        errno = RPC_ERRNO(rpcs);
        if (errno != RPC_ECONNREFUSED && errno != RPC_ETIMEDOUT)
        {
            ERROR("connect() fails after %d attempts", i);
            ERROR_VERDICT("connect() fails with errno %s",
                          errno_rpc2str(errno));
            return errno;
        }
        /*
         * Do not call connect() calls very fast to prevent IUT side
         * considering this as an attack
         */
        sleep(1);
    }

    rpc_gettimeofday(rpcs, &tv, NULL);
    sec = tv.tv_sec - sec;

    if (i != 0)
        VERB("Connect attempts %d", i);

    if (i == ACCEPT_ATTEMPTS_NUM)
    {
        ERROR("connect() fails after %d seconds", sec);
        ERROR_VERDICT("connect() fails with errno %s",
                      errno_rpc2str(errno));
        return errno;
    }
    else if (i > 0)
    {
        RING("Connection has been established after waiting %d seconds",
             sec);
        if (sec < wait_accept_min_s || sec >= wait_accept_max_s)
        {
            if (wait_accept_min_s != -1 && sec < wait_accept_min_s)
            {
                ERROR_VERDICT("Connection has been established too"
                              " quickly");
                return TE_EFAIL;
            }
            if (wait_accept_max_s != -1 && sec >= wait_accept_max_s)
            {
                ERROR_VERDICT("Connection took too long to establish");
                return TE_ETIMEDOUT;
            }
        }
    }

    return 0;

#undef ACCEPT_ATTEMPTS_NUM
#undef WAIT_CONNECT_TO_MS
}
