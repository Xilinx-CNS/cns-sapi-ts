/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-connect_interrupted Check behaviour/influence of the socket after interrupted TCP connect()
 *
 * @objective Check that the socket after interrupted TCP @b connect()
 *            (by the signal, non-blocking socket or @c SO_SNDTIMEO 
 *            on the socket): marks as used local-remote address-port,
 *            ignores address parameter in further @b connect() calls,
 *            blocks send/receive operations before connection
 *            establishment, blocks further @b connect() calls and
 *            return @c 0 in the case of success.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_gw
 *                      - @ref arg_types_env_peer2peer_gw_ipv6
 * @param howto         How to force connect to fail:
 *                      - signal: send a signal;
 *                      - non-blocking: use non-blocking socket;
 *                      - timeout: connections attempt is aborted by timeout.
 * @param failures      Number of failures before success:
 *                      - 1
 *                      - 3
 * @param inuse         Check that address is marked as used until connection
 *                      attempt is finished if @c TRUE.
 * @param another_peer  Try final @b connect() to another peer address if
 *                      @c TRUE.
 * @param iomux         Call I/O multiplexing function:
 *                      - select
 *                      - pselect
 *                      - poll
 *                      - ppoll
 *                      - epoll
 *                      - epoll_pwait
 * @param send_check    Try to send data before successfull @b connect() if
 *                      @c TRUE
 * @param recv_check    Try to receive data before successfull @b connect()if
 *                      @c TRUE
 * @param success       Establish connection:
 *                      - before: before send()/recv()/connect() calls;
 *                      - during: call the functions and then repair the
 *                                channel to finish connection establishment;
 *                      - never
 *
 * @par Scenario:
 *
 * -# Enable forwarding on the host with @p pco_gw;
 * -# Establish routing on the hosts with @p pco_iut and @p pco_tst
 *    to reach each other via @p gw_iut_addr and @p gw_tst_addr
 *    addresses;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Create listening TCP socket @p tst_s on @p pco_tst bound to
 *    @p tst_addr network address and port;
 * -# Create two TCP sockets @p iut_s1 and @p iut_s2 on @p pco_iut;
 * -# Enable @c SO_REUSEADDR socket option on both sockets;
 * -# Bind both sockets to @p iut_addr network address and port;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p howto is equal to @c signal, install on @p pco_iut
 *    @b signal_registrar() signal hander for @c TST_SIGNAL signal;
 * -# If @p howto is equal to @c non-blocking, make @p iut_s1
 *    socket non-blocking using @c FIONBIO IOCTL request;
 * -# If @p howto is equal to @c timeout, set @p iut_s1 socket
 *    option @c SO_SNDTIMEO to 1 second;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Add a new static ARP entry on the host with @p pco_tst to direct
 *    traffic to @p gw_tst_addr network address to alien link-layer
 *    address;
 * -# Repeat the following sequence @p failures times:
 *     -# Start to @b connect() @p iut_s1 socket to @p tst_addr network
 *        address and port;
 *     -# If @p howto is equal to @c signal, send @c TST_SIGNAL signal
 *        to the process with @p pco_iut PID from @p pco_killer and check
 *        that @b connect() returns @c -1 with @c EINTR @b errno and
 *        sent signal is received by the @b signal_registrar;
 *     -# If @p howto is equal to @c non-blocking or @c timeout, check
 *        that @b connect() return -1 with @c EINPROGRESS @b errno in
 *        the case of the first attempt and @c EALREADY @b errno in the
 *        case of further attempts;
 *        \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p inuse is equal to @c TRUE:
 *     -# Create TCP socket @p iut_s2 on @p pco_iut;
 *     -# Enable @c SO_REUSEADDR socket option on @p iut_s2 socket;
 *     -# Bind @p iut_s2 sockets to @p iut_addr network address and port;
 *     -# Try to @b connect() @p iut_s2 socket to @p tst_addr network
 *        address and port, check that it returns @c -1 with 
 *        @c EADDRINUSE or @c EADDRNOTAVAIL @b errno;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p iomux is not equal to @c none, call corresponding I/O
 *    multiplexing function to wait for read and write events on
 *    @p iut_s1 socket with zero timeout and check that it returns @c 0
 *    with no events;
 * -# If @p howto is equal to @c non-blocking, make @p iut_s1
 *    socket blocking using @c FIONBIO IOCTL request;
 * -# If @p howto is equal to @c timeout, set @p iut_s1 socket option
 *    @c SO_SNDTIMEO to @c 0 second / @c 0 microseconds to disable it;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p another_peer is equal to @c TRUE, use @p gw_iut_addr as
 *    peer address in subsequent @b connect() calls;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p success is equal to @c never, @b connect() should return
 *     @c -1 with @c ETIMEDOUT @b errno, @b send() should return @c -1
 *     with @c EPIPE @b errno and send @c SIGPIPE signal, @b recv()
 *     should return @c -1 with @c ENOTCONN @b errno
 * -# If @p success is equal to @c before, using Ethernet sniffer on
 *    the gateway make sure that SYN-ACK with correct address is sent
 *    from @p pco_tst after deletion of the static ARP entry which
 *    prevents connection establishment;
 * -# If @p success is equal to @c during, initiate all operations
 *    (i.e. @b connect(), @b  send(), @b recv()) and then delete static
 *    ARP entry which prevents connection establishment;
 * -# If @p success is equal to @c before or @c during, make sure that
 *    connection is established, accept it on the server and finish
 *    data exchange initiated by the client (i.e. send/receive some
 *    date if required);
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p howto is equal to @c signal, restore on @p pco_iut
 *    signal hander for @c TST_SIGNAL signal;
 * -# Close opened sockets;
 * -# Delete added routes and restore state of forwarding on the host
 *    with @p pco_gw.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/connect_interrupted"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "tapi_tcp.h"
#include "iomux.h"
#include "tapi_route_gw.h"


#define TST_SIGNAL      RPC_SIGUSR1

/* Timeout should be >3 min */
#define TST_CONNECT_TIMEOUT       (5 * 60 * 1000)


int
main(int argc, char *argv[])
{
    const char         *howto= NULL;
    unsigned int        failures = 0;
    te_bool             inuse = FALSE;
    te_bool             another_peer = FALSE;
    const char         *iomux = NULL;
    iomux_call_type     iomux_type;
    const char         *send_check = NULL;
    const char         *recv_check = NULL;
    const char         *success = NULL;
    tapi_route_gateway  gw;

    TAPI_DECLARE_ROUTE_GATEWAY_PARAMS;

    rcf_rpc_server             *pco_iut_snd = NULL;
    rcf_rpc_server             *pco_iut_rcv = NULL;
    rcf_rpc_server             *pco_killer = NULL;
    
    rpc_socket_domain           iut_domain;

    const struct sockaddr      *peer_addr = NULL;
    const struct sockaddr      *tst_lladdr = NULL;
    const struct sockaddr      *gw_tst_lladdr = NULL;

    int                    tst_s = -1;
    int                    acc_s = -1;
    int                    iut_s1 = -1;
    int                    iut_s2 = -1;
    int                    iut_s_snd;
    int                    iut_s_rcv;

    DEFINE_RPC_STRUCT_SIGACTION(old_pipe_act);
    te_bool                restore_pipe_handler = FALSE;
    DEFINE_RPC_STRUCT_SIGACTION(sig_act);
    DEFINE_RPC_STRUCT_SIGACTION(old_sig_act);
    te_bool                restore_sig_handler = FALSE;
    rpc_sigset_p           received_set = RPC_NULL;
    tarpc_timeval          tv = {0, 0};

    unsigned int    i;
    pid_t           pco_iut_pid;
    int             req_val;
    csap_handle_t   csap = CSAP_INVALID_HANDLE;
    
    void       *clnt_send_buf = NULL;
    size_t      clnt_send_buf_len = 0;
    ssize_t     clnt_sent;
    void       *srvr_recv_buf = NULL;
    size_t      srvr_recv_buf_len = 0;
    ssize_t     srvr_recv;
    void       *srvr_send_buf = NULL;
    size_t      srvr_send_buf_len = 0;
    ssize_t     srvr_sent;
    void       *clnt_recv_buf = NULL;
    size_t      clnt_recv_buf_len = 0;
    ssize_t     clnt_recv;
    te_bool     connect_done;
    te_bool     send_done;
    te_bool     recv_done;
    te_bool     neigh_entry_added = FALSE;

    /* Test preambule */
    TEST_START;

    TAPI_GET_ROUTE_GATEWAY_PARAMS;
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_LINK_ADDR(gw_tst_lladdr);

    TEST_GET_STRING_PARAM(howto);
    TEST_GET_INT_PARAM(failures);
    TEST_GET_BOOL_PARAM(inuse);
    TEST_GET_BOOL_PARAM(another_peer);
    TEST_GET_STRING_PARAM(iomux);
    TEST_GET_STRING_PARAM(send_check);
    TEST_GET_STRING_PARAM(recv_check);
    TEST_GET_STRING_PARAM(success);

    TAPI_INIT_ROUTE_GATEWAY(gw);

    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, "pco_killer", &pco_killer));

    if (failures <= 0)
        TEST_FAIL("Number of failures must be positive");

    iomux_type = iomux_call_str2en(iomux);
    iut_domain = rpc_socket_domain_by_addr(iut_addr);

    CHECK_NOT_NULL(clnt_send_buf = 
                      sockts_make_buf_stream(&clnt_send_buf_len));
    CHECK_NOT_NULL(srvr_recv_buf =
                      te_make_buf_min(clnt_send_buf_len, &srvr_recv_buf_len));
    CHECK_NOT_NULL(srvr_send_buf = 
                      sockts_make_buf_stream(&srvr_send_buf_len));
    CHECK_NOT_NULL(clnt_recv_buf =
                      te_make_buf_min(srvr_send_buf_len, &clnt_recv_buf_len));


    /* Scenario */
    
    CHECK_RC(tapi_route_gateway_configure(&gw));

    /* Add static ARP entry to prevent connection establishment */
    CHECK_RC(tapi_route_gateway_break_tst_gw(&gw));
    neigh_entry_added = TRUE;

    CFG_WAIT_CHANGES;

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    iut_s1 = rpc_socket(pco_iut, iut_domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    req_val = TRUE;
    rpc_setsockopt(pco_iut, iut_s1, RPC_SO_REUSEADDR, &req_val);

    rpc_bind(pco_iut, iut_s1, iut_addr);


    if (strcmp(howto, "signal") == 0)
    {
        old_sig_act.mm_mask = rpc_sigset_new(pco_iut);
        rpc_sigaction(pco_iut, TST_SIGNAL, NULL, &old_sig_act);
        sig_act = old_sig_act;
        strcpy(sig_act.mm_handler, SIGNAL_REGISTRAR);
        rpc_sigaction(pco_iut, TST_SIGNAL, &sig_act, NULL);
        restore_sig_handler = TRUE;
    }
    else if (strcmp(howto, "non-blocking") == 0)
    {
        req_val = TRUE;
        rpc_ioctl(pco_iut, iut_s1, RPC_FIONBIO, &req_val);
    }
    else if (strcmp(howto, "timeout") == 0)
    {
        int             ret;
        tarpc_timeval   tv = { 1, 0 };
        
        RPC_AWAIT_IUT_ERROR(pco_iut);
        ret = rpc_setsockopt(pco_iut, iut_s1, RPC_SO_SNDTIMEO, &tv);
        if (ret != 0)
        {
            TEST_VERDICT("setsockopt(SOL_SOCKET, SO_SNDTIMEO) for "
                         "TCP socket failed with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }
    else
    {
        TEST_FAIL("Unsupported value of 'howto' parameter '%s'", howto);
    }

    for (i = 0; i < failures; ++i)
    {
        if (strcmp(howto, "signal") == 0)
        {
            /* Schedule postponed signal sending */
            pco_iut_pid = rpc_getpid(pco_iut);
            rpc_gettimeofday(pco_killer, &tv, NULL);
            /* Sleep 2.5 sec */
            pco_killer->start = (tv.tv_sec + 2) * 1000 + 500 +
                                tv.tv_usec / 1000;
            pco_killer->op = RCF_RPC_CALL;
            rpc_kill(pco_killer, pco_iut_pid,  TST_SIGNAL);
        }

        /* Start connection establishment to be interrupted by signal */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s1, tst_addr);
        if (rc != -1)
        {
            TEST_VERDICT("It is expected that connect() fails and returns -1, "
                         "but it returned %d", rc);
        }
        if (strcmp(howto, "signal") == 0)
        {
            /* Wait for killer */
            pco_killer->op = RCF_RPC_WAIT;
            rpc_kill(pco_killer, pco_iut_pid, TST_SIGNAL);

            if (i == 0)
            {
                CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                                "Signal was sent when connect() was "
                                "trying to establish a new TCP "
                                "connection, it returns -1, but");
            }
            else if (RPC_ERRNO(pco_iut) != RPC_EINTR)
            {
                WARN_VERDICT("connect() was called on the TCP socket "
                             "in SYN-SENT state and signal was sent to "
                             "to interrupt it, however, connect() "
                             "has failed with errno %s instead of EINTR",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
                break;
            }

            /* Check that signal was received */
            received_set = rpc_sigreceived(pco_iut);
            rc = rpc_sigismember(pco_iut, received_set, TST_SIGNAL);
            if (rc == 0)
            {
                TEST_VERDICT("No signal has been recieved");
            }
        }
        else
        {
            te_errno exp_errno = (i == 0) ? RPC_EINPROGRESS : RPC_EALREADY;

            CHECK_RPC_ERRNO(pco_iut, exp_errno,
                            "connect() called on the socket with %s returns "
                            "-1, but",
                            (strcmp(howto, "timeout") == 0) ?
                            "SO_SNDTIMEO option set to 1 second" :
                            "FIONBIO ioctl() request enabled");
        }
    }

    /*
     * Check that corresponding address is in use.
     */
    if (inuse)
    {
        iut_s2 = rpc_socket(pco_iut,
                            iut_domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

        req_val = TRUE;
        rpc_setsockopt(pco_iut, iut_s2, RPC_SO_REUSEADDR, &req_val);

        rpc_bind(pco_iut, iut_s2, iut_addr);

        /* Try the second connect with the same parameters */
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s2, tst_addr);
        if (rc != -1)
        {
            TEST_VERDICT("Another socket initiated the same connection, "
                         "but connect() of this one returns %d instead of -1",
                         rc);
        }
        if (RPC_ERRNO(pco_iut) == RPC_EADDRINUSE)
        {
            /* That's the most logical behaviour, just accept it */
        }
        else if (RPC_ERRNO(pco_iut) == RPC_EADDRNOTAVAIL)
        {
            RING_VERDICT("Another socket has initiated the same "
                         "connection, connect() of this one failed "
                         "with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        else
        {
            TEST_VERDICT("Another socket has initiated the same connection, "
                         "connect() of this one failed with unexpected "
                         "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    if (iomux_type != IC_UNKNOWN)
    {
        iomux_evt_fd            evt_fd;
        struct tarpc_timeval    tv;

        memset(&evt_fd, 0, sizeof(evt_fd));
        evt_fd.fd = iut_s1;
        evt_fd.events = EVT_RDWR;
        
        memset(&tv, 0, sizeof(tv));

        rc = iomux_call(iomux_type, pco_iut, &evt_fd, 1, &tv);
        if (rc != 0 || evt_fd.revents != 0)
        {
            TEST_VERDICT("I/O multiplexing function '%s' returned %d "
                         "(instead of 0) with %s events for the TCP socket "
                         "in SYN-SENT state", iomux_call_en2str(iomux_type),
                         rc, iomux_event_rpc2str(evt_fd.revents));
        }
    }

    /*
     * Remove non-blocking/timeout to block connect() forever the next
     * time.
     */
    if (strcmp(howto, "non-blocking") == 0)
    {
        req_val = FALSE;
        rpc_ioctl(pco_iut, iut_s1, RPC_FIONBIO, &req_val);
    }
    else if (strcmp(howto, "timeout") == 0)
    {
        tarpc_timeval   tv = { 0, 0 };

        rpc_setsockopt(pco_iut, iut_s1, RPC_SO_SNDTIMEO, &tv);
    }

    /*
     * Try to call connect() with another peer address.
     */
    if (another_peer)
    {
        peer_addr    = gw_iut_addr;
    }
    else
    {
        peer_addr    = tst_addr;
    }

    iut_s_snd = iut_s1;
    if (strcmp(send_check, "false") == 0)
    {
        pco_iut_snd = NULL;
    }
    else if (strcmp(send_check, "inline") == 0)
    {
        pco_iut_snd = pco_iut;
    }
    else if (strcmp(send_check, "thread") == 0)
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "sender",
                                              &pco_iut_snd));
    }
    else if (strcmp(send_check, "fork") == 0)
    {
        rpc_create_child_process_socket("forkandexec", 
                                        pco_iut, iut_s1, iut_domain, 
                                        RPC_SOCK_STREAM, &pco_iut_snd,
                                        &iut_s_snd);
    }
    else
    {
        TEST_FAIL("Unsupported '%s' type of 'send_check'",
                  send_check);
    }

    iut_s_rcv = iut_s1;
    if (strcmp(recv_check, "false") == 0)
    {
        pco_iut_rcv = NULL;
    }
    else if (strcmp(recv_check, "inline") == 0)
    {
        pco_iut_rcv = pco_iut;
    }
    else if (strcmp(recv_check, "thread") == 0)
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "receiver",
                                              &pco_iut_rcv));
    }
    else if (strcmp(recv_check, "fork") == 0)
    {
        rpc_create_child_process_socket("forkandexec", 
                                        pco_iut, iut_s1, iut_domain, 
                                        RPC_SOCK_STREAM, &pco_iut_rcv,
                                        &iut_s_rcv);
    }
    else
    {
        TEST_FAIL("Unsupported '%s' type of 'recv_check'",
                  recv_check);
    }

    if (pco_iut_snd != NULL)
    {
        CHECK_RC(tapi_sigaction_simple(pco_iut_snd, RPC_SIGPIPE,
                                       SIGNAL_REGISTRAR,
                                       &old_pipe_act));
        restore_pipe_handler = TRUE;
    }

    if (strcmp(success, "before") == 0)
    {
        /*
         * SYN-ACK should be received before the next connect() call.
         * Use tcp.ip.eth CSAP to wait for SYN-ACK and, then, call
         * connect().
         */
        CHECK_RC(tapi_tcp_ip_eth_csap_create(pco_gw->ta, 0,
                                             gw_tst_if->if_name,
                                             TAD_ETH_RECV_DEF |
                                             TAD_ETH_RECV_NO_PROMISC,
                                             (const uint8_t *)
                                             gw_tst_lladdr->sa_data,
                                             (const uint8_t *)
                                             tst_lladdr->sa_data,
                                             iut_addr->sa_family,
                                             TAD_SA2ARGS(
                                                iut_addr, tst_addr),
                                             &csap));

        CHECK_RC(tapi_tad_trrecv_start(pco_gw->ta, 0, csap, NULL,
                                       20000 /* ms, timeout */,
                                       1 /* number of packets */,
                                       RCF_TRRECV_COUNT));

        TAPI_WAIT_NETWORK;

        CHECK_RC(tapi_route_gateway_repair_tst_gw(&gw));
        neigh_entry_added = FALSE;

        CHECK_RC(rcf_ta_trrecv_wait(pco_gw->ta, 0, csap, NULL, NULL, NULL));

        TAPI_WAIT_NETWORK;
    }
    else if (strcmp(success, "during") == 0) 
    {
        if (pco_iut_snd != NULL)
        {
            pco_iut_snd->timeout = TE_SEC2MS(30);
            pco_iut_snd->op = RCF_RPC_CALL;
            rpc_send(pco_iut_snd, iut_s_snd,
                     clnt_send_buf, clnt_send_buf_len, 0);
        }
        if (pco_iut_rcv != NULL && pco_iut_rcv != pco_iut_snd)
        {
            pco_iut_rcv->timeout = TE_SEC2MS(30);
            pco_iut_rcv->op = RCF_RPC_CALL;
            rpc_recv(pco_iut_rcv, iut_s_rcv,
                     clnt_recv_buf, clnt_recv_buf_len, 0);
        }
        if (pco_iut != pco_iut_snd && pco_iut != pco_iut_rcv)
        {
            pco_iut->op = RCF_RPC_CALL;
            rpc_connect(pco_iut, iut_s1, peer_addr);
            TAPI_WAIT_NETWORK;

            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &connect_done));
            if (connect_done)
            {
                RPC_AWAIT_IUT_ERROR(pco_iut);
                rc = rpc_connect(pco_iut, iut_s1, peer_addr);
                if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EALREADY)
                {
                    TEST_VERDICT("connect() called for TCP socket in "
                                 "SYN-SENT state failed unexpectedly "
                                 "with errno %s",
                                 errno_rpc2str(RPC_ERRNO(pco_iut)));
                }
                RING_VERDICT("connect() called for TCP socket "
                             "in SYN-SENT state immediately "
                             "failed with errno EALREADY");
            }
        }

        CHECK_RC(tapi_route_gateway_repair_tst_gw(&gw));
        neigh_entry_added = FALSE;
    }
    else if (strcmp(success, "never") == 0)
    {
        te_bool got_timedout = FALSE;

        if (pco_iut_snd != NULL)
        {
            pco_iut_snd->op = RCF_RPC_CALL;
            rpc_send(pco_iut_snd, iut_s_snd,
                     clnt_send_buf, clnt_send_buf_len, 0);

            TAPI_WAIT_NETWORK;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_snd, &send_done));

            if (send_done)
            {
                RPC_AWAIT_IUT_ERROR(pco_iut_snd);
                clnt_sent = rpc_send(pco_iut_snd, iut_s_snd,
                                     clnt_send_buf, clnt_send_buf_len, 0);
                if (clnt_sent != -1)
                {
                    TEST_VERDICT("send() have to fail, but it returned %d",
                                 clnt_sent);
                }
                CHECK_RPC_ERRNO(pco_iut_snd, RPC_ENOTCONN,
                                "send() to TCP socket in SYN-SENT state "
                                "immediately failed, but");
            }
        }

        if (pco_iut_rcv != NULL && pco_iut_rcv != pco_iut_snd)
        {
            pco_iut_rcv->op = RCF_RPC_CALL;
            rpc_recv(pco_iut_rcv, iut_s_rcv,
                     clnt_recv_buf, clnt_recv_buf_len, 0);

            TAPI_WAIT_NETWORK;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_rcv, &recv_done));

            if (recv_done)
            {
                RPC_AWAIT_IUT_ERROR(pco_iut_rcv);
                clnt_recv = rpc_recv(pco_iut_rcv, iut_s_rcv,
                                     clnt_recv_buf, clnt_recv_buf_len, 0);
                if (clnt_recv != -1)
                {
                    TEST_VERDICT("recv() have to fail, but it returned %d",
                                 clnt_recv);
                }
                CHECK_RPC_ERRNO(pco_iut_rcv, RPC_ENOTCONN,
                                "recv() to TCP socket in SYN-SENT state "
                                "immediately failed, but");

                /* If we're inline, wait for other errno - state change */
                if (pco_iut_rcv == pco_iut)
                {
                    unsigned int iters = TE_MS2SEC(TST_CONNECT_TIMEOUT) / 10;
                    unsigned int iter = 0;

                    do {
                        RPC_AWAIT_IUT_ERROR(pco_iut_rcv);
                        clnt_recv = rpc_recv(pco_iut_rcv, iut_s_rcv,
                                             clnt_recv_buf,
                                             clnt_recv_buf_len, 0);
                        if (clnt_recv != -1)
                        {
                            TEST_VERDICT("recv() have to fail, but it "
                                         "returned %d", rc);
                        }
                        TAPI_WAIT_NETWORK;
                    } while (RPC_ERRNO(pco_iut) == RPC_ENOTCONN &&
                             iter++ < iters);
                }
            }
        }
        
        if (pco_iut != pco_iut_snd && pco_iut != pco_iut_rcv)
        {
            pco_iut->op = RCF_RPC_CALL;
            rpc_connect(pco_iut, iut_s1, peer_addr);

            TAPI_WAIT_NETWORK;
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &connect_done));

            pco_iut->timeout = TST_CONNECT_TIMEOUT;
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s1, peer_addr);
            if (rc != -1)
            {
                TEST_VERDICT("connect() have to fail, but it returned %d",
                             rc);
            }

            if (connect_done)
            {
                unsigned int iters = TE_MS2SEC(TST_CONNECT_TIMEOUT) / 10;
                unsigned int iter = 0;

                CHECK_RPC_ERRNO(pco_iut, RPC_EALREADY,
                                "connect() called for TCP socket "
                                "in SYN-SENT state immediately "
                                "failed, but");
                do {
                    RPC_AWAIT_IUT_ERROR(pco_iut);
                    rc = rpc_connect(pco_iut, iut_s1, peer_addr);
                    if (rc != -1)
                    {
                        TEST_VERDICT("connect() have to fail, but it "
                                     "returned %d", rc);
                    }
                    TAPI_WAIT_NETWORK;
                } while (RPC_ERRNO(pco_iut) == RPC_EALREADY &&
                         iter++ < iters);
            }

            if (pco_iut_snd == NULL && pco_iut_rcv == NULL)
            {
                /*
                 * Nobody was blocked except connect(), must got
                 * ETIMEDOUT.
                 */
                CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT,
                                "connect() failed, but");
                got_timedout = TRUE;
            }
            else if (RPC_ERRNO(pco_iut) == RPC_ETIMEDOUT)
            {
                got_timedout = TRUE;
            }
            else if (RPC_ERRNO(pco_iut) == RPC_ECONNABORTED)
            {
                /* Another call must got ETIMEDOUT */
            }
            else
            {
                TEST_VERDICT("connect() failed, but set unexpected errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
        
        if (pco_iut_snd != NULL)
        {
            if (send_done && pco_iut_snd == pco_iut &&
                (pco_iut_rcv == NULL || pco_iut_rcv == pco_iut_snd ||
                 recv_done))
            {
                unsigned int iters = TE_MS2SEC(TST_CONNECT_TIMEOUT) / 10;
                unsigned int iter = 0;

                do {
                    RPC_AWAIT_IUT_ERROR(pco_iut_snd);
                    clnt_sent = rpc_send(pco_iut_snd, iut_s_snd,
                                         clnt_send_buf,
                                         clnt_send_buf_len, 0);
                    if (clnt_sent != -1)
                    {
                        TEST_VERDICT("send() have to fail, but it "
                                     "returned %d", rc);
                    }
                    TAPI_WAIT_NETWORK;
                } while (RPC_ERRNO(pco_iut) == RPC_ENOTCONN &&
                         iter++ < iters);
            }
            else
            {
                pco_iut_snd->timeout = TST_CONNECT_TIMEOUT;
                RPC_AWAIT_IUT_ERROR(pco_iut_snd);
                clnt_sent = rpc_send(pco_iut_snd, iut_s_snd,
                                     clnt_send_buf, clnt_send_buf_len, 0);
                if (clnt_sent != -1)
                {
                    TEST_VERDICT("send() should fail because of timeout, "
                                 "but it returned %d", clnt_sent);
                }
            }

            if (RPC_ERRNO(pco_iut_snd) == RPC_ETIMEDOUT)
            {
                if (got_timedout)
                {
                    TEST_VERDICT("Another socket call has already got "
                                 "ETIMEDOUT error");
                }
                got_timedout = TRUE;
            }
            else if (RPC_ERRNO(pco_iut_snd) == RPC_EPIPE)
            {
                /* Another call must got ETIMEDOUT */
                /* Check that SIGPIPE was received */
                received_set = rpc_sigreceived(pco_iut_snd);
                rc = rpc_sigismember(pco_iut_snd, received_set, RPC_SIGPIPE);
                if (rc == 0)
                {
                    TEST_VERDICT("No SIGPIPE signal has been recieved");
                }
            }
            else
            {
                TEST_VERDICT("send() failed, but set unexpected errno %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut_snd)));
            }
        }

        if (pco_iut_rcv != NULL)
        {
            if (pco_iut_rcv == pco_iut_snd || !recv_done ||
                pco_iut_rcv != pco_iut)
            {
                pco_iut_rcv->timeout = TST_CONNECT_TIMEOUT;
                RPC_AWAIT_IUT_ERROR(pco_iut_rcv);
                clnt_recv = rpc_recv(pco_iut_rcv, iut_s_rcv,
                                     clnt_recv_buf, clnt_recv_buf_len, 0);
            }
            
            if (clnt_recv == -1 && RPC_ERRNO(pco_iut_rcv) == RPC_ETIMEDOUT)
            {
                if (got_timedout)
                {
                    TEST_VERDICT("Another socket call has already got "
                                 "ETIMEDOUT error, but subsequent recv() "
                                 "returned it as well");
                }
                got_timedout = TRUE;
            }
            else if (pco_iut_rcv == pco_iut && pco_iut_snd == pco_iut)
            {
                if (clnt_recv != 0)
                {
                    TEST_VERDICT("Another socket call has already got "
                                 "ETIMEDOUT, but subsequent recv() returned "
                                 "%d (%s) instead of expected 0", clnt_recv,
                                 errno_rpc2str(RPC_ERRNO(pco_iut_rcv)));
                }
            }
            else if (pco_iut_snd == NULL && pco_iut_rcv == pco_iut)
            {
                if (clnt_recv != -1)
                {
                    TEST_VERDICT("recv() should fail because of connection "
                                 "timeout, but it returned %d", clnt_recv);
                }
                CHECK_RPC_ERRNO(pco_iut_rcv, RPC_ETIMEDOUT,
                                "recv() failed, but");
                if (got_timedout)
                {
                    TEST_VERDICT("Another socket call has already got "
                                 "ETIMEDOUT error");
                }
                got_timedout = TRUE;
            }
            else if ((clnt_recv == -1 &&
                      RPC_ERRNO(pco_iut_rcv) == RPC_ENOTCONN) ||
                     (clnt_recv == 0))
            {
                /* Another call must got ETIMEDOUT */
            }
            else
            {
                TEST_VERDICT("recv() returned unexpectedly %d with errno %s",
                             clnt_recv, errno_rpc2str(RPC_ERRNO(pco_iut_rcv)));
            }
        }

        if (!got_timedout)
        {
            RING_VERDICT("No socket calls has got ETIMEDOUT error");
        }

        TEST_SUCCESS;
        /* 
         * The rest of the test is common for 'during' and 'before'
         * types of success.
         */
    }
    else
    {
        TEST_FAIL("Unknown '%s' type of 'success'", success);
    }


    pco_tst->timeout = TE_SEC2MS(30);
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    while (pco_iut_snd != NULL)
    {
        /*
         * It is wait of send() in the case of success=during and
         * simple send() otherwise.
         */
        RPC_AWAIT_IUT_ERROR(pco_iut_snd);
        clnt_sent = rpc_send(pco_iut_snd, iut_s_snd, 
                             clnt_send_buf, clnt_send_buf_len, 0);
        if (clnt_sent == -1 && strcmp(success, "during") == 0)
        {
            CHECK_RPC_ERRNO(pco_iut_snd, RPC_ENOTCONN,
                            "send() called for TCP socket in SYN-SENT "
                            "state failed, but");
            RING_VERDICT("send() called for TCP socket in SYN-SENT "
                         "state failed with errno ENOTCONN");
            break;
        }
        if ((size_t)clnt_sent != clnt_send_buf_len)
        {
            TEST_VERDICT("send() called for TCP socket in SYN-SENT state "
                         "failed unexpectedly: sent=%d, errno=%s",
                         (int)clnt_sent,
                         errno_rpc2str(RPC_ERRNO(pco_iut_snd)));
        }

        srvr_recv = rpc_recv(pco_tst, acc_s,
                             srvr_recv_buf, srvr_recv_buf_len, 0);
        if (srvr_recv != clnt_sent)
        {
            TEST_VERDICT("Unexpected number of bytes is received: "
                         "sent=%u, received=%u",
                         (unsigned)clnt_sent, (unsigned)srvr_recv);
        }
        if (memcmp(clnt_send_buf, srvr_recv_buf, clnt_sent) != 0)
        {
            TEST_VERDICT("Data received by the server does not match "
                         "sent from the client");
        }
        
        break;
    }

    while (pco_iut_rcv != NULL)
    {
        RPC_SEND(srvr_sent, pco_tst, acc_s,
                 srvr_send_buf, srvr_send_buf_len, 0);
                
        /*
         * It is wait of recv() in the case of success=during and
         * simple recv() otherwise.
         */
        RPC_AWAIT_IUT_ERROR(pco_iut_rcv);
        clnt_recv = rpc_recv(pco_iut_rcv, iut_s_rcv,
                             clnt_recv_buf, clnt_recv_buf_len, 0);           
        if (clnt_recv == -1 && strcmp(success, "during") == 0)
        {
            CHECK_RPC_ERRNO(pco_iut_rcv, RPC_ENOTCONN,
                            "recv() called for TCP socket in SYN-SENT "
                            "state failed, but");
            RING_VERDICT("recv() called for TCP socket in SYN-SENT "
                         "state failed with errno ENOTCONN");
            break;
        }

        if (clnt_recv != srvr_sent)
        {
            TEST_VERDICT("Unexpected number of bytes is received: "
                         "sent=%u, received=%u",
                         (unsigned)srvr_sent, (unsigned)clnt_recv);
        }
        if (memcmp(srvr_send_buf, clnt_recv_buf, srvr_sent) != 0)
        {
            TEST_VERDICT("Data received by the client does not match "
                         "sent from the server");
        }
        
        break;
    }

/*
 * It is wait of connect() in the case of success=during and
 * send_check=false, simple connect() otherwise.
 */
    pco_iut->timeout = TE_SEC2MS(30);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s1, peer_addr);
    if (rc != 0)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
                        "connect() called on connected TCP socket "
                        "after previously failed connect() failed, "
                        "but");
        RING_VERDICT("connect() called on connected TCP socket "
                     "after previously failed connect() failed "
                     "with errno EISCONN");
    }

    TEST_SUCCESS;

cleanup:
    if (neigh_entry_added)
        CHECK_RC(tapi_route_gateway_repair_tst_gw(&gw));
    /* Do not call CFG_WAIT_CHANGES in hope time till pass in cleanup */

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);

    if (restore_pipe_handler)
        CLEANUP_RPC_SIGACTION(pco_iut_snd, RPC_SIGPIPE, &old_pipe_act, 
                              SIGNAL_REGISTRAR);
    if (restore_sig_handler)
        CLEANUP_RPC_SIGACTION(pco_iut, TST_SIGNAL, &old_sig_act, 
                              SIGNAL_REGISTRAR);
    if (sig_act.mm_mask != RPC_NULL)
    {
        rpc_sigset_delete(pco_iut, sig_act.mm_mask);
        sig_act.mm_mask = RPC_NULL;
    }

    if (csap != CSAP_INVALID_HANDLE)
        CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_gw->ta, 0, csap));

    if (pco_iut_snd != NULL && pco_iut_snd != pco_iut)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_snd));
    if (pco_iut_rcv != NULL && pco_iut_rcv != pco_iut)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_rcv));

    free(clnt_send_buf);
    free(srvr_recv_buf);
    free(srvr_send_buf);
    free(clnt_recv_buf);

    TEST_END;
}
