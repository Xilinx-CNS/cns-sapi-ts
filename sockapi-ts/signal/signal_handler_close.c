/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page signal-signal_handler_close Behavior of close() called by signal handler
 *
 * @objective Check that @b close() called by signal handler works correctly
 *            when signal has been recieved while another function is working
 *            on the process.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_killer    PCO on the same host as @p pco_iut
 * @param pco_gw        PCO on host in the tested network
 *                      that is able to forward incoming packets (router,
 *                      only necessary when testing @b connect() function)
 * @param pco_tst       PCO on TESTER (if we do not test pipes)
 * @p iut_addr          Network address on IUT
 * @p tst_addr          Network address on TESTER (if we do not test pipes)
 * @param func          @b connect(), @b send(), @b write(), @b writev(),
 *                      @b sendfile(), @b recv(), @b read(), @b readv(),
 *                      @b accept(), @b close(), @b select(), @b pselect(),
 *                      @b poll(), @b epoll(), @b epoll_pwait() or
 *                      @b epoll_pwait2() function
 * @param sig_func      @b sigaction(), @b signal(), @b sysv_signal() or @b
 *                      bsd_signal() function
 * @param restart       Set or not @c SA_RESTART flag
 * @param close_aux     Signal handler closes auxiliary or main fd
 * @param test_pipe     Whether to test pipes instead of sockets or not
 *
 * @par Scenario:
 * -# On @p pco_iut PCO install signal handler for @c SIGUSR1 signal
 *    using @p sig_func function with @c SA_RESTART flag if @p restart value
 *    is @c TRUE.
 * -# If @p close_aux is @c TRUE, create @p aux_fd descriptor (file or
 *    socket according to @p test_pipe) on @p pco_iut.
 * -# Create @p iut_fd descriptor on @p pco_iut (and @b bind() it to
 *    @p iut_addr if it is socket).
 * -# If sockets are tested, create @p tst_fd socket on @p pco_tst and
 *    @b bind() it to @p tst_addr; otherwise assign @p tst_fd to the
 *    other end of pipe and @b fork() @p pco_tst from @p pco_iut.
 * -# If sockets are tested but @p func is not @c connect or @c accept
 *    establish connection between IUT and Tester. Obtain @p iut_fd socket
 *    on @p pco_iut.
 * -# If @p func is @c connect, do the following:
 *      - Call @b listen() on @p pco_tst.
 *      - Turn on forwarding on router host.
 *      - Configure routes on IUT and Tester.
 *      - Add static ARP entry to prevent connection establishment.
 *      - Call @b connect() on @p iut_fd socket;
 * -# If @p func is @c close or @c send overfill buffers on @p iut_fd.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Prepare arguments for @b pthread_create() call, that will create
 *    a thread for @p func function;
 * -# Call pthread_create() with appropriately filled arguments;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Sleep for a while to make sure that @p func has started its activity;
 * -# Send @c SIGUSR1 signal to the @p pco_iut process;
 * -# Sleep for a while to make sure that function was unblocked by signal;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# In order to unblock @p func call on IUT do the following:
 *      - If @p func is @c connect delete static ARP entry and sleep for
 *        a while to let the connection be established;
 *      - If @p func is @c accept call @b connect() on @p tst_fd socket;
 *      - If @p func is @c send read all data from @p tst_fd;
 *      - If @p func is @c recv, @c select, @c pselect, @c poll or @c
 *        epoll, @c epoll_pwait, @c epoll_pwait2, and @p close_aux
 *        is @c TRUE or sockets are tested,
 *        send some data from @p tst_fd to @p iut_fd.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b pthread_join() to get @p func return value.
 * -# Check that @p func returned suitable value.
 * -# If @p close_aux is @c TRUE and sockets are tested, check that state
 *    of @p aux_fd socket is @c STATE_CLOSED.
 * -# Else check that state of @p iut_fd socket is @c STATE_CLOSED if
 *    sockets are tested or that @p iut_fd pipe end is really closed if
 *    pipes are tested.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/signal_handler_close"

#include <pthread.h>

#include "sockapi-test.h"
#include "sendfile_common.h"
#include "ts_signal.h"
#include "iomux.h"
#include "tapi_route_gw.h"

#define WAIT_TIME           2
#define TST_READ_TIMEOUT    10 
#define DATA_BULK           4096

/**
 * Maximum length of Onload ZC buffer used by this test.
 * This limitation actually makes sense only for Onload ZC buffers
 * obtained with onload_zc_alloc_buffers(). Those may be larger than
 * 1000 bytes however it seems there is no way to obtain maximum length
 * via API.
 */
#define MAX_ZC_BUF 1000

static uint8_t buf[DATA_BULK];    /**< Auxiliary buffer */
static uint8_t rx_buf[DATA_BULK]; /**< Auxiliary buffer */

typedef enum tst_function {
    tst_read,
    tst_readv,
    tst_write,
    tst_writev,
    tst_connect,
    tst_send,
    tst_onload_zc_send,
    tst_onload_zc_send_user_buf,
    tst_sendfile,
    tst_recv,
    tst_accept,
    tst_select,
    tst_pselect,
    tst_poll,
    tst_ppoll,
    tst_epoll,
    tst_epoll_pwait,
    tst_epoll_pwait2,
    tst_close,
} tst_function;

struct pthread_args
{
    /* Common arguments */
    tst_function    func;       /**< Function */
    rcf_rpc_server *pco;        /**< RPC server */
    int             test_fd;    /**< FD under test */
    int             alloc_fd;   /**< FD used for allocating
                                     and releasing buffers
                                     for ZC functions */

    /* Arguments for connect call */
    const struct sockaddr *addr; /**< Destination address */

    /* Arguments for sendfile call */
    int file_fd;

    /* Arguments for iomux call */
    iomux_call_type iomux; /**< Type of function to be called */
    iomux_evt_fd   *event; /**< Array of event request records */
    rpc_sigset_p    sigmask;

    te_errno prev_errno; /**< Previous errno value on RPC server */
};

enum close_func
{
    CLOSE_BY_CLOSE = 0,
    CLOSE_BY_DUP2 = 1,
    CLOSE_BY_SHUTDOWN = 2,
};

/*
 * Generate pthread_args structure.
 *
 * @param name     Name of function to be called
 * @param pco      PCO
 * @param test_fd  FD for calling function
 * @param addr     Pointer to the address for calling function
 * @param iomux    Type of function to be called
 * @param event    Array of event request records
 * @param sigmask  Sigmask to use in iomux_call()
 *
 * @return Pointer to filled pthread_args structure
 */
static struct pthread_args *
generate_args(tst_function func, rcf_rpc_server *pco,
              int test_fd, const struct sockaddr *addr,
              iomux_call_type iomux, iomux_evt_fd *event,
              rpc_sigset_p sigmask)
{
    struct pthread_args *args;
    args = (struct pthread_args *)tapi_calloc(
                                        sizeof(struct pthread_args),
                                        1);
    args->func = func;
    args->pco = pco;
    args->test_fd = test_fd;
    args->addr = addr;
    args->event = event;
    args->iomux = iomux;
    args->sigmask = sigmask;

    return (void *)args;
}

/*
 * Function to be passed to pthread_create()
 */
static void *
launch_func(void *data)
{
    long int  rc;
    struct pthread_args *args = (struct pthread_args *)data;

    te_bool saved_errno_change_check = args->pco->errno_change_check;

    /*
     * Disable automatic errno change checking so that the test can
     * check it and print verdict.
     */
    args->pco->errno_change_check = FALSE;
    args->prev_errno = RPC_ERRNO(args->pco);

    RPC_AWAIT_ERROR(args->pco);
    switch (args->func)
    {
        case tst_connect:
            rc = rpc_connect(args->pco, args->test_fd, args->addr);
            break;

        case tst_accept:
            rc = rpc_accept(args->pco, args->test_fd, NULL, NULL);
            break;

        case tst_send:
            rc = rpc_send(args->pco, args->test_fd, buf, DATA_BULK, 0);
            break;

        case tst_onload_zc_send:
        case tst_onload_zc_send_user_buf:
        {
            rpc_msghdr msg;
            rpc_iovec iov[DATA_BULK / MAX_ZC_BUF + 1];
            unsigned int i;
            unsigned int remained_len = DATA_BULK;

            memset(&msg, 0, sizeof(msg));
            memset(&iov, 0, sizeof(iov));

            for (i = 0; i < TE_ARRAY_LEN(iov) && remained_len > 0; i++)
            {
                iov[i].iov_base = buf + MAX_ZC_BUF * i;
                iov[i].iov_len = MIN(MAX_ZC_BUF, remained_len);
                iov[i].iov_rlen = iov[i].iov_len;
                remained_len -= iov[i].iov_len;
            }

            msg.msg_iov = iov;
            msg.msg_iovlen = msg.msg_riovlen = i;

            /*
             * In case of onload_zc_send() we should allocate/register
             * ZC buffer before sending and release/unregister it after
             * sending (unless we got it with onload_zc_alloc_buffers()
             * and it was sent successfully). FD passed to ZC buffer
             * management functions just serves to indicate Onload stack,
             * so we use a different FD for this purpose here to avoid
             * failure to release/unregister ZC buffer after the socket
             * FD used for sending is closed in a signal handler.
             */

            if (args->func == tst_onload_zc_send_user_buf)
            {
                rc = rpc_simple_zc_send_sock_user_buf(
                                        args->pco, args->test_fd,
                                        &msg, 0, args->alloc_fd);
            }
            else
            {
                rc = rpc_simple_zc_send_sock(
                                        args->pco, args->test_fd,
                                        &msg, 0, args->alloc_fd);
            }
            break;
        }

        case tst_sendfile:
        {
            tarpc_off_t offset = 0;
            rc = rpc_sendfile(args->pco, args->test_fd, args->file_fd,
                              &offset, DATA_BULK, FALSE);
            break;
        }

        case tst_write:
            rc = rpc_write(args->pco, args->test_fd, buf, DATA_BULK);
            break;

        case tst_writev:
            rc = rpc_send_func_writev(args->pco, args->test_fd, buf,
                                      DATA_BULK, 0);
            break;

        case tst_close:
            rc = rpc_close(args->pco, args->test_fd);
            break;

        case tst_recv:
            rc = rpc_recv(args->pco, args->test_fd, buf, DATA_BULK, 0);
            break;

        case tst_read:
            rc = rpc_read(args->pco, args->test_fd, buf, DATA_BULK);
            break;

        case tst_readv:
            rc = rpc_recv_func_readv(args->pco, args->test_fd, buf,
                                     DATA_BULK, 0);
            break;

        case tst_select:
        case tst_pselect:
        case tst_poll:
        case tst_ppoll:
        case tst_epoll:
        case tst_epoll_pwait:
        case tst_epoll_pwait2:
            {
                tarpc_timeval           tv = {3, 0};
                rc = iomux_call_signal(args->iomux, args->pco,
                                       args->event, 1, &tv, args->sigmask);
            }
            break;
    }

    args->pco->errno_change_check = saved_errno_change_check;

    return (void *)rc;
}


/**
 * Resolve function name.
 *
 * @param name  Function name
 *
 * @return Corresponding tst_function enum value.
 */
tst_function
resolve_func(const char *name)
{
#define IF_CASE(func_) \
    if (strcmp(name, #func_) == 0) \
        return tst_##func_

    IF_CASE(connect);
    else IF_CASE(read);
    else IF_CASE(readv);
    else IF_CASE(write);
    else IF_CASE(writev);
    else IF_CASE(send);
    else IF_CASE(onload_zc_send);
    else IF_CASE(onload_zc_send_user_buf);
    else IF_CASE(sendfile);
    else IF_CASE(recv);
    else IF_CASE(accept);
    else IF_CASE(select);
    else IF_CASE(pselect);
    else IF_CASE(poll);
    else IF_CASE(ppoll);
    else IF_CASE(epoll);
    else IF_CASE(epoll_pwait);
    else IF_CASE(epoll_pwait2);
    else IF_CASE(close);
    else
        TEST_FAIL("Unexpected func parameter value, %s", name);

    return -1; /* Unreachable */
#undef IF_CASE
}

int
main(int argc, char *argv[])
{
    int                     tst_fd = -1;
    int                     iut_fd = -1;
    int                     tmp_iut_s = -1;
    int                     tmp_iut_pipe = -1;
    int                     aux_fd = -1;
    int                     tmp_fd = -1;
    int                     dup_s = -1;
    int                     alloc_fd = -1;
    int                     pipefds[2] = {-1, -1};

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_gw = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *gw_iut_addr = NULL;
    const struct sockaddr  *gw_tst_addr = NULL;
    const void             *alien_link_addr;

    const struct if_nameindex *tst_if = NULL;

    const char             *func;
    const char             *sig_func;
    const char             *close_func;

    tst_function            function;
    tarpc_linger            opt_val;
    uint64_t                total_filled = 0;
    iomux_call_type         iomux;
    iomux_evt_fd            event;

    DEFINE_RPC_STRUCT_SIGACTION(oldsa);

    te_bool                 restore = FALSE;

    const char *file_iut = NULL;

    te_bool                 restart = FALSE;
    te_bool                 close_aux = TRUE;
    te_bool                 route1_set = FALSE;
    te_bool                 route2_set = FALSE;
    te_bool                 test_pipe = FALSE;

    pthread_t               thread;
    struct pthread_args    *args;
    rpc_socket_domain       domain;

    pid_t   pco_iut_pid;

    rpc_sigset_p iomux_sigmask = RPC_NULL;

    te_bool     is_failed = FALSE;

    enum close_func close_func_;
    tarpc_ssize_t   iut_sizeof_int;

    int iut_errno;
    int sighandler_close_failed;
    int sighandler_close_errno;

    /* Test preambule */
    TEST_START;
    TEST_GET_STRING_PARAM(func);
    TEST_GET_STRING_PARAM(sig_func);
    TEST_GET_STRING_PARAM(close_func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_BOOL_PARAM(test_pipe);
    if (!test_pipe)
    {
        TEST_GET_PCO(pco_tst);
        TEST_GET_ADDR(pco_tst, tst_addr);
        TEST_GET_ADDR(pco_iut, iut_addr);
        domain = rpc_socket_domain_by_addr(iut_addr);
    }
    else
        domain = RPC_PF_INET;

    function = resolve_func(func);

    if (function == tst_connect)
    {
        TEST_GET_PCO(pco_gw);
        TEST_GET_ADDR_NO_PORT(gw_iut_addr);
        TEST_GET_ADDR_NO_PORT(gw_tst_addr);
        TEST_GET_LINK_ADDR(alien_link_addr);
        TEST_GET_IF(tst_if);
    }
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_BOOL_PARAM(close_aux);

    pco_iut_pid = rpc_getpid(pco_iut);

    if (strcmp(close_func, "close") == 0)
        close_func_ = CLOSE_BY_CLOSE;
    else if (strcmp(close_func, "dup2") == 0)
        close_func_ = CLOSE_BY_DUP2;
    else
        close_func_ = CLOSE_BY_SHUTDOWN;

    /* Scenario */
    /* Register signal handler */
    if (strcmp(sig_func, "signal") == 0 ||
        strcmp(sig_func, "sysv_signal") == 0)
    {
        rpc_sigaction_init(pco_iut, &oldsa);
        rpc_sigaction(pco_iut, RPC_SIGUSR1, NULL, &oldsa);
        if (strcmp(sig_func, "signal") == 0)
            rpc_signal(pco_iut, RPC_SIGUSR1, "sighandler_close");
        else 
            rpc_sysv_signal(pco_iut, RPC_SIGUSR1, "sighandler_close");
    }
    else
    {
        tapi_set_sighandler(pco_iut, RPC_SIGUSR1, "sighandler_close",
                            sig_func, restart, &oldsa);
    }
    restore = TRUE;

    /* Create FDs */
    if (close_aux)
    {
        if (!test_pipe)
            aux_fd = rpc_socket(pco_iut, domain,
                                RPC_SOCK_STREAM, RPC_PROTO_DEF);
        else
        {
            rpc_pipe(pco_iut, pipefds);
            aux_fd = pipefds[0];
            tmp_iut_pipe = pipefds[1];
        }
    }
    if (!test_pipe)
    {
        iut_fd = rpc_socket(pco_iut, domain,
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_iut, iut_fd, iut_addr);
        tst_fd = rpc_socket(pco_tst, domain,
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst_fd, tst_addr);
    }
    else
    {
        rpc_pipe(pco_iut, pipefds);
        if (function == tst_write || function == tst_writev ||
            function == tst_sendfile)
        {
            iut_fd = pipefds[1];
            tst_fd = pipefds[0];
        }
        else
        {
            iut_fd = pipefds[0];
            tst_fd = pipefds[1];
        }
        rcf_rpc_server_fork_exec(pco_iut, "pco_tst", &pco_tst);
        rpc_close(pco_iut, tst_fd);
        rpc_close(pco_tst, iut_fd);
    }
    tmp_fd = close_aux ? aux_fd : iut_fd;

    if (function == tst_onload_zc_send ||
        function == tst_onload_zc_send_user_buf)
    {
        alloc_fd = rpc_socket(pco_iut, domain,
                              RPC_SOCK_STREAM, RPC_PROTO_DEF);
    }

    if (function != tst_connect && function != tst_accept && !test_pipe)
    {
        rpc_listen(pco_iut, iut_fd, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_tst, tst_fd, iut_addr);
        tmp_iut_s = rpc_accept(pco_iut, iut_fd, NULL, NULL);
        rpc_close(pco_iut, iut_fd);
        iut_fd = tmp_iut_s;
        tmp_iut_s = -1;
        if (!close_aux)
            tmp_fd = iut_fd;
    }

    /* Set value to the 'sock4cl' variable */
    iut_sizeof_int = rpc_get_sizeof(pco_iut, "int");
    rpc_set_var(pco_iut, "sock4cl", iut_sizeof_int, tmp_fd);
    rpc_set_var(pco_iut, "close_func", iut_sizeof_int, close_func_);
    if (close_func_ == CLOSE_BY_DUP2)
    {
        dup_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_set_var(pco_iut, "fd2dup", iut_sizeof_int, dup_s);
    }

    if (function == tst_ppoll || function == tst_pselect ||
        function == tst_epoll_pwait || function == tst_epoll_pwait2)
    {
        iomux_sigmask = rpc_sigset_new(pco_iut);
        rpc_sigemptyset(pco_iut, iomux_sigmask);
        rpc_sigaddset(pco_iut, iomux_sigmask, RPC_SIGPIPE);
    }
    switch (function)
    {
        case tst_connect:
            rpc_listen(pco_tst, tst_fd, SOCKTS_BACKLOG_DEF);

            /* Turn on forwarding on router host */
            CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                          "net/ipv4/ip_forward"));

            /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw_iut_addr' */
            if (tapi_cfg_add_route_via_gw(pco_iut->ta,
                    tst_addr->sa_family,
                    te_sockaddr_get_netaddr(tst_addr),
                    te_netaddr_get_size(tst_addr->sa_family) * 8,
                    te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
            {
                TEST_FAIL("Cannot add route to the dst");
            }
            route1_set = TRUE;

            /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw_tst_addr' */
            if (tapi_cfg_add_route_via_gw(pco_tst->ta,
                    iut_addr->sa_family,
                    te_sockaddr_get_netaddr(iut_addr),
                    te_netaddr_get_size(iut_addr->sa_family) * 8,
                    te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
            {
                TEST_FAIL("Cannot add route to the src");
            }
            route2_set = TRUE;
            CFG_WAIT_CHANGES;

            /* Add static ARP entry to prevent connection establishment */
            CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                                     gw_tst_addr, CVT_HW_ADDR(alien_link_addr),
                                     TRUE));
            CFG_WAIT_CHANGES;

            args = generate_args(function, pco_iut, iut_fd,
                                 tst_addr, 0, NULL, RPC_NULL);
            break;

        case tst_accept:
            rpc_listen(pco_iut, iut_fd, SOCKTS_BACKLOG_DEF);
            args = generate_args(function, pco_iut, iut_fd, NULL, 0, NULL,
                                 RPC_NULL);
            break;

        case tst_send:
        case tst_onload_zc_send:
        case tst_onload_zc_send_user_buf:
            rpc_overfill_buffers(pco_iut, iut_fd, &total_filled);
            args = generate_args(function, pco_iut, iut_fd, NULL, 0, NULL,
                                 RPC_NULL);
            break;

        case tst_write:
        case tst_writev:
            if (!test_pipe)
                rpc_overfill_buffers(pco_iut, iut_fd, &total_filled);
            else
                rpc_overfill_fd(pco_iut, iut_fd, &total_filled);
            args = generate_args(function, pco_iut, iut_fd, NULL, 0, NULL,
                                 RPC_NULL);
            break;

        case tst_sendfile:
            if (!test_pipe)
                rpc_overfill_buffers(pco_iut, iut_fd, &total_filled);
            else
                rpc_overfill_fd(pco_iut, iut_fd, &total_filled);
            file_iut = "sendfile.pco_iut";
            CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'M', DATA_BULK);
            args = generate_args(function, pco_iut, iut_fd, NULL, 0, NULL,
                                 RPC_NULL);
            RPC_FOPEN_D(args->file_fd, args->pco, file_iut, RPC_O_RDONLY, 0);
            break;

        case tst_close:
            rpc_overfill_buffers(pco_iut, iut_fd, &total_filled);

            /* Switch on SO_LINGER socket option */
            opt_val.l_onoff  = 1;
            opt_val.l_linger = WAIT_TIME;
            rpc_setsockopt(pco_iut, iut_fd, RPC_SO_LINGER, &opt_val);

            rpc_getsockopt(pco_iut, iut_fd, RPC_SO_LINGER, &opt_val);
            if (opt_val.l_onoff == 0 || opt_val.l_linger != WAIT_TIME)
                TEST_FAIL("The value of SO_LINGER socket option is not "
                          "updated by setsockopt() function");

            args = generate_args(function, pco_iut, iut_fd, NULL, 0, NULL,
                                 RPC_NULL);
            break;

        case tst_read:
        case tst_readv:
        case tst_recv:
            args = generate_args(function, pco_iut, iut_fd, NULL, 0, NULL,
                                 RPC_NULL);
            break;

        case tst_select:
        case tst_pselect:
        case tst_poll:
        case tst_ppoll:
        case tst_epoll:
        case tst_epoll_pwait:
        case tst_epoll_pwait2:
            iomux = iomux_call_str2en(func);
            event.fd = iut_fd;
            event.events = EVT_RD;
            args = generate_args(function, pco_iut, 0, NULL, iomux, &event,
                                 iomux_sigmask);
            break;
    }

    args->alloc_fd = alloc_fd;

    if (pthread_create(&thread, NULL, launch_func, args) < 0)
    {
        rc = errno;
        TEST_FAIL("Failed to create thread for %s", func);
    }

    TAPI_WAIT_NETWORK;
    /* Send signal to the process */
    rpc_kill(pco_killer, pco_iut_pid, RPC_SIGUSR1);
    TAPI_WAIT_NETWORK;

    /* Unblock blocking function on IUT */
    switch (function)
    {
        case tst_connect:
            /* Delete static ARP entry */
            CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                              gw_tst_addr));
            CFG_WAIT_CHANGES;
            break;

        case tst_accept:
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rc = rpc_connect(pco_tst, tst_fd, iut_addr);
            if (!close_aux)
            {
                if(rc != -1)
                    ERROR_VERDICT("Connection established, though "
                                  "the socket should be closed");
                else
                    CHECK_RPC_ERRNO(pco_tst, RPC_ECONNREFUSED,
                                    "connect() returned -1, but");
            }
            break;

        case tst_write:
        case tst_writev:
        case tst_send:
        case tst_onload_zc_send:
        case tst_onload_zc_send_user_buf:
        case tst_sendfile:
            {
                unsigned total = 0;
                te_bool readable = TRUE;
                do
                {
                    rc = rpc_read(pco_tst, tst_fd, rx_buf, DATA_BULK);
                    if (rc <= 0)
                        break;
                    total += rc;
                    if (total == total_filled + DATA_BULK)
                    {
                        rc = 0;
                        break;
                    }

                    RPC_GET_READABILITY(readable, pco_tst, tst_fd,
                                        TST_READ_TIMEOUT);
                } while (readable);
            }
            break;

        case tst_read:
        case tst_readv:
        case tst_recv:
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rpc_write(pco_tst, tst_fd, "1", sizeof("1"));
            break;

        default:
            break;
    }

#define CHECK_RC_ERRNO(_exp_rc, _exp_errno) \
    do {                                                                \
        if ((_exp_rc) >= 0)                                             \
        {                                                               \
            if (rc != (_exp_rc))                                        \
            {                                                           \
                if (rc >= 0)                                            \
                    TEST_VERDICT("%s() return code is wrong "           \
                                 "(%d instead %d), probably due to "    \
                                 "data corruption.", func, rc,          \
                                 (_exp_rc));                            \
                else                                                    \
                    TEST_VERDICT("%s() unexpectedly failed and set "    \
                                 "errno to %s", func,                   \
                                 errno_rpc2str(iut_errno));             \
            }                                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            if (rc != (_exp_rc))                                        \
            {                                                           \
                if (rc >= 0)                                            \
                    TEST_VERDICT("%s() unexpectedly succeeded", func);  \
                else if ((_exp_errno) == iut_errno)                     \
                    RING_VERDICT("%s() failed with wrong rc "           \
                                 "(%d instead %d), but errno is set "   \
                                 "correctly", func, rc, (_exp_rc));     \
                else                                                    \
                    TEST_VERDICT("%s() failed with wrong rc and errno " \
                                 "(%d instead %d and %s instead %s)",   \
                                 func, rc, (_exp_rc),                   \
                                 errno_rpc2str(iut_errno),              \
                                 errno_rpc2str(_exp_errno));            \
            }                                                           \
            else                                                        \
            {                                                           \
                if ((_exp_errno) != iut_errno)                          \
                    TEST_VERDICT("%s() failed with wrong errno "        \
                                 "(%s instead %s)", func,               \
                                 errno_rpc2str(iut_errno),              \
                                 errno_rpc2str(_exp_errno));            \
            }                                                           \
        }                                                               \
    } while (0)

    if (pthread_join(thread, (void **)&rc) != 0)
        TEST_FAIL("Joining of test thread failed");
    if (rc == -1 && TE_RC_GET_ERROR(pco_iut->_errno) == TE_ERPCTIMEOUT)
        TEST_VERDICT("Test function is hanging");

    if (pco_iut->err_msg[0] != '\0')
    {
        RING_VERDICT("The following error was reported after calling "
                     "the test function: " RPC_ERROR_FMT,
                     RPC_ERROR_ARGS(pco_iut));
    }

    iut_errno = RPC_ERRNO(pco_iut);

    if (rc >= 0 && iut_errno != args->prev_errno)
    {
        ERROR_VERDICT("The checked function succeeded but changed errno to "
                      RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
        is_failed = TRUE;
    }

    sighandler_close_failed = rpc_get_var(pco_iut,
                                          "sighandler_close_failed",
                                          iut_sizeof_int);
    sighandler_close_errno = rpc_get_var(pco_iut,
                                         "sighandler_close_errno",
                                         iut_sizeof_int);
    if (sighandler_close_failed != 0)
    {
        ERROR_VERDICT("Closing function in signal handler failed with "
                      "errno %r", sighandler_close_errno);
        is_failed = TRUE;
    }

    if (restart && (close_aux || close_func_ != CLOSE_BY_CLOSE))
    {
        switch (function)
        {
            case tst_write:
            case tst_writev:
            case tst_send:
            case tst_onload_zc_send:
            case tst_onload_zc_send_user_buf:
            case tst_sendfile:
                switch (close_func_)
                {
                    case CLOSE_BY_CLOSE:
                        CHECK_RC_ERRNO(DATA_BULK, 0);
                        break;

                    case CLOSE_BY_DUP2:
                    case CLOSE_BY_SHUTDOWN:
                        CHECK_RC_ERRNO(-1, RPC_EPIPE);
                        break;
                }
                break;

            case tst_read:
            case tst_readv:
            case tst_recv:
                switch (close_func_)
                {
                    case CLOSE_BY_CLOSE:
                        CHECK_RC_ERRNO((int)sizeof("1"), 0);
                        break;

                    case CLOSE_BY_DUP2:
                        CHECK_RC_ERRNO(-1, RPC_ENOTCONN);
                        break;

                    case CLOSE_BY_SHUTDOWN:
                        CHECK_RC_ERRNO(0, 0);
                        break;
                }
                break;

            case tst_accept:
                if (close_func_ != CLOSE_BY_CLOSE)
                    CHECK_RC_ERRNO(-1, RPC_EINVAL);
                else if (rc < 0)
                {
                    TEST_VERDICT("accept() unexpectedly failed "
                                 "with errno %r", iut_errno);
                    iut_fd = -1;
                }
                else
                    iut_fd = rc;
                break;

            case tst_connect:
                if (rc < 0)
                {
                    TEST_VERDICT("connect() unexpectedly failed "
                                 "with errno %r", iut_errno);
                    iut_fd = -1;
                }
                break;

            case tst_close:
                CHECK_RC_ERRNO(0, 0);
                iut_fd = -1;
                break;

            case tst_select:
            case tst_pselect:
            case tst_poll:
            case tst_ppoll:
            case tst_epoll:
            case tst_epoll_pwait:
            case tst_epoll_pwait2:
                CHECK_RC_ERRNO(-1, RPC_EINTR);
                break;
        }
    }
    else if (restart && (!close_aux))
    {
        switch (function)
        {
            case tst_write:
            case tst_writev:
            case tst_send:
            case tst_onload_zc_send:
            case tst_onload_zc_send_user_buf:
            case tst_sendfile:
                CHECK_RC_ERRNO(-1, RPC_EBADF);
                break;

            case tst_read:
            case tst_readv:
            case tst_recv:
                CHECK_RC_ERRNO(-1, RPC_EBADF);
                break;

            case tst_close:
                CHECK_RC_ERRNO(-1, TE_RC(TE_TAPI, TE_ECORRUPTED));
                iut_fd = -1;
                break;

            case tst_accept:
                if (rc >= 0)
                    iut_fd = rc;
            case tst_connect:
                if (rc < 0)
                    iut_fd = -1;
                CHECK_RC_ERRNO(-1, RPC_EBADF);
                break;

            case tst_select:
            case tst_pselect:
            case tst_poll:
            case tst_ppoll:
            case tst_epoll:
            case tst_epoll_pwait:
            case tst_epoll_pwait2:
                CHECK_RC_ERRNO(-1, RPC_EINTR);
                break;
        }
    }
    else
    {
        switch (function)
        {
            case tst_close:
                iut_fd = -1;
                if (close_aux || close_func_ == CLOSE_BY_DUP2)
                    CHECK_RC_ERRNO(0, 0);
                else
                    CHECK_RC_ERRNO(-1, TE_RC(TE_TAPI, TE_ECORRUPTED));
                break;

            case tst_accept:
                if (rc >= 0)
                    iut_fd = rc;
            case tst_connect:
                if (rc < 0)
                    iut_fd = -1;
            case tst_write:
            case tst_writev:
            case tst_send:
            case tst_onload_zc_send:
            case tst_onload_zc_send_user_buf:
            case tst_sendfile:
            case tst_read:
            case tst_readv:
            case tst_recv:
                CHECK_RC_ERRNO(-1, RPC_EINTR);
                break;

            case tst_select:
            case tst_pselect:
            case tst_poll:
            case tst_ppoll:
            case tst_epoll:
            case tst_epoll_pwait:
            case tst_epoll_pwait2:
                CHECK_RC_ERRNO(-1, RPC_EINTR);
                break;
        }
    }

    /* Check socket state */

    if (!test_pipe)
    {
        switch (close_func_)
        {
            case CLOSE_BY_CLOSE:
                if (function != tst_accept || tmp_fd != iut_fd)
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            STATE_CLOSED);
                else
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            STATE_CONNECTED);
                break;

            case CLOSE_BY_DUP2:
                if (function == tst_connect && restart)
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            STATE_CONNECTED);
                else
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            STATE_CLEAR);
                break;

            case CLOSE_BY_SHUTDOWN:
                if (function == tst_connect)
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            restart ? STATE_CONNECTED : STATE_BOUND);
                else if (function == tst_recv || function == tst_readv ||
                         function == tst_read || function == tst_accept)
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            STATE_BOUND);
                else /* send functions */
                    CHECK_SOCKET_STATE_AND_RETURN_VERDICT(
                            pco_iut, tmp_fd, NULL, -1,
                            STATE_SHUT_RDWR);
                break;
        }
    }
    else
    {
        rcf_rpc_server *pco_tmp = NULL;
        rpc_errno       exp_errno;

        if (iut_fd == pipefds[0])
        {
            RPC_AWAIT_IUT_ERROR(pco_tst);
            rc = rpc_write(pco_tst, tst_fd, buf, DATA_BULK);
            pco_tmp = pco_tst;
            exp_errno = RPC_EPIPE;
        }
        else
        {
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_write(pco_iut, iut_fd, buf, DATA_BULK);
            pco_tmp = pco_iut;
            if (close_func_ == CLOSE_BY_DUP2)
                exp_errno = RPC_EPIPE;
            else
                exp_errno = RPC_EBADF;
        }

        if (close_aux && rc < 0 && RPC_ERRNO(pco_tmp) == (int)exp_errno)
        {
            ERROR_VERDICT("Pipe fd was closed but we closed another fd");
            is_failed = TRUE;
        }
        else if (!close_aux && rc >= 0)
        {
            ERROR_VERDICT("Pipe fd was not closed");
            is_failed = TRUE;
        }

        if (rc < 0 && RPC_ERRNO(pco_tmp) != (int)exp_errno)
        {
            ERROR_VERDICT("write() on pipe fd failed with strange errno %s",
                          errno_rpc2str(RPC_ERRNO(pco_tmp)));
            is_failed = TRUE;
        }
    }

    if (close_aux)
        aux_fd = -1;
    else
        iut_fd = -1;

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (function == tst_ppoll || function == tst_pselect ||
        function == tst_epoll_pwait || function == tst_epoll_pwait2)
        rpc_sigset_delete(pco_iut, iomux_sigmask);

    if (function == tst_connect)
    {
        if (route1_set)
        {
            if (tapi_cfg_del_route_via_gw(pco_iut->ta,
                tst_addr->sa_family,
                te_sockaddr_get_netaddr(tst_addr),
                te_netaddr_get_size(tst_addr->sa_family) * 8,
                te_sockaddr_get_netaddr(gw_iut_addr)) != 0)
            {
                ERROR("Cannot delete first route");
                result = EXIT_FAILURE;
            }
        }

        if (route2_set)
        {
            if (tapi_cfg_del_route_via_gw(pco_tst->ta,
                iut_addr->sa_family,
                te_sockaddr_get_netaddr(iut_addr),
                te_netaddr_get_size(iut_addr->sa_family) * 8,
                te_sockaddr_get_netaddr(gw_tst_addr)) != 0)
            {
                ERROR("Cannot delete second route");
                result = EXIT_FAILURE;
            }
        }
    }
    else if (function == tst_sendfile && file_iut != NULL)
    {
        if (args != NULL)
            CLEANUP_RPC_CLOSE(pco_iut, args->file_fd);
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    }

    if (restore)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rpc_siginterrupt(pco_iut, RPC_SIGUSR1, 0);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_sigaction(pco_iut, RPC_SIGUSR1, &oldsa, NULL) < 0)
            result = -1;
    }

    rpc_sigaction_release(pco_iut, &oldsa);

    CLEANUP_RPC_CLOSE(pco_iut, dup_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    CLEANUP_RPC_CLOSE(pco_iut, aux_fd);
    CLEANUP_RPC_CLOSE(pco_iut, tmp_iut_pipe);
    CLEANUP_RPC_CLOSE(pco_tst, tst_fd);
    CLEANUP_RPC_CLOSE(pco_iut, alloc_fd);

    if (test_pipe && pco_tst != NULL)
        rcf_rpc_server_destroy(pco_tst);

    TEST_END;
}
