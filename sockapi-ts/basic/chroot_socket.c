/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-chroot_socket Socket workability after chrooting
 *
 * @objective Create socket (establish connection for TCP), call @c chroot()
 *            and perform @p action. Check that data transmission works
 *            correctly after all.
 *
 * @type conformance
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param sock_type Socket type:
 *                  - SOCK_STREAM
 *                  - SOCK_DGRAM
 * @param sock_flag Socket flag set on IUT socket creation:
 *                  - none: don't set flags
 *                  - nonblock: SOCK_NONBLOCK
 *                  - cloexec: SOCK_CLOEXEC
 * @param action    Action to perform after chrooting:
 *                  - none
 *                  - fork
 *                  - exec
 *                  - forkexec
 * @param sock_before If @c FALSE - don't create the socket before
 *                    @b chroot(), but create it after that.
 * @param test_epoll  Determines if epoll is tested and calls sequence -
 *                    create epoll fd @c before or @c  after the chrooting. \n
 *                    Values (in couples with @p epoll_func):
 *                    - none
 *                    - before
 *                    - before
 *                    - before
 *                    - after
 *                    - after
 *                    - after
 * @param epoll_func  Tested epoll function:
 *                    - none
 *                    - epoll
 *                    - epoll_pwait
 *                    - epoll_pwait2
 *                    - epoll
 *                    - epoll_pwait
 *                    - epoll_pwait2
 *
 * @par Test sequence:
 *
 * -# If @p sock_before, create a pair of connected sockets
 *    (@p iut_s1 on @p pco_iut, @p tst_s1 on @p pco_tst)
 *    according to @p sock_type and @p sock_flag parameters.
 * -# Call @b chroot() changing root dir to TA folder for
 *    @p pco_iut.
 * -# Perform @p action.
 * -# Create a(nother) pair of connected sockets (@p iut_s1 on
 *    @p pco_iut2, @p tst_s1 on @p pco_tst), where  @p pco_iut2 is
 *    @p pco_iut if @b fork() was not used or its child process
 *    otherwise.
 * -# Check that created socket(s) are usable and behave according
 *    to @p sock_flag parameter.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/chroot_socket"

#include "sockapi-test.h"
#include "tapi_sockets.h"
#include "check_sock_flags.h"
#include "onload.h"
#include "iomux.h"

enum {
    FLAG_NONE,
    FLAG_NONBLOCK,
    FLAG_CLOEXEC
};

enum {
    ACT_NONE,
    ACT_FORK,
    ACT_EXEC,
    ACT_FORKEXEC
};

enum {
    EPOLL_NONE,
    EPOLL_BEFORE,
    EPOLL_AFTER
};

#define SOCK_FLAGS \
    {"none", FLAG_NONE},            \
    {"nonblock", FLAG_NONBLOCK},    \
    {"cloexec", FLAG_CLOEXEC}

#define ACTIONS \
    {"none", ACT_NONE},             \
    {"fork", ACT_FORK},             \
    {"exec", ACT_EXEC},             \
    {"forkexec", ACT_FORKEXEC}

#define TEST_EPOLL \
    {"none", EPOLL_NONE},           \
    {"before", EPOLL_BEFORE},       \
    {"after", EPOLL_AFTER}

#define CHECK_SOCK_TRANSMIT(pco1_, pco2_, s1_, s2_, s1_name_, \
                            s2_name_, msg_) \
    do {                                                                \
        int sent_;                                                      \
        memset(wr_buf, 0, wr_buflen);                                   \
        RPC_AWAIT_IUT_ERROR(pco1_);                                     \
        sent_ = rpc_send(pco1_, s1_, wr_buf, wr_buflen, 0);             \
        TAPI_WAIT_NETWORK;                                              \
        if (sent_ < 0)                                                  \
        {                                                               \
            ERROR_VERDICT("%s, %s: send() failed with errno %s",        \
                          msg_, s1_name_,                               \
                          errno_rpc2str(RPC_ERRNO(pco1_)));             \
            is_failed = TRUE;                                           \
        }                                                               \
        else if (sent_ != (int)wr_buflen)                               \
        {                                                               \
            ERROR_VERDICT("%s, %s: unexpected amount of "               \
                          "data was sent", msg_, s1_name_);             \
            is_failed = TRUE;                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            RPC_AWAIT_IUT_ERROR(pco2_);                                 \
            rc = rpc_recv(pco2_, s2_, rd_buf, rd_buflen, 0);            \
            if (rc < 0)                                                 \
            {                                                           \
                ERROR_VERDICT("%s, %s: recv() failed with errno %s",    \
                              msg_, s2_name_,                           \
                              errno_rpc2str(RPC_ERRNO(pco2_)));         \
                is_failed = TRUE;                                       \
            }                                                           \
            else if (rc != (int)wr_buflen ||                            \
                     memcmp(rd_buf, wr_buf, wr_buflen) != 0)            \
            {                                                           \
                ERROR_VERDICT("%s, %s: Incorrect data was received",    \
                              msg_, s2_name_);                          \
                is_failed = TRUE;                                       \
            }                                                           \
        }                                                               \
    } while (0)

#define CHECK_SOCK_NONBLOCK(pco_, s_, s_name_) \
    do {                                                            \
        te_bool         done_;                                      \
                                                                    \
        pco_->op = RCF_RPC_CALL;                                    \
        rpc_recv(pco_, s_, wr_buf, wr_buflen, 0);                   \
        rcf_rpc_server_is_op_done(pco_, &done_);                    \
        if (!done_)                                                 \
        {                                                           \
            TAPI_WAIT_NETWORK;                                      \
            rcf_rpc_server_is_op_done(pco_, &done_);                \
        }                                                           \
        if (!done_)                                                 \
        {                                                           \
            if (pco_iut2 == pco_)                                   \
            {                                                       \
                iut_s2 = -1;                                        \
                iut2_s1 = -1;                                       \
            }                                                       \
            if (pco_iut == pco_)                                    \
                iut_s1 = -1;                                        \
            rcf_rpc_server_restart(pco_);                           \
            TEST_VERDICT("%s is blocking", s_name_);                \
        }                                                           \
        pco_->op = RCF_RPC_WAIT;                                    \
        RPC_AWAIT_IUT_ERROR(pco_);                                  \
        rc = rpc_recv(pco_, s_, wr_buf, wr_buflen, 0);              \
        if (rc != -1)                                               \
        {                                                           \
            ERROR_VERDICT("%s: recv() returned strange result",     \
                          s_name_);                                 \
            is_failed = TRUE;                                       \
        }                                                           \
        else if (RPC_ERRNO(pco_) != RPC_EAGAIN)                     \
        {                                                           \
            ERROR_VERDICT("%s: recv() returned unexpected "         \
                          "errno %s", s_name_,                      \
                          errno_rpc2str(RPC_ERRNO(pco_)));          \
            is_failed = TRUE;                                       \
        }                                                           \
    } while (0)

/*
 * Be careful: iut_s2 can be the same as iut_s1 if iut_s1 is closed
 * on exec() in child process.
 */
#define SOCK_NAME(pco_, fd_) \
    (fd_ < 0 ? "incorrect fd" :                                           \
        ((fd_ == iut_s2 && pco_ == pco_iut2) ?                            \
         "IUT socket created after chroot()" :                            \
        ((fd_ == iut_s1 && !(pco_ == pco_iut2 &&                          \
                             sock_flag == FLAG_CLOEXEC &&                 \
                             action == ACT_FORKEXEC)) ?                   \
         "IUT socket created before chroot()" :                           \
        (fd_ == tst_s2 ? "Peer of IUT socket created after chroot()" :    \
        (fd_ == tst_s1 ? "Peer of IUT socket created before chroot()" :   \
                        "unknown fd")))))

#define CHECK_EPOLL(pco_, first_sock_, second_sock_, msg_) \
    do {                                                                \
        te_bool first_sent_ = FALSE;                                    \
        te_bool second_sent_ = FALSE;                                   \
        int     i_ = 0;                                                 \
        int     should_ret_ = 0;                                        \
                                                                        \
        if (first_sock_)                                                \
        {                                                               \
            RPC_AWAIT_IUT_ERROR(pco_tst);                               \
            rc = rpc_send(pco_tst, tst_s1, wr_buf, wr_buflen, 0);       \
            if (rc > 0)                                                 \
                first_sent_ = TRUE;                                     \
        }                                                               \
        if (second_sock_)                                               \
        {                                                               \
            RPC_AWAIT_IUT_ERROR(pco_tst);                               \
            rc = rpc_send(pco_tst, tst_s2, wr_buf, wr_buflen, 0);       \
            if (rc > 0)                                                 \
                second_sent_ = TRUE;                                    \
        }                                                               \
                                                                        \
        should_ret_ =  (first_sent_ ? 1 : 0) +                          \
                       (second_sent_ ? 1 : 0);                          \
        TAPI_WAIT_NETWORK;                                              \
        RPC_AWAIT_IUT_ERROR(pco_);                                      \
        rc = iomux_epoll_call(epoll_func, pco_, epfd, events, 2, 1000); \
        if (rc < 0)                                                     \
        {                                                               \
            ERROR_VERDICT("%s%s() unexpectedly failed with errno %s",   \
                          msg_,                                         \
                          iomux_call_en2str(epoll_func),                \
                          errno_rpc2str(RPC_ERRNO(pco_)));              \
            is_failed = TRUE;                                           \
        }                                                               \
        else if (rc != should_ret_)                                     \
        {                                                               \
            if (rc == 1 && should_ret_ == 2)                            \
            {                                                           \
                if (events[0].data.fd == iut_s1)                        \
                    ERROR_VERDICT("%s%s() returned event only for "     \
                                  "the socket created before "          \
                                  "chroot()", msg_,                     \
                                  iomux_call_en2str(epoll_func));       \
                else if (events[0].data.fd == iut_s2)                   \
                    ERROR_VERDICT("%s%s() returned event only for "     \
                                  "the socket created after "           \
                                  "chroot()", msg_,                     \
                                  iomux_call_en2str(epoll_func));       \
            }                                                           \
            ERROR_VERDICT("%s%s() returned %d instead of %d", msg_,     \
                          iomux_call_en2str(epoll_func), rc,            \
                          should_ret_);                                 \
            is_failed = TRUE;                                           \
        }                                                               \
        if (rc > 0)                                                     \
        {                                                               \
            for (i_ = 0; i_ < rc; i_++)                                 \
            {                                                           \
                if ((events[i_].data.fd == iut_s1 && !first_sent_ &&    \
                     !(iut_s1 == iut_s2)) ||                            \
                    (events[i_].data.fd == iut_s2 && !second_sent_ &&   \
                     !(iut_s1 == iut_s2)) ||                            \
                    (iut_s1 == iut_s2 && !first_sent_ &&                \
                     !second_sent_) ||                                  \
                    (events[i_].data.fd != iut_s1 &&                    \
                                    events[i_].data.fd != iut_s2))      \
                {                                                       \
                    ERROR_VERDICT("%s%s() returned an event for "       \
                                  "unexpected %s", msg_,                \
                                  iomux_call_en2str(epoll_func),        \
                                  SOCK_NAME(pco_,                       \
                                            events[i_].data.fd));       \
                    is_failed = TRUE;                                   \
                }                                                       \
                else if (events[i_].events != RPC_EPOLLIN)              \
                {                                                       \
                    ERROR_VERDICT(                                      \
                            "%s%s() returned unexpected events %s "     \
                            "for %s", msg_,                             \
                            iomux_call_en2str(epoll_func),              \
                            epoll_event_rpc2str(events[i_].events),     \
                            SOCK_NAME(pco_,                             \
                                      events[i_].data.fd));             \
                    is_failed = TRUE;                                   \
                }                                                       \
            }                                                           \
        }                                                               \
        if (first_sent_)                                                \
        {                                                               \
            RPC_AWAIT_IUT_ERROR(pco_iut);                               \
            rc = rpc_recv(pco_iut, iut_s1, rd_buf, rd_buflen, 0);       \
        }                                                               \
        if (second_sent_)                                               \
        {                                                               \
            RPC_AWAIT_IUT_ERROR(pco_iut2);                              \
            rc = rpc_recv(pco_iut2, iut_s2, rd_buf, rd_buflen, 0);      \
        }                                                               \
    } while (0)

#define MAX_CMD 1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_iut2 = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    struct sockaddr_storage      iut_addr_aux;
    struct sockaddr_storage      tst_addr_aux;
    const struct sockaddr       *iut_addr;
    const struct sockaddr       *tst_addr;

    rpc_socket_type        sock_type;
    int                    sock_flag;
    te_bool                sock_before;
    int                    action;
    int                    test_epoll;
    iomux_call_type        epoll_func = IC_UNKNOWN;

    int                    iut_s1 = -1;
    int                    tst_s1 = -1;
    int                    iut2_s1 = -1;
    int                    iut_s2 = -1;
    int                    tst_s2 = -1;
    int                    epfd = -1;
    struct rpc_epoll_event events[2];

    void                   *rd_buf = NULL;
    size_t                  rd_buflen;
    void                   *wr_buf = NULL;
    size_t                  wr_buflen;

    te_bool                 is_failed = FALSE;
    te_bool                 first_sock_no_acc = FALSE;
    te_bool                 first_sock_add_fail = FALSE;
    te_bool                 second_sock_add_fail = FALSE;

    cfg_val_type            val_type;
    char                   *ta_dir = NULL;
    char                   *socklib = NULL;
    cfg_handle              ef_no_fail_handle = CFG_HANDLE_INVALID;
    char                   *old_ef_no_fail = NULL;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ENUM_PARAM(sock_flag, SOCK_FLAGS);
    TEST_GET_ENUM_PARAM(action, ACTIONS);
    TEST_GET_BOOL_PARAM(sock_before);
    TEST_GET_ENUM_PARAM(test_epoll, TEST_EPOLL);
    if (test_epoll != EPOLL_NONE)
        TEST_GET_IOMUX_FUNC(epoll_func);

    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &iut_addr_aux));
    CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &tst_addr_aux));

    if (sock_type == RPC_SOCK_STREAM)
        wr_buf = sockts_make_buf_stream(&wr_buflen);
    else
        wr_buf = sockts_make_buf_dgram(&wr_buflen);
    rd_buf = te_make_buf_min(wr_buflen, &rd_buflen);

    val_type = CVT_STRING;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &ta_dir,
                                  "/agent:%s/dir:", pco_iut->ta));

    val_type = CVT_STRING;
    cfg_get_instance_fmt(&val_type, &socklib,
                         "/local:%s/socklib:", pco_iut->ta);

    if (!te_str_is_null_or_empty(socklib) &&
        (action == ACT_EXEC || action == ACT_FORKEXEC))
    {
        ef_no_fail_handle = sockts_set_env(pco_iut, "EF_NO_FAIL", "1",
                                           &old_ef_no_fail);
    }

    if (sock_before)
        gen_conn_with_flags(pco_tst, pco_iut,
                            (const struct sockaddr *)&tst_addr_aux,
                            (const struct sockaddr *)&iut_addr_aux,
                            &tst_s1, &iut_s1, sock_type,
                            sock_flag == FLAG_CLOEXEC ? RPC_SOCK_CLOEXEC :
                                (sock_flag == FLAG_NONBLOCK ?
                                        RPC_SOCK_NONBLOCK : 0),
                            FALSE, TRUE, FALSE);

    if (sock_before && !te_str_is_null_or_empty(socklib) &&
        !tapi_onload_is_onload_fd(pco_iut, iut_s1))
    {
        ERROR_VERDICT("Socket created before chroot() is not accelerated");
        first_sock_no_acc = TRUE;
    }

    if (test_epoll == EPOLL_BEFORE)
    {
        epfd = rpc_epoll_create(pco_iut, 2);
        if (sock_before)
            rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                                 iut_s1, RPC_EPOLLIN);
    }

    /**
     * This call can take more than 10s on PPC64 virtual machine,
     * for other configurations this timeout is harmless.
     */
    pco_iut->timeout = 20000;
    rpc_copy_ta_libs(pco_iut, ta_dir);
    rpc_chroot(pco_iut, ta_dir);

    if (action == ACT_EXEC && sock_flag == FLAG_CLOEXEC && sock_before)
    {
        /*
         * In this case socket usability should be checked before
         * it will be closed on exec().
         */
        CHECK_SOCK_TRANSMIT(pco_iut, pco_tst, iut_s1, tst_s1,
                            "IUT socket", "TESTER socket",
                            "Transmit data via the pair of sockets "
                            "created before chroot() to TESTER "
                            "from pco_iut");
        CHECK_SOCK_TRANSMIT(pco_tst, pco_iut, tst_s1, iut_s1,
                            "TESTER socket", "IUT socket",
                            "Transmit data via the pair of sockets "
                            "created before chroot() from TESTER to "
                            "pco_iut");
        if (test_epoll == EPOLL_BEFORE)
        {
            pco_iut2 = pco_iut;
            CHECK_EPOLL(pco_iut, TRUE, FALSE, "epoll() before exec(): ");
        }
    }

    if (action == ACT_FORK)
    {
        CHECK_RC(rcf_rpc_server_fork(pco_iut, "iut_child", &pco_iut2));
        iut2_s1 = iut_s1;
    }
    else if (action == ACT_EXEC)
    {
        CHECK_RC(rcf_rpc_server_exec(pco_iut));
        SLEEP(2);
        pco_iut2 = pco_iut;
    }
    else if (action == ACT_FORKEXEC)
    {
        CHECK_RC(rcf_rpc_server_fork_exec(pco_iut, "iut_child",
                                          &pco_iut2));
        SLEEP(2);
        if (sock_flag != FLAG_CLOEXEC)
            iut2_s1 = iut_s1;
    }
    else
        pco_iut2 = pco_iut;

    if (action == ACT_EXEC && sock_flag == FLAG_CLOEXEC && sock_before)
    {
        /* The first socket should be cloused as a result of execve() */
        check_sock_cloexec(pco_iut, pco_tst, iut_s1,
                           tst_s1, sock_type, FALSE, &is_failed,
                           "Socket created before chroot() should be "
                           "closed after exec() in pco_iut, but: ");
        iut_s1 = -1;
    }
    else if (action == ACT_FORKEXEC && sock_flag == FLAG_CLOEXEC &&
             sock_before)
    {
        check_sock_cloexec(pco_iut2, pco_tst, iut_s1,
                           tst_s1, sock_type, TRUE, &is_failed,
                           "Socket created before chroot() should be "
                           "closed after fork() and exec() in child "
                           "process, but: ");
        iut2_s1 = -1;
    }

    gen_conn_with_flags(pco_tst, pco_iut2, tst_addr, iut_addr,
                        &tst_s2, &iut_s2, sock_type,
                        sock_flag == FLAG_CLOEXEC ? RPC_SOCK_CLOEXEC :
                            (sock_flag == FLAG_NONBLOCK ?
                                    RPC_SOCK_NONBLOCK : 0),
                        FALSE, TRUE, FALSE);

    if (!te_str_is_null_or_empty(socklib) &&
        !tapi_onload_is_onload_fd(pco_iut2, iut_s2))
    {
        RING_VERDICT("Socket created after chroot() is not accelerated");
    }

    if (test_epoll == EPOLL_AFTER)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut2);
        epfd = rpc_epoll_create(pco_iut2, 2);
        if (epfd < 0)
        {
            ERROR_VERDICT("Calling epoll_create() after chroot() "
                          "resulted in %s error",
                          errno_rpc2str(RPC_ERRNO(pco_iut2)));
            is_failed = TRUE;
            test_epoll = EPOLL_NONE;
        }
        else if (sock_before &&
                 !((action == ACT_EXEC ||
                 (action == ACT_FORKEXEC && test_epoll == EPOLL_AFTER))
                 && sock_flag == FLAG_CLOEXEC))
        {
            RPC_AWAIT_IUT_ERROR(pco_iut2);
            rc = rpc_epoll_ctl_simple(pco_iut2, epfd, RPC_EPOLL_CTL_ADD,
                                      iut_s1, RPC_EPOLLIN);
            if (rc < 0)
            {
                ERROR_VERDICT("Failed to add IUT socket created before "
                              "chroot() into epoll set created after it");
                is_failed = TRUE;
                first_sock_add_fail = TRUE;
            }
        }
    }

    if (test_epoll != EPOLL_NONE)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut2);
        rc = rpc_epoll_ctl_simple(pco_iut2, epfd, RPC_EPOLL_CTL_ADD,
                                  iut_s2, RPC_EPOLLIN);
        if (rc < 0)
        {
            ERROR_VERDICT("Failed to add IUT socket created after "
                          "chroot() into epoll set created %s it",
                          test_epoll == EPOLL_AFTER ? "after" : "before");
            is_failed = TRUE;
            second_sock_add_fail = TRUE;
        }
    }

    if (!(action == ACT_EXEC && sock_flag == FLAG_CLOEXEC) && sock_before)
    {
        CHECK_SOCK_TRANSMIT(pco_iut, pco_tst, iut_s1, tst_s1,
                            "IUT socket", "TESTER socket",
                            "Transmit data via the pair of sockets "
                            "created before chroot() to TESTER from "
                            "pco_iut");
        CHECK_SOCK_TRANSMIT(pco_tst, pco_iut, tst_s1, iut_s1,
                            "TESTER socket", "IUT socket",
                            "Transmit data via the pair of sockets "
                            "created before chroot() from TESTER to "
                            "pco_iut");
    }

    if (!(action == ACT_FORKEXEC && sock_flag == FLAG_CLOEXEC) &&
        sock_before && pco_iut2 != pco_iut)
    {
        CHECK_SOCK_TRANSMIT(pco_iut2, pco_tst, iut_s1, tst_s1,
                            "IUT socket", "TESTER socket",
                            "Transmit data via the pair of sockets "
                            "created before chroot() to TESTER from "
                            "child IUT process");
        CHECK_SOCK_TRANSMIT(pco_tst, pco_iut2, tst_s1, iut_s1,
                            "TESTER socket", "IUT socket",
                            "Transmit data via the pair of sockets "
                            "created before chroot() from TESTER to "
                            "child IUT process");
    }

    CHECK_SOCK_TRANSMIT(pco_iut2, pco_tst, iut_s2, tst_s2,
                        "IUT socket", "TESTER socket",
                        "Transmit data via the pair of sockets "
                        "created after chroot() to TESTER from IUT");
    CHECK_SOCK_TRANSMIT(pco_tst, pco_iut2, tst_s2, iut_s2,
                        "TESTER socket", "IUT socket",
                        "Transmit data via the pair of sockets "
                        "created after chroot() from TESTER to IUT");

    if (test_epoll != EPOLL_NONE)
    {
        if (!((action == ACT_EXEC ||
               (action == ACT_FORKEXEC && test_epoll == EPOLL_AFTER))
               && sock_flag == FLAG_CLOEXEC) &&
            sock_before)
        {
            if (!(first_sock_add_fail && second_sock_add_fail))
                CHECK_EPOLL(pco_iut2, first_sock_add_fail ? FALSE : TRUE,
                            second_sock_add_fail ? FALSE : TRUE, "");
        }
        else if (!second_sock_add_fail)
            CHECK_EPOLL(pco_iut2, FALSE, TRUE, "");

        if (sock_before && pco_iut2 != pco_iut &&
            !(action == ACT_EXEC && sock_flag == FLAG_CLOEXEC) &&
            test_epoll == EPOLL_BEFORE)
            CHECK_EPOLL(pco_iut, TRUE, FALSE, "In parent process: ");
    }

    if (sock_flag == FLAG_CLOEXEC)
    {
        rcf_rpc_server_exec(pco_iut2);
        if (pco_iut2 != pco_iut)
            rcf_rpc_server_exec(pco_iut);
        SLEEP(2);

        if (action != ACT_EXEC && sock_before)
        {
            check_sock_cloexec(pco_iut, pco_tst, iut_s1,
                               tst_s1, sock_type, FALSE, &is_failed,
                               "IUT socket created before chroot() "
                               "should be closed after "
                               "exec() in pco_iut, but: ");
            if (action != ACT_FORKEXEC && pco_iut2 != pco_iut)
                check_sock_cloexec(pco_iut2, pco_tst, iut_s1,
                                   tst_s1, sock_type, TRUE, &is_failed,
                                   "IUT socket created before chroot() "
                                   "should be closed after "
                                   "exec() in child process, but:");
        }

        check_sock_cloexec(pco_iut2, pco_tst, iut_s2,
                           tst_s2, sock_type, FALSE, &is_failed,
                           "IUT socket created after chroot() "
                           "should be closed after "
                           "exec(), but:");
        iut_s1 = -1;
        iut2_s1 = -1;
        iut_s2 = -1;
    }
    else if (sock_flag == FLAG_NONBLOCK)
    {
        if (is_failed)
            TEST_STOP;

        if (sock_before)
        {
            CHECK_SOCK_NONBLOCK(pco_iut, iut_s1, "IUT socket created "
                                "before chroot()");
            if (pco_iut2 != pco_iut)
                CHECK_SOCK_NONBLOCK(pco_iut2, iut_s1, "IUT socket "
                                    "created before chroot() (in "
                                    "child process)");
        }
        CHECK_SOCK_NONBLOCK(pco_iut2, iut_s2, "IUT socket created "
                            "after chroot()");
    }

    if (is_failed || first_sock_no_acc)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (sock_before)
    {
        CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
        CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
        CLEANUP_RPC_CLOSE(pco_iut2, iut2_s1);
    }
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_iut2, iut_s2);

    if (test_epoll == EPOLL_BEFORE)
    {
        CLEANUP_RPC_CLOSE(pco_iut, epfd);
        if (pco_iut2 != pco_iut)
            CLEANUP_RPC_CLOSE(pco_iut2, epfd);
    }
    else if (test_epoll == EPOLL_AFTER)
        CLEANUP_RPC_CLOSE(pco_iut2, epfd);

    /* To "undo" chroot() */
    rcf_rpc_server_restart(pco_iut);
    rpc_rm_ta_libs(pco_iut, ta_dir);

    if (pco_iut2 != pco_iut)
        rcf_rpc_server_destroy(pco_iut2);

    CLEANUP_CHECK_RC(sockts_restore_env(pco_iut, ef_no_fail_handle,
                                        old_ef_no_fail));

    free(rd_buf);
    free(wr_buf);

    sockts_kill_zombie_stacks_if_many(pco_iut);

    TEST_END;
}
