/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros for epoll tests 
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 *
 * $Id$
 */

#include "derived_instances.h"
#include "iomux.h"

/**
 * Parse "evts" argument
 *
 * @param evts_     Can be "in", "inout" or "out"
 * @param event_    Events to be passed to @b epoll()
 * @param exp_ev_   Events expected to be returned by
 *                  @b epoll()
 */
#define PARSE_EVTS(evts_, event_, exp_ev_) \
    do {                                                \
        if (strcmp(evts_, "in") == 0)                   \
        {                                               \
            exp_ev_ = RPC_EPOLLIN;                      \
            event_ = exp_ev_;                           \
        }                                               \
        else if (strcmp(evts_, "out") == 0)             \
        {                                               \
            exp_ev_ = RPC_EPOLLOUT;                     \
            event_ = exp_ev_;                           \
        }                                               \
        else if (strcmp(evts_, "inout") == 0)           \
        {                                               \
            exp_ev_ = RPC_EPOLLOUT;                     \
            event_ = RPC_EPOLLIN | RPC_EPOLLOUT;        \
        }                                               \
        else                                            \
            TEST_FAIL("evts parameter has incorrect "   \
                      "value '%s'.", evts_);            \
    } while (0)

/**
 * Parse "func" argument
 *
 * @param func_         "execve", "fork_exec", "fork", "dup" or
 *                      "thread_create"
 * @param pco_          RPC server
 * @param pco_child_    Child RPC server to be created
 * @param epfd_         @b epoll() file descriptor on @p pco_
 * @param child_epfd_   @b epoll() file descriptor in child process
 *                      (thread)
 * @param inst_num_     Will be set to 1 if @b epoll() file desctiptor
 *                      was not duplicated and to 2 otherwise.
 */
#define PARSE_FUNC(func_, pco_, pco_child_, epfd_, \
                   child_epfd_, inst_num_) \
    do {                                                                \
        derived_test_instance  *instances_ = NULL;                      \
        if (strcmp(func, "fork_exec") == 0)                             \
        {                                                               \
            if ((instances_ = create_instances("inherit", "fork",       \
                                               pco_, epfd_,             \
                                               &inst_num_, 0,           \
                                               0)) == NULL)             \
                TEST_FAIL("Cannot create test instances");              \
            CHECK_RC(rcf_rpc_server_exec(instances_[1].rpcs));          \
        }                                                               \
        else if (strcmp(func_, "thread_create") != 0)                   \
        {                                                               \
            if ((instances_ = create_instances("inherit", func_, pco_,  \
                                              epfd_, &inst_num_,        \
                                              0, 0)) == NULL)           \
                TEST_FAIL("Cannot create test instances");              \
        }                                                               \
        if (strcmp(func_, "dup") == 0 ||                                \
            strcmp(func_, "execve") == 0 ||                             \
            strcmp(func_, "thread_create") == 0)                        \
        {                                                               \
            rc = rcf_rpc_server_thread_create(pco_, "child_thread",     \
                                              &pco_child_);             \
            if (rc != 0)                                                \
            {                                                           \
                free(instances_);                                       \
                TEST_FAIL("Failed to create new thread");               \
            }                                                           \
        }                                                               \
        else                                                            \
            pco_child_ = instances_[inst_num_ - 1].rpcs;                \
        if (strcmp(func_, "thread_create") == 0)                        \
            child_epfd_ = epfd_;                                        \
        else                                                            \
            child_epfd_ = instances_[inst_num_ - 1].s;                  \
        free(instances_);                                               \
    } while (0)

/**
 * Call @b epoll_wait() on one of two RPC servers with
 * @c RCF_RPC_CALL set.
 *
 * @param selector_     If @c TRUE, call @b epoll_wait() on
 *                      the first server, otherwise do it on the
 *                      second one.
 * @param pco1_         The first RPC server
 * @param pco2_         The second RPC server
 * @param epfd1_        Epoll file descriptor on @p pco1_
 * @param epfd2_        Epoll file descriptor on @p pco2_
 * @param events_       Epoll events
 * @param maxevents_    Maximum number of events to be returned
 * @param timeout_      Time to wait for events
 * @param iomux_        Type of iomux function
 */
#define CALL_EPOLL_WAIT(selector_, pco1_, pco2_, epfd1_, epfd2_, \
                        events_, maxevents_, timeout_, iomux_) \
do {                                                                    \
    rcf_rpc_server *rpcs_ = selector_ ? pco1_ : pco2_;                  \
    int             epfd_ = selector_ ? epfd1_ : epfd2_;                \
                                                                        \
    rpcs_->op = RCF_RPC_CALL;                                           \
    if (iomux_ == IC_OO_EPOLL)                                          \
    {                                                                   \
        rpc_onload_ordered_epoll_event *oo_events_;                     \
                                                                        \
        oo_events_ = calloc(maxevents_, sizeof(*oo_events_));           \
        rc = rpc_onload_ordered_epoll_wait(rpcs_, epfd_, events_,       \
                                           oo_events_, maxevents_,      \
                                           timeout_);                   \
        free(oo_events_);                                               \
    }                                                                   \
    else                                                                \
        rc = rpc_epoll_wait(rpcs_, epfd_, events_, maxevents_, timeout_); \
} while (0)

/**
 * Wait or call @b epoll_wait() in dependence on @p non_blocking_.
 *
 * @param rpcs_         RPC server
 * @param epfd_         Epoll file descriptor
 * @param events_       Epoll events
 * @param maxevents_    Maximum number of events to be returned
 * @param timeout_      Time to wait for events
 * @param iomux_        Type of iomux function
 * @param non_blocking_ Use @c TRUE if call is blocking
 */
#define WAIT_EPOLL_WAIT(rpcs_, epfd_, events_, maxevents_, \
                        timeout_, iomux_, non_blocking_)                \
do {                                                                    \
    (rpcs_)->op = (non_blocking_) ? RCF_RPC_CALL_WAIT : RCF_RPC_WAIT;   \
    if (iomux_ == IC_OO_EPOLL)                                          \
    {                                                                   \
        rpc_onload_ordered_epoll_event *oo_events_;                     \
                                                                        \
        oo_events_ = calloc(maxevents_, sizeof(*oo_events_));           \
        rc = rpc_onload_ordered_epoll_wait(rpcs_, epfd_, events_,       \
                                           oo_events_, maxevents_,      \
                                           timeout_);                   \
        free(oo_events_);                                               \
    }                                                                   \
    else                                                                \
        rc = rpc_epoll_wait(rpcs_, epfd_, events_, maxevents_, timeout_); \
} while (0)


/**
 * Call @b epoll_ctl() on one of two RPC servers; check that it
 * terminated immediately.
 *
 * @param selector_     If @c TRUE, call @b epoll_ctl() on
 *                      the first server, otherwise do it on the
 *                      second one.
 * @param pco1_         The first RPC server
 * @param pco2_         The second RPC server
 * @param epfd1_        Epoll file descriptor on @p pco1_
 * @param epfd2_        Epoll file descriptor on @p pco2_
 * @param op_           Operation to be done (add, delete or
 *                      modify)
 * @param s_            Socket
 * @param event_        Epoll event
 */
#define CALL_EPOLL_CTL(selector_, pco1_, pco2_, epfd1_, epfd2_, \
                       op_, s_, event_) \
    do {                                                        \
        if (selector_)                                          \
            rpc_epoll_ctl_simple(pco1_, epfd1_, op_,            \
                                 s_, event_);                   \
        else                                                    \
            rpc_epoll_ctl_simple(pco2_, epfd2_, op_,            \
                                 s_, event_);                   \
                                                                \
        CHECK_CALL_DURATION_INT_GEN(                            \
                    (selector_ ? pco1_ : pco2_)->duration,      \
                    TST_TIME_INACCURACY,                        \
                    TST_TIME_INACCURACY_MULTIPLIER,             \
                    0, 0, RING,                                 \
                    RING_VERDICT, "epoll_ctl() call took "      \
                    "too much time", "");                       \
    } while (0)

/**
 * Make sure that there are only expected events raised on a given
 * IUT socket before calling @b epoll_ctl with it.
 *
 * @param have_         Should the socket have any events raised on it?
 * @param before_       Should these events be raised before
 *                      @b epoll_ctl call?
 * @param evts_         "in", "out" or "inout"
 * @param sock_type_    Sock type
 * @param wait_child_   Wherher @b epoll_wait() should be called
 *                      in parent or in child process (thread)?
 * @param pco_iut_      Parent RPC server
 * @param pco_child_    Child RPC server
 * @param iut_s_        Socket on @p pco_iut_
 * @param pco_tst_      RPC server on TESTER
 * @param tst_s_        Socket on @p pco_tst_
 * @param buffer_       Buffer
 * @param size_         Size of buffer
 * @param nblk_         if @c FALSE, blocking @b epoll_wait() call
 *                      is to be made before @b epoll_ctl() call.
 */
#define CONFIGURE_EVENTS_BEFORE(have_, before_, evts_, sock_type_, \
                                wait_child_, pco_iut_, pco_child_, \
                                iut_s_, pco_tst_, tst_s_, buffer_, \
                                size_, nblk_) \
    do {                                                            \
        if ((!have_ || !before_) && strcmp(evts_, "in") != 0)       \
        {                                                           \
            if (sock_type_ == RPC_SOCK_DGRAM)                       \
                TEST_FAIL("Cannot overfill buffers on "             \
                          "a datagram socket");                     \
            rpc_overfill_buffers_gen(wait_child_ ?                  \
                                        pco_iut_ : pco_child_,      \
                                     iut_s_, NULL, FUNC_EPOLL);     \
        }                                                           \
        if (have_ && before_ && strcmp(evts_, "in") == 0)           \
        {                                                           \
            RPC_WRITE(rc, pco_tst_, tst_s_, buffer_, size_);        \
            if (!nblk_)                                             \
                TAPI_WAIT_NETWORK;                                  \
        }                                                           \
    } while (0)

/**
 * Make sure that there are expected events raised on a given
 * IUT socket after calling @b epoll_ctl() with it.
 *
 * @param have_         Should the socket have any events raised on it?
 * @param before_       Should these events be raised before
 *                      @b epoll_ctl() call?
 * @param evts_         "in", "out" or "inout"
 * @param pco_tst_      RPC server on TESTER
 * @param tst_s_        Socket on @p pco_tst_
 * @param buffer_       Buffer
 * @param size_         Size of buffer
 * @param nblk_         if @c FALSE, blocking @b epoll_wait() call
 *                      is to be made before @b epoll_ctl() call.
 */
#define CONFIGURE_EVENTS_AFTER(have_, before_, evts_, \
                               pco_tst_, tst_s_, buffer_, \
                               size_, nblk_) \
    do {                                                                \
        if (have_ && !before_)                                          \
        {                                                               \
            if (strcmp(evts, "in") == 0)                                \
                RPC_WRITE(rc, pco_tst_, tst_s_, buffer_, size_);        \
            else                                                        \
            {                                                           \
                do {                                                    \
                    RPC_AWAIT_IUT_ERROR(pco_tst_);                      \
                    rc = rpc_recv(pco_tst_, tst_s_, buffer_,            \
                                  size_, RPC_MSG_DONTWAIT);             \
                } while (rc >= 0);                                      \
                                                                        \
                if (RPC_ERRNO(pco_tst_) != RPC_EAGAIN)                  \
                    TEST_FAIL("recv() returned unexpected errno %s",    \
                              errno_rpc2str(RPC_ERRNO(pco_tst_)));      \
            }                                                           \
            if (nblk_)                                                  \
                TAPI_WAIT_NETWORK;                                      \
        }                                                               \
    } while (0)

/**
 * Create a pair of connected file descriptors (ends of pipe or
 * connected sockets).
 *
 * @param pco1_         RPC server
 * @param pco2_         Another RPC server
 * @param is_pipe_      Whether we should use pipe or sockets
 * @param sock_type_    Socket type
 * @param pco1_addr_    Network address on @p pco1_
 * @param pco2_addr_    Network address on @p pco2_
 * @param fd1_          Where to store file descriptor created on
 *                      pco1_
 * @param fd2_          Where to store file descriptor created on
 *                      pco2_
 * @param first_active_ For @c SOCK_STREAM sockets determines whether
 *                      connection will be active or passive
 *                      from the point of view of @p pco1_. For pipe
 *                      determines whether @p fd1_ should be write
 *                      or read end of pipe.
 * @param conn_1_to_2_  Makes sense only for @c SOCK_DGRAM sockets.
 *                      If @c FALSE, do not @b connect() @p fd1_ to
 *                      @p fd2_ if @p first_active is @p FALSE or
 *                      @p fd2_ to @p fd1_ otherwise.
 */
#define GET_CONNECTED_FDS(pco1_, pco2_, is_pipe_, sock_type_, \
                          pco1_addr_, pco2_addr_, fd1_, fd2_, \
                          first_active_, conn_1_to_2_) \
    do {                                                                \
        if (!is_pipe_)                                                  \
        {                                                               \
            if (first_active_)                                          \
            {                                                           \
                if ((sock_type_) == RPC_SOCK_DGRAM)                     \
                    GEN_DGRAM_CONN((pco2_), (pco1_), RPC_PROTO_DEF,     \
                                   (pco2_addr_), (pco1_addr_),          \
                                   &(fd2_), &(fd1_), (conn_1_to_2_),    \
                                   TRUE);                               \
                else                                                    \
                    GEN_CONNECTION((pco2_), (pco1_), (sock_type_),      \
                                   RPC_PROTO_DEF, (pco2_addr_),         \
                                   (pco1_addr_), &(fd2_), &(fd1_));     \
            }                                                           \
            else                                                        \
            {                                                           \
                if ((sock_type_) == RPC_SOCK_DGRAM)                     \
                    GEN_DGRAM_CONN((pco1_), (pco2_), RPC_PROTO_DEF,     \
                                   (pco1_addr_), (pco2_addr_),          \
                                   &(fd1_), &(fd2_), (conn_1_to_2_),    \
                                   TRUE);                               \
                else                                                    \
                    GEN_CONNECTION((pco1_), (pco2_), (sock_type_),      \
                                   RPC_PROTO_DEF, (pco1_addr_),         \
                                   (pco2_addr_), &(fd1_), &(fd2_));     \
            }                                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            int pipefds_[2] = {-1, -1};                                 \
            rpc_pipe((pco1_), (pipefds_));                              \
            if (first_active_)                                          \
            {                                                           \
                fd1_ = pipefds_[1];                                     \
                fd2_ = pipefds_[0];                                     \
            }                                                           \
            else                                                        \
            {                                                           \
                fd1_ = pipefds_[0];                                     \
                fd2_ = pipefds_[1];                                     \
            }                                                           \
        }                                                               \
    } while (0);

/**
 * Create a connection of type @c SOCK_STREAM between two PCO and add client
 * socket to epoll fd before @b bind().
 *
 * @param srvr          PCO where server socket is created
 * @param clnt          PCO where client socket is created
 * @param srvr_addr     Server address to be used as a template 
 *                      for @b bind() on server side
 * @param clnt_addr     Address to bind client to or @c NULL
 * @param srvr_s        Descriptor of the socket reside on @p srvr (OUT)
 * @param clnt_s        Descriptor of the socket reside on @p clnt (OUT)
 * @param epfds         Epoll file descriptors (OUT)
 * @param epfds_num     Number of epoll file descriptors to be created
 * @param evts          Events for adding clnt_s to epfd
 *
 * @return Status of the operation
 *
 * @retval @c  0 Connection successfully created
 * @retval @c -1 Creating connection failed
 */
extern int rpc_stream_conn_early_epfd_add(rcf_rpc_server *srvr,
                                          rcf_rpc_server *clnt,
                                          const struct sockaddr *srvr_addr,
                                          const struct sockaddr *clnt_addr,
                                          int *srvr_s, int *clnt_s,
                                          int *epfds, int epfds_num,
                                          uint32_t evts);

/**
 * Create a pair of connected file descriptors (ends of pipe or
 * connected sockets) and epoll file descriptor.
 *
 * @param pco1_         RPC server
 * @param pco2_         Another RPC server
 * @param is_pipe_      Whether we should use pipe or sockets
 * @param sock_type_    Socket type
 * @param pco1_addr_    Network address on @p pco1_
 * @param pco2_addr_    Network address on @p pco2_
 * @param fd1_          Where to store file descriptor created on
 *                      pco1_
 * @param fd2_          Where to store file descriptor created on
 *                      pco2_
 * @param first_active_ For @c SOCK_STREAM sockets determines whether
 *                      connection will be active or passive
 *                      from the point of view of @p pco1_. For pipe
 *                      determines whether @p fd1_ should be write
 *                      or read end of pipe.
 * @param conn_1_to_2_  Makes sense only for @c SOCK_DGRAM sockets.
 *                      If @c FALSE, do not @b connect() @p fd1_ to
 *                      @p fd2_ if @p first_active is @p FALSE or
 *                      @p fd2_ to @p fd1_ otherwise.
 * @param epfd_         Where to store epoll file descriptor
 * @param early_ctl_    In case it is @c TRUE add fd1_ to epfd early
 * @param evts_         Exents for epoll_ctl() call
 */
#define GET_CONNECTED_ADD_EPFD(pco1_, pco2_, is_pipe_, sock_type_, \
                               pco1_addr_, pco2_addr_, fd1_, fd2_, \
                               first_active_, conn_1_to_2_, epfd_, \
                               early_ctl_, evts_) \
    do {                                                                 \
        if (early_ctl_ && !is_pipe_ &&                                   \
            (sock_type_ == RPC_SOCK_DGRAM || first_active_ == TRUE))     \
        {                                                                \
            if (sock_type_ == RPC_SOCK_DGRAM)                            \
            {                                                            \
                fd1_ = rpc_socket(pco1_,                                 \
                                  rpc_socket_domain_by_addr(pco1_addr_), \
                                  RPC_SOCK_DGRAM, RPC_PROTO_DEF);        \
                if (epfd_ == -1)                                         \
                    epfd_ = rpc_epoll_create(pco1_, 1);                  \
                rpc_epoll_ctl_simple(pco1_, epfd_, RPC_EPOLL_CTL_ADD,    \
                                     fd1_, evts_);                       \
                rpc_bind(pco1_, fd1_, pco1_addr_);                       \
                fd2_ = rpc_create_and_bind_socket(pco2_,                 \
                                                  RPC_SOCK_DGRAM,        \
                                                  RPC_PROTO_DEF,         \
                                                  FALSE,                 \
                                                  FALSE,                 \
                                                  SA(pco2_addr_));       \
                rpc_connect(pco2_, fd2_, pco1_addr_);                    \
                if (conn_1_to_2_)                                        \
                    rpc_connect(pco1_, fd1_, pco2_addr_);                \
            }                                                            \
            else if (sock_type_ == RPC_SOCK_STREAM)                      \
            {                                                            \
                if (rpc_stream_conn_early_epfd_add(pco2_, pco1_,         \
                                                   pco2_addr_,           \
                                                   pco1_addr_,           \
                                                   &(fd2_), &(fd1_),     \
                                                   &(epfd_), 1,          \
                                                   evts_) != 0)          \
                {                                                        \
                    TEST_FAIL("Cannot create a SOCK_STREAM connection "  \
                              "and add socket to epoll fd early");       \
                }                                                        \
            }                                                            \
            else                                                         \
            {                                                            \
                TEST_FAIL("Incorrect socket type");                      \
            }                                                            \
        }                                                                \
        else                                                             \
        {                                                                \
            GET_CONNECTED_FDS(pco1_, pco2_, is_pipe_, sock_type_,        \
                              pco1_addr_, pco2_addr_, fd1_, fd2_,        \
                              first_active_, conn_1_to_2_)               \
            if (epfd_ == -1)                                             \
                epfd_ = rpc_epoll_create(pco1_, 1);                      \
            rpc_epoll_ctl_simple(pco1_, epfd_, RPC_EPOLL_CTL_ADD,        \
                                 fd1_, evts_);                           \
        }                                                                \
    } while (0);

/**
 * Get RPC server from which the second file descriptor should be
 * accessed. If it is not the end of a pipe, it just assign
 * @p pco2_ to @p pco_tst_.
 *
 * @param pco1_     RPC server for accessing @p fd1_
 * @param pco2_     RPC server for accessing @p fd2_
 * @param pco_tst_  RPC server on TESTER or NULL
 * @param is_pipe_  Whether to test a pipe or sockets
 * @param fd1_      The first file descriptor
 * @param fd2_      The second file descriptor
 */
#define GET_FD2_PCO(pco1_, pco2_, pco_tst_, is_pipe_, \
                    fd1_, fd2_) \
    do {                                                        \
        if (!is_pipe_)                                          \
            pco2_ = pco_tst_;                                   \
        else                                                    \
        {                                                       \
            if (pco2_ == NULL)                                  \
                CHECK_RC(rcf_rpc_server_fork(pco1_,             \
                                             "pco1_child",      \
                                             &pco2_));          \
            rpc_close(pco1_, fd2_);                             \
            rpc_close(pco2_, fd1_);                             \
        }                                                       \
    } while (0)

/**
 * Check result of epoll() call which is expected to return
 * a single event.
 *
 * @param rpcs        RPC server handle.
 * @param iomux       Epoll call type.
 * @param rc          Returned value.
 * @param event       Returned event.
 * @param exp_rc      Expected return value.
 * @param exp_errno   Expected errno (use @c RPC_EUNKNOWN
 *                    if errno should not be checked).
 * @param exp_fd      Expected file descriptor.
 * @param exp_events  Expected events.
 * @param err_msg     String to add to verdicts
 *                    in case of failure.
 */
extern void epoll_check_single_event(rcf_rpc_server *rpcs,
                                     iomux_call_type iomux,
                                     int rc, struct rpc_epoll_event *event,
                                     int exp_rc, te_errno exp_errno,
                                     int exp_fd, uint32_t exp_events,
                                     const char *err_msg);
