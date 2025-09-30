/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 *
 * @brief Socket API Test Suite
 *
 * Implementation of functions used for I/O Multiplexing.
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 *
 * $Id$
 */

/** Log user */
#define TE_LGR_USER "IomuxLib"

#include "sockapi-ts.h"
#include "iomux.h"
#include "tapi_mem.h"

/* See the iomux.h file for the description. */
tapi_iomux_type
iomux_call_get_default()
{
    char    *default_iomux = getenv("TE_RPC_DEFAULT_IOMUX");
    return (default_iomux == NULL) ? TAPI_IOMUX_POLL :
                sockts_iomux_call_str2en(default_iomux);
}

/* See the iomux.h file for the description. */
tapi_iomux_type
sockts_iomux_call_str2en(const char *iomux)
{
    if (strcmp(iomux, "oo_epoll") == 0)
        return TAPI_IOMUX_OO_EPOLL;

    return tapi_iomux_call_str2en(iomux);
}

/* See the iomux.h file for the description. */
const char *
sockts_iomux_call_en2str(tapi_iomux_type iomux_type)
{
    if (iomux_type == TAPI_IOMUX_RESERVED)
        return "oo_epoll";

    return tapi_iomux_call_en2str(iomux_type);
}

static iomux_state cur_state = {RPC_NULL, RPC_NULL, RPC_NULL,
                                NULL, { {0, 0, 0}, },
                                { {0, {0}}, }, -1, RPC_NULL};

static iomux_state *cur_st_p = &cur_state;

/* See the iomux.h file for the description. */
iomux_state *
iomux_switch_state(iomux_state *new_state)
{
    iomux_state     *val;

    val = cur_st_p;

    if (new_state != NULL)
        cur_st_p = new_state;

    return val;
}

/** 
 * Call one of epoll functions.
 *
 * @param call_type     Type of function to be called
 * @param rpcs          RPC server, where the @b iomux() function is called
 * @param events        Array of event request records
 * @param n_evts        Length of @a events
 * @param timeout       Timeout of operation, may be NULL
 * @param sigmask       Signal mask, may be NULL
 * @param save_op       Initial RPC operation
 *
 * @return Forward return value of the epoll functions
 */
static int
iomux_call_epoll_internal(iomux_call_type call_type, rcf_rpc_server *rpcs,
                          iomux_evt_fd *events, size_t n_evts,
                          struct tarpc_timeval *timeout,
                          rpc_sigset_p sigmask, rcf_rpc_op save_op)
{
    struct rpc_epoll_event *p_events;
    int epoll_timeout;
    struct tarpc_timespec timeout_timespec;
    struct tarpc_timespec *p_timeout_timespec;
    int rc = 0;

    VERB("Epoll requested");

    if (rpcs->op != RCF_RPC_WAIT)
    {
        /* 'size' value for 'epoll_create()' function is set to 1 because
         * kernel code doesn't use it.
         */
        rpcs->op = RCF_RPC_CALL_WAIT;
        cur_st_p->epfd = rpc_epoll_create(rpcs, 1);
        if (events)
        {
            unsigned int i;

            for (i = 0; i < n_evts; i++)
            {
                rpcs->op = RCF_RPC_CALL_WAIT;
                rpc_epoll_ctl_simple(rpcs, cur_st_p->epfd,
                                     RPC_EPOLL_CTL_ADD,
                            events[i].fd,
                            tapi_iomux_evt_to_epoll(events[i].events));
                VERB("Add epoll event, fd %d, evts %x",
                    events[i].fd, events[i].events);
            }
        }
    }

    switch (call_type)
    {
        case TAPI_IOMUX_EPOLL:
        case TAPI_IOMUX_EPOLL_PWAIT:
        case TAPI_IOMUX_OO_EPOLL:
            if (timeout != NULL)
            {
                epoll_timeout = TE_SEC2MS(timeout->tv_sec) +
                                TE_US2MS(timeout->tv_usec);
            }
            else
            {
                epoll_timeout = -1;
            }

            VERB("Epoll timeout %dms", epoll_timeout);
            break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            if (timeout != NULL)
            {
                timeout_timespec.tv_sec = timeout->tv_sec;
                timeout_timespec.tv_nsec = TE_US2NS(timeout->tv_usec);
                p_timeout_timespec = &timeout_timespec;
            }
            else
            {
                p_timeout_timespec = NULL;
            }
            VERB("Epoll_pwait2 timeout (timespec) %s",
                 tarpc_timespec2str(p_timeout_timespec));
            break;

        case TAPI_IOMUX_DEFAULT:
            ERROR("%s can't be used with default iomux call", __FUNCTION__);
            break;

        default:
            ERROR("Wrong type of epoll function");
    }

    rpcs->op = save_op;
    RPC_AWAIT_IUT_ERROR(rpcs);
    if (n_evts == 0 && events == 0)
    {
        n_evts = 1;
        p_events = cur_st_p->epoll_evt_array;
    }
    else
        p_events = events ? cur_st_p->epoll_evt_array : NULL;

    switch (call_type)
    {
        case TAPI_IOMUX_EPOLL:
            rc = rpc_epoll_wait(rpcs, cur_st_p->epfd, p_events, n_evts,
                                epoll_timeout);
        break;

        case TAPI_IOMUX_EPOLL_PWAIT:
            rc = rpc_epoll_pwait(rpcs, cur_st_p->epfd, p_events, n_evts,
                                 epoll_timeout, sigmask);
        break;

        case TAPI_IOMUX_EPOLL_PWAIT2:
            rc = rpc_epoll_pwait2(rpcs, cur_st_p->epfd, p_events, n_evts,
                                  p_timeout_timespec, sigmask);
        break;

        case TAPI_IOMUX_OO_EPOLL:
        {
            rpc_onload_ordered_epoll_event *oo_events;

            oo_events = calloc(n_evts, sizeof(*oo_events));
            rc = rpc_onload_ordered_epoll_wait(rpcs, cur_st_p->epfd,
                p_events, oo_events, n_evts, epoll_timeout);
            free(oo_events);
        }
        break;

        case TAPI_IOMUX_DEFAULT:
            ERROR("%s can't be used with default iomux call", __FUNCTION__);
            break;

        default:
            ERROR("Wrong type of epoll function");
    }

    return rc;
}

/**
 * Macro to check that fdset is inited on specified RPC
 *
 * @param rpcs_         RPC server
 * @param fd_set_       pointer to fdset to be checked and initialized
 *
 * @se on error logs respective message and return -1 from function. 
 */
#define CHECK_INIT_RPC_FDSET(rpcs_, fd_set_) \
        do {                                                            \
            if ((fd_set_) == RPC_NULL)                                  \
            {                                                           \
                fd_set_ = rpc_fd_set_new(rpcs_);                        \
                rpc_do_fd_zero((rpcs_), (fd_set_));                     \
            }                                                           \
        } while(0)


/* See the iomux.h file for the description. */
int
iomux_call_gen(iomux_call_type call_type, rcf_rpc_server *rpcs,
               iomux_evt_fd *events, size_t n_evts,
               struct tarpc_timeval *timeout, rpc_sigset_p sigmask,
               uint64_t *duration)
{
    rcf_rpc_op  save_op;
    int         rc = 0;
    int         aux_errno = 0;

    if (rpcs == NULL)
    {
        ERROR("Null RPC server handle passed to iomux_call");
        return -1;
    }

    if (call_type == TAPI_IOMUX_DEFAULT)
        call_type = iomux_call_get_default();

    if (call_type == TAPI_IOMUX_UNKNOWN)
    {
        ERROR("Wrong parameter 'iomux' passed to iomux_call");
        return -1;
    }

    if (n_evts > (sizeof(cur_st_p->poll_fd_array) /
                  sizeof(cur_st_p->poll_fd_array[0])))
    {
        ERROR("iomux_call: too large n_evts %d, not supported");
        return -1;
    }

    if (sigmask != RPC_NULL &&
        (call_type == TAPI_IOMUX_POLL || call_type == TAPI_IOMUX_SELECT ||
         call_type == TAPI_IOMUX_EPOLL || call_type == TAPI_IOMUX_OO_EPOLL))
        ERROR("Non-null sigmsk is specified for select()/poll()/epoll()/"
              "onload_ordered_epoll_wait()");

    VERB("iomux_call, current RPC server %x, requested RPC op %d",
         cur_st_p->srv_current, rpcs->op);
    if (cur_st_p->srv_current == NULL)
    {
        switch (rpcs->op)
        {
            case RCF_RPC_CALL:
                cur_st_p->srv_current = rpcs;
                /* FALLTHROUGH */

            case RCF_RPC_CALL_WAIT:
                break;

            case RCF_RPC_WAIT:
                ERROR("Error in iomux_call: "
                      "'wait' RPC request without previous 'call'");
                return -1;

            default:
                ERROR("%s(): Invalid RPC operation %u",
                      __FUNCTION__, rpcs->op);
                return -1;
        }
    }
    else
    {
        if (cur_st_p->srv_current != rpcs)
        {
            ERROR("Error in iomux_call: "
                  "simultaneous work with more then one RPC servers "
                  "requires different context for each server: "
                  "use iomux_switch_state() to change context");
            return -1;
        }

        switch (rpcs->op)
        {
            case RCF_RPC_CALL:
            case RCF_RPC_CALL_WAIT:
                ERROR("Error in iomux_call: "
                      "specified RPC server already blocked");
                return -1;

            case RCF_RPC_WAIT:
                cur_st_p->srv_current = NULL;
                break;

            default:
                ERROR("%s(): Invalid RPC operation %u",
                      __FUNCTION__, rpcs->op);
                return -1;
        }
    }

    save_op = rpcs->op;

    if (call_type == TAPI_IOMUX_POLL || call_type == TAPI_IOMUX_PPOLL)
    {
        int poll_timeout;
        struct tarpc_timespec ppoll_timeout;

        VERB("iomux_call, poll or ppoll requested");

        if (events)
        {
            unsigned int i;

            for (i = 0; i < n_evts; i++)
            {
                cur_st_p->poll_fd_array[i].fd = events[i].fd;
                cur_st_p->poll_fd_array[i].events =
                               tapi_iomux_evt_to_poll(events[i].events);
                cur_st_p->poll_fd_array[i].revents = events[i].revents;
                VERB("Add poll event, fd %d, evts %x",
                        events[i].fd, events[i].events);
            }
        }

        if (call_type == TAPI_IOMUX_POLL)
        {
            if (timeout != NULL)
            {
                poll_timeout = timeout->tv_sec * 1000 +
                               timeout->tv_usec / 1000;
            }
            else
                poll_timeout = -1;
        }
        else
        {
            if (timeout != NULL)
            {
                ppoll_timeout.tv_sec = timeout->tv_sec;
                ppoll_timeout.tv_nsec = timeout->tv_usec * 1000;
            }
        }
        VERB("Poll timeout %d", poll_timeout);

        rpcs->op = save_op;
        RPC_AWAIT_IUT_ERROR(rpcs);
        if (call_type == TAPI_IOMUX_POLL)
            rc = rpc_poll(rpcs, events ? cur_st_p->poll_fd_array : NULL,
                          n_evts, poll_timeout);
        else
            rc = rpc_ppoll(rpcs, events ? cur_st_p->poll_fd_array : NULL,
                           n_evts,
                           timeout != NULL ? &ppoll_timeout : NULL,
                           sigmask);
        if (duration != NULL)
            *duration = rpcs->duration;

        VERB("(P)Poll rc %d", rc);

        if (events)
        {
            unsigned int i;

            for (i = 0; i < n_evts; i++)
            {
                events[i].revents = tapi_iomux_poll_to_evt(
                                        cur_st_p->poll_fd_array[i].revents);
                VERB("Got poll event, fd %d, orig: asked 0x%x,"
                     " detected 0x%x, "
                     "converted 0x%x",
                     (int)events[i].fd,
                     (int)cur_st_p->poll_fd_array[i].events,
                     (int)cur_st_p->poll_fd_array[i].revents,
                     (int)events[i].revents);
            }
        }

        return rc;
    }
    else if (call_type == TAPI_IOMUX_EPOLL ||
             call_type == TAPI_IOMUX_EPOLL_PWAIT ||
             call_type == TAPI_IOMUX_EPOLL_PWAIT2 ||
             call_type == TAPI_IOMUX_OO_EPOLL)
    {
        rc = iomux_call_epoll_internal(call_type, rpcs, events, n_evts,
                                       timeout, sigmask, save_op);

        if (duration != NULL)
            *duration = rpcs->duration;

        VERB("Epoll rc %d", rc);

        if (events)
        {
            unsigned int i;
            int re_num = 0;

            for (i = 0; i < n_evts; i++)
                events[i].revents = 0;
            for (i = 0; i < n_evts && re_num < rc; )
            {
                if (cur_st_p->epoll_evt_array[re_num].data.fd !=
                        events[i].fd)
                {
                    i++;
                    continue;
                }
                events[i].revents = tapi_iomux_epoll_to_evt(
                                  cur_st_p->epoll_evt_array[re_num].events);
                VERB("Got epoll event, fd %d, orig: detected 0x%x, "
                     "converted 0x%x",
                     (int)events[i].fd,
                     (int)cur_st_p->epoll_evt_array[re_num].events,
                     (int)events[i].revents);
                re_num++;
                i = 0;
            }
        }

        if (save_op != RCF_RPC_CALL)
        {
            if (rc < 0)
                aux_errno = rpcs->_errno;
            rpc_close(rpcs, cur_st_p->epfd);
            cur_st_p->epfd = -1;
            if (rc < 0)
                rpcs->_errno = aux_errno;
        }
        return rc;
    }
    else /* Process select and pselect */
    {
        static int    max_fd = 0;
        unsigned int  i;
        int           select_rc = 0;

        VERB("Select or pselect requested");

        rpcs->op = RCF_RPC_CALL_WAIT;

        switch (save_op)
        {
            case RCF_RPC_CALL:
            case RCF_RPC_CALL_WAIT:

                max_fd = 0;

                if (events)
                {
                    for (i = 0; i < n_evts; i++)
                    {
                        /* Check read events request */
                        if (events[i].events &
                            (EVT_RD | EVT_RD_NORM))
                        {
                            CHECK_INIT_RPC_FDSET(rpcs, cur_st_p->read_fds);
                            rpc_do_fd_set(rpcs, events[i].fd,
                                          cur_st_p->read_fds);
                            VERB("Set fd %d to read set", events[i].fd);
                        }
                        /* Check write events request */
                        if (events[i].events &
                            (EVT_WR | EVT_WR_NORM))
                        {
                            CHECK_INIT_RPC_FDSET(rpcs, cur_st_p->write_fds);
                            rpc_do_fd_set(rpcs, events[i].fd,
                                          cur_st_p->write_fds);
                            VERB("Set fd %d to write set", events[i].fd);
                        }
                        /* Check exception events request */
                        if (events[i].events &
                            (EVT_EXC | EVT_HUP | EVT_ERR | EVT_NVAL |
                             EVT_RD_BAND | EVT_WR_BAND | EVT_PRI |
                             EVT_RDHUP))
                        {
                            CHECK_INIT_RPC_FDSET(rpcs, cur_st_p->exc_fds);
                            rpc_do_fd_set(rpcs, events[i].fd,
                                          cur_st_p->exc_fds);
                            VERB("Set fd %d to except set", events[i].fd);
                        }

                        if (max_fd <= events[i].fd)
                            max_fd = events[i].fd + 1;
                    }
                }
                break;

            case RCF_RPC_WAIT:
                /* do nothing, fdsets and max_fd are ready */
                break;

            default:
                ERROR("%s(): Invalid RPC operation %u",
                      __FUNCTION__, rpcs->op);
                return -1;
        }


        rpcs->op = save_op;

        if (call_type == TAPI_IOMUX_SELECT)
        {
            RPC_AWAIT_IUT_ERROR(rpcs);
            select_rc = rpc_select(rpcs, max_fd,
                                   cur_st_p->read_fds, cur_st_p->write_fds,
                                   cur_st_p->exc_fds,
                                   timeout);
        }
        else
        {
            struct tarpc_timespec psel_timeout;

            if (timeout != NULL)
            {
                psel_timeout.tv_sec = timeout->tv_sec;
                psel_timeout.tv_nsec = timeout->tv_usec * 1000;
            }

            RPC_AWAIT_IUT_ERROR(rpcs);
            select_rc = rpc_pselect(rpcs, max_fd,
                                    cur_st_p->read_fds, cur_st_p->write_fds,
                                    cur_st_p->exc_fds,
                                    timeout != NULL ? &psel_timeout : NULL,
                                    sigmask);
        }

        if (duration != NULL)
            *duration = rpcs->duration;

        if (select_rc == -1)
        {
            aux_errno = rpcs->_errno;
        }

        switch (save_op)
        {
            case RCF_RPC_CALL:
                /* do nothing, leave fdsets allocated */
                break;

            case RCF_RPC_CALL_WAIT:
            case RCF_RPC_WAIT:
                {
                    uint16_t evnt;
                    for (i = 0; i < n_evts; i++)
                    {
                        evnt = 0;
                        if (cur_st_p->read_fds != RPC_NULL)
                        {
                            rc = rpc_do_fd_isset(rpcs, events[i].fd,
                                                 cur_st_p->read_fds);

                            if (rc > 0)
                                evnt |= EVT_RD;
                        }
                        if (cur_st_p->write_fds != RPC_NULL)
                        {
                            rc = rpc_do_fd_isset(rpcs, events[i].fd,
                                                 cur_st_p->write_fds);

                            if (rc > 0)
                                evnt |= EVT_WR;
                        }
                        if (cur_st_p->exc_fds != RPC_NULL)
                        {
                            rc = rpc_do_fd_isset(rpcs, events[i].fd,
                                                 cur_st_p->exc_fds);

                            if (rc > 0)
                                evnt |= EVT_EXC;
                        }
                        events[i].revents = evnt;
                        VERB("Got index %d, fd %d events 0x%x",
                                i, events[i].fd, events[i].revents);
                    }
                }
#if 1 /* Do not reuse fdsets since it is memleak on TA */
                if (cur_st_p->read_fds  != RPC_NULL)
                {
                    rpc_fd_set_delete(rpcs, cur_st_p->read_fds);
                    cur_st_p->read_fds = RPC_NULL;
                }
                if (cur_st_p->write_fds != RPC_NULL)
                {
                    rpc_fd_set_delete(rpcs, cur_st_p->write_fds);
                    cur_st_p->write_fds = RPC_NULL;
                }
                if (cur_st_p->exc_fds   != RPC_NULL)
                {
                    rpc_fd_set_delete(rpcs, cur_st_p->exc_fds);
                    cur_st_p->exc_fds = RPC_NULL;
                }
#endif
                break;

            default:
                ERROR("%s(): Invalid RPC operation %u",
                      __FUNCTION__, rpcs->op);
                return -1;
        }
        if (rc >= 0)
        {
            rc = select_rc;
            rpcs->_errno = aux_errno;
        }
        return rc;
    }

    return 0;
}
#undef CHECK_INIT_RPC_FDSET

int
iomux_call(iomux_call_type call_type, rcf_rpc_server *rpcs,
           iomux_evt_fd *events, size_t n_evts,
           struct tarpc_timeval *timeout)
{
    int rc = 0;
    int aux_errno = 0;
    int signal_call = 0;
    rcf_rpc_op save_op = rpcs->op;

    if (call_type == TAPI_IOMUX_DEFAULT)
        call_type = iomux_call_get_default();

    if (call_type == TAPI_IOMUX_PSELECT || call_type == TAPI_IOMUX_PPOLL ||
        call_type == TAPI_IOMUX_EPOLL_PWAIT ||
        call_type == TAPI_IOMUX_EPOLL_PWAIT2)
        signal_call = 1;

    if (signal_call && rpcs->op != RCF_RPC_WAIT)
    {
        rpcs->op = RCF_RPC_CALL_WAIT;
        cur_st_p->iomux_call_sigmask = rpc_sigset_new(rpcs);
        rpc_sigemptyset(rpcs, cur_st_p->iomux_call_sigmask);
        rpc_sigaddset(rpcs, cur_st_p->iomux_call_sigmask, RPC_SIGUSR1);
        rpcs->op = save_op;
    }
    rc = iomux_call_signal(call_type, rpcs, events, n_evts, timeout,
                           (signal_call) ?
                                cur_st_p->iomux_call_sigmask : RPC_NULL);

    if (signal_call && save_op != RCF_RPC_CALL)
    {
        if (rc < 0)
            aux_errno = rpcs->_errno;
        rpc_sigset_delete(rpcs, cur_st_p->iomux_call_sigmask);
        if (rc < 0)
            rpcs->_errno = aux_errno;
    }

    return rc;
}

int
iomux_call_default_simple(rcf_rpc_server *rpcs, int sock, iomux_evt evt,
                          iomux_evt *revt, int timeout)
{
    iomux_evt_fd    event = { sock, evt, 0 };
    tarpc_timeval   tv;
    int rc;

    if (timeout >= 0)
    {
        tv.tv_sec = TE_MS2SEC(timeout);
        tv.tv_usec = TE_MS2US(timeout) % 1000000L;
    }

    rc = iomux_call(TAPI_IOMUX_DEFAULT, rpcs, &event, 1,
                    (timeout < 0) ? NULL : &tv);
    if (revt != NULL)
        *revt = event.revents;
    return rc;
}

/**
 * Is socket writable from iomux function point of view.
 *
 * @param rpcs      RPC server handle
 * @param sock      file descriptor
 * @param iomux     I/O multiplexing function to be used
 * @param ok        Location to return status of the operation
 */
static te_bool
iomux_is_writable(rcf_rpc_server *rpcs, int sock, iomux_call_type iomux,
                  te_bool *ok)
{
    int             rc;
    iomux_evt_fd    evt;
    tarpc_timeval   tv = { 2, 0 };

    assert(ok != NULL);

    if (iomux == TAPI_IOMUX_DEFAULT)
        iomux = iomux_call_get_default();

    memset(&evt, 0, sizeof(evt));
    evt.fd = sock;
    evt.events = EVT_WR;

    rc = iomux_call(iomux, rpcs, &evt, 1, &tv);
    if (rc < 0)
    {
        ERROR("%s(): iomux_call() failed", __FUNCTION__);
        *ok = FALSE;
        return FALSE;
    }
    else if (rc == 0)
    {
        *ok = TRUE;
        return FALSE;
    }
    else if (rc == 1)
    {
        *ok = TRUE;
        if ((evt.revents & ~(EVT_WR | EVT_WR_NORM)) != 0)
            ERROR("Unexpected event(s) 0x%x has been returned by "
                  "iomux_call()", evt.revents);
        return (evt.revents & (EVT_WR | EVT_WR_NORM));
    }
    else
    {
        ERROR("Unexpected value %d has been returned by iomux_call()", rc);
        *ok = FALSE;
        return FALSE;
    }
}

/* See the iomux.h file for the description. */ 
int
iomux_fill_io_buffers(rcf_rpc_server *rpcs, int sock,
                      iomux_call_type iomux, ssize_t *ts)
{
    uint8_t     buf[SOCKTS_BUF_SZ];
    size_t      total_sent = 0;
    ssize_t     sent;
    uint32_t    i = 0;
    uint32_t    j = 1;
    uint8_t    *m = (uint8_t *)&j;
    te_bool     iomux_ok;

    if (iomux == TAPI_IOMUX_DEFAULT)
        iomux = iomux_call_get_default();

    while (iomux_is_writable(rpcs, sock, iomux, &iomux_ok) && iomux_ok)
    {
        uint32_t  ii;

        for (ii = 0; ii < SOCKTS_BUF_SZ; ii++)
        {
            j += i;
            m[0] = m[0] + m[1] + m[2] + m[3];
            buf[ii] = m[0];
            i++; j++;
        }

        RPC_AWAIT_IUT_ERROR(rpcs);
        sent = rpc_send(rpcs, sock, buf, sizeof(buf), RPC_MSG_DONTWAIT);
        if (sent < 0)
        {
            int err = RPC_ERRNO(rpcs);

            ERROR("send() function failed while filling the buffer "
                  "of a socket, errno is %r", TE_RC_GET_ERROR(err));
            return -1;
        }
        total_sent += sent;
        *ts = total_sent;
        if (total_sent > (4 << 20))
        {
            ERROR("Failed to fill in socket buffer, sent %u bytes",
                  total_sent);
            return -1;
        }
    }

    if (iomux_ok)
    {
        return 0;
    }
    else
    {
        ERROR("iomux_is_writable() failed: %r", RPC_ERRNO(rpcs));
        return -1;
    }
}

/* See the iomux.h file for the description. */ 
int 
iomux_common_steps(iomux_call_type iomux, rcf_rpc_server *iut, int iut_s,
                   iomux_evt *events, iomux_timeout_t timeout,
                   te_bool fill_buffer, rcf_rpc_server *tst, int tst_s,
                   rpc_shut_how how, int *iomux_ret_val)
{
    /* structure used by iomux_call() function */
    iomux_evt_fd    sock_fd;

    int             iomux_result = -1;
    tarpc_timeval   prepared_timeout = { 0, 0 }; 

    if (iomux == TAPI_IOMUX_DEFAULT)
        iomux = iomux_call_get_default();

    if (timeout == IOMUX_TIMEOUT_RAND)
    {
        prepared_timeout.tv_sec = rand_range(5, 10);
    }
    
    sock_fd.fd = iut_s;
    sock_fd.events = *events; 
    sock_fd.revents = 0;
    
    /* filling the buffer of tst_s socket from ius_s socket */
    if (fill_buffer)
    {
        uint64_t sent;

        /**
         * Buffer overfilling function is implemented in TE, so it does not
         * support WODA API. Usual epoll is used instead Onload ordered
         * epoll.
         */
        rpc_overfill_buffers_gen(iut, iut_s, &sent,
                                 iomux == TAPI_IOMUX_OO_EPOLL ?
                                          TAPI_IOMUX_EPOLL : iomux);
    }
    *events = 0;

    /* iomux() function call is blocking so we must use iut->op */

    if (how != RPC_SHUT_NONE)
    {
        iut->op = RCF_RPC_CALL;
    }

    iomux_result = iomux_call(iomux, iut, &sock_fd, 1, &prepared_timeout);
    if (iomux_result < 0)
    {
        ERROR("iomux call %s failed", sockts_iomux_call_en2str(iomux));
        return -1;
    }
    
    if (how != RPC_SHUT_NONE)
    {
        rpc_shutdown(tst, tst_s, how);
        iut->op = RCF_RPC_WAIT; 
        iomux_result = iomux_call(iomux, iut, &sock_fd, 1, &prepared_timeout);
    }

    *events = sock_fd.revents;
    VERB("Got events in iomux_common_block : %x", sock_fd.revents);
    
    *iomux_ret_val = iomux_result; 

    return 0;
}

int
iomux_epoll_call(iomux_call_type call_type, rcf_rpc_server *rpcs, int epfd,
                 struct rpc_epoll_event *events, int maxevents, int timeout)
{
    if (call_type == TAPI_IOMUX_DEFAULT)
        call_type = iomux_call_get_default();

    switch (call_type)
    {
        case TAPI_IOMUX_EPOLL:
            return rpc_epoll_wait(rpcs, epfd, events, maxevents, timeout);

        case TAPI_IOMUX_EPOLL_PWAIT:
        case TAPI_IOMUX_EPOLL_PWAIT2:
        {
            struct tarpc_timespec  tv;
            struct tarpc_timespec *tv_ptr = &tv;
            int rc = 0;
            rcf_rpc_op save_op = rpcs->op;
            uint64_t duration;
            te_bool err_jump = rpcs->err_jump;
            te_bool iut_err_jump = rpcs->iut_err_jump;
            int rpc_errno;

            if (rpcs->op != RCF_RPC_WAIT)
            {
                /*
                 * Let auxiliary RPC calls to jump to cleanup in any case,
                 * or their failure will be hidden when user disables
                 * such jumping for epoll_wait().
                 */
                rpcs->err_jump = TRUE;
                rpcs->iut_err_jump = TRUE;

                rpcs->op = RCF_RPC_CALL_WAIT;
                cur_st_p->iomux_call_sigmask = rpc_sigset_new(rpcs);
                rpc_sigemptyset(rpcs, cur_st_p->iomux_call_sigmask);
                rpc_sigaddset(rpcs, cur_st_p->iomux_call_sigmask, RPC_SIGUSR1);
                rpcs->op = save_op;

                rpcs->err_jump = err_jump;
                rpcs->iut_err_jump = iut_err_jump;
            }

            if (call_type == TAPI_IOMUX_EPOLL_PWAIT)
            {
                rc = rpc_epoll_pwait(rpcs, epfd, events, maxevents, timeout,
                                     cur_st_p->iomux_call_sigmask);
            }
            else
            {
                if (timeout < 0)
                    tv_ptr = NULL;
                else
                    TE_NS2TS(TE_MS2NS(timeout), tv_ptr);
                rc = rpc_epoll_pwait2(rpcs, epfd, events, maxevents, tv_ptr,
                                      cur_st_p->iomux_call_sigmask);
            }
            duration = rpcs->duration;
            rpc_errno = rpcs->_errno;
            if (save_op != RCF_RPC_CALL &&
                TE_RC_GET_ERROR(rpc_errno) != TE_ERPCDEAD &&
                TE_RC_GET_ERROR(rpc_errno) != TE_ERPCTIMEOUT &&
                TE_RC_GET_ERROR(rpc_errno) != TE_ERPCKILLED)
            {
                rpc_sigset_delete(rpcs, cur_st_p->iomux_call_sigmask);
                rpcs->duration = duration;
                rpcs->_errno = rpc_errno;
            }
            return rc;
        }

        case TAPI_IOMUX_OO_EPOLL:
        {
            rpc_onload_ordered_epoll_event oo_events;

            return rpc_onload_ordered_epoll_wait(rpcs, epfd, events,
                                                 &oo_events, maxevents,
                                                 timeout);
        }
        break;

        default:
            ERROR("Wrong parameter 'iomux' passed to iomux_call");
    }

    return -1;
}

/* See the iomux.h file for the description. */ 
int
iomux_init_rd_error(iomux_evt_fd *event, int iut_s, iomux_call_type iomux,
                    te_bool select_err_queue, int *rc)
{
    int exp;

    if (iomux == TAPI_IOMUX_DEFAULT)
        iomux = iomux_call_get_default();

    event->fd = iut_s;
    event->events = EVT_RD | EVT_PRI;
    event->revents = 0;

    if (rc != NULL)
        *rc = 1;

    switch (iomux)
    {
        case TAPI_IOMUX_SELECT:
        case TAPI_IOMUX_PSELECT:
            exp = EVT_RD;
            if (select_err_queue)
            {
                if (rc != NULL)
                    *rc = 2;
                exp |= EVT_EXC;
            }
            break;

        case TAPI_IOMUX_POLL:
        case TAPI_IOMUX_PPOLL:
        case TAPI_IOMUX_EPOLL:
        case TAPI_IOMUX_EPOLL_PWAIT:
        case TAPI_IOMUX_EPOLL_PWAIT2:
        case TAPI_IOMUX_OO_EPOLL:
            exp = EVT_EXC | EVT_ERR;
            if (select_err_queue)
                exp |= EVT_PRI;
            break;

        default:
            TEST_FAIL("Unknown iomux");
    }

    return exp;
}

/**
 * Perform @c epoll_wait() call.
 *
 * @param iomux     The multiplexer handle.
 * @param timeout   Timeout to block in the call in milliseconds.
 * @param revts     Returned events.
 *
 * @return Events number.
 */
static int
sockts_iomux_oo_epoll_call(tapi_iomux_handle *iomux, int timeout,
                           tapi_iomux_evt_fd **revts)
{
    rpc_onload_ordered_epoll_event *oo_events;
    int rc;

    if (iomux->rpcs->op != RCF_RPC_WAIT)
    {
        iomux->epoll.events = tapi_calloc(iomux->fds_num,
                                          sizeof(*iomux->epoll.events));
        free(iomux->opaque);
        oo_events = tapi_calloc(iomux->fds_num, sizeof(*oo_events));
        iomux->opaque = oo_events;
    }

    rc = rpc_onload_ordered_epoll_wait(iomux->rpcs, iomux->epoll.epfd,
                        iomux->epoll.events,
                        (rpc_onload_ordered_epoll_event *)iomux->opaque,
                        iomux->fds_num, timeout);

    if (iomux->rpcs->op == RCF_RPC_WAIT)
        return rc;

    if (rc > 0)
        *revts = tapi_iomux_epoll_get_events(iomux, iomux->epoll.events,
                                             rc);
    free(iomux->epoll.events);

    return rc;
}

/**
 * Close a epoll file descriptor and release resources.
 *
 * @param iomux The multiplexer handle.
 */
static void
sockts_iomux_oo_epoll_destroy(tapi_iomux_handle *iomux)
{
    int rc;

    free(iomux->opaque);

    RPC_AWAIT_IUT_ERROR(iomux->rpcs);
    rc = rpc_close(iomux->rpcs, iomux->epoll.epfd);
    if (rc != 0)
        TEST_VERDICT("Failed to close epoll set: %r",
                     RPC_ERRNO(iomux->rpcs));
}

/**
 * Initialize @c oo_epoll methods.
 *
 * @param iomux The multiplexer handle.
 */
static void
sockts_set_oo_epoll_methods(tapi_iomux_handle *iomux)
{
    static tapi_iomux_methods methods = { .call = NULL };

    if (methods.call != NULL)
        return;

    memcpy(&methods, iomux->methods, sizeof(methods));
    methods.call = sockts_iomux_oo_epoll_call;
    methods.destroy = sockts_iomux_oo_epoll_destroy;
    iomux->methods = &methods;
}

/* See the description in iomux.h. */
tapi_iomux_handle *
sockts_iomux_create(rcf_rpc_server *rpcs, tapi_iomux_type type)
{
    tapi_iomux_handle *iomux;

    if (type == TAPI_IOMUX_OO_EPOLL)
    {
        iomux = tapi_iomux_create(rpcs, TAPI_IOMUX_EPOLL);
        /* Copy */
        sockts_set_oo_epoll_methods(iomux);
    }
    else
        iomux = tapi_iomux_create(rpcs, type);

    return iomux;
}

int
iomux_epoll_pwait_call(iomux_call_type iomux, rcf_rpc_server *rpcs, int epfd,
                       struct rpc_epoll_event *events, int maxevents,
                       int timeout_ms, const rpc_sigset_p sigmask)
{
    switch (iomux)
    {
        case TAPI_IOMUX_EPOLL_PWAIT:
            return rpc_epoll_pwait(rpcs, epfd, events, maxevents, timeout_ms,
                                   sigmask);

        case TAPI_IOMUX_EPOLL_PWAIT2:
        {
            struct tarpc_timespec tv;
            struct tarpc_timespec *tv_ptr = &tv;

            if (timeout_ms < 0)
                tv_ptr = NULL;
            else
                TE_NS2TS(TE_MS2NS(timeout_ms), tv_ptr);
            return rpc_epoll_pwait2(rpcs, epfd, events, maxevents, tv_ptr,
                                    sigmask);
        }

        default:
            TEST_FAIL("Incorrect value of 'iomux' parameter. "
                      "It should be either EPOLL_PWAIT or EPOLL_PWAIT2.");
    }
}
