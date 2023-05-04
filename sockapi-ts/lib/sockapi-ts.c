/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * implementation of common functions.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 *
 * $Id$
 */

/** User name of Socket API test suite library */
#define TE_LGR_USER     "Library"

#include "sockapi-ts.h"
#include "tapi_cfg.h"
#include "tapi_test.h"
#include "tapi_file.h"
#include "tapi_mem.h"
#include "tapi_route_gw.h"
#include "onload.h"
#include "iomux.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

/* Maximum waiting time for killing Onload zombie stacks. */
#define SOCKTS_ZOMBIE_STACK_KILLING_TIMEOUT 5

static int
mcast_join_leave(rcf_rpc_server *rpcs, int sockd, rpc_sockopt opt_name,
                 const struct sockaddr *mcast_addr, int if_index);


/* See description in sockapi-ts.h */
struct rpc_iovec *
sockts_make_iovec_gen(int *iovlen, ssize_t *buflen,
                      int empty_bufs)
{
    int              *non_empty;
    double            p;
    struct rpc_iovec *res;
    int               i, j, k;
    int               n_nempty;
    int               n_empty;

    ENTRY("iovlen=0x%x(%d) buflen=%d",
          iovlen, (iovlen == NULL) ? 0 : *iovlen, buflen);

    if (iovlen == NULL)
        return NULL;

    if (*iovlen == -1)
        *iovlen = rand_range(1, 5);
    else if (iovlen == 0)
        *iovlen = 1;
    VERB("%s(): final iovlen=%d", __FUNCTION__, *iovlen);

    n_nempty = *iovlen - (empty_bufs > 0 ? empty_bufs : 0);

    if (*buflen == -1)
        *buflen = rand_range(1, 1024);
    VERB("%s(): final buflen=%d", __FUNCTION__, *buflen);

    res = calloc(*iovlen, sizeof(*res));
    if (res == NULL)
        return NULL;

    non_empty = calloc(n_nempty, sizeof(*non_empty));
    if (non_empty == NULL)
    {
        free(res);
        return NULL;
    }

    /* Generate random length to split buffer into parts*/
    for (i = 0; i < n_nempty - 1; ++i)
    {
        do {
            non_empty[i] = rand_range(0, *buflen);

            if (empty_bufs < 0 || i > *buflen)
                break;
            for (j = 0; j < i; j++)
                if (non_empty[j] == non_empty[i])
                    break;
        } while (j < i);

        VERB("%s(): stage #1: item %d len=%u",
             __FUNCTION__, i, non_empty[i]);
        /* Sort iov_len length fields in increasing order */
        for (j = i - 1, k = i; j >= 0; --j)
        {
            if (non_empty[k] < non_empty[j])
            {
                size_t tmp = non_empty[k];

                non_empty[k] = non_empty[j];
                non_empty[j] = tmp;
                k = j;
            }
        }
    }
    non_empty[n_nempty - 1] = *buflen;
    /* Now iov_len fields contain total length of all previous buffers */

    /* Make iov_len fields to contain length of the buffer */
    for (i = n_nempty - 1; i > 0; --i)
    {
        non_empty[i] -= non_empty[i - 1];
        VERB("%s(): stage #2: item %d len=%u",
             __FUNCTION__, i, non_empty[i]);
    }
    VERB("%s(): stage #2: item 0 len=%u", __FUNCTION__, non_empty[0]);

    if (empty_bufs >= 0)
        p = (double) empty_bufs / ((double) *iovlen);

    n_empty = 0;

    /* Allocate buffer with overabundant space */
    for (k = 0, i = 0; i < *iovlen; ++i)
    {
        if (empty_bufs >= 0)
        {
            if (((double) rand() / ((double) RAND_MAX) < p ||
                 k == n_nempty) && n_empty < empty_bufs)
            {
                res[i].iov_len = 0;
                n_empty++;
            }
            else
                res[i].iov_len = non_empty[k++];
        }
        else
            res[i].iov_len = non_empty[i];

        if (res[i].iov_len == 0)
        {
            res[i].iov_base = NULL;
            res[i].iov_rlen = 0;
        }
        else
            res[i].iov_base = te_make_buf_min(res[i].iov_len,
                                              &res[i].iov_rlen);

        if (res[i].iov_base == NULL && res[i].iov_rlen != 0)
            return NULL;
    }

    return res;
}


/* See description in sockapi-ts.h */
struct rpc_iovec *
sockts_make_iovec(int *iovlen, ssize_t *buflen)
{
    return sockts_make_iovec_gen(iovlen, buflen, -1);
}

/* See description in sockapi-ts.h */
te_errno
create_plain_iovecs(rpc_iovec **iovecs, int buf_len, int iov_len)
{
    int i = 0;

    *iovecs = calloc(iov_len, sizeof(**iovecs));
    if (*iovecs == NULL)
    {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < iov_len; i++)
    {
        (*iovecs)[i].iov_base = calloc(buf_len, sizeof(char));
        if ((*iovecs)[i].iov_base == NULL)
        {
            ERROR("Out of memory");
            return -1;
        }
        (*iovecs)[i].iov_rlen = (*iovecs)[i].iov_len = 
                                        buf_len * sizeof(char);
    }

    return 0;
}

/* See description in sockapi-ts.h */
int
iovecs_to_buf(rpc_iovec *iovecs, int iov_len, char *buf, int buf_len)
{
    int i = 0;
    int cur_pos = 0;
    int remained = buf_len;
    int to_copy = 0;

    for (i = 0; i < iov_len; i++)
    {
        to_copy = (int)iovecs[i].iov_len > remained ?
                                        remained : (int)iovecs[i].iov_len;
        memcpy(buf + cur_pos, iovecs[i].iov_base, to_copy);
        remained -= to_copy;
        cur_pos += to_copy;
        if (remained == 0)
            break;
    }

    return cur_pos;
}

/* See description in sockapi-ts.h */
void
sockts_free_iovecs(struct rpc_iovec *iovec, size_t iovcnt)
{
    if (iovec != NULL)
    {
        size_t  i;

        for (i = 0; i < iovcnt; ++i)
            free(iovec[i].iov_base);

        free(iovec);
    }
}


/* See description in sockapi-ts.h */
struct rpc_msghdr *
sockts_make_msghdr(int namelen, int iovlen, ssize_t *buflen, int ctrllen)
{
    struct rpc_msghdr  *res;
    size_t              tmp;

    res = calloc(1, sizeof(*res));
    if (res == NULL)
        return NULL;

    res->msg_namelen = (namelen >= 0) ? (socklen_t)namelen :
                                        sizeof(struct sockaddr_storage);
    if (res->msg_namelen != 0)
    {
        res->msg_name = te_make_buf_min(res->msg_namelen, &tmp);
        if (res->msg_name == NULL)
            return NULL;
        res->msg_rnamelen = tmp;
    }

    res->msg_iov = sockts_make_iovec(&iovlen, buflen);
    res->msg_iovlen = res->msg_riovlen = iovlen;

    res->msg_controllen = (ctrllen != -1) ? ctrllen : rand_range(64, 256);
    if (res->msg_controllen != 0)
    {
        res->msg_control = te_make_buf_by_len(res->msg_controllen);
        if (res->msg_control == NULL)
            return NULL;
        res->msg_cmsghdr_num = 1;
    }

    return res;
}


/* See description in sockapi-ts.h */
void
sockts_free_msghdr(struct rpc_msghdr *msg)
{
    if (msg != NULL)
    {
        free(msg->msg_name);
        sockts_free_iovecs(msg->msg_iov, msg->msg_riovlen);
        free(msg->msg_control);
        free(msg);
    }
}

/* See description in sockapi-ts.h */
int
sockts_compare_sock_peer_name(rcf_rpc_server *local, int sock,
                              rcf_rpc_server *remote, int peer)
{
    int rc;
    struct sockaddr_storage local_addr, peer_addr;
    socklen_t               local_addrlen, peer_addrlen;

    local_addrlen = sizeof(local_addr);
    memset(&local_addr, 0, sizeof(local_addr));
    RPC_AWAIT_IUT_ERROR(local);
    rc = rpc_getsockname(local, sock, SA(&local_addr), &local_addrlen);
    if (rc != 0)
        return -1;

    peer_addrlen = sizeof(peer_addr);
    memset(&peer_addr, 0, sizeof(peer_addr));
    RPC_AWAIT_IUT_ERROR(remote);
    rc = rpc_getpeername(remote, peer, SA(&peer_addr), &peer_addrlen);
    if (rc != 0)
        return -1;

    if (peer_addr.ss_family == AF_INET6 &&
        IN6_IS_ADDR_LINKLOCAL(&SIN6(&peer_addr)->sin6_addr))
        SIN6(&peer_addr)->sin6_scope_id = SIN6(&local_addr)->sin6_scope_id;

    if (te_sockaddrcmp(SA(&local_addr), local_addrlen,
                       SA(&peer_addr), peer_addrlen) != 0)
        return -1;

    return 0;
}

/* See description in sockapi-ts.h */
sockts_iovec_buf_cmp_result
sockts_compare_iovec_and_buffer(struct rpc_iovec *iov,
                                size_t iov_num,
                                char *buf,
                                size_t buf_len)
{
    size_t iov_count;
    size_t buf_offset = 0;
    size_t cmp_len;

    for (iov_count = 0; iov_count < iov_num; iov_count++)
    {
        if (buf_offset + iov[iov_count].iov_len > buf_len)
        {
            if (buf_offset >= buf_len)
                return SOCKTS_BUF_INCLUDED_IN_IOVEC;
            cmp_len = buf_len - buf_offset;
        }
        else
        {
            cmp_len = iov[iov_count].iov_len;
        }

        if (memcmp(buf + buf_offset,
                   iov[iov_count].iov_base,
                   cmp_len) != 0)
            return SOCKTS_BUF_DONT_MATCH_IOVEC;

        buf_offset += iov[iov_count].iov_len;
    }

    if (buf_offset < buf_len)
        return SOCKTS_BUF_INCLUDES_IOVEC;
    if (buf_offset > buf_len)
        return SOCKTS_BUF_INCLUDED_IN_IOVEC;

    return SOCKTS_BUF_EQUAL_IOVEC;
}

/* See description in sockapi-ts.h */
te_bool
sockts_iovec_buf_cmp_start(struct rpc_iovec *iov,
                           size_t iov_num,
                           char *buf,
                           size_t buf_len)
{
    int rc;

    rc = sockts_compare_iovec_and_buffer(iov, iov_num, buf, buf_len);
    if (rc == SOCKTS_BUF_EQUAL_IOVEC ||
        rc == SOCKTS_BUF_INCLUDED_IN_IOVEC)
        return TRUE;
    else
        return FALSE;
}

/* See description in sockapi-ts.h */
int
sockts_compare_txrx_msgdata(rpc_msghdr *tx_msghdr, rpc_msghdr *rx_msghdr,
                            const struct sockaddr *addr,
                            size_t tx_len, size_t rx_len)
{
    if (rpc_iovec_cmp(tx_len, tx_msghdr->msg_iov, tx_msghdr->msg_iovlen,
                      rx_len, rx_msghdr->msg_iov, rx_msghdr->msg_iovlen) != 0)
    {
        ERROR("Received data are not equal to sent");
        return -1;
    }
    if (te_sockaddrcmp((const struct sockaddr *)rx_msghdr->msg_name,
                       rx_msghdr->msg_namelen, addr,
                       te_sockaddr_get_size(addr)) != 0)
    {
        ERROR("Invalid peer address returned by recvmsg()");
        return -1;
    }
    return 0;
}

/* See description in sockapi-ts.h */
const char *
socket_state2str(sockts_socket_state_t state)
{
    switch (state)
    {
        case STATE_CLEAR: return "STATE_CLEAR";
        case STATE_BOUND: return "STATE_BOUND";
        case STATE_LISTENING: return "STATE_LISTENING";
        case STATE_CONNECTED: return "STATE_CONNECTED";
        case STATE_SHUT_RD: return "STATE_SHUT_RD";
        case STATE_SHUT_WR: return "STATE_SHUT_WR";
        case STATE_SHUT_RDWR: return "STATE_SHUT_RDWR";
        case STATE_CLOSED: return "STATE_CLOSED";

        default: return "Unknown";
    }
}

/**
 * Macro for perform cleanup of allocated resources in 
 * function sockts_get_socket_state and log message about error.
 * Always perform exit from function with rc = -1.
 *
 * @param _msg    format string for log message
 */
#define TST_VERDICT(_msg...) \
    do {                                                \
        char msg_buf[200];                              \
                                                        \
        snprintf(msg_buf, sizeof(msg_buf), _msg);       \
        err = RPC_ERRNO(pco);                           \
        if (IS_IUT_ERRNO(err))                          \
        {                                               \
            ERROR("RPC %s failed RPC_errno=%X",         \
                  msg_buf, TE_RC_GET_ERROR(err));       \
        }                                               \
                                                        \
        if (sock_dgm_aux > 0)                           \
            rpc_close(pco, sock_dgm_aux);               \
                                                        \
        VERB("%s failed at %d with rc %X",              \
                __FUNCTION__, __LINE__, err);           \
        if (rdset)                                      \
            rpc_fd_set_delete(pco, rdset);              \
        if (wrset)                                      \
            rpc_fd_set_delete(pco, wrset);              \
        return -1;                                      \
    } while(0)

/**
 * Macro to check expected errno from some RPC call. 
 *
 * @param _call_name      string with name of call
 * @param _exp_rpc_errno  expected errno
 *
 * @se If check fails, return from function with rc = -1.
 */
#define CHECK_EXPECTED_ERRNO(_call_name, _exp_rpc_errno) 
#undef CHECK_EXPECTED_ERRNO /* really define it below */


/* See description in sockapi-ts.h */
int
sockts_get_socket_state(rcf_rpc_server *pco, int sock,
                        rcf_rpc_server *peer, int peer_s,
                        sockts_socket_state_t *state)
{ 
    /**  
     * @par Algorithm
     */ 
    struct sockaddr_storage addr, peer_name;
    socklen_t               addrlen = sizeof(addr);
    socklen_t               peer_name_len = sizeof(peer_name);

    uint8_t     buf[1] = { 0 };
    int         rc, err;
    int         sock_type = -1;
    int         optval;
    te_bool     shut_rd = FALSE;
    te_bool     shut_wr = FALSE;

    if ((peer == NULL) != (peer_s == -1))
    {
        ERROR("%s: incorrect peer parameters in function call: "
              "peer=0x%x peer_s=%d", __FUNCTION__, peer, peer_s);
        return -1;
    }

    RING("Get socket state %s:%d vs %s:%d", pco->ta, sock,
         peer == NULL ? "NONE" : peer->ta, peer_s);
    
    /* Make happy RPC logging */
    memset(&addr, 0, sizeof(addr));
    memset(&peer_name, 0, sizeof(peer_name));
    addr.ss_family = peer_name.ss_family = AF_INET;

    /** 
     * Call @b getsockopt with option @c SO_TYPE to discover 
     * socket type and check existance of the socket. 
     */
    RPC_AWAIT_IUT_ERROR(pco);
    if (rpc_getsockopt(pco, sock, RPC_SO_TYPE, &sock_type) != 0)
    {
        err = RPC_ERRNO(pco);

        if (err != RPC_EBADF && err != RPC_ENOTSOCK)
        {
            ERROR("getsockopt(%d, SO_TYPE) failed", sock);
            return -1;
        }
        
        /** 
         * If @b errno is @c EBADF or @c ENOTSOCK, call @b close for 
         * this socket, check that it fails with same @b errno, set 
         * @a state to @c STATE_CLOSED and return 0. 
         */ 
        RPC_AWAIT_IUT_ERROR(pco);
        if (rpc_closesocket(pco, sock) == 0)
        {
            ERROR("close(%d) successful after getsockopt() failure", sock);
            return -1;
        }
        else if (RPC_ERRNO(pco) != err)
        {
            ERROR("close(%d) failed with unexpected errno", sock);
            return -1;
        } 
        *state = STATE_CLOSED;
        return 0;
    }

    /** Call @b getsockname to check binding of the socket. */ 
    addrlen = sizeof(addr);
    RPC_AWAIT_IUT_ERROR(pco);
    if ((rc = rpc_getsockname(pco, sock, SA(&addr), &addrlen)) != 0)
    {
        ERROR("getsockname(%d) failed", sock);
        return -1;
    }

    if (rc != 0 || te_sockaddr_get_port(SA(&addr)) == 0)
    {
        /** 
         * If @b getsockname was succesfull, but detect zero port, 
         * socket is not bound. Set @a state to @c STATE_CLEAR, return 0. 
         */ 
        *state = STATE_CLEAR;
        return 0;
    }

    /** Call @c getpeername to find out if the socket is connected */
    RPC_AWAIT_IUT_ERROR(pco);
    if (rpc_getpeername(pco, sock, SA(&peer_name), &peer_name_len) != 0)
    {
        if (RPC_ERRNO(pco) == RPC_ENOTCONN)
        {
            /* The most logical and expected result */
            *state = STATE_BOUND;
        }
        else if (RPC_ERRNO(pco) == RPC_EINVAL)
        {
            RING_VERDICT("getpeername() failed with errno EINVAL, "
                         "assuming that socket is connected and "
                         "shut down for writing");
        }
        else
        {
            ERROR("getpeername() failed with unexpected errno %s",
                  errno_rpc2str(RPC_ERRNO(pco)));
            return -1;
        }
    }
    else
    {
        *state = STATE_CONNECTED;
    }

    /** Get socket option @c SO_ACCEPTCONN of @a sock. */
    while (sock_type == RPC_SOCK_STREAM && *state != STATE_CONNECTED)
    {
        /** 
         * If it returns 0, socket is in listening state. 
         * If it returned -1 with @c errno @c ENOPROTOOPT, get socket
         * option SO_ACCEPTFILTER. If it returned 0, socket is in
         * listening state.
         */
        RPC_AWAIT_IUT_ERROR(pco);
        if (rpc_getsockopt(pco, sock, RPC_SO_ACCEPTCONN, &optval) != 0)
        {
            char optval_acc_f[256] = { 0, };

            if (RPC_ERRNO(pco) != RPC_ENOPROTOOPT)
            {
                ERROR("getsockopt(%d, SO_ACCEPTCONN) failed", sock);
                return -1;
            }
    
            RPC_AWAIT_IUT_ERROR(pco);
            if (rpc_getsockopt(pco, sock, RPC_SO_ACCEPTFILTER,
                               optval_acc_f) != 0)
            {
                err = RPC_ERRNO(pco);

                if (TE_RC_GET_ERROR(err) == TE_EINVAL)
                    break;
                ERROR("getsockopt(%d, SO_ACCEPTFILTER) failed", sock);
                return -1;
            }
        }
        else if (optval == 0)
            break;

        *state = STATE_LISTENING;
        
        /** 
         * Check that socket is really listening:
         *     -# Call @b bind() on @p socket with @a address, got by
         *        @b getsockname(). 
         *     -# Check that @b bind failed with @b errno @c EINVAL.
         *     -# Call @b recv() on @p socket with correct data buffer.
         *     -# Check that calls returned 0 or failed with @b errno
         *        @c ENOTCONN.
         *     -# return state @c STATE_LISTENING.
         */

        RPC_AWAIT_IUT_ERROR(pco);
        rc = rpc_bind(pco, sock, SA(&addr));
        if (rc == 0)
        {
            ERROR("bind() successful for listening socket");
            return -1;
        }
        err = RPC_ERRNO(pco);
        if (err != RPC_EINVAL)
        {
            ERROR("bind() returned unexpected errno %s",
                  errno_rpc2str(err));
            return -1;
        }

        RPC_AWAIT_IUT_ERROR(pco);
        rc = rpc_recv(pco, sock, buf, sizeof(buf), RPC_MSG_DONTWAIT);
        if (rc == 0)
        {
            /* Verdict? */
            RING("recv() for listening socket returned 0");
        }
        else if (rc > 0)
        {
            ERROR("recv() for listening socket returned %d", rc);
            return -1;
        }
        else
        {
            err = RPC_ERRNO(pco);
            if (err != RPC_ENOTCONN)
            {
                ERROR("recv() for listening socket set unexpected "
                      "errno %s", errno_rpc2str(err));
                return -1;
            }
        }

        return 0;
    }

    /** If socket is not connected, return 0. */
    if (*state == STATE_BOUND)
        return 0;
    
    /** 
     * At the moment we have a connected socket. Check whether
     * it is in shutdown state or not.
     * Install empty handler for @c SIGPIPE.
     * Send data bulk with length 0 to the socket.
     * If it fails with @c errno @c ESHUTDOWN or @c EPIPE, 
     * then write is disabled on the socket.
     */
     do {
        DEFINE_RPC_STRUCT_SIGACTION(old_act);
        CHECK_RC(tapi_sigaction_simple(pco, RPC_SIGPIPE,
                                       SIGNAL_REGISTRAR, &old_act));

        RPC_AWAIT_IUT_ERROR(pco);
        rc = rpc_send(pco, sock, buf, 0, 0);

        err = RPC_ERRNO(pco);

        rpc_sigaction(pco, RPC_SIGPIPE, &old_act, NULL);
        rpc_sigset_delete(pco, old_act.mm_mask);

        if (rc == 0 || err == RPC_EADDRNOTAVAIL)
        {
            if (rc == 0 && sock_type == RPC_SOCK_DGRAM && 
                *state == STATE_CONNECTED && peer != NULL)
            {
                RPC_AWAIT_IUT_ERROR(peer);
                rpc_recv(peer, peer_s, buf, sizeof(buf), 0);
            }
            break;
        }

        if (err != RPC_EPIPE)
        {
            ERROR("send(%d) failed with unexpected errno", sock);
            return -1;
        }

        shut_wr = TRUE;
    } while (0);

#ifndef DOXYGEN_TEST_SPEC
#define CHECK_ERRNO(func) \
    do {                                         \
        if (RPC_ERRNO(pco) != 0)                 \
        {                                        \
            ERROR("%s failed on the PCO", func); \
            return -1;                           \
        }                                        \
    } while (0)
#endif

    /**
     * Call @b iomux_call() for read events with zero timeout
     * to check shutdown for reading.
     * If socket is shutdowned, this call will return 1, otherwise
     * it will return 0. 
     */
    RPC_AWAIT_IUT_ERROR(pco);
    rc = iomux_call_default_simple(pco, sock, EVT_RD, NULL, 1000);
    CHECK_ERRNO("iomux_call");
    if (rc == 1)
        shut_rd = 1; 

    /** Set @a state according to obtained shutdown state */
    if (shut_rd && shut_wr)
        *state = STATE_SHUT_RDWR;
    else if (shut_rd)
        *state = STATE_SHUT_RD;
    else if (shut_wr)
        *state = STATE_SHUT_WR;

    return 0; 
}

/* See the description in sockapi-ts.h */
rpc_socket_addr_family
sockts_domain2family(rpc_socket_domain domain)
{
    switch (domain)
    {
        case RPC_PF_INET:
            return RPC_AF_INET;

        case RPC_PF_INET6:
            return RPC_AF_INET6;

        default:
            ERROR("%s(): Domain %s (%d) is not supported, "
                  "operation has no effect", __FUNCTION__, 
                  domain_rpc2str(domain), domain);
    }

    return RPC_AF_UNKNOWN;
}

/* See the description in sockapi-ts.h */
int
sockaddr_get_size_by_domain(rpc_socket_domain domain)
{
    switch (domain)
    {
        case RPC_PF_INET:
            return sizeof(struct sockaddr_in);

        case RPC_PF_INET6:
            return sizeof(struct sockaddr_in6);

        default:
            ERROR("%s(): Domain %s (%d) is not supported, "
                  "operation has no effect", __FUNCTION__,
                  domain_rpc2str(domain), domain);
    }

    return 0;
}

/* See the description in sockapi-ts.h */
int
inaddr_get_size_by_domain(rpc_socket_domain domain)
{
    switch (domain)
    {
        case RPC_PF_INET:
            return sizeof(struct in_addr);
        case RPC_PF_INET6:
            return sizeof(struct in6_addr);
        default:
            ERROR("%s(): Domain %s (%d) is not supported, "
                  "operation has no effect", __FUNCTION__,
                  domain_rpc2str(domain), domain);
    }
    return 0;
}

/* See the description in sockapi-ts.h */
int
mcast_join(rcf_rpc_server *rpcs, int sockd, 
           const struct sockaddr *mcast_addr,
           int if_index)
{
    switch (mcast_addr->sa_family)
    {
        case AF_INET:
            return mcast_join_leave(rpcs, sockd, RPC_IP_ADD_MEMBERSHIP,
                                    mcast_addr, if_index);
        default:
            ERROR("%s(): Address family %d is not supported, "
                  "operation has no effect", __FUNCTION__,
                  mcast_addr->sa_family);
    }

    return -1;
}

/* See the description in sockapi-ts.h */
int
mcast_leave(rcf_rpc_server *rpcs, int sockd, 
            const struct sockaddr *mcast_addr,
            int if_index)
{
    switch (mcast_addr->sa_family)
    {
        case AF_INET:
            return mcast_join_leave(rpcs, sockd, RPC_IP_DROP_MEMBERSHIP,
                                    mcast_addr, if_index);
        default:
            ERROR("%s(): Address family %d is not supported, "
                  "operation has no effect", __FUNCTION__,
                  mcast_addr->sa_family);
    }

    return -1;
}

/**
 * Perform multicast join/leave oprtation on specified socket
 * 
 * @param rpcs            RPC server handle
 * @param sockd           Socket descriptor
 * @param opt_level       Option level
 * @param opt_name        Option name
 * @param mcast_addr      Address of the multicast group the the socket leaves
 * @param if_index        Interface index of the interface that should leave
 *                        the multiaddr group
 *
 */
static int
mcast_join_leave(rcf_rpc_server *rpcs, int sockd, rpc_sockopt opt_name,
                 const struct sockaddr *mcast_addr, int if_index)
{
    switch (mcast_addr->sa_family)
    {
        case AF_INET:
        {
            struct tarpc_mreqn mreqn;
            
            memset(&mreqn, 0, sizeof(mreqn));
            mreqn.type = OPT_MREQN;

            memcpy(&(mreqn.multiaddr), &(SIN(mcast_addr)->sin_addr),
                   sizeof(struct in_addr));
                   
            mreqn.ifindex = if_index;
            
            return rpc_setsockopt(rpcs, sockd, opt_name, &mreqn);
            break;
        }
        case AF_INET6:
        {
            struct ipv6_mreq mreqn;
            
            memcpy(&mreqn.ipv6mr_multiaddr, &(SIN6(mcast_addr)->sin6_addr),
                   sizeof(struct in6_addr));
            mreqn.ipv6mr_interface = if_index;
            
            return rpc_setsockopt(rpcs, sockd, opt_name, &mreqn);
            break;
        }
        default:
            ERROR("%s(): Address family %d is not supported, "
                  "operation has no effect", __FUNCTION__,
                  mcast_addr->sa_family);
            return -1;
    }

    return 0;

}

/** Maximum buffer size for ifconf request */
#define IFCONF_BUFFER_MAX       512

/* See the description in sockapi-ts.h */
int
get_ifconf_size(rcf_rpc_server *rpcs, int sockd, int *size)
{
    int            n_reqs = 0;
    int            prev_len;
    struct ifreq  *ifreq_ptr = NULL;
    struct ifconf  ifconf_var;

    if (size == NULL)
    {
        ERROR("%s(): 'size' parameter is not allowed to be NULL",
              __FUNCTION__);
        return -1;
    }

    do {
        struct ifreq *ptr;
        int           total_length;

        prev_len = n_reqs * sizeof(struct ifreq);
        total_length = ((++n_reqs) * sizeof(struct ifreq));
        ptr = ifreq_ptr;

        if ((ifreq_ptr = (struct ifreq *)realloc(ptr, total_length)) == NULL)
        {
            free(ptr);
            ERROR("Cannot allocate necessary amount of memory");
            return -1;
        }

        ifconf_var.ifc_len = total_length;
        ifconf_var.ifc_req = ifreq_ptr;

        RPC_AWAIT_IUT_ERROR(rpcs);
        rpc_ioctl(rpcs, sockd, RPC_SIOCGIFCONF, &ifconf_var);
    } while ((prev_len != ifconf_var.ifc_len) &&
             (prev_len < IFCONF_BUFFER_MAX));

    if (prev_len >= IFCONF_BUFFER_MAX)
    {
        ERROR("Too big buffer for 'ifconf' allocated, it looks "
              "like SIOCGIFCONF use all buffer in any case");
        return -1;
    }

    free(ifreq_ptr);

    *size = prev_len;

    return 0;
}

int
is_addr_inuse(rcf_rpc_server *rpcs, rpc_socket_domain domain,
              rpc_socket_type sock_type, const struct sockaddr *addr)
{
    int     sockd;
    int     rc;
    te_bool result = FALSE;
    
    sockd = rpc_socket(rpcs, domain, sock_type, RPC_PROTO_DEF);

    /* Try to bind the socket to the specified address */
    RPC_AWAIT_IUT_ERROR(rpcs);
    rc = rpc_bind(rpcs, sockd, addr);
    if (rc == -1)
    {
        if (RPC_ERRNO(rpcs) != RPC_EADDRINUSE)
        {
            ERROR("Unexpected errno is set by bind()");
            goto unexp_err;
        }
        result = TRUE;
    }
    else if (rc != 0)
    {
        ERROR("bind() returns unexpected code %d", rc);
        goto unexp_err;
    }

    rpc_close(rpcs, sockd);

    return result;

unexp_err:
    rpc_close(rpcs, sockd);
    return -1;
}

/**
 * Check whether source address of received packet (connection
 * request) matches expectation.
 *
 * @param src_addr      Source address.
 * @param addr_len      Source address length.
 * @param exp_addr      Expected address.
 * @param dst_domain    Domain of receiving socket.
 *
 * @return @c TRUE if source address is expected, @c FALSE otherwise.
 */
static te_bool
check_src_addr(const struct sockaddr *src_addr,
               socklen_t addr_len,
               const struct sockaddr *exp_addr,
               rpc_socket_domain dst_domain)
{
    struct sockaddr_storage exp_addr_aux;

    if (exp_addr == NULL)
        return TRUE;

    memset(&exp_addr_aux, 0, sizeof(exp_addr_aux));

    if (dst_domain == rpc_socket_domain_by_addr(exp_addr) ||
        dst_domain == RPC_PF_UNKNOWN)
    {
        tapi_sockaddr_clone_exact(exp_addr, &exp_addr_aux);
    }
    else if (dst_domain == RPC_PF_INET)
    {
        /*
         * Destination socket is IPv4, source address is IPv6,
         * so it must be IPv4-mapped IPv6.
         */
        if (SIN6(exp_addr)->sin6_addr.s6_addr32[0] != 0 ||
            SIN6(exp_addr)->sin6_addr.s6_addr32[1] != 0 ||
            SIN6(exp_addr)->sin6_addr.s6_addr16[4] != 0 ||
            SIN6(exp_addr)->sin6_addr.s6_addr16[5] != htons(0xFFFF))
        {
            /* Address is not IPv4-mapped IPv6 */
            return FALSE;
        }

        SIN(&exp_addr_aux)->sin_family = AF_INET;
        SIN(&exp_addr_aux)->sin_port = CONST_SIN6(exp_addr)->sin6_port;
        SIN(&exp_addr_aux)->sin_addr.s_addr =
               CONST_SIN6(exp_addr)->sin6_addr.s6_addr32[3];
    }
    else
    {
        /*
         * Destination socket is IPv6, source address is IPv4,
         * so IPv4-mapped IPv6 address must be reported by
         * destination socket.
         */
        SIN6(&exp_addr_aux)->sin6_family = AF_INET6;
        SIN6(&exp_addr_aux)->sin6_port = CONST_SIN(exp_addr)->sin_port;
        SIN6(&exp_addr_aux)->sin6_addr.s6_addr16[5] = htons(0xFFFF);
        SIN6(&exp_addr_aux)->sin6_addr.s6_addr32[3] =
                                    CONST_SIN(exp_addr)->sin_addr.s_addr;
    }

    if (te_sockaddrcmp(src_addr, addr_len,
                       SA(&exp_addr_aux),
                       te_sockaddr_get_size(SA(&exp_addr_aux))) == 0)
    {
        return TRUE;
    }

    return FALSE;
}

/* See description in sockapi-ts.h */
const char *
sockts_test_send_rc2str(sockts_test_send_rc rc)
{
    switch (rc)
    {
        case SOCKTS_TEST_SEND_SUCCESS:
            return "success";

        case SOCKTS_TEST_SEND_FIRST_SEND_FAIL:
            return "the first sending call failed";

        case SOCKTS_TEST_SEND_NON_FIRST_SEND_FAIL:
            return "not the first sending call failed";

        case SOCKTS_TEST_SEND_UNEXP_SEND_RC:
            return "sending function returned unexpected value";

        case SOCKTS_TEST_SEND_ZERO_SEND_RC:
            return "sending function returned zero";

        case SOCKTS_TEST_SEND_NO_DATA:
            return "no data was received";

        case SOCKTS_TEST_SEND_RECV_FAIL:
            return "receiving function failed";

        case SOCKTS_TEST_SEND_ZERO_RECV_RC:
            return "receiving function returned zero";

        case SOCKTS_TEST_SEND_RECV_UNEXP_ADDR:
            return "receiving function returned unexpected address";

        case SOCKTS_TEST_SEND_UNEXP_DGRAM:
            return "unexpected datagram was received";

        case SOCKTS_TEST_SEND_LOST_DGRAM:
            return "datagram was lost";

        case SOCKTS_TEST_SEND_REORDERED_DGRAMS:
            return "datagrams were received in a wrong order";

        case SOCKTS_TEST_SEND_UNEXP_RECV_DATA_LEN:
            return "unexpected number of bytes was received";

        case SOCKTS_TEST_SEND_UNEXP_RECV_DATA:
            return "received data did not match sent data";

        case SOCKTS_TEST_SEND_OUT_OF_MEMORY:
            return "out of memory";
    }

    return "unknown error";
}

/** Packet description used by sockts_test_send_ext() */
typedef struct sockts_test_send_pkt {
    char      tx_buf[SOCKTS_MSG_DGRAM_MAX];   /**< Sent data */
    size_t    pkt_size;                       /**< Number of bytes sent */
    te_bool   received;                       /**< Set to @c TRUE when
                                                   the packet is received */
} sockts_test_send_pkt;

/* See description in sockapi-ts.h */
sockts_test_send_rc
sockts_test_send_ext(sockts_test_send_ext_args *args)
{
#define REPORT_ERROR(_format...) \
    do {                                  \
        if (args->print_verdicts)         \
            ERROR_VERDICT(_format);       \
        else                              \
            ERROR(_format);               \
    } while (0)

    te_dbuf recv_dbuf = TE_DBUF_INIT(0);
    te_dbuf send_dbuf = TE_DBUF_INIT(0);
    char    rx_buf[SOCKTS_MSG_DGRAM_MAX];
    te_bool wrong_dgram_order = FALSE;
    te_bool wrong_dgram = FALSE;
    te_bool readable;
    int     len;
    int     rc;

    sockts_test_send_pkt  *pkts = NULL;
    unsigned int           i;
    unsigned int           j;

    struct sockaddr_storage from_addr;
    socklen_t               from_addr_len;

    sockts_test_send_rc     ret = SOCKTS_TEST_SEND_SUCCESS;

    const char *pref_str = (args->vpref != NULL ? args->vpref : "");
    const char *pref_delim = (pref_str[0] != '\0' ? ": " : "");

    if (args->pkts_num == 0)
    {
        WARN("%s(): zero packets number was requested", __FUNCTION__);
        goto cleanup;
    }

    pkts = TE_ALLOC(args->pkts_num * sizeof(*pkts));
    if (pkts == NULL)
        return SOCKTS_TEST_SEND_OUT_OF_MEMORY;

    for (i = 0; i < args->pkts_num; i++)
    {
        pkts[i].received = FALSE;
        len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);
        pkts[i].pkt_size = len;
        te_fill_buf(pkts[i].tx_buf, len);

        RPC_AWAIT_ERROR(args->rpcs_send);
        if (args->dst_addr == NULL)
        {
            rc = rpc_send(args->rpcs_send, args->s_send, pkts[i].tx_buf,
                          len, 0);
        }
        else
        {
            rc = rpc_sendto(args->rpcs_send, args->s_send, pkts[i].tx_buf,
                            len, 0, args->dst_addr);
        }

        if (rc < 0)
        {
            REPORT_ERROR("%s%ssend() unexpectedly failed with "
                         "errno %r", pref_str, pref_delim,
                         RPC_ERRNO(args->rpcs_send));
            if (i == 0)
                ret = SOCKTS_TEST_SEND_FIRST_SEND_FAIL;
            else
                ret = SOCKTS_TEST_SEND_NON_FIRST_SEND_FAIL;

            goto cleanup;
        }
        else if (rc != len)
        {
            REPORT_ERROR("%s%ssend() returned %s",
                         pref_str, pref_delim,
                         rc == 0 ? "zero" : "unexpected value");
            if (rc == 0)
                ret = SOCKTS_TEST_SEND_ZERO_SEND_RC;
            else
                ret = SOCKTS_TEST_SEND_UNEXP_SEND_RC;
            goto cleanup;
        }

        if (!args->check_dgram)
            te_dbuf_append(&send_dbuf, pkts[i].tx_buf, len);

        if (args->send_wait > 0 && i < args->pkts_num - 1)
            MSLEEP(args->send_wait);
    }

    rpc_get_rw_ability(&readable, args->rpcs_recv, args->s_recv,
                       args->recv_timeout, "READ");
    if (!readable)
    {
        REPORT_ERROR("%s%sData was sent but peer socket is not "
                     "readable", pref_str, pref_delim);
        ret = SOCKTS_TEST_SEND_NO_DATA;
        goto cleanup;
    }

    i = 0;
    do {
        from_addr_len = sizeof(from_addr);
        RPC_AWAIT_ERROR(args->rpcs_recv);
        rc = rpc_recvfrom(args->rpcs_recv, args->s_recv,
                          rx_buf, sizeof(rx_buf),
                          RPC_MSG_DONTWAIT, SA(&from_addr),
                          &from_addr_len);
        if (rc > 0)
        {
            if (args->check_dgram)
            {
                if (i >= args->pkts_num)
                {
                    wrong_dgram = TRUE;
                }
                else
                {
                    for (j = 0; j < args->pkts_num; j++)
                    {
                        if (!pkts[j].received &&
                            pkts[j].pkt_size == (size_t)rc &&
                            memcmp(pkts[j].tx_buf, rx_buf, rc) == 0)
                        {
                            pkts[j].received = TRUE;
                            break;
                        }
                    }

                    if (j < args->pkts_num)
                    {
                        if (j != i)
                            wrong_dgram_order = TRUE;
                    }
                    else
                    {
                        wrong_dgram = TRUE;
                    }
                }
            }
            else
            {
                te_dbuf_append(&recv_dbuf, rx_buf, rc);
            }
        }
        else if (rc < 0)
        {
            if (RPC_ERRNO(args->rpcs_recv) == RPC_EAGAIN)
                break;

            REPORT_ERROR("%s%srecvfrom() call failed with errno %r",
                         pref_str, pref_delim, RPC_ERRNO(args->rpcs_recv));
            ret = SOCKTS_TEST_SEND_RECV_FAIL;
            goto cleanup;
        }
        else
        {
            REPORT_ERROR("%s%srecvfrom() call returned zero",
                         pref_str, pref_delim);
            ret = SOCKTS_TEST_SEND_ZERO_RECV_RC;
            goto cleanup;
        }

        if (!check_src_addr(SA(&from_addr), from_addr_len,
                            args->src_addr, args->s_recv_domain))
        {
            REPORT_ERROR("%s%srecvfrom() call returned unexpected "
                         "address", pref_str, pref_delim);
            RING("Expected address was %s", sockaddr_h2str(args->src_addr));
            ret = SOCKTS_TEST_SEND_RECV_UNEXP_ADDR;
            goto cleanup;
        }

        /*
         * It is possible that part of data is still on its way,
         * this is used simply to wait for it.
         */
        if ((args->check_dgram && i < args->pkts_num - 1) ||
            recv_dbuf.len < send_dbuf.len)
        {
            RPC_GET_READABILITY(readable, args->rpcs_recv, args->s_recv,
                                args->recv_timeout);
        }

        i++;
    } while (TRUE);

    if (args->check_dgram)
    {
        if (wrong_dgram)
        {
            REPORT_ERROR("%s%sUnexpected datagram was received", pref_str,
                         pref_delim);
            ret = SOCKTS_TEST_SEND_UNEXP_DGRAM;
            goto cleanup;
        }

        if (i < args->pkts_num)
        {
            REPORT_ERROR("%s%sSome datagrams were lost", pref_str,
                         pref_delim);
            ret = SOCKTS_TEST_SEND_LOST_DGRAM;
            goto cleanup;
        }

        if (wrong_dgram_order)
        {
            REPORT_ERROR("%s%sDatagrams were received in a different "
                         "order", pref_str, pref_delim);
            ret = SOCKTS_TEST_SEND_REORDERED_DGRAMS;
            goto cleanup;
        }
    }
    else
    {
        if (send_dbuf.len != recv_dbuf.len)
        {
            REPORT_ERROR("%s%sIncorrect amount of data is received",
                         pref_str, pref_delim);
            ret = SOCKTS_TEST_SEND_UNEXP_RECV_DATA_LEN;
            goto cleanup;
        }

        if (memcmp(send_dbuf.ptr, recv_dbuf.ptr, send_dbuf.len) != 0)
        {
            REPORT_ERROR("%s%sUnexpected data was received", pref_str,
                         pref_delim);
            ret = SOCKTS_TEST_SEND_UNEXP_RECV_DATA;
            goto cleanup;
        }
    }

cleanup:

    te_dbuf_free(&send_dbuf);
    te_dbuf_free(&recv_dbuf);
    free(pkts);

    return ret;
#undef REPORT_ERROR
}

/* See the description in sockapi-ts.h */
te_errno
sockts_test_send(rcf_rpc_server *rpcs1, int s1,
                 rcf_rpc_server *rpcs2, int s2,
                 const struct sockaddr *s1_addr,
                 const struct sockaddr *s2_addr,
                 rpc_socket_domain s2_domain,
                 te_bool check_dgram,
                 const char *vpref)
{
    sockts_test_send_rc       rc;
    sockts_test_send_ext_args args = SOCKTS_TEST_SEND_EXT_ARGS_INIT;

    args.rpcs_send = rpcs1;
    args.s_send = s1;
    args.rpcs_recv = rpcs2;
    args.s_recv = s2;
    args.s_recv_domain = s2_domain;
    args.src_addr = s1_addr;
    args.dst_addr = s2_addr;
    args.check_dgram = check_dgram;
    args.vpref = vpref;

    rc = sockts_test_send_ext(&args);

    if (rc == SOCKTS_TEST_SEND_NO_DATA)
        return TE_ENODATA;
    else if (rc != 0)
        return TE_EFAIL;

    return 0;
}

/**
 * Check that traffic may be sent/received via connection in both
 * directions.
 *
 * @param rpcs1         RPC server holding the first connection endpoint
 * @param s1            socket corresponding to the first endpoint
 * @param rpcs2         RPC server holding the second connection endpoint
 * @param s2            socket corresponding to the first endpoint
 */
void
sockts_test_connection(rcf_rpc_server *rpcs1, int s1,
                       rcf_rpc_server *rpcs2, int s2)
{
    CHECK_RC(sockts_test_send(rpcs1, s1, rpcs2, s2, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));
    CHECK_RC(sockts_test_send(rpcs2, s2, rpcs1, s1, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));
}

/* See the description in sockapi-ts.h */
int
sockts_tcp_connect(rcf_rpc_server *rpcs_clnt, int s_conn,
                   rcf_rpc_server *rpcs_srv, int s_listener,
                   const struct sockaddr *src_addr,
                   const struct sockaddr *conn_addr,
                   rpc_socket_domain srv_domain,
                   const char *vpref)
{
    int           old_flags = 0;
    int           rc = 0;
    te_bool       readable = FALSE;
    int           acc_s = -1;

    struct sockaddr_storage from_addr;
    socklen_t               from_addr_len;

    const char *pref_str = (vpref != NULL ? vpref : "");
    const char *pref_delim = (pref_str[0] != '\0' ? ": " : "");

    old_flags = rpc_fcntl(rpcs_clnt, s_conn, RPC_F_GETFL, 0);
    rpc_fcntl(rpcs_clnt, s_conn, RPC_F_SETFL, old_flags | RPC_O_NONBLOCK);

    RPC_AWAIT_ERROR(rpcs_clnt);
    rc = rpc_connect(rpcs_clnt, s_conn, conn_addr);
    if (rc < 0 && RPC_ERRNO(rpcs_clnt) != RPC_EINPROGRESS)
    {
        ERROR_VERDICT("%s%snonblocking connect() failed with "
                      "unexpected errno %r",
                      pref_str, pref_delim, RPC_ERRNO(rpcs_clnt));

        goto cleanup;
    }

    RPC_GET_READABILITY(readable, rpcs_srv, s_listener,
                        TAPI_WAIT_NETWORK_DELAY);
    if (!readable)
    {
        ERROR_VERDICT("%s%sListener socket did not become readable",
                      pref_str, pref_delim);
        goto cleanup;
    }

    from_addr_len = sizeof(from_addr);
    RPC_AWAIT_ERROR(rpcs_srv);
    acc_s = rpc_accept(rpcs_srv, s_listener, SA(&from_addr),
                       &from_addr_len);
    if (acc_s < 0)
    {
        ERROR_VERDICT("%s%saccept() failed with errno %r",
                      pref_str, pref_delim, RPC_ERRNO(rpcs_srv));
    }

    if (!check_src_addr(SA(&from_addr), from_addr_len,
                        src_addr, srv_domain))
    {
        ERROR_VERDICT("%s%saccept() call returned unexpected "
                      "address", pref_str, pref_delim);
        RPC_CLOSE(rpcs_srv, acc_s);
    }

cleanup:

    rpc_fcntl(rpcs_clnt, s_conn, RPC_F_SETFL, old_flags);

    return acc_s;
}

/* See the description in sockapi-ts.h */
te_errno
sockts_check_recv_accept(rcf_rpc_server *rpcs1, int s1,
                         rcf_rpc_server *rpcs2, int s2,
                         const struct sockaddr *s1_addr,
                         const struct sockaddr *s2_addr,
                         rpc_socket_domain s2_domain,
                         rpc_socket_type sock_type,
                         int *s_acc,
                         const char *vpref)
{
    if (sock_type == RPC_SOCK_STREAM)
    {
        *s_acc = sockts_tcp_connect(rpcs1, s1, rpcs2, s2, s1_addr, s2_addr,
                                    s2_domain, vpref);
        if (*s_acc < 0)
            return TE_ENOTCONN;
    }
    else
    {
        return sockts_test_send(rpcs1, s1, rpcs2, s2, s1_addr, s2_addr,
                                s2_domain, TRUE, vpref);
    }

    return 0;
}

/* See the description in sockapi-ts.h */
void
sockts_test_connection_ext(rcf_rpc_server *rpcs1, int s1,
                           rcf_rpc_server *rpcs2, int s2,
                           const struct sockaddr *s2_addr,
                           sockts_socket_type sock_type)
{
    if (sock_type == SOCKTS_SOCK_UDP_NOTCONN)
    {
        sockts_test_udp_sendto(rpcs1, s1, rpcs2, s2,
                               s2_addr);
    }
    else
    {
        CHECK_RC(sockts_test_send(rpcs1, s1, rpcs2, s2, NULL, NULL,
                                  RPC_PF_UNSPEC, FALSE, ""));
    }

    CHECK_RC(sockts_test_send(rpcs2, s2, rpcs1, s1, NULL, NULL,
                              RPC_PF_UNSPEC, FALSE, ""));
}

/* See the description in sockapi-ts.h */
void
sockts_test_udp_sendto(rcf_rpc_server *rpcs1, int s1,
                       rcf_rpc_server *rpcs2, int s2,
                       const struct sockaddr *dst_addr)
{
    CHECK_RC(sockts_test_send(rpcs1, s1, rpcs2, s2,
                              NULL, dst_addr, RPC_PF_UNKNOWN,
                              TRUE, ""));
}

/* See the description in sockapi-ts.h */
void
sockts_test_udp_sendto_bidir(rcf_rpc_server *rpcs1, int s1,
                             const struct sockaddr *addr1,
                             rcf_rpc_server *rpcs2, int s2,
                             const struct sockaddr *addr2)
{
    sockts_test_udp_sendto(rpcs1, s1, rpcs2, s2, addr2);
    sockts_test_udp_sendto(rpcs2, s2, rpcs1, s1, addr1);
}

/* See the description in sockapi-ts.h */
void
sockts_leak_file_name(rcf_rpc_server *rpcs, char *suf,
                      char *name, size_t len)
{
#ifdef HOST_NAME_MAX
    char  hname[HOST_NAME_MAX];
#else
    char  hname[256];
#endif

    memset(hname, 0, sizeof(hname));
    rpc_gethostname(rpcs, hname, sizeof(hname));
    snprintf(name, len, "/tmp/netstat_%s%s", hname,
             (suf == NULL) ? "" : suf);
}

/* See the description in sockapi-ts.h */
int
sockts_save_netstat_out(rcf_rpc_server *rpcs, char *name)
{
    char *out_str = NULL;
    int   file;

    rpcs->use_libc = TRUE;
    rpc_shell_get_all(rpcs, &out_str, "netstat -autpn", -1);
    if (out_str == NULL)
    {
        ERROR("Could not get output of 'netstat -autpn' command");
        rpcs->use_libc = FALSE;
        return -1;
    }
    if ((file = open(name, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU)) == -1)
    {
        ERROR("Could not create file %s", name);
        rpcs->use_libc = FALSE;
        return -1;
    }
    if (write(file, out_str, strlen(out_str)) != (ssize_t)strlen(out_str))
    {
        ERROR("Could not write %d bytes to file %s", strlen(out_str), name);
        rpcs->use_libc = FALSE;
        return -1;
    }
    if (close(file) == -1)
    {
        ERROR("Could not close file %s", name);
        rpcs->use_libc = FALSE;
        return -1;
    }
    free(out_str);
    rpcs->use_libc = FALSE;

    return 0;
}

/** Get output from pipe stream
 *
 * @param buf   Output of command
 * @param len   Length of buffer
 * @param cmd   Command for generate output
 *
 * @return 0 on success and -1 on failure
 */
static int
sockts_get_popen_out(char *buf, size_t len, char *cmd, ...)
{
    va_list    ap;
    char       cmd_str[1024];
    FILE      *fp;

    va_start(ap, cmd);

    vsnprintf(cmd_str, sizeof(cmd_str), cmd, ap);

    va_end(ap);

    if ((fp = popen(cmd_str, "r")) == NULL)
    {
        ERROR("popen(%s) failed", cmd_str);
        return -1;
    }
    if ((fread (buf, len, 1, fp) < len) &&
        (ferror(fp) != 0))
    {
        ERROR("fread() failed");
        return -1;
    }
    if (pclose(fp) == -1)
    {
        ERROR("Could not close pipe");
        return -1;
    }

    return 0;
}

/* See the description in sockapi-ts.h */
/* TODO: This way doesn't found leakage for bound but not listening TCP
 * socket.
 */
int
sockts_cmp_netstat_out(char *name1, char *name2)
{
    char  name_diff[SOCKTS_LEAK_FNAME_MAX_LEN];
    char  buf[2048];
    int   file;
    int   new_s_num;

    snprintf(name_diff, sizeof(name_diff), "/tmp/diff.XXXXXX");
    if ((file = mkstemp(name_diff)) == -1)
    {
        ERROR("Could not create temporary file");
        return -1;
    }

    if (sockts_get_popen_out(buf, sizeof(buf), "diff -u %s %s", name1,
                             name2) == -1)
    {
        ERROR("Could not get output of 'diff -u %s %s'", name1, name2);
        return -1;
    }
    if (write(file, buf, strlen(buf)) != (ssize_t)strlen(buf))
    {
        ERROR("Could not write %d bytes to file %s", strlen(buf),
              name_diff);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    if (sockts_get_popen_out(buf, sizeof(buf),
                             "grep -v ^+++ %s | grep -v TIME_WAIT "
                             "| grep -c ^+ | grep -", name_diff) == -1)
    {
        ERROR("Could not get output of grep command");
        return -1;
    }
    new_s_num = atoi(buf);
    memset(buf, 0, sizeof(buf));
    if (sockts_get_popen_out(buf, sizeof(buf),
                             "grep -v ^+++ %s | grep -v TIME_WAIT "
                             "| grep ^+ | grep -", name_diff) == -1)
    {
        ERROR("Could not get output of grep command");
        return -1;
    }
    if (new_s_num != 0)
        ERROR("Number of leak sockets: %d\n Description:\n%s",
              new_s_num, buf);

    if (close(file) == -1)
    {
        ERROR("Could not close file %s", name_diff);
        return -1;

    }
    unlink(name_diff);
    return new_s_num;
}

/* See the description in sockapi-ts.h */
int
gen_conn_with_flags(rcf_rpc_server *pco1, rcf_rpc_server *pco2,
                    const struct sockaddr *addr1,
                    const struct sockaddr *addr2,
                    int *s1, int *s2, rpc_socket_type sock_type,
                    rpc_socket_flags sock_flags, te_bool sf_first,
                    te_bool sf_second, te_bool accept4_first)
{
    int s1_listening = -1;
    int rc = 0;

    rpc_errno err = 0;

    if (sf_first)
    {
        RPC_AWAIT_IUT_ERROR(pco1);
        *s1 = rpc_socket(pco1,
                         rpc_socket_domain_by_addr(addr1),
                         sock_type | sock_flags, RPC_PROTO_DEF);
        if (*s1 == -1)
            TEST_VERDICT("Call socket() with %s flag(s) failed",
                         socket_flags_rpc2str(sock_flags));
    }
    else
        *s1 = rpc_socket(pco1,
                         rpc_socket_domain_by_addr(addr1),
                         sock_type, RPC_PROTO_DEF);

    if (sf_second)
    {
        RPC_AWAIT_IUT_ERROR(pco2);
        *s2 = rpc_socket(pco2,
                         rpc_socket_domain_by_addr(addr2),
                         sock_type | sock_flags, RPC_PROTO_DEF);
        if (*s2 == -1)
            TEST_VERDICT("Call socket() with %s flag(s) failed",
                         socket_flags_rpc2str(sock_flags));
    }
    else
        *s2 = rpc_socket(pco2,
                         rpc_socket_domain_by_addr(addr2),
                         sock_type, RPC_PROTO_DEF);

    if (sock_type == RPC_SOCK_STREAM)
    {
        s1_listening = *s1;
        *s1 = -1;
        rpc_bind(pco1, s1_listening, addr1);
        rpc_listen(pco1, s1_listening, SOCKTS_BACKLOG_DEF);
        if (sf_second &&
            (sock_flags & RPC_SOCK_NONBLOCK))
            RPC_AWAIT_IUT_ERROR(pco2); 
        rc = rpc_connect(pco2, *s2, addr1);
        if (rc < 0 && RPC_ERRNO(pco2) != RPC_EINPROGRESS)
            TEST_VERDICT("%s(): connect failed with the strange "
                         "errno %s on the second socket", __FUNCTION__,
                         errno_rpc2str(RPC_ERRNO(pco2)));

        if (sock_flags & RPC_SOCK_NONBLOCK)
            TAPI_WAIT_NETWORK;

        if (accept4_first)
        {
            RPC_AWAIT_IUT_ERROR(pco1);
            *s1 = rpc_accept4(pco1, s1_listening, NULL,
                              NULL, sock_flags);
            if (*s1 == -1)
            {
                err = RPC_ERRNO(pco1);
                RPC_AWAIT_IUT_ERROR(pco1);
                rpc_close(pco1, s1_listening);
                TEST_VERDICT("Call accept4() with %s flag(s) "
                             "failed with errno %s",
                             socket_flags_rpc2str(sock_flags),
                             errno_rpc2str(err));
            }
        }
        else
            *s1 = rpc_accept(pco1, s1_listening, NULL, NULL);
        rpc_close(pco1, s1_listening);
    }
    else
    {
        rpc_bind(pco2, *s2, addr2);
        rpc_bind(pco1, *s1, addr1);

        if (sf_first &&
            (sock_flags & RPC_SOCK_NONBLOCK))
            RPC_AWAIT_IUT_ERROR(pco1); 
        rc = rpc_connect(pco1, *s1, addr2);
        if (rc < 0)
            TEST_VERDICT("%s(): connect failed with the strange "
                         "errno %s on the first socket", __FUNCTION__,
                         errno_rpc2str(RPC_ERRNO(pco1)));

        if (sf_second &&
            (sock_flags & RPC_SOCK_NONBLOCK))
            RPC_AWAIT_IUT_ERROR(pco2); 
        rc = rpc_connect(pco2, *s2, addr1);
        if (rc < 0)
            TEST_VERDICT("%s(): connect failed with the strange "
                         "errno %s on the second socket", __FUNCTION__,
                         errno_rpc2str(RPC_ERRNO(pco2)));
    }

    return 0;
}

/* See the description in sockapi-ts.h */
int
sockts_share_socket_2proc(rcf_rpc_server *rpcs1, rcf_rpc_server *rpcs2,
                          int sock)
{
    rpc_msghdr          msg;
    char                cmsg_buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr     *cmsg;
    int                 rpcs1_us = -1;
    int                 rpcs2_us = -1;
    struct sockaddr_un  us_addr;
    te_string           us_path = TE_STRING_BUF_INIT(us_addr.sun_path);
    char                rmcmd[sizeof(us_addr.sun_path) + 4];

    memset(&msg, 0, sizeof(msg));
    memset(&us_addr, 0, sizeof(us_addr));
    memset(&cmsg_buf, 0, sizeof(cmsg_buf));

    rpcs1_us = rpc_socket(rpcs1, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);
    rpcs2_us = rpc_socket(rpcs2, RPC_PF_UNIX, RPC_SOCK_DGRAM,
                         RPC_PROTO_DEF);

    us_addr.sun_family = AF_UNIX;
    tapi_file_make_custom_pathname(&us_path, "/tmp", "_share_usocket");

    rpc_bind(rpcs2, rpcs2_us, (struct sockaddr *)&us_addr);
    rpc_connect(rpcs1, rpcs1_us, (struct sockaddr *)&us_addr);

    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);
    msg.msg_cmsghdr_num = 1;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(sock));
    memcpy(CMSG_DATA(cmsg), &sock, sizeof(sock));

    rpc_sendmsg(rpcs1, rpcs1_us, &msg, 0);

    memset(&cmsg_buf, 0, sizeof(cmsg_buf));
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    rpc_recvmsg(rpcs2, rpcs2_us, &msg, 0);
 
    RPC_CLOSE(rpcs2, rpcs2_us);
    RPC_CLOSE(rpcs1, rpcs1_us);

    snprintf(rmcmd, sizeof(rmcmd), "rm %s", us_addr.sun_path);
    rpc_system(rpcs1, rmcmd);

    if (cmsg->cmsg_type != SCM_RIGHTS)
        TEST_FAIL("Failed to pass file descriptor to the second process");

    return *((int*)CMSG_DATA(cmsg));
}

void
sockts_get_kill_zombie_stacks(rcf_rpc_server *rpcs, te_bool check_only)
{
    char    *onload_gnu = getenv("SFC_ONLOAD_GNU");

    if (onload_gnu != NULL && strcmp(onload_gnu, "") != 0)
    {
        if (check_only)
            rpc_system(rpcs, "te_onload_stdump -z");
        else
            rpc_system(rpcs, "te_onload_stdump -z kill");
    }
    else
        ERROR("SFC_ONLOAD_GNU variable is not set");
}

/* See description in sockapi-ts.h */
void
update_arp(rcf_rpc_server *rpcs_src, const struct if_nameindex *iface_src,
           rcf_rpc_server *rpcs_dest, const struct if_nameindex *iface_dest,
           const struct sockaddr *addr_dest,
           const struct sockaddr *link_addr_dest, te_bool is_static)
{
    if (rpcs_src == NULL || iface_src == NULL)
        TEST_FAIL("rpcs_src and iface_src arguments of "
                  "update_arp() must not be NULL");

    CHECK_RC(tapi_update_arp(
                      rpcs_src->ta, iface_src->if_name,
                      (rpcs_dest == NULL ? NULL : rpcs_dest->ta),
                      (iface_dest == NULL ? NULL : iface_dest->if_name),
                      addr_dest, link_addr_dest, is_static));
}

/* See description in the sockapi-ts.h */
void
sockts_close_sockets(rcf_rpc_server *rpcs, int *s, int num)
{
    int i;

    if (s == NULL)
        return;

    for (i = 0; i < num; i++)
    {
        if (s[i] == -1)
            break;
        rpc_close(rpcs, s[i]);
    }
}

/* See description in the sockapi-ts.h */
void
init_mmsghdr(int num, int length, struct rpc_mmsghdr **mmsg_o)
{
    struct rpc_iovec *vector;
    struct rpc_mmsghdr *mmsg;
    int i;

    mmsg = te_calloc_fill(num, sizeof(*mmsg), 0);

    for (i = 0; i < num; i++)
    {
        vector = te_calloc_fill(1, sizeof(*vector), 0);
        vector->iov_base = te_make_buf_by_len(length);
        vector->iov_len = vector->iov_rlen = length;

        mmsg[i].msg_hdr.msg_iovlen = mmsg[i].msg_hdr.msg_riovlen = 1;
        mmsg[i].msg_hdr.msg_iov = vector;
        mmsg[i].msg_hdr.msg_control = te_calloc_fill(1, SOCKTS_CMSG_LEN, 0);
        mmsg[i].msg_hdr.msg_controllen = SOCKTS_CMSG_LEN;
        mmsg[i].msg_hdr.msg_cmsghdr_num = 1;
        mmsg[i].msg_hdr.msg_flags = 0;
        mmsg[i].msg_hdr.msg_name = NULL;
        mmsg[i].msg_hdr.msg_namelen = mmsg[i].msg_hdr.msg_rnamelen = 0;
    }

    *mmsg_o = mmsg;
}

/* See description in the sockapi-ts.h */
void
cleanup_mmsghdr(struct rpc_mmsghdr *mmsg, int num)
{
    int i;

    if (mmsg == NULL)
      return;

    for (i = 0; i < num; i++)
    {
        free(mmsg[i].msg_hdr.msg_control);
        free(mmsg[i].msg_hdr.msg_iov->iov_base);
        free(mmsg[i].msg_hdr.msg_iov);
    }

    free(mmsg);
}

/* See description in the sockapi-ts.h */
void
sockts_extend_cong_window_req(rcf_rpc_server *rpcs1, int s1,
                              rcf_rpc_server *rpcs2, int s2,
                              unsigned int req_window)
{
#define TCP_WIND_LOOP_LIMIT1 30
#define TCP_WIND_LOOP_LIMIT2 5
#define TCP_WIND_DATA_TOTAL 20000000
#define TCP_WIND_DATA_SEND 50000
#define TCP_WIND_DATA_READ 50000
#define TCP_WIND_WAIT 100000

    uint64_t      received;
    unsigned int  got_window = 0;
    unsigned int  old_snd_cwnd = 0;
    unsigned int  i = 0;
    unsigned int  same_cnt = 0;
    rpc_tcp_info  tcp_info;
    rpc_ptr       ptr1;
    rpc_ptr       ptr2;
    int           rc;
    int           num = TCP_WIND_DATA_TOTAL / TCP_WIND_DATA_SEND;

    ptr1 = rpc_malloc(rpcs1, TCP_WIND_DATA_SEND);
    ptr2 = rpc_malloc(rpcs2, TCP_WIND_DATA_READ);

    rpcs1->silent = rpcs1->silent_default = TRUE;
    rpcs2->silent = rpcs2->silent_default = TRUE;

    RING("Extending TCP congestion window, this can take some time...");

    for (i = 0; i < TCP_WIND_LOOP_LIMIT1; i++)
    {
        rpcs2->op = RCF_RPC_CALL;
        rpc_readbuf(rpcs2, s2, ptr2, TCP_WIND_DATA_READ);

        rpcs1->op = RCF_RPC_CALL;
        rpc_many_send_num(rpcs1, s1, TCP_WIND_DATA_SEND, num, -1,
                          FALSE, FALSE, NULL);

        received = 0;
        do {
            RPC_AWAIT_IUT_ERROR(rpcs2);
            rc = rpc_readbuf(rpcs2, s2, ptr2, TCP_WIND_DATA_READ);
            if (rc < 0)
                break;
            received += rc;
        } while (received != TCP_WIND_DATA_TOTAL);
        if (rc < 0)
            break;

        RPC_AWAIT_IUT_ERROR(rpcs1);
        rc = rpc_many_send_num(rpcs1, s1, TCP_WIND_DATA_SEND, num, -1,
                          FALSE, FALSE, NULL);
        if (rc < 0)
            break;

        RPC_AWAIT_IUT_ERROR(rpcs1);
        rc = rpc_getsockopt(rpcs1, s1, RPC_TCP_INFO, &tcp_info);
        if (rc != 0)
            break;

        if (old_snd_cwnd > 0)
        {
            if (old_snd_cwnd >= tcp_info.tcpi_snd_cwnd)
                same_cnt++;
            else
                same_cnt = 0;

            if (same_cnt >= TCP_WIND_LOOP_LIMIT2)
                break;
        }

        old_snd_cwnd = tcp_info.tcpi_snd_cwnd;

        if (req_window > 0 && got_window > req_window)
            break;

        got_window = tcp_info.tcpi_snd_cwnd * tcp_info.tcpi_snd_mss;
        RING("In progress: current send window size is %u bytes", got_window);

        usleep(TCP_WIND_WAIT);
    }

    rpcs1->silent = rpcs1->silent_default = FALSE;
    rpcs2->silent = rpcs2->silent_default = FALSE;

    rpc_free(rpcs1, ptr1);
    rpc_free(rpcs2, ptr2);

    RING("Finally send window size is %u bytes", got_window);

    if (rc < 0)
        TEST_FAIL("Failed to increase TCP congestion window");

    if (req_window > 0)
        RING("Requested send window size is %u bytes", req_window);

    if (req_window > 0 && req_window > got_window)
        TEST_FAIL("Failed to get requested TCP send window");

#undef TCP_WIND_LOOP_LIMIT1
#undef TCP_WIND_LOOP_LIMIT2
#undef TCP_WIND_DATA_TOTAL
#undef TCP_WIND_DATA_SEND
#undef TCP_WIND_DATA_READ
#undef TCP_WIND_WAIT
}

/* See description in the sockapi-ts.h */
void
sockts_close(rcf_rpc_server *rpcs, rcf_rpc_server *parent, int *sock,
             closing_way way)
{
    rpc_wait_status st;
    rcf_rpc_op      op = rpcs->op;
    uint64_t        duration;
    pid_t           pid;
    int             rc;

    switch (way)
    {
        case CL_CLOSE:
            if (TEST_BEHAVIOUR(cleanup_fd_close_enforce_libc))
                rpcs->use_libc_once = TRUE;
            RPC_CLOSE(rpcs, *sock);
            break;

        case CL_SHUTDOWN:
            /* shutdown() must immediately return zero */
            rpc_shutdown(rpcs, *sock, RPC_SHUT_RDWR);
            CHECK_CALL_DURATION_INT(rpcs->duration, TST_TIME_INACCURACY,
                                    TST_TIME_INACCURACY_MULTIPLIER,
                                    0, 0);
            /** Delay to make sure TCP machine has finished shutdown
             * operation. */
            TAPI_WAIT_NETWORK;
            RPC_CLOSE(rpcs, *sock);
            break;

        case CL_EXIT:
        {
            pid = rpc_getpid(rpcs);
            rpc_exit(rpcs, 0);
            if (parent != NULL)
                rpc_waitpid(parent, pid, &st, 0);
            else
                /* We cannot evaluate closing time in this case. */
                rpcs->duration = 1;
            duration = rpcs->duration;
            rcf_rpc_server_restart(rpcs);
            rpcs->duration = duration;
            break;
        }

        case CL_KILL:
        {
            pid = rpc_getpid(rpcs);
            rpc_kill(parent, pid,  RPC_SIGINT);

            if (parent != NULL)
            {
                RPC_AWAIT_IUT_ERROR(parent);
                rc = rpc_waitpid(parent, pid, &st, 0);
                if (rc != pid || st.value != RPC_WAIT_STATUS_SIGNALED)
                    TEST_VERDICT("waitpid() returned unexpected result: %d,"
                                 " state 0x%x", rc, st.value);
            }
            else
                /* We cannot evaluate closing time in this case. */
                rpcs->duration = 1;

            duration = rpcs->duration;
            rcf_rpc_server_restart(rpcs);
            rpcs->duration = duration;
            break;
        }

        case CL_DUP2:
        {
            int tmp_s = rpc_socket(rpcs, RPC_AF_INET, RPC_SOCK_STREAM,
                                   RPC_PROTO_DEF);

            rpc_dup2(rpcs, tmp_s, *sock);

            duration = rpcs->duration;
            RPC_CLOSE(rpcs, tmp_s);
            RPC_CLOSE(rpcs, *sock);
            rpcs->duration = duration;

            break;
        }

        default:
            TEST_FAIL("Unknown socket closing way value %d", way);
    }

    if (op != RCF_RPC_CALL)
        *sock = -1;
}

void
sockts_kill_check_zombie_stack(rcf_rpc_server *rpcs, te_bool reboot)
{
    struct timeval tv_start;
    struct timeval tv_end;
    char          *ef_name;

    if (reboot)
    {
        ef_name = rpc_getenv(rpcs, "EF_NAME");
        if (ef_name != NULL && strcmp(ef_name, "") != 0)
            CHECK_RC(rcf_rpc_server_create(rpcs->ta, "pco_reuse_stack",
                                           NULL));
    }

    gettimeofday(&tv_start, NULL);
    while (tapi_onload_stacks_number(rpcs) > 0)
    {
        sockts_kill_zombie_stacks(rpcs);
        TAPI_WAIT_NETWORK;
        gettimeofday(&tv_end, NULL);
        if (TE_US2SEC(TIMEVAL_SUB(tv_end, tv_start)) >=
            SOCKTS_ZOMBIE_STACK_KILLING_TIMEOUT)
        {
            ERROR_VERDICT("Failed to kill zombie stacks");
            break;
        }
    }
}

/* See description in sockapi-ts.h */
te_bool
sockts_zf_shim_run(void)
{
    const char *val = getenv("ZF_SHIM_RUN");

    if (val == NULL)
        return FALSE;

    if (strcmp(val, "true") == 0)
        return TRUE;

    return FALSE;
}

/* See description in sockapi-ts.h */
char *
sockts_zf_stackdump_path(rcf_rpc_server *rpcs)
{
    char *path = NULL;
    char *agt_dir = NULL;
    cfg_val_type val_type;
    int len;
    int rc;

    val_type = CVT_STRING;
    CHECK_RC(cfg_get_instance_fmt(&val_type, &agt_dir, "/agent:%s/dir:",
                                  rpcs->ta));

    len = snprintf(path, 0, "%s/%s", agt_dir, ZF_STACKDUMP_NAME);
    if (len < 0)
        TEST_FAIL("snprintf() failed rc=%d, errno=%s: get "
                  "zf_stackdump location length", len, strerror(errno));

    /* Increase length to fit \0. */
    len++;
    path = tapi_malloc(len);

    rc = snprintf(path, len, "%s/%s", agt_dir, ZF_STACKDUMP_NAME);
    if (rc < 0 || rc >= len)
        TEST_FAIL("snprintf() failed rc=%d, errno=%s: combine "
                  "zf_stackdump destination path", rc, strerror(errno));

    free(agt_dir);

    return path;
}

/* See description in sockapi-ts.h */
int
sockts_socket(sockts_socket_func sock_func,
              rcf_rpc_server *rpcs,
              rpc_socket_domain domain,
              rpc_socket_type type,
              rpc_socket_proto protocol)
{
    switch (sock_func)
    {
        case SOCKTS_SOCK_FUNC_SOCKET:
            return rpc_socket(rpcs, domain, type, protocol);

        case SOCKTS_SOCK_FUNC_ONLOAD_UNICAST_NONACC:
            return rpc_onload_socket_unicast_nonaccel(rpcs, domain,
                                                      type, protocol);
    }

    ERROR("%s(): unknown socket function type", __FUNCTION__);
    rpcs->_errno = TE_RC(TE_TAPI, TE_EINVAL);
    return -1;
}

/* See description in sockapi-ts.h */
void
sockts_recreate_onload_stack(rcf_rpc_server *pco_iut)
{
    rcf_rpc_server *pco_reuse_stack = NULL;
    char           *ef_name;
    char           *out_str = NULL;
    int             cnt = 15;

    ef_name = rpc_getenv(pco_iut, "EF_NAME");
    if (ef_name != NULL && strcmp(ef_name, "") != 0)
    {
        CHECK_RC(rcf_rpc_server_get(pco_iut->ta, "pco_reuse_stack", NULL,
                                    RCF_RPC_SERVER_GET_EXISTING,
                                    &pco_reuse_stack));

        /* Restart IUT RPC server to make sure that no Onload stack users
         * left. */
        CHECK_RC(rcf_rpc_server_restart(pco_iut));

        /* Check zombie stacks and kill them */
        rpc_shell_get_all(pco_iut, &out_str,
                          "cat /proc/driver/onload/stacks", -1);
        while (strcmp(out_str, "") != 0 && cnt > 0)
        {
            free(out_str);
            out_str = NULL;
            SLEEP(5);
            rpc_shell_get_all(pco_iut, &out_str,
                              "cat /proc/driver/onload/stacks", -1);
            cnt--;
        }
        if (cnt == 0)
        {
            sockts_get_zombie_stacks(pco_iut);
            sockts_kill_zombie_stacks(pco_iut);
            SLEEP(1);
            ERROR_VERDICT("Tester run leaves zombie stacks:\n%s", out_str);
        }

        rcf_rpc_setlibname(pco_reuse_stack, pco_iut->nv_lib);
        rpc_socket(pco_reuse_stack, RPC_AF_INET, RPC_SOCK_STREAM,
                   RPC_PROTO_DEF);
    }
}

/* See description in sockapi-ts.h */
void
sockts_set_multicast_addr(struct sockaddr *addr)
{
    if (addr->sa_family != AF_INET)
        TEST_FAIL("Unsupported address family");

    SIN(addr)->sin_addr.s_addr = htonl(rand_range(0xe0000100, 0xefffffff));
}

/* See description in sockapi-ts.h */
te_errno
sockts_interface_is_sfc(const char *ta, const char *ifname, te_bool *sfc)
{
    te_errno rc;
    char    *drivername;

    rc = tapi_cfg_if_deviceinfo_drivername_get(ta, ifname, &drivername);
    if (rc == 0)
    {
        if (strcmp(drivername, "sfc") == 0)
            *sfc = TRUE;
        else
            *sfc = FALSE;
        free(drivername);
    }

    return rc;
}

/* See description in sockapi-ts.h */
void
sockts_inc_rlimit(rcf_rpc_server *rpcs, int resource, size_t lim)
{
    tarpc_rlimit rlim = {0, 0};

    rpc_getrlimit(rpcs, resource, &rlim);

    if ((size_t)rlim.rlim_cur < lim)
    {
        rlim.rlim_cur = lim;
        if (rlim.rlim_max < rlim.rlim_cur)
            rlim.rlim_max = lim;

        rpc_setrlimit(rpcs, resource, &rlim);
    }
}

/* See description in sockapi-ts.h */
te_errno
sockts_get_csap_pkt_ts(asn_value *pkt, struct timeval *tv)
{
    uint32_t    secs = 0;
    uint32_t    usecs = 0;
    int         rc = 0;

    if (pkt == NULL || tv == NULL)
    {
        ERROR("%s(): incorrect arguments passed", __FUNCTION__);
        return TE_EINVAL;
    }

    rc = asn_read_uint32(pkt, &secs, "received.seconds");
    if (rc != 0)
    {
        ERROR("%s(): failed to get seconds from CSAP packet: %r",
              __FUNCTION__, rc);
        return rc;
    }
    tv->tv_sec = secs;

    rc = asn_read_uint32(pkt, &usecs, "received.micro-seconds");
    if (rc != 0)
    {
        ERROR("%s(): failed to get microseconds from CSAP packet: %r",
              __FUNCTION__, rc);
        return rc;
    }
    tv->tv_usec = usecs;

    return 0;
}

/* See description in sockapi-ts.h */
te_errno
sockts_wait_for_if_up(rcf_rpc_server *rpcs, const char *if_name)
{
    int                     sock;
    struct ifreq            ifreq_val;
    struct ethtool_value    et_val = {0};
    struct timespec         tv_start;
    struct timespec         tv_now;
    /* Typically, the max wait time is 60 seconds, but sometimes it is
     * too short: see ST-1976 */
    const time_t            max_wait_seconds = 180;

    if (rpcs == NULL || if_name == NULL)
    {
        ERROR("%s(): wrong argument value", __FUNCTION__);
        return TE_EINVAL;
    }
    memset(&ifreq_val, 0, sizeof(ifreq_val));

    strncpy(ifreq_val.ifr_name, if_name, sizeof(ifreq_val.ifr_name));
    ifreq_val.ifr_data = (char *)&et_val;
    et_val.cmd = RPC_ETHTOOL_GLINK;

    if (clock_gettime(CLOCK_MONOTONIC, &tv_start) < 0)
    {
        ERROR("%s(): clock_gettime(tv_start) failed", __FUNCTION__);
        return TE_RC(TE_TAPI, te_rc_os2te(errno));
    }
    sock = rpc_socket(rpcs, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    do {
        rpc_ioctl(rpcs, sock, RPC_SIOCETHTOOL, &ifreq_val);
        if (et_val.data)
        {
            ifreq_val.ifr_data = NULL;
            rpc_ioctl(rpcs, sock, RPC_SIOCGIFFLAGS, &ifreq_val);
            /* After interface is up in a correct way
               IFF_NOARP flag is set for ~10s */
            if ((ifreq_val.ifr_flags & RPC_IFF_UP) &&
                (ifreq_val.ifr_flags & RPC_IFF_NOARP))
            {
                /* interface in up state now */
                rpc_close(rpcs, sock);
                return 0;
            }
            else
            {
                ifreq_val.ifr_data = (char *)&et_val;
            }
        }

        if (usleep(1000000) < 0) /* one second */
        {
            ERROR("%s(): usleep() failed", __FUNCTION__);
            rpc_close(rpcs, sock);
            return TE_RC(TE_TAPI, te_rc_os2te(errno));
        }

        if (clock_gettime(CLOCK_MONOTONIC, &tv_now) < 0)
        {
            ERROR("%s(): clock_gettime(tv_now) failed", __FUNCTION__);
            rpc_close(rpcs, sock);
            return TE_RC(TE_TAPI, te_rc_os2te(errno));
        }

    } while ((tv_now.tv_sec - tv_start.tv_sec) < max_wait_seconds);
    rpc_close(rpcs, sock);
    /* failed to wait up state */
    return TE_ETIMEDOUT;
}

/* See description in sockapi-ts.h */
te_errno
sockts_ifs_down_up(rcf_rpc_server *rpcs1,
                   const struct if_nameindex *intf1, ...)
{
    va_list  vl;
    te_errno rc = 0;

    rcf_rpc_server            *rpcs;
    const struct if_nameindex *intf;

    rc = tapi_cfg_base_if_down_up(rpcs1->ta, intf1->if_name);
    if (rc != 0)
        return rc;

    va_start(vl, intf1);
    while ((rpcs = va_arg(vl, rcf_rpc_server *)) != NULL)
    {
        intf = va_arg(vl, const struct if_nameindex *);
        rc = tapi_cfg_base_if_down_up(rpcs->ta, intf->if_name);
        if (rc != 0)
            return rc;
    }
    va_end(vl);

    rc = sockts_wait_for_if_up(rpcs1, intf1->if_name);
    if (rc != 0)
        return rc;

    va_start(vl, intf1);
    while ((rpcs = va_arg(vl, rcf_rpc_server *)) != NULL)
    {
        intf = va_arg(vl, const struct if_nameindex *);
        rc = sockts_wait_for_if_up(rpcs, intf->if_name);
        if (rc != 0)
            return rc;
    }
    va_end(vl);

    return 0;
}

/* See description in sockapi-ts.h */
te_errno
sockts_restart_all_env_ifs(tapi_env *env)
{
    tapi_env_if       *intf;
    tapi_env_process  *proc;
    tapi_env_pco      *pco;
    te_errno           rc;
    te_errno           res = 0;
    te_bool            restarted;
    rpc_wait_status    status;

    CIRCLEQ_FOREACH(intf, &env->ifs, links)
    {
        /*
         * Loopback interface should not be touched, it may
         * break testing.
         */
        if (intf->if_info.if_index == 1 ||
            strcmp(intf->if_info.if_name, "lo") == 0)
            continue;

        restarted = FALSE;
        if (intf->host != NULL)
        {
            proc = SLIST_FIRST(&intf->host->processes);
            if (proc != NULL)
            {
                pco = STAILQ_FIRST(&proc->pcos);
                if (pco != NULL && pco->rpcs != NULL)
                {
                    rc = tapi_cfg_base_if_down_up(pco->rpcs->ta,
                                                  intf->if_info.if_name);
                    if (rc != 0)
                    {
                        ERROR("%s(): failed to restart %s (%s)",
                              __FUNCTION__, intf->name,
                              intf->if_info.if_name);
                        return rc;
                    }

                    rc = sockts_wait_for_if_up(pco->rpcs,
                                               intf->if_info.if_name);
                    if (rc != 0)
                    {
                        ERROR("%s(): failed to wait for %s (%s)",
                              __FUNCTION__, intf->name,
                              intf->if_info.if_name);
                        return rc;
                    }

                    /*
                     * This is done to ensure that IPv6 FAILED neighbor
                     * table entries are gone on RHEL7. See ST-2205.
                     */
                    RPC_AWAIT_ERROR(pco->rpcs);
                    status = rpc_system_ex(pco->rpcs,
                                           "ip -6 neigh flush dev %s",
                                           intf->if_info.if_name);
                    if (status.flag != RPC_WAIT_STATUS_EXITED ||
                        status.value != 0)
                    {
                        ERROR("%s(): system(ip -6 neigh flush dev %s) "
                              "returned unexpected status on %s, FAILED "
                              "IPv6 neighbor table entries may be left",
                              __FUNCTION__, intf->if_info.if_name,
                              pco->rpcs->name);
                        res = TE_EFAIL;
                    }

                    restarted = TRUE;
                }
            }
        }

        if (!restarted)
        {
            WARN("%s(): interface %s (%s) was skipped because "
                 "RPC server was not found",
                 __FUNCTION__, intf->name,
                 intf->if_info.if_name);
        }
    }

    return res;
}

/* See description in sockapi-ts.h */
te_errno
sockts_get_addrs_from_tcp_asn(asn_value *pkt,
                              struct sockaddr_storage *src,
                              struct sockaddr_storage *dst)
{
    te_errno          rc;
    const asn_value  *ip_pdu;

    uint8_t           src_addr[16] = { 0, };
    uint8_t           dst_addr[16] = { 0, };
    size_t            len;
    uint32_t          src_port = 0;
    uint32_t          dst_port = 0;
    int               af;

    rc = asn_read_uint32(pkt, &src_port,
                         "pdus.0.#tcp.src-port");
    if (rc != 0)
    {
        ERROR("%s(): failed to get source port: %r", __FUNCTION__, rc);
        return rc;
    }

    rc = asn_read_uint32(pkt, &dst_port,
                         "pdus.0.#tcp.dst-port");
    if (rc != 0)
    {
        ERROR("%s(): failed to get destination port: %r", __FUNCTION__, rc);
        return rc;
    }

    rc = asn_get_descendent(pkt, (asn_value **)&ip_pdu, "pdus.1.#ip4");
    if (rc == 0)
    {
        af = AF_INET;
    }
    else
    {
        rc = asn_get_descendent(pkt, (asn_value **)&ip_pdu, "pdus.1.#ip6");
        if (rc == 0)
        {
            af = AF_INET6;
        }
        else
        {
            ERROR("%s(): failed to get either IPv4 or IPv6 PDU",
                  __FUNCTION__);
            return TE_RC(TE_TAPI, TE_ENOENT);
        }
    }

    len = sizeof(src_addr);
    rc = asn_read_value_field(ip_pdu, src_addr, &len, "src-addr");
    if (rc != 0)
    {
        ERROR("%s(): failed to get source address: %r", __FUNCTION__, rc);
        return rc;
    }
    if (len != te_netaddr_get_size(af))
    {
        ERROR("%s(): returned source address has unexpected size %"
              TE_PRINTF_SIZE_T "u", __FUNCTION__, len);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    len = sizeof(dst_addr);
    rc = asn_read_value_field(ip_pdu, dst_addr, &len, "dst-addr");
    if (rc != 0)
    {
        ERROR("%s(): failed to get destination address: %r", __FUNCTION__,
              rc);
        return rc;
    }
    if (len != te_netaddr_get_size(af))
    {
        ERROR("%s(): returned destination address has unexpected size %"
              TE_PRINTF_SIZE_T "u", __FUNCTION__, len);
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    memset(src, 0, sizeof(*src));
    memset(dst, 0, sizeof(*dst));
    SA(src)->sa_family = af;
    SA(dst)->sa_family = af;
    te_sockaddr_set_port(SA(src), htons(src_port));
    te_sockaddr_set_port(SA(dst), htons(dst_port));
    if (te_sockaddr_set_netaddr(SA(src), src_addr) < 0)
    {
        ERROR("%s(): failed to set address in src", __FUNCTION__);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }
    if (te_sockaddr_set_netaddr(SA(dst), dst_addr) < 0)
    {
        ERROR("%s(): failed to set address in dst", __FUNCTION__);
        return TE_RC(TE_TAPI, TE_EFAIL);
    }

    return 0;
}

/**
 * Structure to store data for processing packets captured
 * by CSAP, used when checking that a specific packet header
 * field has expected value.
 */
typedef struct check_field_pkts_data {
    te_bool       failed;       /**< Will be set to @c TRUE in case of
                                     an error when processing a packet */

    const char   *field_labels; /**< ASN labels of the checked field */
    long int      exp_value;    /**< Expected field value; if negative,
                                     it is checked that the field has the
                                     same (arbitrary) non-zero value in all
                                     packets */
    long int      wrong_value;  /**< Known "wrong value" which should not
                                     be used; ignored if <= @c 0 */

    te_bool       got_wrong;    /**< Will be set to @c TRUE if known "wrong
                                     value" was encountered in the checked
                                     field */
    te_bool       got_unknown;  /**< Will be set to @c TRUE if unknown
                                     non-zero value was encountered in the
                                     checked field */
    te_bool       got_zero;     /**< Will be set to @c TRUE if zero value
                                     was encountered in the checked field */
} check_field_pkts_data;

/**
 * Callback for processing packets captured by CSAP when
 * checking whether specific field in packet headers has
 * expected value.
 *
 * @param pkt         Packet described in ASN.
 * @param user_data   Pointer to check_field_pkts_data structure.
 */
static void
check_field_pkts_handler(asn_value *pkt, void *user_data)
{
    check_field_pkts_data   *data = (check_field_pkts_data *)user_data;
    uint32_t                 value;
    te_errno                 rc;

    rc = asn_read_uint32(pkt, &value, data->field_labels);
    if (rc != 0)
    {
        ERROR("Failed to read %s field: %r", data->field_labels, rc);
        data->failed = TRUE;
        goto cleanup;
    }

    if (data->exp_value < 0 && value > 0)
    {
        data->exp_value = value;
        RING("%s = %u in the first packet, expecting it in other "
             "packets now", data->field_labels, value);
    }

    if (data->wrong_value > 0 && (long int)value == data->wrong_value)
    {
        data->got_wrong = TRUE;
        ERROR("Known wrong value %u of %s was encountered",
              value, data->field_labels);
    }
    else if (value == 0)
    {
        if (data->exp_value != 0)
        {
            ERROR("Zero value of %s was encountered",
                  data->field_labels);
        }
        data->got_zero = TRUE;
    }
    else if ((long int)value != data->exp_value)
    {
        data->got_unknown = TRUE;
        ERROR("Unexpected value %u of %s was encountered",
              value, data->field_labels);
    }

cleanup:

    asn_free_value(pkt);
}

/* See description in sockopts_common.h */
void
sockts_check_field(rcf_rpc_server *pco,
                   const char *field_name,
                   const char *field_labels,
                   const char *exp_value_name,
                   long int exp_value,
                   const char *wrong_value_name,
                   long int wrong_value,
                   csap_handle_t csap,
                   te_bool *failed,
                   const char *err_msg)
{
    check_field_pkts_data     pkts_data;
    tapi_tad_trrecv_cb_data   cb_data;
    unsigned int              pkts_num = 0;

    memset(&cb_data, 0, sizeof(cb_data));
    memset(&pkts_data, 0, sizeof(pkts_data));
    pkts_data.field_labels = field_labels;
    pkts_data.exp_value = exp_value;
    pkts_data.wrong_value = wrong_value;
    cb_data.callback = &check_field_pkts_handler;
    cb_data.user_data = &pkts_data;

    CHECK_RC(tapi_tad_trrecv_get(pco->ta, 0, csap,
                                 &cb_data, &pkts_num));
    if (pkts_num == 0)
    {
        ERROR_VERDICT("%s: no packets were captured", err_msg);
        *failed = TRUE;
        return;
    }

    if (pkts_data.failed)
    {
        ERROR_VERDICT("%s: failed to process some of the captured packets",
                      err_msg);
        *failed = TRUE;
    }

    if (pkts_data.got_wrong)
    {
        ERROR_VERDICT("%s: in some packets %s value was set instead of "
                      "%s value in %s header field", err_msg,
                      wrong_value_name, exp_value_name, field_name);
        *failed = TRUE;
    }

    if (pkts_data.got_unknown)
    {
        if (exp_value < 0)
        {
            ERROR_VERDICT("%s: not all packets had the same value of %s "
                          "header field", err_msg, field_name);
        }
        else
        {
            ERROR_VERDICT("%s: in some packets unknown non-zero value was "
                          "set in %s header field",
                          err_msg, field_name);
        }
        *failed = TRUE;
    }

    if (pkts_data.got_zero && exp_value != 0)
    {
        ERROR_VERDICT("%s: in some packets zero value was set in %s "
                      "header field", err_msg, field_name);
        *failed = TRUE;
    }
}

/* See description in sockapi-ts.h */
void
sockts_send_check_field(rcf_rpc_server *pco_iut, int iut_s,
                        rcf_rpc_server *pco_tst, int tst_s,
                        sockts_socket_type sock_type,
                        const struct sockaddr *tst_addr,
                        const char *field_name,
                        const char *field_labels,
                        const char *exp_value_name,
                        long int exp_value,
                        const char *wrong_value_name,
                        long int wrong_value,
                        csap_handle_t csap,
                        te_bool *failed,
                        const char *err_msg)
{

    CHECK_RC(sockts_test_send(pco_iut, iut_s, pco_tst, tst_s,
                              NULL,
                              (sock_type == SOCKTS_SOCK_UDP_NOTCONN ?
                                                        tst_addr : NULL),
                              RPC_PF_UNKNOWN,
                              (sock_type == SOCKTS_SOCK_UDP_NOTCONN ||
                               sock_type == SOCKTS_SOCK_UDP),
                              err_msg));

    sockts_check_field(pco_tst, field_name, field_labels, exp_value_name, exp_value,
                       wrong_value_name, wrong_value, csap, failed, err_msg);
}

/* See description in sockapi-ts.h */
te_errno
sockts_get_net_addrs_from_if(rcf_rpc_server *rpcs, const char *if_name,
                             tapi_env_net *net, int af,
                             struct sockaddr_storage **addrs_out,
                             unsigned int *addrs_num_out)
{
    struct sockaddr_storage   *addrs = NULL;
    unsigned int               addrs_num = 0;
    unsigned int               i;
    cfg_handle                *addrs_hndls = NULL;
    unsigned int               addrs_hndls_num = 0;
    char                      *addr_str = NULL;
    int                        rc = 0;

    if ((rc = cfg_find_pattern_fmt(&addrs_hndls_num, &addrs_hndls,
                                   "/agent:%s/interface:%s/net_addr:*",
                                   rpcs->ta, if_name)) != 0)
    {
        ERROR("%s(): failed to get net_addr list for "
              "/agent:%s/interface:%s/",
              __FUNCTION__, rpcs->ta, if_name);
        return rc;
    }

    addrs = TE_ALLOC(sizeof(*addrs) * addrs_hndls_num);
    if (addrs == NULL)
    {
        ERROR("%s(): out of memory", __FUNCTION__);
        rc = TE_ENOMEM;
        goto cleanup;
    }

    for (i = 0; i < addrs_hndls_num; i++)
    {
        struct sockaddr_storage    cmp_addr;
        struct sockaddr           *net_addr;

        rc = cfg_get_inst_name(addrs_hndls[i], &addr_str);
        if (rc != 0)
        {
            ERROR("%s(): failed to get address instance name, rc=%r",
                  __FUNCTION__, rc);
            goto cleanup;
        }

        rc = te_sockaddr_netaddr_from_string(addr_str,
                                             SA(&addrs[addrs_num]));
        if (rc != 0)
        {
            ERROR("%s(): failed to convert '%s' to address, rc=%r",
                  __FUNCTION__, addr_str, rc);
            goto cleanup;
        }

        free(addr_str);
        addr_str = NULL;

        if (SA(&addrs[addrs_num])->sa_family != af)
            continue;

        tapi_sockaddr_clone_exact(SA(&addrs[addrs_num]), &cmp_addr);
        rc = te_sockaddr_cleanup_to_prefix(SA(&cmp_addr),
                                           (af == AF_INET ?
                                                net->ip4pfx :
                                                net->ip6pfx));
        if (rc != 0)
        {
            ERROR("%s(): te_sockaddr_cleanup_to_prefix() returned %r",
                  __FUNCTION__, rc);
            goto cleanup;
        }

        net_addr = (af == AF_INET ? net->ip4addr : net->ip6addr);

        if (te_sockaddrcmp_no_ports(
                          net_addr,
                          te_sockaddr_get_size(net_addr),
                          SA(&cmp_addr),
                          te_sockaddr_get_size(SA(&cmp_addr))) != 0)
        {
            continue;
        }

        addrs_num++;
    }

    RING("%s(): %u addresses were obtained", __FUNCTION__, addrs_num);

    if (addrs_num == 0)
    {
        ERROR("%s(): no suitable addresses were found on Tester",
              __FUNCTION__);
        rc = TE_ENOENT;
        goto cleanup;
    }

cleanup:

    free(addrs_hndls);
    free(addr_str);
    if (rc != 0)
    {
        free(addrs);
    }
    else
    {
        *addrs_out = addrs;
        *addrs_num_out = addrs_num;
    }

    return rc;
}

/* See description in sockapi-ts.h */
void
sockts_check_blocking(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst,
                      void *func, te_bool is_send, int iut_fd, int tst_fd,
                      te_bool flag, size_t data_size, char *stage_fmt, ...)
{
    te_bool  operation_done = FALSE;
    char    *data_buf = NULL;
    ssize_t  ret;
    char     stage[1024];
    va_list  arg;

    va_start(arg, stage_fmt);
    vsnprintf(stage, sizeof(stage), stage_fmt, arg);
    va_end(arg);

    data_buf = te_make_buf_by_len(data_size);

    pco_iut->op = RCF_RPC_CALL;
    rpc_call_send_recv(pco_iut, func, is_send, iut_fd,
                       data_buf, data_size, 0);
    MSLEEP(pco_iut->def_timeout / 20);

    rcf_rpc_server_is_op_done(pco_iut, &operation_done);
    RING("%s: %s, operation is %sdone", pco_iut->name,
         flag ? "blocking" : "non-blocking",
         operation_done ? "" : "not ");

    /* Unblock blocking call */
    if (flag)
    {
        if (is_send)
        {
            void *buf = NULL;
            size_t num = 0;

            rpc_read_fd(pco_tst, tst_fd, TAPI_WAIT_NETWORK_DELAY, 0, &buf,
                        &num);

            free(buf);
        }
        else
            rpc_write(pco_tst, tst_fd, data_buf, data_size);
    }

    RPC_AWAIT_ERROR(pco_iut);
    ret = rpc_call_send_recv(pco_iut, func, is_send, iut_fd,
                             data_buf, data_size, 0);

    if (flag)
    {
        if (ret < 0)
        {
            if (TE_RC_GET_ERROR(RPC_ERRNO(pco_iut)) == TE_ERPCTIMEOUT)
            {
                TEST_VERDICT("%s: Tested function was not unblocked", stage);
            }
            else
            {
                TEST_VERDICT("%s: Failed unexpectedly with errno %r",
                             stage, RPC_ERRNO(pco_iut));
            }
        }
        else if (ret != (ssize_t)data_size)
        {
            TEST_VERDICT("%s: Function returned wrong received/sent data size",
                         stage);
        }
    }
    else
    {
        if (ret >= 0)
        {
            TEST_VERDICT("%s: Function succeeded unexpectedly", stage);
        }
        else if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        {
            TEST_VERDICT("%s: Failed with %r errno instead of EAGAIN",
                         stage, RPC_ERRNO(pco_iut));
        }
    }

    if (operation_done == flag)
    {
        TEST_VERDICT("%s: Wrong blocking state of file descriptor on %s",
                     stage, pco_iut->name);
    }

    free(data_buf);
}

/* See description in sockapi-ts.h */
void
sockts_init_pat_sender_receiver(tapi_pat_sender *send_ctx,
                                tapi_pat_receiver *recv_ctx,
                                int min_pkt_len, int max_pkt_len,
                                int transmit_time, int receive_time,
                                unsigned int time2wait)
{
    tarpc_pat_gen_arg *pat_arg = NULL;

    tapi_pat_sender_init(send_ctx);
    send_ctx->gen_func = RPC_PATTERN_GEN_LCG;
    tapi_rand_gen_set(&send_ctx->size, min_pkt_len, max_pkt_len, 0);
    send_ctx->duration_sec = transmit_time;
    send_ctx->time2wait = time2wait;

    pat_arg = &send_ctx->gen_arg;
    pat_arg->offset = 0;
    pat_arg->coef1 = rand_range(0, RAND_MAX);
    pat_arg->coef2 = rand_range(1, RAND_MAX);
    pat_arg->coef3 = rand_range(0, RAND_MAX);

    tapi_pat_receiver_init(recv_ctx);
    recv_ctx->gen_func = RPC_PATTERN_GEN_LCG;
    recv_ctx->duration_sec = receive_time;
    recv_ctx->time2wait = time2wait;
    memcpy(&recv_ctx->gen_arg, pat_arg, sizeof(*pat_arg));
}

ssize_t
sockts_sendmsg_with_cmsg(rcf_rpc_server *pco,
                         int socket,
                         const struct sockaddr *addr,
                         te_bool with_cmsg,
                         int cmsg_level,
                         int cmsg_type,
                         int data,
                         void *buffer,
                         ssize_t buflen)
{
    rpc_msghdr         *msg;
    struct cmsghdr     *cmsg;
    socklen_t addrlen = addr == NULL ? 0: te_sockaddr_get_size(addr);
    ssize_t rc;

    msg = sockts_make_msghdr(addrlen, 1, &buflen,
                             with_cmsg ? CMSG_SPACE(sizeof(data)) : 0);
    memcpy(msg->msg_name, addr, addrlen);
    memcpy(msg->msg_iov->iov_base, buffer, buflen);

    if (with_cmsg)
    {
        cmsg = rpc_cmsg_firsthdr(msg);
        cmsg->cmsg_level = cmsg_level;
        cmsg->cmsg_type = cmsg_type;
        cmsg->cmsg_len = CMSG_LEN(sizeof(data));
        memcpy(CMSG_DATA(cmsg), &data, sizeof(data));
    }

    rc = rpc_sendmsg(pco, socket, msg, 0);

    sockts_free_msghdr(msg);
    return rc;
}

/* See description in sockapi-ts.h */
void
sockts_send_check_field_cmsg(rcf_rpc_server *pco_sender,
                             rcf_rpc_server *pco_receiver,
                             int sender_s, int receiver_s,
                             const struct sockaddr *receiver_addr,
                             csap_handle_t csap,
                             const char *field_name,
                             const char *field_labels,
                             const char *exp_value_name,
                             int expected_field_value,
                             const char *unexp_value_name,
                             int unexpected_field_value,
                             te_bool with_cmsg,
                             int cmsg_level,
                             int cmsg_type,
                             int data,
                             te_bool *test_failed,
                             const char *err_msg)
{
    const ssize_t           buflen = 256;
    char                   *msg_buf = te_make_buf_by_len(buflen);
    char                    rx_buf[buflen];
    int                     rc = 0;

    rc = sockts_sendmsg_with_cmsg(pco_sender, sender_s, receiver_addr,
                                  with_cmsg, cmsg_level, cmsg_type, data,
                                  msg_buf, buflen);

    if (rc != buflen)
        TEST_VERDICT("%s: only part of data sent", err_msg);

    RPC_AWAIT_ERROR(pco_receiver);
    rc = rpc_recv(pco_receiver, receiver_s, rx_buf,
                  sizeof(rx_buf), 0);

    if (rc < 0)
    {
        TEST_VERDICT("%s: recv() failed with %r", err_msg,
                     RPC_ERRNO(pco_receiver));
    }

    if (rc != buflen)
        TEST_VERDICT("%s: only part of data received", err_msg);

    if (memcmp(msg_buf, rx_buf, buflen))
        TEST_VERDICT("%s: invalid data received", err_msg);

    if (csap != CSAP_INVALID_HANDLE)
    {
        sockts_check_field(pco_receiver, field_name, field_labels,
                           exp_value_name, expected_field_value,
                           unexp_value_name, unexpected_field_value,
                           csap, test_failed, err_msg);
    }

    free(msg_buf);
}

/* See description in sockapi-ts.h */
te_bool
sockts_iface_is_iut(tapi_env *env, const char *name)
{
    const tapi_env_if *env_if = tapi_env_get_env_if(env, name);

    if (env_if == NULL)
        TEST_FAIL("There is no '%s' interface in environment", name);

    if (env_if->net == NULL)
        TEST_FAIL("There is no network pointer for '%s' interface", name);

    return (env_if->net->type == TAPI_ENV_IUT);
}

/* See description in sockapi-ts.h */
void
sockts_kmemleak_get_report(const char *ta)
{
    rpc_wait_status rc;
    char *out_str = NULL;
    rcf_rpc_server *pco_kmemleak= NULL;

    CHECK_RC(rcf_rpc_server_create(ta, "pco_kmemleak",
                                   &pco_kmemleak));

    /* Scanning and reading may take more than 10 seconds on some hosts */
    pco_kmemleak->timeout = pco_kmemleak->def_timeout = TE_SEC2MS(60);

    RPC_AWAIT_IUT_ERROR(pco_kmemleak);
    rc = rpc_system(pco_kmemleak, "echo scan > " SOCKTS_SYS_KERN_DBG_KMEMLEAK);
    if (rc.value != 0)
    {
        ERROR_VERDICT("%s() intermediate memory scan failed", __func__);
        goto cleanup;
    }

    RPC_AWAIT_IUT_ERROR(pco_kmemleak);
    rc = rpc_shell_get_all(pco_kmemleak, &out_str,
                           "cat " SOCKTS_SYS_KERN_DBG_KMEMLEAK, -1);
    if (rc.value != 0)
        ERROR_VERDICT("%s() getting report from kmemleak failed", __func__);

    if (out_str != NULL)
    {
        if (out_str[0] != '\0')
        {
            ERROR_VERDICT("Kmemleak detected possible kernel memory leaks");
            WARN("%s", out_str);
        }
        free(out_str);
    }

cleanup:
    CHECK_RC(rcf_rpc_server_destroy(pco_kmemleak));
}

/* See description in sockapi-ts.h */
void
sockts_kmemleak_clear(const char *ta)
{
    rpc_wait_status rc;
    rcf_rpc_server *pco_kmemleak= NULL;

    CHECK_RC(rcf_rpc_server_create(ta, "pco_kmemleak",
                                   &pco_kmemleak));
    RPC_AWAIT_IUT_ERROR(pco_kmemleak);
    rc = rpc_system(pco_kmemleak, "echo clear > " SOCKTS_SYS_KERN_DBG_KMEMLEAK);
    if (rc.value != 0)
        ERROR_VERDICT("%s() clear the list of all current possible memory "
                      "leaks failed", __func__);

    CHECK_RC(rcf_rpc_server_destroy(pco_kmemleak));
}

/* See description in sockapi-ts.h */
te_errno
sockts_find_parent_netns(rcf_rpc_server *rpcs,
                         const char *ifname,
                         char *agent_parent,
                         char *ifname_parent)
{
    char          *parent = NULL;
    char          *point = NULL;
    char           hostname[RCF_MAX_NAME];
    cfg_val_type   type = CVT_STRING;
    int            token_pos = 0;;
    char          *token;
    int            rc = 0;

    rpc_gethostname(rpcs, hostname, sizeof(hostname));
    /* If host with domain is retrieved, leave only host name */
    point = strchr(hostname, '.');
    if (point != NULL)
       *point = '\0';

    rc = cfg_get_instance_fmt(&type, &parent,
                              "/local:/host:%s/agent:%s/interface:%s/parent:0",
                              hostname, rpcs->ta, ifname);

    if (rc != 0)
    {
        ERROR("Failed to find instance of parent of netns interface");
        return rc;
    }

    token = strtok(parent, "/");
    while (token != NULL)
    {
        switch (token_pos)
        {
            case 2:
                if (agent_parent != NULL)
                    sscanf(token, "agent:%s", agent_parent);
                break;
            case 3:
                if (ifname_parent != NULL)
                    sscanf(token, "interface:%s", ifname_parent);
                break;
            default:
                break;
        }

        token_pos++;
        token = strtok(NULL, "/");
    }

    free(parent);

    return 0;
}

/** Name of agent that would be used in tests */
static char *used_agt_name = NULL;

/** Name of interface that would be used in tests */
static char *used_interface_name = NULL;

/**
 * Initializer for used_agt_name and used_interface_name
 *
 * @param rpcs                RPC server handle
 * @param ifname              Interface name
 */
static void
sockts_init_used_params_name(rcf_rpc_server *rpcs,
                             const char *ifname)
{
    used_agt_name = malloc(RCF_MAX_NAME);
    used_interface_name = malloc(IF_NAMESIZE);

    if (sockts_not_pure_netns_used())
    {
        sockts_find_parent_netns(rpcs, ifname,
                                 used_agt_name,
                                 used_interface_name);
        return;
    }

    TE_STRLCPY(used_agt_name, rpcs->ta, RCF_MAX_NAME);
    TE_STRLCPY(used_interface_name, ifname, IF_NAMESIZE);
}

void
sockts_free_used_params_name()
{
    free(used_agt_name);
    free(used_interface_name);
}

/**
 * Determine if agent name is the same as the name of agent from env variable
 *
 * @param agt_name      Name of agent
 * @param env_agt_name  Name of env variable
 *
 * @return  @c TRUE in case of match, @c FALSE otherwise
 */
static te_bool
sockts_is_agt_name_pattern(const char *agt_name, const char *env_agt_name)
{
    char *env_name = getenv(env_agt_name);

    if (env_name != NULL)
        return (strcmp(agt_name, env_name) == 0);
    else
        ERROR("ENV variable %s is set to NULL", env_agt_name);

    return FALSE;
}

/**
 * Determine if agent name is @c TE_IUT_TA_NAME_NS
 *
 * @param agt_name    Name of agent
 *
 * @return  @c TRUE in case of match, @c FALSE otherwise
 */
static te_bool
sockts_is_agt_netns(const char *agt_name)
{
    return sockts_is_agt_name_pattern(agt_name, "TE_IUT_TA_NAME_NS");
}

/**
 * Determine if agent name is @c TE_IUT_TA_NAME
 *
 * @param agt_name    Name of agent
 *
 * @return  @c TRUE in case of match, @c FALSE otherwise
 */
static te_bool
sockts_is_agt_A(const char *agt_name)
{
    return sockts_is_agt_name_pattern(agt_name, "TE_IUT_TA_NAME");
}

/* See description in sockapi-ts.h */
char*
sockts_get_used_agt_name(rcf_rpc_server *rpcs,
                         const char *ifname)
{
    if (!sockts_is_agt_netns(rpcs->ta))
        return rpcs->ta;

    if (used_agt_name == NULL)
        sockts_init_used_params_name(rpcs, ifname);

    return used_agt_name;
}

/* See description in sockapi-ts.h */
char*
sockts_get_used_if_name(rcf_rpc_server *rpcs,
                        const char *ifname)
{
    if (!sockts_is_agt_A(rpcs->ta))
        return ifname;

    if (used_interface_name == NULL)
        sockts_init_used_params_name(rpcs, ifname);

    return used_interface_name;
}

/**
 * Extended version of sockts_find_parent_if.
 *
 * @param find_netns_parent  If @c TRUE, find parent
 *                           agent/interface for namespaced @p ifname.
 */
static void
sockts_find_parent_if_ext(rcf_rpc_server *rpcs,
                          const char *ifname,
                          tqh_strings *ifaces,
                          te_bool find_netns_parent)
{
    te_interface_kind   kind;
    tqh_strings         slaves;
    tqe_string         *slave;
    te_errno            rc = 0;
    rcf_rpc_server     *rpcs_used = rpcs;
    char               *real_ta_name = rpcs->ta;
    char                real_ifname[IF_NAMESIZE];
    char                buf[IF_NAMESIZE];
    char                netns_ifname[IF_NAMESIZE];
    char                netns_agt[RCF_MAX_NAME];

    if (sockts_not_pure_netns_used() && find_netns_parent)
    {
        if (sockts_find_parent_netns(rpcs, ifname,
                                     netns_agt,
                                     netns_ifname) == 0)
        {
            real_ta_name = netns_agt;
            TE_STRLCPY(real_ifname, netns_ifname, IF_NAMESIZE);
            CHECK_RC(rcf_rpc_server_create(real_ta_name, "rpc_used",
                                           &rpcs_used));
        }
        else
        {
            TEST_FAIL("Failed to find a parent of NETNS interface: %s.", ifname);
        }
    }
    else
    {
        TE_STRLCPY(real_ifname, ifname, IF_NAMESIZE);
    }

    CHECK_RC(tapi_cfg_get_if_kind(real_ta_name, real_ifname, &kind));

    switch (kind)
    {
        case TE_INTERFACE_KIND_NONE:
            rc = tq_strings_add_uniq_dup(ifaces, real_ifname);
            if (rc == 0)
                return;
            else if (rc != 1)
                CHECK_RC(rc);
            break;

        case TE_INTERFACE_KIND_VLAN:
        case TE_INTERFACE_KIND_MACVLAN:
        case TE_INTERFACE_KIND_IPVLAN:
            CHECK_RC(tapi_cfg_get_if_parent(real_ta_name, real_ifname, buf, sizeof(buf)));
            /*
             * In case of a net namespace the function is not able to find
             * parent interface and returns an empty string. In such case
             * consider the vlan interface as a parent one.
             */
            if (*buf != '\0')
                sockts_find_parent_if_ext(rpcs_used, buf, ifaces, FALSE);
            else
                CHECK_RC(tq_strings_add_uniq_dup(ifaces, real_ifname));
            break;

        case TE_INTERFACE_KIND_BOND:
        case TE_INTERFACE_KIND_TEAM:
            rpc_bond_get_slaves(rpcs_used, real_ifname, &slaves, NULL);
            for (slave = TAILQ_FIRST(&slaves);
                 slave != NULL;
                 slave = TAILQ_NEXT(slave, links))
            {
                sockts_find_parent_if_ext(rpcs_used, slave->v, ifaces, FALSE);
            }
            tq_strings_free(&slaves, &free);
            break;

        default:
            TEST_FAIL("Unknown kind of interface: %s.", real_ifname);
            break;
    }

    if (sockts_not_pure_netns_used() && find_netns_parent)
        rcf_rpc_server_destroy(rpcs_used);
}

/* See description in sockapi-ts.h */
void
sockts_find_parent_if(rcf_rpc_server *rpcs,
                      const char *ifname,
                      tqh_strings *ifaces)
{
    sockts_find_parent_if_ext(rpcs, ifname, ifaces, TRUE);
}